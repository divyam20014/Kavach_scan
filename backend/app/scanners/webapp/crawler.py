"""Bounded same-scope crawler (MASTER_SPEC Module 5.1).

- Breadth-first from the targets and seed paths; `max_depth` and `max_pages` bound it.
- Links are canonicalized (scheme/host/port lowercased, default port dropped, dot segments
  removed, fragment dropped, query parameters sorted) and deduplicated; ambiguous URLs
  that the scope canonicalizer rejects are skipped.
- Loop/trap defenses: visited set, a cap on query variants per path, and rejection of
  paths whose segments repeat (e.g. /a/b/a/b/a/b).
- Only links that pass the scope policy's STATIC check are queued; out-of-scope links are
  counted and never requested. Every request still goes through the full guard.
- robots.txt is honoured by default (policy shown in the profile); it is a crawler
  courtesy, never an authorization mechanism.
- Only HTML is parsed; obvious static assets are inventoried but not fetched.
"""

from __future__ import annotations

from collections import Counter, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit
from urllib.robotparser import RobotFileParser

from app.integrations.http_service import HttpExchange, HttpService
from app.scanners.webapp.html import HtmlInfo, parse_html
from app.scope.canonical import CanonicalizationError, normalize_target
from app.scope.engine import ScopePolicy

HTML_TYPES = ("text/html", "application/xhtml+xml")
MAX_QUERY_VARIANTS_PER_PATH = 10
MAX_SEGMENT_REPEAT = 3
MAX_URL_CHARS = 2048
SKIP_EXTENSIONS = frozenset(
    ".png .jpg .jpeg .gif .svg .ico .webp .bmp .css .js .mjs .map .woff .woff2 .ttf .eot "
    ".otf .pdf .zip .gz .tgz .rar .7z .tar .mp3 .mp4 .avi .mov .webm .wav .exe .dmg .iso "
    ".bin .msi .apk .doc .docx .xls .xlsx .ppt .pptx".split()
)
_NON_HTTP = ("javascript:", "mailto:", "tel:", "data:", "ftp:", "file:", "about:", "blob:")


def canonical_url(url: str) -> str | None:
    """Canonical form used for deduplication, or None when the URL is unusable."""
    if len(url) > MAX_URL_CHARS:
        return None
    try:
        target = normalize_target(url)
    except CanonicalizationError:
        return None
    query = urlsplit(url).query
    pairs = sorted(parse_qsl(query, keep_blank_values=True))
    return target.url + (f"?{urlencode(pairs)}" if pairs else "")


def _looks_like_loop(path: str) -> bool:
    segments = [s for s in path.split("/") if s]
    if not segments:
        return False
    counts = Counter(segments)
    return max(counts.values()) > MAX_SEGMENT_REPEAT


def _content_type(exchange: HttpExchange) -> str:
    if exchange.response is None:
        return ""
    value = exchange.response.header("Content-Type") or ""
    return value.split(";", 1)[0].strip().lower()[:100]


@dataclass
class FormRecord:
    page: str
    action: str
    method: str
    fields: list[str]
    login_form: bool  # contains a password input (key avoids the redactor's 'pass')


@dataclass
class PageRecord:
    url: str
    depth: int
    status: int | None = None
    content_type: str = ""
    title: str = ""
    bytes: int = 0
    truncated: bool = False
    final_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    redirect_blocked_to: str = ""
    parameters: list[str] = field(default_factory=list)
    links_found: int = 0
    forms: int = 0
    error: str = ""
    source: str = "crawl"  # crawl | seed | target

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class CrawlResult:
    pages: list[PageRecord] = field(default_factory=list)
    forms: list[FormRecord] = field(default_factory=list)
    out_of_scope_links: Counter[str] = field(default_factory=Counter)  # host -> count
    skipped: Counter[str] = field(default_factory=Counter)  # reason -> count
    robots: dict[str, str] = field(default_factory=dict)  # origin -> status
    resources: set[str] = field(default_factory=set)
    limit_reached: str = ""


PageCallback = Callable[[PageRecord, HttpExchange, HtmlInfo | None], None]


class Crawler:
    def __init__(
        self,
        service: HttpService,
        policy: Callable[[], ScopePolicy],
        *,
        max_pages: int,
        max_depth: int,
        respect_robots: bool,
        checkpoint: Callable[[], None],
        progress: Callable[[int, int], None] = lambda _done, _total: None,
        on_page: PageCallback | None = None,
    ) -> None:
        self.service = service
        self.policy = policy  # re-read each time: the job refreshes its guard
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.respect_robots = respect_robots
        self.checkpoint = checkpoint
        self.progress = progress
        self.on_page = on_page
        self.result = CrawlResult()  # filled incrementally: survives a mid-crawl stop
        self._robots: dict[str, RobotFileParser | None] = {}
        self._variants: Counter[str] = Counter()

    # ------------------------------------------------------------------ robots

    def _robots_for(self, url: str, result: CrawlResult) -> RobotFileParser | None:
        origin = normalize_target(url).origin
        if origin in self._robots:
            return self._robots[origin]
        parser: RobotFileParser | None = None
        exchange = self.service.fetch("GET", origin + "/robots.txt")
        if exchange.response is not None and exchange.response.status == 200:
            ctype = _content_type(exchange)
            if ctype in ("text/plain", ""):
                parser = RobotFileParser()
                text = exchange.response.body[: 256 * 1024].decode("utf-8", "replace")
                parser.parse(text.splitlines())
                result.robots[origin] = "honoured"
            else:
                result.robots[origin] = f"ignored (content type {ctype})"
        else:
            result.robots[origin] = (
                f"none (HTTP {exchange.status})" if exchange.status else "unavailable"
            )
        self._robots[origin] = parser
        return parser

    # ------------------------------------------------------------------ queueing

    def _admit(self, url: str, result: CrawlResult) -> str | None:
        """Return the canonical URL if it may be queued, else record why not."""
        if url.lower().startswith(_NON_HTTP):
            result.skipped["non_http_link"] += 1
            return None
        canonical = canonical_url(url)
        if canonical is None:
            result.skipped["unusable_url"] += 1
            return None
        decision = self.policy().is_target_in_scope(canonical)
        if not decision.allowed:
            host = urlsplit(canonical).hostname or "?"
            result.out_of_scope_links[host[:100]] += 1
            return None
        path = urlsplit(canonical).path
        ext = path[path.rfind(".") :].lower() if "." in path.rsplit("/", 1)[-1] else ""
        if ext in SKIP_EXTENSIONS:
            result.resources.add(canonical)
            result.skipped["static_asset"] += 1
            return None
        if _looks_like_loop(path):
            result.skipped["loop_suspected"] += 1
            return None
        base = canonical.split("?", 1)[0]
        if "?" in canonical:
            if self._variants[base] >= MAX_QUERY_VARIANTS_PER_PATH:
                result.skipped["query_variant_cap"] += 1
                return None
        return canonical

    # ------------------------------------------------------------------ crawl

    def crawl(self, starts: list[tuple[str, str]]) -> CrawlResult:
        """`starts` = [(url, source)] with source 'target' or 'seed'."""
        result = self.result
        queue: deque[tuple[str, int, str]] = deque()
        seen: set[str] = set()
        for url, source in starts:
            canonical = self._admit(url, result)
            if canonical and canonical not in seen:
                seen.add(canonical)
                queue.append((canonical, 0, source))
        while queue:
            self.checkpoint()
            if len(result.pages) >= self.max_pages:
                result.limit_reached = f"page limit ({self.max_pages}) reached"
                result.skipped["page_limit"] += len(queue)
                break
            url, depth, source = queue.popleft()
            if self.respect_robots:
                robots = self._robots_for(url, result)
                if robots is not None and not robots.can_fetch("*", url):
                    result.skipped["robots_disallowed"] += 1
                    continue
            if "?" in url:
                self._variants[url.split("?", 1)[0]] += 1
            page, exchange, info = self._fetch(url, depth, source)
            result.pages.append(page)
            self.progress(len(result.pages), len(result.pages) + len(queue))
            if self.on_page is not None:
                self.on_page(page, exchange, info)
            if info is None:
                continue
            for form in info.forms:
                result.forms.append(
                    FormRecord(
                        page=url,
                        action=urljoin(page.final_url or url, form.action or url)[:2048],
                        method=form.method,
                        fields=form.fields,
                        login_form=form.has_password,
                    )
                )
            base = (
                urljoin(page.final_url or url, info.base_href)
                if info.base_href
                else (page.final_url or url)
            )
            for resource in info.resources[:500]:
                result.resources.add(urljoin(base, resource)[:2048])
            if depth >= self.max_depth:
                if info.links:
                    result.skipped["depth_limit"] += len(info.links)
                continue
            for link in info.links:
                absolute = urljoin(base, link.strip())
                canonical = self._admit(absolute, result)
                if canonical is None or canonical in seen:
                    continue
                seen.add(canonical)
                queue.append((canonical, depth + 1, "crawl"))
        return result

    def _fetch(
        self, url: str, depth: int, source: str
    ) -> tuple[PageRecord, HttpExchange, HtmlInfo | None]:
        exchange = self.service.fetch("GET", url)
        page = PageRecord(url=url, depth=depth, source=source)
        page.parameters = sorted({k for k, _ in parse_qsl(urlsplit(url).query, True)})[:50]
        page.redirect_chain = [h.url for h in exchange.hops[:-1]]
        page.final_url = exchange.final_url
        if exchange.redirect_blocked is not None:
            page.redirect_blocked_to = (
                exchange.redirect_blocked.target or exchange.redirect_blocked.input
            )[:500]
        if exchange.response is None:
            page.error = (exchange.error_kind + ": " + exchange.error)[:300]
            return page, exchange, None
        response = exchange.response
        page.status = response.status
        page.content_type = _content_type(exchange)
        page.bytes = len(response.body)
        page.truncated = response.truncated
        info: HtmlInfo | None = None
        if page.content_type in HTML_TYPES and response.body:
            text = response.body.decode(_charset(response.header("Content-Type")), "replace")
            info = parse_html(text)
            page.title = info.title
            page.links_found = len(info.links)
            page.forms = len(info.forms)
        return page, exchange, info


def _charset(content_type: str | None) -> str:
    for part in (content_type or "").split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key.lower() == "charset" and value:
            name = value.strip().strip('"').lower()
            try:
                "".encode(name)
            except LookupError:
                return "utf-8"
            return name
    return "utf-8"
