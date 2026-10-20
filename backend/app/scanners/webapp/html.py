"""Minimal, robust HTML extraction (stdlib parser; no JavaScript execution)."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser

MAX_LINKS = 2000
MAX_FORMS = 100
MAX_FIELDS = 100


@dataclass
class FormInfo:
    action: str
    method: str
    fields: list[str] = field(default_factory=list)
    has_password: bool = False


@dataclass
class HtmlInfo:
    title: str = ""
    links: list[str] = field(default_factory=list)  # navigable: a/area/iframe/frame
    resources: list[str] = field(default_factory=list)  # script/link/img src (not crawled)
    forms: list[FormInfo] = field(default_factory=list)
    generator: str = ""
    base_href: str = ""
    meta_refresh: str = ""


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.info = HtmlInfo()
        self._in_title = False
        self._form: FormInfo | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        info = self.info
        if tag == "title":
            self._in_title = True
        elif tag in ("a", "area") and a.get("href") and len(info.links) < MAX_LINKS:
            info.links.append(a["href"])
        elif tag in ("iframe", "frame") and a.get("src") and len(info.links) < MAX_LINKS:
            info.links.append(a["src"])
        elif tag in ("script", "img") and a.get("src") and len(info.resources) < MAX_LINKS:
            info.resources.append(a["src"])
        elif tag == "link" and a.get("href") and len(info.resources) < MAX_LINKS:
            info.resources.append(a["href"])
        elif tag == "base" and a.get("href") and not info.base_href:
            info.base_href = a["href"]
        elif tag == "meta":
            name = a.get("name", "").lower()
            if name == "generator" and not info.generator:
                info.generator = a.get("content", "")[:200]
            if a.get("http-equiv", "").lower() == "refresh":
                info.meta_refresh = a.get("content", "")[:500]
        elif tag == "form" and len(info.forms) < MAX_FORMS:
            self._form = FormInfo(
                action=a.get("action", ""), method=(a.get("method") or "GET").upper()[:10]
            )
            info.forms.append(self._form)
        elif tag in ("input", "select", "textarea", "button") and self._form is not None:
            name = a.get("name", "")
            if name and len(self._form.fields) < MAX_FIELDS and name not in self._form.fields:
                self._form.fields.append(name[:100])
            if a.get("type", "").lower() == "password":
                self._form.has_password = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self.info.title) < 300:
            self.info.title += data


def parse_html(text: str) -> HtmlInfo:
    parser = _Extractor()
    try:
        parser.feed(text)
        parser.close()
    except Exception:  # noqa: BLE001, S110 - malformed markup: keep what was extracted
        pass
    info = parser.info
    info.title = " ".join(info.title.split())[:300]
    return info
