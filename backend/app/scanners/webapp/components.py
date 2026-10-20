"""Component/version detection and the CVE-catalog adapter contract (Module 5.6).

Detection uses only data the crawl already saw (headers, generator metadata, asset paths,
cookie names). Every component carries its sources, evidence and a confidence; versions
come only from explicit strings, never from guesses.

CVE matching is a contract only in this phase: `CveCatalog` is the interface a locally
imported catalog will implement (Phase 11 integrations). With no catalog imported the
check is SKIPPED with that reason; no CVE identifiers or affected versions are ever
produced by this module itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal, Protocol

from app.models.common import Confidence
from app.scanners.webapp.rules import CheckResult, EvidenceDraft, Outcome

_RANK = {Confidence.POTENTIAL: 0, Confidence.PROBABLE: 1, Confidence.CONFIRMED: 2}

HEADER_PRODUCTS = re.compile(r"(?P<name>[A-Za-z][\w.+-]{1,40})(?:/(?P<version>\d+(?:\.\d+){0,3}))?")
ASSET_LIBRARIES = re.compile(
    r"(?i)(?P<name>jquery-ui|jquery|bootstrap|angular(?:js)?|react-dom|react|vue|lodash|moment|"
    r"handlebars|backbone|underscore|dojo|ember|knockout)"
    r"(?:[-.@/]|\.min[-.])v?(?P<version>\d+\.\d+(?:\.\d+)?)"
)
GENERATOR = re.compile(r"(?P<name>[A-Za-z][\w !.-]{1,40}?)\s*v?(?P<version>\d+(?:\.\d+){0,3})?\s*$")
COOKIE_HINTS = {
    "phpsessid": "PHP",
    "jsessionid": "Java Servlet container",
    "asp.net_sessionid": "ASP.NET",
    "aspxauth": "ASP.NET",
    "laravel_session": "Laravel",
    "connect.sid": "Express (Node.js)",
    "ci_session": "CodeIgniter",
    "wordpress_logged_in": "WordPress",
}
PATH_HINTS = {
    "/wp-content/": "WordPress",
    "/wp-includes/": "WordPress",
    "/sites/default/files/": "Drupal",
    "/_next/static/": "Next.js",
    "/static/js/main.": "Create React App bundle",
}


@dataclass
class Component:
    name: str
    version: str = ""
    confidence: Confidence = Confidence.POTENTIAL
    sources: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    locations: list[str] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, str]:
        return (self.name.lower(), self.version)

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "confidence": self.confidence.value,
            "sources": self.sources,
            "evidence": self.evidence,
            "locations": self.locations[:10],
        }


class ComponentDetector:
    def __init__(self) -> None:
        self._found: dict[tuple[str, str], Component] = {}

    def _add(
        self,
        name: str,
        version: str,
        confidence: Confidence,
        source: str,
        evidence: str,
        location: str,
    ) -> None:
        name = name.strip()[:80]
        version = version.strip()[:40]
        if not name:
            return
        key = (name.lower(), version)
        comp = self._found.setdefault(key, Component(name=name, version=version))
        if _RANK[confidence] > _RANK.get(comp.confidence, 0):
            comp.confidence = confidence
        if source not in comp.sources:
            comp.sources.append(source)
        if len(comp.evidence) < 5 and evidence[:200] not in comp.evidence:
            comp.evidence.append(evidence[:200])
        if len(comp.locations) < 20 and location not in comp.locations:
            comp.locations.append(location)

    def observe_headers(self, url: str, headers: tuple[tuple[str, str], ...]) -> None:
        for name, value in headers:
            lname = name.lower()
            if lname in ("server", "x-powered-by"):
                for m in HEADER_PRODUCTS.finditer(value[:300]):
                    product = m.group("name")
                    if product.lower() in ("ubuntu", "debian", "centos", "win32", "win64", "unix"):
                        continue
                    self._add(
                        product,
                        m.group("version") or "",
                        Confidence.PROBABLE if m.group("version") else Confidence.POTENTIAL,
                        f"{name} header",
                        f"{name}: {value[:150]}",
                        url,
                    )
            elif lname in ("x-aspnet-version", "x-aspnetmvc-version"):
                label = "ASP.NET" if lname == "x-aspnet-version" else "ASP.NET MVC"
                self._add(
                    label,
                    value.strip(),
                    Confidence.PROBABLE,
                    f"{name} header",
                    f"{name}: {value[:100]}",
                    url,
                )
            elif lname == "set-cookie":
                cookie = value.split("=", 1)[0].strip().lower()
                for hint, product in COOKIE_HINTS.items():
                    if cookie.startswith(hint):
                        self._add(
                            product,
                            "",
                            Confidence.POTENTIAL,
                            "cookie name",
                            f"cookie {cookie[:60]}",
                            url,
                        )

    def observe_generator(self, url: str, generator: str) -> None:
        if not generator:
            return
        m = GENERATOR.match(generator.strip())
        if m:
            self._add(
                m.group("name"),
                m.group("version") or "",
                Confidence.PROBABLE,
                "meta generator",
                f'<meta name="generator" content="{generator[:120]}">',
                url,
            )

    def observe_resource(self, url: str) -> None:
        lowered = url.lower()
        m = ASSET_LIBRARIES.search(lowered.rsplit("?", 1)[0])
        if m:
            self._add(
                m.group("name"),
                m.group("version"),
                Confidence.PROBABLE,
                "asset path",
                url[:200],
                url,
            )
        for hint, product in PATH_HINTS.items():
            if hint in lowered:
                self._add(product, "", Confidence.POTENTIAL, "asset path", url[:200], url)
        if lowered.endswith(".map"):
            self._add("Source map", "", Confidence.CONFIRMED, "asset path", url[:200], url)

    def components(self) -> list[Component]:
        # Drop a version-less entry when the same product was also seen with a version.
        versioned = {c.name.lower() for c in self._found.values() if c.version}
        return sorted(
            (c for c in self._found.values() if c.version or c.name.lower() not in versioned),
            key=lambda c: (c.name.lower(), c.version),
        )

    def results(self) -> list[CheckResult]:
        out: list[CheckResult] = []
        for comp in self.components():
            label = f"{comp.name} {comp.version}".strip()
            out.append(
                CheckResult(
                    "WEB-COMP-001",
                    Outcome.OBSERVATION,
                    label,
                    f"{label} detected via {', '.join(comp.sources)} ({comp.confidence.value})",
                    confidence=comp.confidence,
                    evidence=EvidenceDraft(
                        evidence_type="text_excerpt", response_excerpt="\n".join(comp.evidence)
                    ),
                    data=comp.as_dict(),
                )
            )
        return out


# ---------------------------------------------------------------------- CVE adapter contract


@dataclass(frozen=True)
class CveMatch:
    cve_id: str
    component: str
    version: str
    match: Literal["exact", "range"]
    affected_range: str  # as stated by the catalog, e.g. ">=1.0,<1.2.3"
    catalog_id: str
    catalog_version: str
    references: tuple[str, ...] = ()


class CveCatalog(Protocol):
    """Implemented by a locally imported CVE catalog (never by a guessing heuristic)."""

    catalog_id: str
    catalog_version: str
    updated_at: str

    @property
    def available(self) -> bool: ...

    def match(self, product: str, version: str) -> list[CveMatch]: ...


class NoCveCatalog:
    catalog_id = "none"
    catalog_version = ""
    updated_at = ""
    reason = "No local CVE catalog has been imported; CVE matching was not performed."

    @property
    def available(self) -> bool:
        return False

    def match(self, product: str, version: str) -> list[CveMatch]:
        return []


def cve_results(components: list[Component], catalog: CveCatalog) -> list[CheckResult]:
    if not catalog.available:
        reason = getattr(catalog, "reason", "CVE catalog unavailable")
        return [CheckResult("WEB-COMP-002", Outcome.SKIPPED, "all components", reason)]
    out: list[CheckResult] = []
    for comp in components:
        label = f"{comp.name} {comp.version}".strip()
        if not comp.version:
            out.append(
                CheckResult(
                    "WEB-COMP-002",
                    Outcome.SKIPPED,
                    label,
                    "no version identified; matching would not be defensible",
                )
            )
            continue
        matches = catalog.match(comp.name, comp.version)
        if not matches:
            out.append(
                CheckResult(
                    "WEB-COMP-002",
                    Outcome.PASS,
                    label,
                    f"no entries in {catalog.catalog_id} {catalog.catalog_version} "
                    f"(updated {catalog.updated_at})",
                )
            )
        for m in matches:
            out.append(
                CheckResult(
                    "WEB-COMP-002",
                    Outcome.FINDING,
                    label,
                    f"{m.cve_id} listed for {m.component} {m.affected_range} ({m.match} match, "
                    f"catalog {m.catalog_id} {m.catalog_version})",
                    parameter=m.cve_id,
                    data={"cve": m.__dict__},
                )
            )
    return out
