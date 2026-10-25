"""Curated CWE title subset (MASTER_SPEC Module 9).

This is deliberately NOT a reproduction of the full MITRE CWE list (no bundled third-party
database, per TBD-028): it covers only the CWE IDs this codebase's own rule catalogs
(`app/scanners/{webapp,surface,apisec}/rules.py`) actually assign to a check today. Titles
are compiled by hand from the public MITRE CWE List (cwe.mitre.org) at the date below, not
fetched live (TBD-018: external lookups disabled by default) and not independently
re-verified against a live feed in this environment — flagged in TBD_DECISIONS.md for an
owner/security-reviewer sanity check, same as the existing OWASP category tables.

A CWE id outside this subset is still stored on a `Finding` (the raw id is never dropped);
it simply has no title here, and the UI must show that honestly rather than guessing one.
"""

from __future__ import annotations

CWE_SOURCE = "https://cwe.mitre.org/ (compiled by hand; not fetched live)"
CWE_IMPORTED_AT = "2026-10-25"
CWE_CATALOG_VERSION = f"curated-{CWE_IMPORTED_AT}"

CWE_TITLES: dict[int, str] = {
    79: "Cross-Site Scripting (XSS)",
    200: "Exposure of Sensitive Information to an Unauthorized Actor",
    209: "Generation of Error Message Containing Sensitive Information",
    284: "Improper Access Control",
    295: "Improper Certificate Validation",
    298: "Improper Validation of Certificate Expiration",
    306: "Missing Authentication for Critical Function",
    319: "Cleartext Transmission of Sensitive Information",
    327: "Use of a Broken or Risky Cryptographic Algorithm",
    525: "Use of Web Browser Cache Containing Sensitive Information",
    538: "Insertion of Sensitive Information into Externally-Accessible File or Directory",
    548: "Exposure of Information Through Directory Listing",
    601: "URL Redirection to Untrusted Site ('Open Redirect')",
    614: "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    639: "Authorization Bypass Through User-Controlled Key",
    693: "Protection Mechanism Failure",
    770: "Allocation of Resources Without Limits or Throttling",
    915: "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    942: "Permissive Cross-domain Policy with Untrusted Domains",
    1004: "Sensitive Cookie Without 'HttpOnly' Flag",
    1021: "Improper Restriction of Rendered UI Layers or Frames ('Clickjacking')",
    1104: "Use of Unmaintained Third Party Components",
    1188: "Insecure Default Initialization of Resource",
    1275: "Sensitive Cookie with Improper SameSite Attribute",
}


def cwe_title(cwe_id: int) -> str:
    """Best-effort title for a CWE id from the curated subset; "" when not known locally."""
    return CWE_TITLES.get(cwe_id, "")
