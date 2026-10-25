"""CVSS base-score computation via the maintained `cvss` PyPI library (TBD-019).

A base score is never trusted verbatim from an untrusted source (an operator paste, an
imported report, or a scanner rule): it is always recomputed from the vector by this
library, so `Finding.cvss.base_score` can never be fabricated or silently mismatched
from its own vector. Only CVSS v3.1 and v4.0 are supported (the versions this project
has decided to carry, TBD-019); any other version/vector is rejected outright.
"""

from __future__ import annotations

from importlib.metadata import version as _pkg_version

from cvss import CVSS3, CVSS4
from cvss.exceptions import CVSSError

CALCULATOR_NAME = "cvss"
CALCULATOR_VERSION = _pkg_version("cvss")
CALCULATOR_LABEL = f"{CALCULATOR_NAME} {CALCULATOR_VERSION}"


class CvssValidationError(ValueError):
    """A CVSS vector failed to parse, or does not match its declared version."""


def compute_base_score(version: str, vector: str) -> float:
    """Return the base score the library computes for `vector`. Raises
    `CvssValidationError` for a malformed vector or an unsupported version."""
    try:
        if version == "3.1":
            calc = CVSS3(vector)
        elif version == "4.0":
            calc = CVSS4(vector)
        else:
            raise CvssValidationError(f"unsupported CVSS version {version!r}")
    except CVSSError as exc:
        raise CvssValidationError(f"invalid CVSS {version} vector: {exc}") from exc
    return round(float(calc.base_score), 1)
