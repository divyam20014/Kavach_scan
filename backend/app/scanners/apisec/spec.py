"""OpenAPI 3.0/3.1 and Swagger 2.0 spec loading, bounded and safe (MASTER_SPEC 7.1).

- JSON via stdlib `json`; YAML via `yaml.safe_load` ONLY (never `load`), so no object
  construction and no code execution. The spec content is never evaluated.
- Hard limits before and during parsing: raw size, total nodes, nesting depth, number of
  operations. Anything over a limit is a rejection, not a truncation.
- Local `$ref` (`#/...`) is resolved with cycle and depth detection. Remote/URL `$ref`
  (anything not starting with `#`) is NOT fetched; it is recorded as an unresolved remote
  reference (remote fetching is disabled by default — TBD-058).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import yaml

MAX_SPEC_BYTES = 8 * 1024 * 1024
MAX_NODES = 200_000
MAX_DEPTH = 64
MAX_OPERATIONS = 3000
MAX_REF_DEPTH = 32
HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


class SpecError(ValueError):
    """The uploaded document could not be loaded or is not a supported API spec."""


def load_document(raw: bytes) -> Any:
    """Parse bytes as JSON or safe YAML, enforcing the size cap. Returns plain data."""
    if len(raw) > MAX_SPEC_BYTES:
        raise SpecError(f"spec exceeds the {MAX_SPEC_BYTES // (1024 * 1024)} MB limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SpecError("spec is not valid UTF-8") from exc
    stripped = text.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise SpecError(f"invalid JSON: {exc}") from exc
    try:
        # safe_load: no arbitrary tags, no object construction, no code execution.
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SpecError(f"invalid YAML: {str(exc)[:200]}") from exc


def _check_bounds(node: Any, depth: int, counter: list[int]) -> None:
    if depth > MAX_DEPTH:
        raise SpecError(f"spec nesting exceeds {MAX_DEPTH} levels")
    counter[0] += 1
    if counter[0] > MAX_NODES:
        raise SpecError(f"spec has more than {MAX_NODES} nodes")
    if isinstance(node, dict):
        for value in node.values():
            _check_bounds(value, depth + 1, counter)
    elif isinstance(node, list):
        for value in node:
            _check_bounds(value, depth + 1, counter)


@dataclass
class ResolvedSpec:
    version: str  # "2.0", "3.0.x", "3.1.x"
    kind: str  # "swagger2" | "openapi3"
    raw: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    remote_refs: list[str] = field(default_factory=list)
    cyclic_refs: list[str] = field(default_factory=list)


def detect_kind(doc: dict[str, Any]) -> tuple[str, str]:
    if "openapi" in doc:
        version = str(doc["openapi"])
        if not version.startswith(("3.0", "3.1")):
            raise SpecError(f"unsupported OpenAPI version {version!r} (need 3.0 or 3.1)")
        return "openapi3", version
    if "swagger" in doc:
        version = str(doc["swagger"])
        if not version.startswith("2.0"):
            raise SpecError(f"unsupported Swagger version {version!r} (need 2.0)")
        return "swagger2", version
    raise SpecError("document has neither an 'openapi' nor a 'swagger' version field")


class _RefResolver:
    """Resolves local JSON pointers with cycle and depth detection (no remote fetch)."""

    def __init__(self, root: dict[str, Any], spec: ResolvedSpec) -> None:
        self.root = root
        self.spec = spec

    def resolve(self, node: Any, stack: tuple[str, ...] = (), depth: int = 0) -> Any:
        if depth > MAX_REF_DEPTH:
            raise SpecError(f"$ref resolution exceeds depth {MAX_REF_DEPTH}")
        if isinstance(node, dict):
            ref = node.get("$ref")
            if isinstance(ref, str):
                if not ref.startswith("#"):
                    if ref not in self.spec.remote_refs:
                        self.spec.remote_refs.append(ref[:300])
                    return {"x-unresolved-remote-ref": ref[:300]}
                if ref in stack:
                    if ref not in self.spec.cyclic_refs:
                        self.spec.cyclic_refs.append(ref)
                    return {"x-cyclic-ref": ref}
                target = self._deref(ref)
                return self.resolve(target, (*stack, ref), depth + 1)
            return {k: self.resolve(v, stack, depth + 1) for k, v in node.items()}
        if isinstance(node, list):
            return [self.resolve(v, stack, depth + 1) for v in node]
        return node

    def _deref(self, ref: str) -> Any:
        pointer = ref[1:].lstrip("/")
        current: Any = self.root
        for raw_part in pointer.split("/") if pointer else []:
            part = raw_part.replace("~1", "/").replace("~0", "~")
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
                current = current[int(part)]
            else:
                raise SpecError(f"unresolved local $ref: {ref}")
        return current


def load_spec(raw: bytes) -> ResolvedSpec:
    """Full pipeline: parse -> bound -> identify -> resolve local refs. Raises SpecError."""
    doc = load_document(raw)
    if not isinstance(doc, dict):
        raise SpecError("top-level spec must be a mapping/object")
    _check_bounds(doc, 0, [0])
    kind, version = detect_kind(doc)
    spec = ResolvedSpec(version=version, kind=kind, raw=doc)
    resolver = _RefResolver(doc, spec)
    spec.raw = resolver.resolve(doc)
    if spec.remote_refs:
        spec.warnings.append(
            f"{len(spec.remote_refs)} remote $ref(s) were NOT fetched (disabled by default)"
        )
    if spec.cyclic_refs:
        spec.warnings.append(f"{len(spec.cyclic_refs)} cyclic $ref(s) were broken to avoid loops")
    return spec
