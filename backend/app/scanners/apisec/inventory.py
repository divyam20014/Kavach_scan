"""Turn a resolved spec into a bounded, typed API inventory (MASTER_SPEC 7.2).

No network access here: this is the "dry inventory only" mode. Mutability is classified
from the HTTP method and operation hints; GET/HEAD/OPTIONS are read-only, everything else
is "potentially mutating" and is never probed with a write unless the operator marks it
test-safe with a fixture and cleanup (handled by the runner, not here).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urljoin

from app.scanners.apisec.spec import HTTP_METHODS, MAX_OPERATIONS, ResolvedSpec, SpecError

READ_ONLY_METHODS = frozenset({"get", "head", "options"})
MAX_PARAMS = 200
MAX_SERVERS = 50


@dataclass
class ParamInfo:
    name: str
    location: str  # query | header | path | cookie | body | formData
    required: bool = False
    type: str = ""
    schema_ref: str = ""


@dataclass
class Operation:
    op_id: str
    method: str  # upper
    path: str  # templated path as written in the spec
    summary: str = ""
    tags: list[str] = field(default_factory=list)
    deprecated: bool = False
    auth_schemes: list[str] = field(default_factory=list)
    security_required: bool = False
    parameters: list[ParamInfo] = field(default_factory=list)
    request_content_types: list[str] = field(default_factory=list)
    request_schema_props: list[str] = field(default_factory=list)
    request_required_props: list[str] = field(default_factory=list)
    response_codes: list[str] = field(default_factory=list)
    response_content_types: list[str] = field(default_factory=list)
    mutating: bool = False

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"

    def as_dict(self) -> dict[str, Any]:
        d = dict(self.__dict__)
        d["parameters"] = [p.__dict__ for p in self.parameters]
        d["key"] = self.key
        return d


@dataclass
class ServerUrl:
    raw: str
    expanded: str
    variables: dict[str, str] = field(default_factory=dict)


@dataclass
class ApiInventory:
    kind: str
    version: str
    title: str
    spec_title_version: str
    servers: list[ServerUrl]
    operations: list[Operation]
    security_schemes: dict[str, str]  # name -> type/description
    warnings: list[str]
    remote_refs: list[str]
    cyclic_refs: list[str]
    global_security: bool  # a top-level security requirement exists

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "version": self.version,
            "title": self.title,
            "spec_title_version": self.spec_title_version,
            "servers": [s.__dict__ for s in self.servers],
            "operations": [o.as_dict() for o in self.operations],
            "security_schemes": self.security_schemes,
            "warnings": self.warnings,
            "remote_refs": self.remote_refs,
            "cyclic_refs": self.cyclic_refs,
            "global_security": self.global_security,
            "operation_count": len(self.operations),
        }


def _expand_servers_openapi(raw: dict[str, Any], warnings: list[str]) -> list[ServerUrl]:
    out: list[ServerUrl] = []
    for server in raw.get("servers", []) or []:
        if not isinstance(server, dict):
            continue
        url = str(server.get("url", "")).strip()
        if not url:
            continue
        variables = server.get("variables", {}) or {}
        values: dict[str, str] = {}
        ambiguous = False
        expanded = url
        for name, var in variables.items() if isinstance(variables, dict) else []:
            default = str(var.get("default", "")) if isinstance(var, dict) else ""
            if not default and isinstance(var, dict) and var.get("enum"):
                default = str(var["enum"][0])
                ambiguous = True
            values[name] = default
            expanded = expanded.replace("{" + name + "}", default)
        if ambiguous:
            warnings.append(f"server {url!r} has enum variables; used the first/default value")
        if "{" in expanded:
            warnings.append(f"server {url!r} still has unresolved variables after defaults")
        out.append(ServerUrl(raw=url, expanded=expanded, variables=values))
        if len(out) >= MAX_SERVERS:
            break
    return out


def _servers_swagger(raw: dict[str, Any]) -> list[ServerUrl]:
    host = str(raw.get("host", "")).strip()
    base_path = str(raw.get("basePath", "") or "").strip()
    schemes = raw.get("schemes") or (["https"] if host else [])
    out: list[ServerUrl] = []
    for scheme in schemes:
        if host:
            url = f"{scheme}://{host}{base_path}"
            out.append(ServerUrl(raw=url, expanded=url))
    return out


def _security_scheme_names(raw: dict[str, Any], kind: str) -> dict[str, str]:
    if kind == "openapi3":
        schemes = (raw.get("components", {}) or {}).get("securitySchemes", {}) or {}
    else:
        schemes = raw.get("securityDefinitions", {}) or {}
    out: dict[str, str] = {}
    if isinstance(schemes, dict):
        for name, scheme in schemes.items():
            if isinstance(scheme, dict):
                kind_s = str(scheme.get("type", "?"))
                extra = scheme.get("scheme") or scheme.get("in") or ""
                out[str(name)] = f"{kind_s}{(' ' + str(extra)) if extra else ''}"
    return out


def _params(method_obj: dict[str, Any], path_obj: dict[str, Any], kind: str) -> list[ParamInfo]:
    out: list[ParamInfo] = []
    seen: set[tuple[str, str]] = set()
    for source in (path_obj, method_obj):
        for param in source.get("parameters", []) or []:
            if not isinstance(param, dict):
                continue
            name = str(param.get("name", ""))
            location = str(param.get("in", ""))
            if not name or (name, location) in seen:
                continue
            seen.add((name, location))
            schema = param.get("schema") if kind == "openapi3" else param
            ptype = str(schema.get("type", "")) if isinstance(schema, dict) else ""
            out.append(
                ParamInfo(
                    name=name[:120],
                    location=location[:20],
                    required=bool(param.get("required", location == "path")),
                    type=ptype[:40],
                )
            )
            if len(out) >= MAX_PARAMS:
                return out
    return out


def _request_body(method_obj: dict[str, Any], kind: str) -> tuple[list[str], list[str], list[str]]:
    content_types: list[str] = []
    props: list[str] = []
    required: list[str] = []
    if kind == "openapi3":
        body = method_obj.get("requestBody", {}) or {}
        content = body.get("content", {}) if isinstance(body, dict) else {}
        for ctype, media in content.items() if isinstance(content, dict) else []:
            content_types.append(str(ctype)[:80])
            schema = media.get("schema", {}) if isinstance(media, dict) else {}
            props += [str(p) for p in (schema.get("properties", {}) or {})][:200]
            required += [str(p) for p in (schema.get("required", []) or [])][:200]
    else:
        for param in method_obj.get("parameters", []) or []:
            if isinstance(param, dict) and param.get("in") == "body":
                schema = param.get("schema", {}) or {}
                props += [str(p) for p in (schema.get("properties", {}) or {})][:200]
                required += [str(p) for p in (schema.get("required", []) or [])][:200]
                content_types += [str(c) for c in (method_obj.get("consumes", []) or [])][:20]
    return (
        list(dict.fromkeys(content_types)),
        list(dict.fromkeys(props)),
        list(dict.fromkeys(required)),
    )


def build_inventory(spec: ResolvedSpec) -> ApiInventory:
    raw = spec.raw
    info = raw.get("info", {}) or {}
    title = str(info.get("title", "API"))[:200]
    spec_tv = f"{title} {info.get('version', '')}".strip()[:200]
    warnings = list(spec.warnings)
    if spec.kind == "openapi3":
        servers = _expand_servers_openapi(raw, warnings)
    else:
        servers = _servers_swagger(raw)
    if not servers:
        warnings.append("spec declares no server URL; requests require an explicit in-scope server")
    schemes = _security_scheme_names(raw, spec.kind)
    global_security = bool(raw.get("security"))
    paths = raw.get("paths", {}) or {}
    if not isinstance(paths, dict):
        raise SpecError("'paths' must be a mapping")
    operations: list[Operation] = []
    for path, path_obj in paths.items():
        if not isinstance(path_obj, dict):
            continue
        for method in HTTP_METHODS:
            method_obj = path_obj.get(method)
            if not isinstance(method_obj, dict):
                continue
            security = method_obj.get("security", raw.get("security"))
            auth_schemes: list[str] = []
            for req in security or []:
                if isinstance(req, dict):
                    auth_schemes += list(req.keys())
            content_types, props, required = _request_body(method_obj, spec.kind)
            responses = raw_responses(method_obj)
            operations.append(
                Operation(
                    op_id=str(method_obj.get("operationId", f"{method}:{path}"))[:150],
                    method=method.upper(),
                    path=str(path)[:500],
                    summary=str(method_obj.get("summary", ""))[:300],
                    tags=[str(t)[:60] for t in (method_obj.get("tags", []) or [])][:20],
                    deprecated=bool(method_obj.get("deprecated")),
                    auth_schemes=list(dict.fromkeys(auth_schemes))[:10],
                    security_required=security is not None and len(security) > 0,
                    parameters=_params(method_obj, path_obj, spec.kind),
                    request_content_types=content_types,
                    request_schema_props=props,
                    request_required_props=required,
                    response_codes=responses[0],
                    response_content_types=responses[1],
                    mutating=method not in READ_ONLY_METHODS,
                )
            )
            if len(operations) > MAX_OPERATIONS:
                raise SpecError(f"spec has more than {MAX_OPERATIONS} operations")
    return ApiInventory(
        kind=spec.kind,
        version=spec.version,
        title=title,
        spec_title_version=spec_tv,
        servers=servers,
        operations=operations,
        security_schemes=schemes,
        warnings=warnings,
        remote_refs=spec.remote_refs,
        cyclic_refs=spec.cyclic_refs,
        global_security=global_security,
    )


def raw_responses(method_obj: dict[str, Any]) -> tuple[list[str], list[str]]:
    responses = method_obj.get("responses", {}) or {}
    codes = [str(c) for c in responses][:40] if isinstance(responses, dict) else []
    ctypes: list[str] = []
    if isinstance(responses, dict):
        for resp in responses.values():
            content = resp.get("content", {}) if isinstance(resp, dict) else {}
            ctypes += [str(c) for c in content][:20] if isinstance(content, dict) else []
            produces = method_obj.get("produces", []) or []
            ctypes += [str(c) for c in produces][:20]
    return codes, list(dict.fromkeys(ctypes))[:20]


def operation_url(server: str, path: str, path_params: dict[str, str] | None = None) -> str:
    """Build a concrete URL from a server base and a templated path (params substituted).

    A path parameter is ONE path segment (RFC 6570 simple string expansion): it must never
    introduce a `/`, a scheme, or a host. Each value is percent-encoded before substitution so
    an operator-entered object ID (e.g. IDOR ownership mapping) or a parameter default/example
    from the spec can never turn a relative path into an absolute URL pointing elsewhere
    (`urljoin` treats a leading `scheme://` or `//host` in the remainder as absolute). This is
    defense in depth: `ScopeGuard.authorize_request` independently re-validates the final URL.
    """
    filled = path
    for name, value in (path_params or {}).items():
        filled = filled.replace("{" + name + "}", quote(str(value), safe=""))
    return urljoin(server.rstrip("/") + "/", filled.lstrip("/"))
