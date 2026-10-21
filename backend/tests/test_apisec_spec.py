"""Phase 07: spec loading (JSON/YAML, limits, safe YAML, refs) and inventory extraction."""

from __future__ import annotations

import pytest

from app.scanners.apisec.inventory import build_inventory, operation_url
from app.scanners.apisec.spec import (
    MAX_DEPTH,
    MAX_SPEC_BYTES,
    SpecError,
    load_spec,
)
from tests.apifixtures import (
    CYCLIC_REF_JSON,
    EXTERNAL_REF_JSON,
    MALFORMED_SCHEMA_JSON,
    NOT_A_SPEC_JSON,
    OPENAPI3_JSON,
    OPENAPI3_YAML,
    SWAGGER2_JSON,
    as_bytes,
)


def test_load_openapi3_json_inventory() -> None:
    inv = build_inventory(load_spec(as_bytes(OPENAPI3_JSON)))
    assert inv.kind == "openapi3" and inv.version == "3.0.3"
    assert inv.servers[0].expanded == "https://api.shop.test/v1"
    keys = {o.key: o for o in inv.operations}
    assert "GET /orders/{orderId}" in keys and "POST /users" in keys
    assert keys["GET /orders/{orderId}"].mutating is False
    assert keys["GET /orders/{orderId}"].security_required is True
    assert keys["POST /users"].mutating is True
    # $ref to the User schema resolved -> sensitive property visible
    assert "isAdmin" in keys["POST /users"].request_schema_props
    assert inv.security_schemes["bearerAuth"] == "http bearer"


def test_load_swagger2_inventory() -> None:
    inv = build_inventory(load_spec(as_bytes(SWAGGER2_JSON)))
    assert inv.kind == "swagger2" and inv.version == "2.0"
    assert inv.servers[0].expanded == "https://legacy.test/api"
    put = next(o for o in inv.operations if o.key == "PUT /items/{itemId}")
    assert put.mutating and "owner_id" in put.request_schema_props


def test_load_yaml_with_server_variables() -> None:
    inv = build_inventory(load_spec(OPENAPI3_YAML.encode()))
    assert inv.kind == "openapi3"
    assert inv.servers[0].expanded == "https://yaml.test/v2"
    assert any("enum variables" in w for w in inv.warnings)


def test_yaml_safe_load_does_not_execute_tags() -> None:
    # a python/object tag must NOT be constructed (safe_load ignores/raises, never executes)
    evil = b"openapi: '3.0.0'\ninfo: !!python/object/apply:os.system ['echo pwned']\n"
    with pytest.raises(SpecError):
        load_spec(evil)


def test_external_ref_is_not_fetched() -> None:
    spec = load_spec(as_bytes(EXTERNAL_REF_JSON))
    assert spec.remote_refs == ["https://evil.test/schemas.json#/Thing"]
    assert any("remote $ref" in w and "NOT fetched" in w for w in spec.warnings)


def test_cyclic_ref_is_broken_not_infinite() -> None:
    spec = load_spec(as_bytes(CYCLIC_REF_JSON))  # must terminate
    assert spec.cyclic_refs == ["#/components/schemas/Node"]
    assert any("cyclic" in w for w in spec.warnings)


def test_malformed_and_unsupported_are_rejected() -> None:
    with pytest.raises(SpecError):
        load_spec(MALFORMED_SCHEMA_JSON.encode())
    with pytest.raises(SpecError):
        load_spec(as_bytes(NOT_A_SPEC_JSON))
    with pytest.raises(SpecError):
        load_spec(as_bytes({"openapi": "4.0.0", "paths": {}}))
    with pytest.raises(SpecError):
        load_spec(as_bytes({"swagger": "3.0", "paths": {}}))


def test_size_depth_and_operation_limits() -> None:
    with pytest.raises(SpecError, match="MB limit"):
        load_spec(b"x" * (MAX_SPEC_BYTES + 1))
    deep: dict = {"v": 1}
    node = deep
    for _ in range(MAX_DEPTH + 5):
        node["child"] = {}
        node = node["child"]
    with pytest.raises(SpecError, match="nesting"):
        load_spec(as_bytes({"openapi": "3.0.0", "info": deep, "paths": {}}))


def test_operation_url_substitutes_path_params() -> None:
    assert (
        operation_url("https://api.test/v1", "/users/{id}", {"id": "7"})
        == "https://api.test/v1/users/7"
    )
    assert operation_url("https://api.test/v1/", "/a/b", None) == "https://api.test/v1/a/b"


# ---------------------------------------------------------------------- parameter gating


def test_parameter_gating() -> None:
    from app.scanners.apisec.profile import validate_parameters

    base = {"import_id": "imp_" + "a" * 32}
    assert validate_parameters(base) == []
    assert validate_parameters({**base, "unknown_key": 1})  # unknown rejected
    # IDOR needs identities + ownership + risk ack
    idor = validate_parameters({**base, "enable_idor": True, "risk_ack": True})
    assert any("two test identities" in p for p in idor)
    # mass-assignment write needs fixture + cleanup + ops + ack
    mass = validate_parameters({**base, "enable_mass_assignment_write": True})
    assert any("fixture" in p for p in mass) and any("cleanup" in p for p in mass)
    # rate probe needs a designated op
    rate = validate_parameters({**base, "enable_rate_probe": True, "risk_ack": True})
    assert any("designated safe operation" in p for p in rate)
    # auth secret must be an env alias, not a literal
    bad_secret = validate_parameters(
        {**base, "auth_profiles": [{"alias": "a", "secret_ref": "literal-token"}]}
    )
    assert bad_secret


def test_rate_probe_count_is_capped() -> None:
    from app.scanners.apisec.profile import RATE_PROBE_MAX, parse_parameters

    p = parse_parameters({"import_id": "imp_" + "a" * 32, "rate_probe_count": RATE_PROBE_MAX})
    assert p.rate_probe_count == RATE_PROBE_MAX
    import pytest as _pytest

    with _pytest.raises(Exception):  # noqa: B017 - over the cap is rejected
        parse_parameters({"import_id": "imp_" + "a" * 32, "rate_probe_count": RATE_PROBE_MAX + 1})
