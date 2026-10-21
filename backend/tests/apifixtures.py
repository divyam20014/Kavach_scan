"""Phase 07 fixtures: OpenAPI 3 / Swagger 2 specs (JSON+YAML), external/cyclic refs,
malformed schema, and a local HTTP fixture API that serves endpoints the checks exercise.
All services bind to 127.0.0.1 only and count requests."""

from __future__ import annotations

import json
from typing import Any

# ---------------------------------------------------------------------- spec documents

OPENAPI3_JSON: dict[str, Any] = {
    "openapi": "3.0.3",
    "info": {"title": "Shop API", "version": "2.1"},
    "servers": [{"url": "https://api.shop.test/v1"}],
    "components": {
        "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
        "schemas": {
            "User": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "email": {"type": "string"},
                    "role": {"type": "string"},
                    "isAdmin": {"type": "boolean"},
                },
                "required": ["name"],
            },
        },
    },
    "paths": {
        "/orders/{orderId}": {
            "get": {
                "operationId": "getOrder",
                "tags": ["orders"],
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "orderId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {"200": {"content": {"application/json": {}}}, "404": {}},
            },
        },
        "/users": {
            "post": {
                "operationId": "createUser",
                "requestBody": {
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/User"}}
                    }
                },
                "responses": {"201": {}},
            },
            "get": {"operationId": "listUsers", "responses": {"200": {}}},
        },
        "/health": {"get": {"operationId": "health", "responses": {"200": {}}}},
    },
}

SWAGGER2_JSON: dict[str, Any] = {
    "swagger": "2.0",
    "info": {"title": "Legacy API", "version": "1.0"},
    "host": "legacy.test",
    "basePath": "/api",
    "schemes": ["https"],
    "securityDefinitions": {"apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}},
    "paths": {
        "/items/{itemId}": {
            "get": {
                "operationId": "getItem",
                "security": [{"apiKey": []}],
                "parameters": [
                    {"name": "itemId", "in": "path", "required": True, "type": "string"}
                ],
                "responses": {"200": {}},
            },
            "put": {
                "operationId": "updateItem",
                "parameters": [
                    {
                        "name": "body",
                        "in": "body",
                        "schema": {"properties": {"title": {}, "owner_id": {}}},
                    }
                ],
                "responses": {"200": {}},
            },
        },
    },
}

OPENAPI3_YAML = """openapi: 3.0.1
info:
  title: YAML API
  version: "3.0"
servers:
  - url: https://yaml.test/v2
    variables:
      env:
        enum: [prod, staging]
paths:
  /ping:
    get:
      operationId: ping
      responses:
        "200":
          description: ok
"""

EXTERNAL_REF_JSON: dict[str, Any] = {
    "openapi": "3.0.0",
    "info": {"title": "Ext", "version": "1"},
    "paths": {
        "/x": {
            "get": {
                "operationId": "x",
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "https://evil.test/schemas.json#/Thing"}
                            }
                        }
                    }
                },
            }
        }
    },
}

CYCLIC_REF_JSON: dict[str, Any] = {
    "openapi": "3.0.0",
    "info": {"title": "Cycle", "version": "1"},
    "components": {
        "schemas": {
            "Node": {
                "type": "object",
                "properties": {"next": {"$ref": "#/components/schemas/Node"}},
            }
        }
    },
    "paths": {
        "/n": {
            "get": {
                "operationId": "n",
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Node"}}
                        }
                    }
                },
            }
        }
    },
}

MALFORMED_SCHEMA_JSON = '{"openapi": "3.0.0", "info": {"title": "Bad"}, "paths": {'  # truncated

NOT_A_SPEC_JSON: dict[str, Any] = {"hello": "world", "paths": {}}


def as_bytes(doc: Any) -> bytes:
    return json.dumps(doc).encode("utf-8")


# ---------------------------------------------------------------------- local fixture API

import socketserver  # noqa: E402
import threading  # noqa: E402
from http.server import BaseHTTPRequestHandler  # noqa: E402


class ApiHandler(BaseHTTPRequestHandler):
    """A tiny API: /health (ok), /orders/{id} returns the object for the caller's token,
    /trace raises a stack trace, /noratelimit never throttles. Counts requests."""

    requests: list[tuple[str, str, str]] = []  # (method, path, authorization)
    protocol_version = "HTTP/1.1"

    def log_message(self, *_a: object) -> None:
        return

    def _send(self, status: int, body: bytes, headers: list[tuple[str, str]] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in headers or []:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        auth = self.headers.get("Authorization", "")
        type(self).requests.append(("GET", self.path, auth))
        path = self.path.split("?", 1)[0]
        banner = [("Server", "gunicorn/20.1.0")]
        if path == "/v1/health":
            self._send(200, b'{"status":"ok"}', banner)
        elif path.startswith("/v1/orders/"):
            # object "1" belongs to token A; "2" belongs to token B. No ownership check here
            # for /v1/orders/leaky (returns the same body regardless of token = BOLA).
            oid = path.rsplit("/", 1)[-1]
            if oid == "leaky":
                self._send(200, b'{"order":"leaky-shared"}', banner)
            elif oid == "1" and "token-a" in auth:
                self._send(200, b'{"order":"1","owner":"A"}', banner)
            elif oid == "2" and "token-b" in auth:
                self._send(200, b'{"order":"2","owner":"B"}', banner)
            else:
                self._send(403, b'{"error":"forbidden"}', banner)
        elif path == "/v1/trace":
            self._send(
                500,
                b'Traceback (most recent call last):\n  File "app.py"\nValueError: boom',
                banner,
            )
        elif path == "/v1/noratelimit":
            self._send(200, b'{"ok":true}', banner)
        else:
            self._send(404, b'{"error":"not found"}', banner)


class _QuietTCP(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        return


def start_api() -> Any:
    ApiHandler.requests = []
    from http.server import HTTPServer

    class Server(HTTPServer):
        daemon_threads = True

        def handle_error(self, request: Any, client_address: Any) -> None:
            return

    server = Server(("127.0.0.1", 0), ApiHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
