import pytest

from app.core.redaction import REDACTED, redact, redact_headers, redact_text

SECRET_SAMPLES = [
    ("Authorization: Bearer abcdefghijklmnop.qrstu", "abcdefghijklmnop"),
    ("cookie: session=s3cr3tvalue; theme=dark", "s3cr3tvalue"),
    ("Set-Cookie: sid=deadbeefcafe; HttpOnly", "deadbeefcafe"),
    ("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlX2hlcmU", "eyJzdWIiOiIxMjM0In0"),
    ("key AKIAABCDEFGHIJKLMNOP leaked", "AKIAABCDEFGHIJKLMNOP"),
    ("https://admin:hunter2@example.com/x", "hunter2"),
    ("GET /login?user=bob&password=hunter2&x=1", "hunter2"),
    ("GET /cb?access_token=tok_123456789&state=a", "tok_123456789"),
    ("password = 'p@ss w0rd'", "p@ss w0rd"),
    ("api_key: sk_live_abcdefghijklmn", "sk_live_abcdefghijklmn"),
    ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "ghp_abcdefghijklmnopqrstuvwxyz"),
    (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
        "MIIEowIBAAKCAQEA",
    ),
    ("Basic dXNlcjpodW50ZXIy", "dXNlcjpodW50ZXIy"),
]


@pytest.mark.parametrize(("text", "secret"), SECRET_SAMPLES)
def test_secret_patterns_redacted(text: str, secret: str) -> None:
    out = redact_text(text)
    assert secret not in out
    assert REDACTED in out


def test_sensitive_keys_redacted_recursively() -> None:
    data = {
        "headers": {
            "Authorization": "Bearer x",
            "Cookie": "a=b",
            "X-Api-Key": "k",
            "Accept": "text/html",
        },
        "nested": [{"password": "p"}, {"client_secret": "s"}, {"refresh_token": "t"}],
        "authorized_by": "CISO",  # must NOT be redacted (not a secret)
        "count": 3,
    }
    out = redact(data)
    assert out["headers"]["Authorization"] == REDACTED
    assert out["headers"]["Cookie"] == REDACTED
    assert out["headers"]["X-Api-Key"] == REDACTED
    assert out["headers"]["Accept"] == "text/html"
    assert out["nested"] == [
        {"password": REDACTED},
        {"client_secret": REDACTED},
        {"refresh_token": REDACTED},
    ]
    assert out["authorized_by"] == "CISO"
    assert out["count"] == 3


def test_redact_headers_list() -> None:
    assert redact_headers([("Set-Cookie", "a=b"), ("Server", "nginx")]) == {
        "Set-Cookie": REDACTED,
        "Server": "nginx",
    }


def test_benign_text_untouched_and_long_text_truncated() -> None:
    assert redact_text("Server: nginx/1.25 returned 200 OK") == "Server: nginx/1.25 returned 200 OK"
    assert redact_text("a" * 5000).endswith("[TRUNCATED]")


def test_depth_and_size_bounded() -> None:
    deep: dict[str, object] = {}
    cur = deep
    for _ in range(50):
        cur["x"] = {}
        cur = cur["x"]  # type: ignore[assignment]
    assert "TRUNCATED-DEPTH" in str(redact(deep))
    assert redact(list(range(1000)))[-1] == "[TRUNCATED-ITEMS]"


@pytest.mark.parametrize(
    "benign",
    [
        '<form><input type="password" name="password" autocomplete="off"></form>',
        "Server: nginx/1.25.3",
        "The authorization window ends 2026-12-01",
        "authorized_by=CISO reference=SOW-42",
        "Missing HttpOnly flag on session cookie",
        "GET /search?q=tokenizer&page=2",
    ],
)
def test_benign_security_text_not_over_redacted(benign: str) -> None:
    assert redact_text(benign) == benign


def test_redaction_is_idempotent() -> None:
    once = redact_text('Authorization: Bearer abcdefghijkl {"password": "x"} token=abc')
    assert redact_text(once) == once


# ---------------------------------------------------------------------- Phase 05 verification


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        (
            '{"note": "password=hunter2-in-json"}',
            "hunter2-in-json",
        ),  # key=value opening a quoted string
        ("'token=abcdef123456'", "abcdef123456"),
        ("password=trueSecretValue", "trueSecretValue"),  # only exact booleans are exempt
    ],
)
def test_key_value_secrets_inside_quotes_are_redacted(raw: str, secret: str) -> None:
    assert secret not in redact_text(raw)


def test_redaction_keeps_json_structure_and_boolean_values() -> None:
    assert redact_text('{"note": "password=x1y2z3"}') == '{"note": "password=[REDACTED]"}'
    assert redact_text("Access-Control-Allow-Credentials: true") == (
        "Access-Control-Allow-Credentials: true"
    )
    assert redact_text("token: false") == "token: false"
