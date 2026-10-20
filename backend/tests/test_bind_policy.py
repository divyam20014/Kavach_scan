import pytest

from app.core.config import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    InsecureBindError,
    load_bind_config,
)

NON_LOOPBACK = [
    "0.0.0.0",  # noqa: S104 - input asserted to be refused, never bound
    "::",
    "192.168.1.10",
    "10.0.0.1",
    "169.254.169.254",
    "example.com",
    "localhost.evil.test",
    "127.0.0.1.nip.io",
    "127.1",  # shorthand is ambiguous; only canonical literals accepted
    "",
    "[]",
    "[0.0.0.0]",
]


def test_defaults_to_localhost() -> None:
    cfg = load_bind_config({})
    assert cfg.host == DEFAULT_HOST == "127.0.0.1"
    assert cfg.port == DEFAULT_PORT


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("127.0.0.1", "127.0.0.1"),
        ("127.0.0.2", "127.0.0.2"),
        (" 127.0.0.1 ", "127.0.0.1"),
        ("::1", "::1"),
        ("[::1]", "::1"),
        ("0:0:0:0:0:0:0:1", "::1"),
        ("localhost", "127.0.0.1"),
        ("LOCALHOST", "127.0.0.1"),
    ],
)
def test_loopback_hosts_allowed_and_canonicalized(raw: str, expected: str) -> None:
    assert load_bind_config({"VAPT_HOST": raw}).host == expected


@pytest.mark.parametrize("host", NON_LOOPBACK)
def test_non_loopback_refused(host: str) -> None:
    with pytest.raises(InsecureBindError):
        load_bind_config({"VAPT_HOST": host})


@pytest.mark.parametrize("port", ["0", "65536", "abc", "", "-1", "+80", "8_765", "80.0", "٨٠"])
def test_bad_port_rejected(port: str) -> None:
    with pytest.raises(ValueError):
        load_bind_config({"VAPT_PORT": port})


def test_port_whitespace_tolerated() -> None:
    assert load_bind_config({"VAPT_PORT": " 9000 "}).port == 9000
