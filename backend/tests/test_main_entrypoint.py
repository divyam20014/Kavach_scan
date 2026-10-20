"""`python -m app` must refuse unsafe config before uvicorn is ever started."""

import pytest

import app.__main__ as entry


def _fail_if_called(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("uvicorn.run must not be called")


@pytest.mark.parametrize(
    ("env", "fragment"),
    [
        ({"VAPT_HOST": "0.0.0.0"}, "non-loopback"),  # noqa: S104 - asserted to be refused
        ({"VAPT_PORT": "not-a-port"}, "VAPT_PORT"),
    ],
)
def test_main_refuses_bad_config_without_starting_server(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    env: dict[str, str],
    fragment: str,
) -> None:
    monkeypatch.delenv("VAPT_HOST", raising=False)
    monkeypatch.delenv("VAPT_PORT", raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(entry.uvicorn, "run", _fail_if_called)
    assert entry.main() == 2
    assert fragment in capsys.readouterr().err


def test_main_starts_uvicorn_on_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VAPT_HOST", raising=False)
    monkeypatch.delenv("VAPT_PORT", raising=False)
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(entry.uvicorn, "run", lambda target, **kw: calls.append(kw))
    assert entry.main() == 0
    assert calls == [{"host": "127.0.0.1", "port": 8765}]
