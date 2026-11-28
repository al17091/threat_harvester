"""Tests for the batch entrypoint."""

import pytest

from worker import app


def test_batch_is_the_default_mode(monkeypatch):
    calls = []
    monkeypatch.delenv("MODE", raising=False)
    monkeypatch.setattr(app.sys, "argv", ["app"])
    monkeypatch.setattr(app, "run_batch", lambda: calls.append("batch"))
    app.main()
    assert calls == ["batch"]


def test_retired_api_mode_exits_with_error(monkeypatch):
    monkeypatch.setenv("MODE", "api")
    monkeypatch.setattr(app.sys, "argv", ["app"])
    monkeypatch.setattr(app, "run_batch", lambda: pytest.fail("batch must not run"))
    with pytest.raises(SystemExit) as exit_info:
        app.main()
    assert exit_info.value.code == 2
