import pytest

from app.api import Api
from app.debug_log import debug
from simple_sftp_server import APP_VERSION


def test_debug_warnings_drain_once(monkeypatch):
    api = Api(APP_VERSION)
    monkeypatch.setattr(debug, "is_enabled", lambda: True)

    api._on_debug_warning("first")
    api._on_debug_warning("second")

    assert api.drain_debug_warnings() == {"warnings": ["first", "second"], "enabled": True}
    assert api.drain_debug_warnings() == {"warnings": [], "enabled": True}


def test_set_debug_returns_drained_warnings(monkeypatch):
    api = Api(APP_VERSION)
    api._on_debug_warning("write failed")
    monkeypatch.setattr(debug, "set_enabled", lambda on: True)
    monkeypatch.setattr(debug, "is_enabled", lambda: True)
    monkeypatch.setattr(debug, "log", lambda *args: None)

    assert api.set_debug(True) == {"ok": True, "enabled": True, "warnings": ["write failed"]}


def test_start_server_logs_and_reraises_unexpected_exception(monkeypatch):
    api = Api(APP_VERSION)
    logged = []

    def fail(port, quick):
        raise RuntimeError("simulated start failure")

    monkeypatch.setattr(api._service, "start", fail)
    monkeypatch.setattr(debug, "log", lambda *args: logged.append(args))
    monkeypatch.setattr("app.api.valid_port", lambda port: (True, 2222, ""))
    monkeypatch.setattr(api, "_load_config", lambda: {"users": [{}], "settings": {}})
    monkeypatch.setattr(api, "_save_config", lambda cfg: True)

    with pytest.raises(RuntimeError, match="simulated start failure"):
        api.start_server("2222")

    assert logged[0][0] == "start server failed"
    assert "RuntimeError: simulated start failure" in logged[0][1]
