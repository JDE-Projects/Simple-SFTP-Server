"""Tests for port validation: valid_port(), and the api.py callers that gate
on it (start_server, check_port, quick_start's config-save failure path)."""

from app import paths
from app.api import Api
from app.constants import DEFAULT_PORT
from app.services.network import valid_port


def _api(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    return Api()


# ---- valid_port() ----

def test_valid_port_accepts_valid_values():
    for value, expected in (("2222", 2222), (2222, 2222), ("1", 1), ("65535", 65535)):
        ok, port, error = valid_port(value)
        assert ok is True
        assert port == expected
        assert error is None


def test_valid_port_rejects_empty_string():
    ok, port, error = valid_port("")
    assert ok is False
    assert port is None
    assert error


def test_valid_port_rejects_whitespace_only():
    ok, port, error = valid_port("   ")
    assert ok is False
    assert port is None
    assert error


def test_valid_port_rejects_non_numeric_text():
    for value in ("abc", "22.5", "2222x"):
        ok, port, error = valid_port(value)
        assert ok is False, value
        assert port is None
        assert error


def test_valid_port_rejects_zero():
    ok, port, error = valid_port("0")
    assert ok is False
    assert port is None
    assert error


def test_valid_port_rejects_negative():
    ok, port, error = valid_port("-1")
    assert ok is False
    assert port is None
    assert error


def test_valid_port_rejects_oversized():
    ok, port, error = valid_port("65536")
    assert ok is False
    assert port is None
    assert error


# ---- check_port() ----

def test_check_port_returns_error_for_invalid_input(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    for value in ("abc", "0", "-1", "65536"):
        result = api.check_port(value)
        assert "error" in result and result["error"]
        assert result["free"] is False


def test_check_port_returns_free_dict_for_valid_port(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    monkeypatch.setattr("app.api.port_is_free", lambda port: True)
    result = api.check_port("2222")
    assert result == {"free": True}


# ---- start_server() rejects invalid ports without starting the service ----

def _api_with_user(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    api._load_config = lambda: {"settings": {"port": DEFAULT_PORT},
                                 "users": [{"username": "bob", "home": str(tmp_path)}]}
    started = {"called": False}

    def fake_start(port, quick=False):
        started["called"] = True
        return {"ok": True, "port": port}

    monkeypatch.setattr(api.service, "start", fake_start)
    return api, started


def test_start_server_rejects_empty_port(tmp_path, monkeypatch):
    api, started = _api_with_user(tmp_path, monkeypatch)
    result = api.start_server("")
    assert result["ok"] is False
    assert "error" in result
    assert started["called"] is False


def test_start_server_rejects_non_numeric_port(tmp_path, monkeypatch):
    api, started = _api_with_user(tmp_path, monkeypatch)
    result = api.start_server("abc")
    assert result["ok"] is False
    assert "error" in result
    assert started["called"] is False


def test_start_server_rejects_zero_port(tmp_path, monkeypatch):
    api, started = _api_with_user(tmp_path, monkeypatch)
    result = api.start_server("0")
    assert result["ok"] is False
    assert "error" in result
    assert started["called"] is False


# ---- start_server() surfaces a config-save failure without refusing to start ----

def test_start_server_warns_but_still_starts_when_save_fails(tmp_path, monkeypatch):
    api, started = _api_with_user(tmp_path, monkeypatch)
    monkeypatch.setattr(api, "_save_config", lambda cfg: False)

    result = api.start_server("2222")

    assert started["called"] is True
    assert result["ok"] is True
    assert "warning" in result and result["warning"]
