import builtins
import json

from app import atomic, paths
from app.api import CONFIG_CHANGED_ERROR, Api
from app.atomic import atomic_write_json
from app.constants import DEFAULT_PORT
from app.server import DEFAULT_PERMISSIONS
from simple_sftp_server import APP_VERSION


def _perms(**overrides):
    permissions = {name: True for name in DEFAULT_PERMISSIONS}
    permissions.update(overrides)
    return permissions


def _api(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    api = Api(APP_VERSION)
    assert api._save_config({"settings": {"port": DEFAULT_PORT}, "users": []})
    return api


def _payload(home, password="correct horse battery staple"):
    return {
        "username": "alice",
        "home": str(home),
        "permissions": _perms(),
        "auth": "password",
        "password": password,
    }


def _saved_user(api, home):
    result = api.save_user(_payload(home))
    assert result["ok"], result
    return result["users"][0]


def _config(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _change_before_final_check(monkeypatch, change):
    real_current_bytes = atomic._current_bytes

    def current_bytes(path):
        change()
        return real_current_bytes(path)

    monkeypatch.setattr(atomic, "_current_bytes", current_bytes)


def test_save_refused_when_file_changes_before_replace(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)
    config_path = tmp_path / "server_config.json"
    hand_edit = _config(config_path)
    hand_edit["settings"]["port"] = DEFAULT_PORT + 1
    hand_bytes = json.dumps(hand_edit, indent=4).encode("utf-8")
    calls = []
    monkeypatch.setattr(api._service, "disconnect_user", lambda name: calls.append(name))
    _change_before_final_check(monkeypatch, lambda: config_path.write_bytes(hand_bytes))

    result = api.save_user({**_payload(home, password=""), "rev": user["rev"]}, original="alice")

    assert result["ok"] is False
    assert result["stale"] is True
    assert result["error"] == CONFIG_CHANGED_ERROR
    assert config_path.read_bytes() == hand_bytes
    assert calls == []


def test_delete_refused_when_file_changes_before_replace(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)
    config_path = tmp_path / "server_config.json"
    hand_edit = _config(config_path)
    hand_edit["settings"]["port"] = DEFAULT_PORT + 1
    hand_bytes = json.dumps(hand_edit, indent=4).encode("utf-8")
    calls = []
    monkeypatch.setattr(api._service, "disconnect_user", lambda name: calls.append(name))
    _change_before_final_check(monkeypatch, lambda: config_path.write_bytes(hand_bytes))

    result = api.delete_user("alice", delete_folder=True, rev=user["rev"])

    assert result["ok"] is False
    assert result["stale"] is True
    assert result["error"] == CONFIG_CHANGED_ERROR
    assert _config(config_path)["users"][0]["username"] == "alice"
    assert home.is_dir()
    assert calls == []


def test_save_refused_when_file_deleted_before_replace(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)
    config_path = tmp_path / "server_config.json"

    _change_before_final_check(monkeypatch, config_path.unlink)

    result = api.save_user({**_payload(home, password="new password"), "rev": user["rev"]},
                           original="alice")

    assert result["ok"] is False
    assert result["stale"] is True
    assert not config_path.exists()


def test_save_refused_when_file_created_before_replace(tmp_path, monkeypatch):
    config_path = tmp_path / "server_config.json"
    monkeypatch.setattr(paths, "CONFIG_FILE", str(config_path))
    api = Api(APP_VERSION)
    home = tmp_path / "alice"
    home.mkdir()
    injected = b'{"settings": {"port": 2222}, "users": []}'
    _change_before_final_check(monkeypatch, lambda: config_path.write_bytes(injected))

    result = api.save_user(_payload(home))

    assert result["ok"] is False
    assert result["stale"] is True
    assert config_path.read_bytes() == injected


def test_conflict_refresh_does_not_move_unreadable_file(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)
    config_path = tmp_path / "server_config.json"
    invalid = b"{invalid json"
    _change_before_final_check(monkeypatch, lambda: config_path.write_bytes(invalid))

    result = api.save_user({**_payload(home, password=""), "rev": user["rev"]}, original="alice")

    assert result["ok"] is False
    assert result["stale"] is True
    assert config_path.read_bytes() == invalid
    assert list(tmp_path.glob("server_config.corrupt-*.json")) == []


def test_save_without_conflict_still_writes(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()

    result = api.save_user(_payload(home))

    assert result["ok"] is True
    assert _config(tmp_path / "server_config.json")["users"][0]["username"] == "alice"


def test_password_hashed_before_config_load(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    config_path = tmp_path / "server_config.json"
    order = []
    real_open = builtins.open

    def tracked_open(file, *args, **kwargs):
        if str(file) == str(config_path) and args and args[0] == "rb":
            order.append("load")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr("app.api.hash_password", lambda password: order.append("hash") or "hash")
    monkeypatch.setattr(builtins, "open", tracked_open)

    result = api.save_user(_payload(home))

    assert result["ok"] is True
    assert order[:2] == ["hash", "load"]


def test_atomic_write_without_expected_bytes_unchanged(tmp_path):
    target = tmp_path / "server_config.json"
    target.write_text('{"old": true}', encoding="utf-8")

    atomic_write_json(str(target), {"new": True})

    assert json.loads(target.read_text(encoding="utf-8")) == {"new": True}
