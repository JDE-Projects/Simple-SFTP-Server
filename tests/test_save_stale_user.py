import json

from app import paths
from app.api import Api
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


def _payload(home, username="alice", **overrides):
    payload = {
        "username": username,
        "home": str(home),
        "permissions": _perms(),
        "auth": "password",
        "password": "correct horse battery staple",
    }
    payload.update(overrides)
    return payload


def _saved_user(api, home, username="alice"):
    result = api.save_user(_payload(home, username))
    assert result["ok"], result
    return next(user for user in result["users"] if user["username"] == username)


def _config(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write_config(path, config, **kwargs):
    path.write_text(json.dumps(config, **kwargs), encoding="utf-8")


def _edit_payload(home, rev, **overrides):
    return _payload(home, password="", rev=rev, **overrides)


def test_hand_edit_refused(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)
    config_path = tmp_path / "server_config.json"
    config = _config(config_path)
    config["users"][0]["permissions"]["download"] = False
    _write_config(config_path, config, indent=4)
    before = config_path.read_bytes()

    result = api.save_user(_edit_payload(home, user["rev"]), original="alice")

    assert result["ok"] is False
    assert result["stale"] is True
    assert config_path.read_bytes() == before


def test_hand_delete_refused(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)
    config_path = tmp_path / "server_config.json"
    config = _config(config_path)
    config["users"] = []
    _write_config(config_path, config, indent=2)
    before = config_path.read_bytes()

    result = api.save_user(_edit_payload(home, user["rev"]), original="alice")

    assert result["ok"] is False
    assert result["stale"] is True
    assert _config(config_path)["users"] == []
    assert config_path.read_bytes() == before


def test_hand_rename_refused(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)
    config_path = tmp_path / "server_config.json"
    config = _config(config_path)
    config["users"][0]["username"] = "renamed"
    _write_config(config_path, config, indent=2)
    before = config_path.read_bytes()

    result = api.save_user(_edit_payload(home, user["rev"]), original="alice")

    assert result["ok"] is False
    assert result["stale"] is True
    assert config_path.read_bytes() == before


def test_reformatted_file_saves(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)
    config_path = tmp_path / "server_config.json"
    _write_config(config_path, _config(config_path), indent=4, sort_keys=True)

    result = api.save_user(_edit_payload(home, user["rev"], permissions=_perms(download=False)),
                           original="alice")

    assert result["ok"] is True


def test_correct_rev_saves(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)

    result = api.save_user(_edit_payload(home, user["rev"], permissions=_perms(download=False)),
                           original="alice")

    assert result["ok"] is True
    assert api._load_config()["users"][0]["permissions"]["download"] is False


def test_missing_rev_refused(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    _saved_user(api, home)

    result = api.save_user(_payload(home, password=""), original="alice")

    assert result["ok"] is False
    assert result["stale"] is True


def test_app_rename_with_rev_saves(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)

    result = api.save_user(_edit_payload(home, user["rev"], username="renamed"), original="alice")

    assert result["ok"] is True
    assert api._load_config()["users"][0]["username"] == "renamed"


def test_other_user_change_keeps_rev(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    alice_home = tmp_path / "alice"
    bob_home = tmp_path / "bob"
    alice_home.mkdir()
    bob_home.mkdir()
    alice = _saved_user(api, alice_home)
    _saved_user(api, bob_home, "bob")
    config_path = tmp_path / "server_config.json"
    config = _config(config_path)
    next(user for user in config["users"] if user["username"] == "bob")["permissions"]["download"] = False
    _write_config(config_path, config, indent=2)

    result = api.save_user(_edit_payload(alice_home, alice["rev"], permissions=_perms(upload=False)),
                           original="alice")

    assert result["ok"] is True


def test_server_port_save_keeps_rev(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)
    config_path = tmp_path / "server_config.json"
    config = _config(config_path)
    config["settings"]["port"] = DEFAULT_PORT + 1
    _write_config(config_path, config, indent=2)

    result = api.save_user(_edit_payload(home, user["rev"], permissions=_perms(upload=False)),
                           original="alice")

    assert result["ok"] is True


def test_stale_refusal_returns_fresh_users(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)
    config_path = tmp_path / "server_config.json"
    config = _config(config_path)
    config["users"][0]["permissions"]["download"] = False
    _write_config(config_path, config, indent=2)

    stale = api.save_user(_edit_payload(home, user["rev"]), original="alice")

    fresh = stale["users"][0]
    assert fresh["permissions"]["download"] is False
    retry = api.save_user(_edit_payload(home, fresh["rev"], permissions=fresh["permissions"]),
                          original="alice")
    assert retry["ok"] is True


def test_stale_refusal_creates_no_folder(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)
    config_path = tmp_path / "server_config.json"
    config = _config(config_path)
    config["users"][0]["permissions"]["download"] = False
    _write_config(config_path, config, indent=2)
    missing_home = tmp_path / "missing" / "home"

    result = api.save_user(_edit_payload(missing_home, user["rev"]), original="alice")

    assert result["ok"] is False
    assert result["stale"] is True
    assert not missing_home.exists()
