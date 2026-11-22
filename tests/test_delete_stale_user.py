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


def _payload(home, username="alice"):
    return {
        "username": username,
        "home": str(home),
        "permissions": _perms(),
        "auth": "password",
        "password": "correct horse battery staple",
    }


def _saved_user(api, home, username="alice"):
    result = api.save_user(_payload(home, username))
    assert result["ok"], result
    return next(user for user in result["users"] if user["username"] == username)


def _config(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write_config(path, config, **kwargs):
    path.write_text(json.dumps(config, **kwargs), encoding="utf-8")


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

    result = api.delete_user("alice", delete_folder=True, rev=user["rev"])

    assert result["ok"] is False
    assert result["stale"] is True
    assert config_path.read_bytes() == before
    assert home.is_dir()


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

    result = api.delete_user("alice", rev=user["rev"])

    assert result["ok"] is False
    assert result["stale"] is True
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

    result = api.delete_user("alice", rev=user["rev"])

    assert result["ok"] is False
    assert result["stale"] is True
    assert config_path.read_bytes() == before
    assert _config(config_path)["users"][0]["username"] == "renamed"


def test_missing_rev_refused(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    _saved_user(api, home)

    result = api.delete_user("alice")

    assert result["ok"] is False
    assert result["stale"] is True
    assert _config(tmp_path / "server_config.json")["users"][0]["username"] == "alice"


def test_correct_rev_deletes(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)

    result = api.delete_user("alice", rev=user["rev"])

    assert result["ok"] is True
    assert _config(tmp_path / "server_config.json")["users"] == []


def test_correct_rev_deletes_folder(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "elsewhere" / "alice-home"
    home.mkdir(parents=True)
    (home / "file.txt").write_text("hello", encoding="utf-8")
    user = _saved_user(api, home)

    result = api.delete_user("alice", delete_folder=True, rev=user["rev"])

    assert result["ok"] is True
    assert not home.exists()


def test_reformatted_file_deletes(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)
    config_path = tmp_path / "server_config.json"
    _write_config(config_path, _config(config_path), indent=4, sort_keys=True)

    result = api.delete_user("alice", rev=user["rev"])

    assert result["ok"] is True


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

    result = api.delete_user("alice", rev=alice["rev"])

    assert result["ok"] is True
    bob = _config(config_path)["users"][0]
    assert bob["username"] == "bob"
    assert bob["permissions"]["download"] is False


def test_server_port_save_keeps_rev(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)
    config_path = tmp_path / "server_config.json"
    config = _config(config_path)
    config["settings"]["port"] = DEFAULT_PORT + 1
    _write_config(config_path, config, indent=2)

    result = api.delete_user("alice", rev=user["rev"])

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

    stale = api.delete_user("alice", rev=user["rev"])

    fresh = stale["users"][0]
    assert fresh["permissions"]["download"] is False
    retry = api.delete_user("alice", rev=fresh["rev"])
    assert retry["ok"] is True


def test_stale_refusal_does_not_disconnect(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)
    config_path = tmp_path / "server_config.json"
    config = _config(config_path)
    config["users"][0]["permissions"]["download"] = False
    _write_config(config_path, config, indent=2)
    calls = []
    monkeypatch.setattr(api._service, "disconnect_user", lambda name: calls.append(name))

    result = api.delete_user("alice", rev=user["rev"])

    assert result["ok"] is False
    assert result["stale"] is True
    assert calls == []


def test_stale_refusal_message_matches_save(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    user = _saved_user(api, home)
    config_path = tmp_path / "server_config.json"
    config = _config(config_path)
    config["users"][0]["permissions"]["download"] = False
    _write_config(config_path, config, indent=2)

    delete_result = api.delete_user("alice", rev=user["rev"])
    save_result = api.save_user(
        {**_payload(home), "password": "", "rev": user["rev"]}, original="alice")

    assert delete_result["error"] == save_result["error"]
