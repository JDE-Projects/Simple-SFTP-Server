"""Sign-in registration and fresh-record checks around account saves."""

import threading

import paramiko

from app import paths
from app.api import Api
from app.constants import DEFAULT_PORT
from app.server import DEFAULT_PERMISSIONS, ServerIface, SFTPService
from app.services.passwords import hash_password
from simple_sftp_server import APP_VERSION
from tests.sftp_helpers import (
    CountingApi,
    authorized_key_line,
    free_port,
    make_host_key,
    make_user,
    sftp_key,
    sftp_password,
)

PASSWORD = "correct horse battery staple"


def _perms(**overrides):
    permissions = {key: True for key in DEFAULT_PERMISSIONS}
    permissions.update(overrides)
    return permissions


class _Transport:
    def __init__(self, username="alice"):
        self.username = username
        self.closed = False

    def get_username(self):
        return self.username

    def close(self):
        self.closed = True


def _iface(user):
    users = {user["username"]: user}
    service = SFTPService(CountingApi(users=users))
    transport = _Transport(user["username"])
    service._conns[1] = {"transport": transport, "thread": None, "gen": 1,
                         "ip": "127.0.0.1", "user": ""}
    return ServerIface(service, "127.0.0.1", 1, transport), service, users, transport


def _key_user(tmp_path, auth="key", comment="old"):
    key = paramiko.RSAKey.generate(1024)
    line = authorized_key_line(key) + " " + comment
    return make_user("alice", tmp_path, _perms(), auth=auth, authorized_keys=[line]), key, line


def test_key_removed_between_match_and_session_refused(tmp_path):
    user, key, _line = _key_user(tmp_path)
    iface, service, users, _transport = _iface(user)

    assert iface.check_auth_publickey("alice", key) == paramiko.AUTH_SUCCESSFUL
    users["alice"] = make_user("alice", tmp_path, _perms(), auth="key", authorized_keys=[])

    assert iface._finish_sign_in() is False
    assert service.conns_for_user("alice") == []


def test_key_comment_change_between_match_and_session_allowed(tmp_path):
    user, key, line = _key_user(tmp_path)
    iface, _service, users, _transport = _iface(user)
    renamed = line.rsplit(" ", 1)[0] + " new-comment"

    assert iface.check_auth_publickey("alice", key) == paramiko.AUTH_SUCCESSFUL
    users["alice"] = make_user("alice", tmp_path, _perms(), auth="key", authorized_keys=[renamed])

    assert iface._finish_sign_in() is True
    assert iface.key_line == renamed


def test_password_changed_during_verification_refused(tmp_path, monkeypatch):
    user = make_user("alice", tmp_path, _perms(), password=PASSWORD)
    iface, service, users, _transport = _iface(user)
    from app import server as server_module

    real_verify = server_module.verify_password

    def verify_then_change(password, password_hash):
        result = real_verify(password, password_hash)
        if result:
            users["alice"] = {**users["alice"], "password_hash": hash_password("new password")}
        return result

    monkeypatch.setattr(server_module, "verify_password", verify_then_change)

    assert iface.check_auth_password("alice", PASSWORD) == paramiko.AUTH_FAILED
    assert service.conns_for_user("alice") == []


def test_auth_method_switched_during_sign_in_refused(tmp_path):
    user, key, _line = _key_user(tmp_path, auth="both")
    iface, service, users, _transport = _iface(user)

    assert iface.check_auth_publickey("alice", key) == paramiko.AUTH_SUCCESSFUL
    users["alice"] = make_user("alice", tmp_path, _perms(), auth="password", password=PASSWORD)

    assert iface._finish_sign_in() is False
    assert service.conns_for_user("alice") == []


def test_user_deleted_during_sign_in_refused(tmp_path):
    user, key, _line = _key_user(tmp_path)
    iface, service, users, _transport = _iface(user)

    assert iface.check_auth_publickey("alice", key) == paramiko.AUTH_SUCCESSFUL
    users.pop("alice")

    assert iface._finish_sign_in() is False
    assert service.conns_for_user("alice") == []


def test_registered_then_deleted_is_disconnected(tmp_path):
    user = make_user("alice", tmp_path, _perms(), password=PASSWORD)
    iface, service, _users, transport = _iface(user)

    assert iface.check_auth_password("alice", PASSWORD) == paramiko.AUTH_SUCCESSFUL
    assert service.disconnect_user("alice") == 1
    assert transport.closed is True


def test_registration_refused_when_connection_entry_gone(tmp_path):
    user = make_user("alice", tmp_path, _perms(), password=PASSWORD)
    iface, service, _users, _transport = _iface(user)
    service._conns.pop(1)

    assert iface.check_auth_password("alice", PASSWORD) == paramiko.AUTH_FAILED
    assert service.active_conns() == []


def test_fresh_record_used_for_home_and_permissions(tmp_path):
    old_home = tmp_path / "old"
    new_home = tmp_path / "new"
    user, key, _line = _key_user(old_home)
    iface, _service, users, _transport = _iface(user)
    fresh = make_user("alice", new_home, _perms(upload=False), auth="key",
                      authorized_keys=user["authorized_keys"])

    assert iface.check_auth_publickey("alice", key) == paramiko.AUTH_SUCCESSFUL
    users["alice"] = fresh

    assert iface._finish_sign_in() is True
    assert iface.user is fresh


def test_rename_disconnects_old_and_new_name(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    api = Api(APP_VERSION)
    home = tmp_path / "home"
    home.mkdir()
    assert api._save_config({"settings": {"port": DEFAULT_PORT}, "users": []})
    assert api.save_user({"username": "old", "home": str(home), "permissions": _perms(),
                          "auth": "password", "password": PASSWORD})["ok"]
    transport = _Transport("old")
    api._service._conns[1] = {"transport": transport, "thread": None, "gen": 1,
                              "ip": "127.0.0.1", "user": "old"}

    result = api.save_user({"username": "new", "home": str(home), "permissions": _perms(),
                            "auth": "password", "password": PASSWORD}, original="old")

    assert result["ok"] is True
    assert result["disconnected"] == 1
    assert transport.closed is True


def test_quick_start_sign_in_still_works(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    monkeypatch.setattr(paths, "QUICK_FOLDER", str(tmp_path / "quick"))
    api = Api(APP_VERSION)
    api.host_key = make_host_key(tmp_path)
    api._service.host_key = api.host_key
    port = free_port()
    assert api._save_config({"settings": {"port": port}, "users": []})
    result = api.quick_start()
    assert result["ok"], result

    client, sftp = sftp_password(port, "quickstart", api._quick_password)
    try:
        assert sftp.listdir(".") == []
    finally:
        sftp.close()
        client.close()
        api.stop_server()


def test_real_password_and_key_sign_in_still_work(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    (home / "file.txt").write_text("contents")
    key = paramiko.RSAKey.generate(1024)
    user = make_user("alice", home, _perms(), auth="both", password=PASSWORD,
                     authorized_keys=[authorized_key_line(key)])
    handle = sftp_server([user])

    password_client, password_sftp = sftp_password(handle.port, "alice", PASSWORD)
    key_client, key_sftp = sftp_key(handle.port, "alice", key)
    try:
        assert password_sftp.listdir(".") == ["file.txt"]
        assert key_sftp.listdir(".") == ["file.txt"]
    finally:
        password_sftp.close()
        password_client.close()
        key_sftp.close()
        key_client.close()


def test_session_after_slow_handle_gets_current_record(tmp_path, sftp_server, monkeypatch):
    old_home = tmp_path / "old"
    new_home = tmp_path / "new"
    old_home.mkdir()
    new_home.mkdir()
    (old_home / "old.txt").write_text("old")
    (new_home / "new.txt").write_text("new")
    user = make_user("alice", old_home, _perms(), password=PASSWORD)
    handle = sftp_server([user])
    users = handle.service.api._users
    entered = threading.Event()
    release = threading.Event()
    real_activity = handle.service.activity

    def slow_activity(*args, **kwargs):
        entered.set()
        release.wait(timeout=5)
        return real_activity(*args, **kwargs)

    from app import server as server_module
    real_verify = server_module.verify_password

    def verify_then_update(password, password_hash):
        result = real_verify(password, password_hash)
        if result:
            fresh = make_user("alice", new_home, _perms(download=False), password=PASSWORD)
            fresh["password_hash"] = users["alice"]["password_hash"]
            users["alice"] = fresh
        return result

    monkeypatch.setattr(handle.service, "activity", slow_activity)
    monkeypatch.setattr(server_module, "verify_password", verify_then_update)
    client, sftp = sftp_password(handle.port, "alice", PASSWORD)
    try:
        assert entered.wait(timeout=5)
        assert sftp.listdir(".") == ["new.txt"]
    finally:
        release.set()
        sftp.close()
        client.close()
