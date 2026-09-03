"""Phase 3 authoritative shutdown: editing or deleting a user account forces
that account's live sessions closed immediately, so revoked access takes
effect right away instead of waiting for the client to notice on its own.
Creating a brand-new user disconnects nothing, since it has no prior sessions.
"""

import time

from app import paths
from app.api import Api
from app.constants import DEFAULT_PORT
from app.server import DEFAULT_PERMISSIONS
from tests.sftp_helpers import make_user, sftp_password


def _perms(**overrides):
    p = {k: True for k in DEFAULT_PERMISSIONS}
    p.update(overrides)
    return p


def _api(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    return Api()


def _seed_config(tmp_path, api):
    api._save_config({"settings": {"port": DEFAULT_PORT}, "users": []})


# ───────────── loopback (server-level) ─────────────
def test_disconnect_user_drops_live_client(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(), password="correct horse battery staple")
    handle = sftp_server([user])
    service = handle.service

    client, sftp = sftp_password(handle.port, "bob", "correct horse battery staple")
    try:
        assert len(service.active_conns()) == 1

        dropped = service.disconnect_user("bob")
        assert dropped == 1
        assert service.active_conns() == []

        deadline = time.time() + 2
        transport = client.get_transport()
        while time.time() < deadline and transport is not None and transport.is_active():
            time.sleep(0.1)
        assert transport is not None
        assert not transport.is_active()
    finally:
        client.close()


def test_disconnect_user_with_no_sessions_returns_zero(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(), password="correct horse battery staple")
    handle = sftp_server([user])
    service = handle.service

    assert service.disconnect_user("bob") == 0


# ───────────── api wiring ─────────────
def test_save_user_edit_disconnects_that_account(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    _seed_config(tmp_path, api)
    home = tmp_path / "bob"
    home.mkdir()

    r = api.save_user({"username": "bob", "home": str(home),
                        "permissions": _perms(), "auth": "password",
                        "password": "correct horse battery staple"})
    assert r["ok"], r

    calls = []
    monkeypatch.setattr(api.service, "disconnect_user", lambda name: (calls.append(name), 1)[1])

    r = api.save_user({"username": "bob", "home": str(home),
                        "permissions": _perms(download=False), "auth": "password",
                        "password": "another horse battery staple"}, original="bob")
    assert r["ok"], r
    assert "bob" in calls
    assert r["disconnected"] == 1


def test_delete_user_disconnects_that_account(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    _seed_config(tmp_path, api)
    home = tmp_path / "bob"
    home.mkdir()

    r = api.save_user({"username": "bob", "home": str(home),
                        "permissions": _perms(), "auth": "password",
                        "password": "correct horse battery staple"})
    assert r["ok"], r

    calls = []
    monkeypatch.setattr(api.service, "disconnect_user", lambda name: (calls.append(name), 1)[1])

    r = api.delete_user("bob")
    assert r["ok"], r
    assert "bob" in calls
    assert r["disconnected"] == 1


def test_create_user_does_not_disconnect(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    _seed_config(tmp_path, api)
    home = tmp_path / "carol"
    home.mkdir()

    calls = []
    monkeypatch.setattr(api.service, "disconnect_user", lambda name: (calls.append(name), 1)[1])

    r = api.save_user({"username": "carol", "home": str(home),
                        "permissions": _perms(), "auth": "password",
                        "password": "correct horse battery staple"})
    assert r["ok"], r
    assert calls == []
    assert r["disconnected"] == 0
