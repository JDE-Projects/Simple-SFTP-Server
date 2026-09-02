"""Phase 4 authoritative shutdown: the remaining end-to-end loopback scenarios
not already covered by test_shutdown.py (active-client Stop, immediate
restart) or test_revocation.py (server-level and API-spy revocation). This
file covers a mid-flight transfer teardown, a Quick Start teardown through the
real Api, and one true end-to-end revocation of a live connected client.
"""

import time

from app import paths
from app.api import Api
from app.server import DEFAULT_PERMISSIONS
from tests.sftp_helpers import free_port, make_host_key, make_user, sftp_password


def _perms(**overrides):
    p = {k: True for k in DEFAULT_PERMISSIONS}
    p.update(overrides)
    return p


def test_stop_tears_down_a_mid_flight_transfer(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(), password="correct horse battery staple")
    handle = sftp_server([user])
    service = handle.service

    client, sftp = sftp_password(handle.port, "bob", "correct horse battery staple")
    f = None
    try:
        f = sftp.open("big.bin", "wb")
        f.write(b"0" * 500000)

        conns = service.connections()
        assert conns and conns[0]["active"] >= 1

        r = service.stop()
        assert r == {"ok": True}
        assert service.active_conns() == []
        assert service._accept_thread is None
        assert service._pump_thread is None
    finally:
        if f is not None:
            try:
                f.close()
            except Exception:
                pass
        client.close()


def test_quick_start_teardown(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    monkeypatch.setattr(paths, "QUICK_FOLDER", str(tmp_path / "quick"))
    api = Api()
    api.service.host_key = make_host_key(tmp_path)

    port = free_port()
    api._save_config({"settings": {"port": port}, "users": []})

    r = api.quick_start()
    assert r["ok"], r
    password = api._quick_password

    client, sftp = sftp_password(port, "quickstart", password)
    try:
        assert len(api.service.active_conns()) == 1
    finally:
        client.close()

    api.stop_server()
    assert api.service.running is False
    assert api.service.active_conns() == []
    assert api._quick_user is None
    assert api.service._accept_thread is None
    assert api.service._pump_thread is None


def test_revoking_a_user_kicks_their_live_client(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    api = Api()
    api.service.host_key = make_host_key(tmp_path)

    home = tmp_path / "bob"
    home.mkdir()
    r = api.save_user({"username": "bob", "home": str(home),
                        "permissions": _perms(), "auth": "password",
                        "password": "correct horse battery staple"})
    assert r["ok"], r

    port = free_port()
    r = api.service.start(port)
    assert r["ok"], r

    client = None
    try:
        client, sftp = sftp_password(port, "bob", "correct horse battery staple")
        assert len(api.service.active_conns()) == 1

        r = api.save_user({"username": "bob", "home": str(home),
                            "permissions": _perms(download=False), "auth": "password",
                            "password": "a new horse battery staple"}, original="bob")
        assert r["ok"], r

        assert api.service.active_conns() == []

        deadline = time.time() + 2
        transport = client.get_transport()
        while time.time() < deadline and transport is not None and transport.is_active():
            time.sleep(0.1)
        assert transport is not None
        assert not transport.is_active()
    finally:
        if client is not None:
            client.close()
        api.service.stop()
