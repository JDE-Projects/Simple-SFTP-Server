"""Phase 2 authoritative shutdown: SFTPService.stop() actively closes every
live connection and waits for all its threads to finish under one shared time
budget before reporting stopped, so an immediate restart on the same port is
clean.
"""

import time

from app.server import DEFAULT_PERMISSIONS
from tests.sftp_helpers import make_user, sftp_password


def _perms(**overrides):
    p = {k: True for k in DEFAULT_PERMISSIONS}
    p.update(overrides)
    return p


def test_stop_closes_active_client_and_clears_registry(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(), password="correct horse battery staple")
    handle = sftp_server([user])
    service = handle.service

    client, sftp = sftp_password(handle.port, "bob", "correct horse battery staple")
    try:
        assert len(service.active_conns()) == 1

        r = service.stop()
        assert r == {"ok": True}
        assert service.active_conns() == []

        deadline = time.time() + 2
        transport = client.get_transport()
        while time.time() < deadline and transport is not None and transport.is_active():
            time.sleep(0.1)
        assert transport is not None
        assert not transport.is_active()
    finally:
        client.close()


def test_stop_then_start_allows_immediate_restart_on_same_port(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(), password="correct horse battery staple")
    handle = sftp_server([user])
    service = handle.service

    client, sftp = sftp_password(handle.port, "bob", "correct horse battery staple")
    sftp.close()
    client.close()
    service.stop()

    r = service.start(handle.port)
    assert r["ok"], r

    client2, sftp2 = sftp_password(handle.port, "bob", "correct horse battery staple")
    try:
        assert len(service.active_conns()) == 1
        sftp2.listdir(".")
    finally:
        sftp2.close()
        client2.close()


def test_stop_finishes_the_servers_own_threads(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(), password="correct horse battery staple")
    handle = sftp_server([user])
    service = handle.service

    client, sftp = sftp_password(handle.port, "bob", "correct horse battery staple")
    sftp.close()
    client.close()
    service.stop()

    assert service._accept_thread is None
    assert service._pump_thread is None
