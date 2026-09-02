"""Phase 1 bookkeeping regression: SFTPService tracks every live Paramiko
transport in a sid-keyed registry (app.server.SFTPService._conns), stamps each
with the server generation it was accepted under, and clears the entry on
disconnect. This is pure bookkeeping: it does not change stop() behavior or
force any disconnects.
"""

import time

from app.server import DEFAULT_PERMISSIONS
from tests.sftp_helpers import make_user, sftp_password


def _perms(**overrides):
    p = {k: True for k in DEFAULT_PERMISSIONS}
    p.update(overrides)
    return p


def test_registry_tracks_live_session_and_clears_on_disconnect(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(), password="correct horse battery staple")
    handle = sftp_server([user])
    service = handle.service

    client, sftp = sftp_password(handle.port, "bob", "correct horse battery staple")
    try:
        conns = service.active_conns()
        assert len(conns) == 1
        entry = conns[0]
        assert entry["user"] == "bob"
        assert entry["gen"] == service._generation
    finally:
        sftp.close()
        client.close()

    deadline = time.time() + 5
    while time.time() < deadline and service.active_conns():
        time.sleep(0.1)
    assert service.active_conns() == []


def test_generation_increments_on_restart_and_stamps_new_connections(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(), password="correct horse battery staple")
    handle = sftp_server([user])
    service = handle.service

    g1 = service._generation

    service.stop()
    r = service.start(handle.port)
    assert r["ok"], r
    assert service._generation == g1 + 1

    client, sftp = sftp_password(handle.port, "bob", "correct horse battery staple")
    try:
        conns = service.active_conns()
        assert len(conns) == 1
        assert conns[0]["gen"] == service._generation
    finally:
        sftp.close()
        client.close()
