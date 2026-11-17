"""Channel limits: each SSH connection gets one session channel and one SFTP
subsystem. The connection limits count TCP connections, so without this cap a
signed-in client could open many SFTP sessions over a single connection and
bypass them. These tests drive the real SFTPService over loopback.
"""

import threading
import time

import paramiko
import pytest

from app.server import DEFAULT_PERMISSIONS
from tests.sftp_helpers import make_user, sftp_password

PASSWORD = "correct horse battery staple"


def _perms():
    return {k: True for k in DEFAULT_PERMISSIONS}


def _start(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    (home / "a.txt").write_text("hello")
    user = make_user("bob", home, _perms(), password=PASSWORD)
    return sftp_server([user])


def _server_transport(service):
    conns = service.active_conns()
    assert len(conns) == 1
    return conns[0]["transport"]


def _sftp_threads(server_transport):
    """Live SFTP server threads running on the given server-side connection."""
    return [th for th in threading.enumerate()
            if isinstance(th, paramiko.SFTPServer) and th.is_alive()
            and th.sock.get_transport() is server_transport]


def _wait_for(cond, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(0.05)
    return cond()


def test_second_channel_on_one_connection_is_refused(tmp_path, sftp_server):
    handle = _start(tmp_path, sftp_server)
    service = handle.service
    client, sftp = sftp_password(handle.port, "bob", PASSWORD)
    try:
        with pytest.raises(paramiko.ChannelException):
            client.get_transport().open_session()

        # The first session still works, and only one SFTP thread exists.
        assert sftp.listdir(".") == ["a.txt"]
        assert len(_sftp_threads(_server_transport(service))) == 1
        assert service._conn_count == 1
    finally:
        sftp.close()
        client.close()

    # The connection slot is released on disconnect and a new client works.
    assert _wait_for(lambda: service._conn_count == 0 and not service.active_conns())
    client2, sftp2 = sftp_password(handle.port, "bob", PASSWORD)
    try:
        assert sftp2.listdir(".") == ["a.txt"]
    finally:
        sftp2.close()
        client2.close()


def test_second_sftp_subsystem_on_one_channel_is_refused(tmp_path, sftp_server):
    handle = _start(tmp_path, sftp_server)
    service = handle.service
    client = paramiko.SSHClient()
    # Trust exactly this test server's host key instead of accepting any key.
    client.get_host_keys().add("[127.0.0.1]:%d" % handle.port,
                               service.host_key.get_name(), service.host_key)
    client.connect("127.0.0.1", port=handle.port, username="bob", password=PASSWORD,
                   allow_agent=False, look_for_keys=False, timeout=10)
    try:
        chan = client.get_transport().open_session()
        chan.invoke_subsystem("sftp")
        server_t = _server_transport(service)
        assert _wait_for(lambda: len(_sftp_threads(server_t)) == 1)

        with pytest.raises(paramiko.SSHException):
            chan.invoke_subsystem("sftp")

        # The Paramiko client closes a channel when one of its requests is
        # refused, so the first SFTP thread winds down here. What must never
        # happen is a second thread starting alongside it.
        peak = 0
        deadline = time.time() + 0.5
        while time.time() < deadline:
            peak = max(peak, len(_sftp_threads(server_t)))
            time.sleep(0.01)
        assert peak <= 1
    finally:
        client.close()

