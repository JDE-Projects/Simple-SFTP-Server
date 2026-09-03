"""Security boundary regression suite: runs a real SFTPService on a loopback
port and drives it with a real Paramiko client, covering auth, the jail that
confines every path to a user's home folder, the permission gates, transfer
byte counting, brute-force lockout, and session cleanup on disconnect.

This does not cover server-stop or account-revocation lifecycle behavior;
that is reserved for other test files.
"""

import time

import paramiko
import pytest

from app.constants import LOCKOUT_THRESHOLD
from app.server import DEFAULT_PERMISSIONS
from tests.sftp_helpers import authorized_key_line, make_user, sftp_key, sftp_password


def _perms(**overrides):
    """DEFAULT_PERMISSIONS with everything granted, except the overrides."""
    p = {k: True for k in DEFAULT_PERMISSIONS}
    p.update(overrides)
    return p


def _close(client, sftp=None):
    try:
        if sftp is not None:
            sftp.close()
    finally:
        client.close()


# ───────────── password auth ─────────────

def test_password_auth_success_can_list(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(), password="correct horse battery staple")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "correct horse battery staple")
    try:
        assert sftp.listdir(".") == []
    finally:
        _close(client, sftp)


def test_password_auth_wrong_password_rejected(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(), password="correct horse battery staple")
    handle = sftp_server([user])

    with pytest.raises(paramiko.AuthenticationException):
        sftp_password(handle.port, "bob", "wrong password")


def test_password_auth_unknown_username_rejected(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(), password="correct horse battery staple")
    handle = sftp_server([user])

    with pytest.raises(paramiko.AuthenticationException):
        sftp_password(handle.port, "nobody", "whatever")


# ───────────── key auth ─────────────

def test_key_auth_authorized_key_connects(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    client_key = paramiko.RSAKey.generate(2048)
    user = make_user("alice", home, _perms(), auth="key",
                      authorized_keys=[authorized_key_line(client_key)])
    handle = sftp_server([user])

    client, sftp = sftp_key(handle.port, "alice", client_key)
    try:
        assert sftp.listdir(".") == []
    finally:
        _close(client, sftp)


def test_key_auth_unauthorized_key_rejected(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    client_key = paramiko.RSAKey.generate(2048)
    other_key = paramiko.RSAKey.generate(2048)
    user = make_user("alice", home, _perms(), auth="key",
                      authorized_keys=[authorized_key_line(client_key)])
    handle = sftp_server([user])

    with pytest.raises(paramiko.AuthenticationException):
        sftp_key(handle.port, "alice", other_key)


def test_key_only_user_rejects_password_auth(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    client_key = paramiko.RSAKey.generate(2048)
    user = make_user("alice", home, _perms(), auth="key",
                      authorized_keys=[authorized_key_line(client_key)])
    handle = sftp_server([user])

    with pytest.raises(paramiko.AuthenticationException):
        sftp_password(handle.port, "alice", "some password")


# ───────────── jail ─────────────

def test_jail_blocks_traversal_and_absolute_paths(tmp_path, sftp_server):
    sandbox = tmp_path / "sandbox"
    home = sandbox / "home"
    home.mkdir(parents=True)
    outside_dir = sandbox / "outside"
    outside_dir.mkdir()
    outside_file = outside_dir / "secret.txt"
    outside_file.write_text("top secret")
    (home / "a.txt").write_text("in jail")

    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.stat("../outside/secret.txt")
        with pytest.raises(IOError):
            sftp.stat(str(outside_file).replace("\\", "/"))
        assert sftp.listdir(".") == ["a.txt"]
        assert sftp.listdir("/") == ["a.txt"]
    finally:
        _close(client, sftp)


def test_jail_empty_home_denies_everything(tmp_path, sftp_server):
    user = make_user("bob", "", _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.listdir(".")
        with pytest.raises(IOError):
            sftp.stat(".")
    finally:
        _close(client, sftp)


# ───────────── permission matrix ─────────────

def test_list_denied_without_list_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(list=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.listdir(".")
    finally:
        _close(client, sftp)


def test_download_denied_without_download_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    (home / "a.txt").write_bytes(b"data")
    user = make_user("bob", home, _perms(download=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.get("a.txt", str(tmp_path / "out.txt"))
    finally:
        _close(client, sftp)


def test_upload_denied_without_upload_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    src = tmp_path / "src.txt"
    src.write_bytes(b"data")
    user = make_user("bob", home, _perms(upload=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.put(str(src), "new.txt")
    finally:
        _close(client, sftp)


def test_overwrite_denied_without_delete_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    (home / "existing.txt").write_bytes(b"original")
    src = tmp_path / "src.txt"
    src.write_bytes(b"replacement")
    user = make_user("bob", home, _perms(delete=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.put(str(src), "existing.txt")
        assert (home / "existing.txt").read_bytes() == b"original"
    finally:
        _close(client, sftp)


def test_overwrite_allowed_with_delete_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    (home / "existing.txt").write_bytes(b"original")
    src = tmp_path / "src.txt"
    src.write_bytes(b"replacement")
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        sftp.put(str(src), "existing.txt")
        assert (home / "existing.txt").read_bytes() == b"replacement"
    finally:
        _close(client, sftp)


def test_remove_denied_without_delete_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    (home / "a.txt").write_bytes(b"data")
    user = make_user("bob", home, _perms(delete=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.remove("a.txt")
        assert (home / "a.txt").exists()
    finally:
        _close(client, sftp)


def test_rename_file_denied_without_rename_file_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    (home / "a.txt").write_bytes(b"data")
    user = make_user("bob", home, _perms(rename_file=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.rename("a.txt", "b.txt")
    finally:
        _close(client, sftp)


def test_rename_dir_denied_without_rename_dir_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    (home / "adir").mkdir()
    user = make_user("bob", home, _perms(rename_dir=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.rename("adir", "bdir")
    finally:
        _close(client, sftp)


def test_mkdir_denied_without_mkdir_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(mkdir=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.mkdir("newdir")
    finally:
        _close(client, sftp)


def test_rmdir_denied_without_delete_dir_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    (home / "adir").mkdir()
    user = make_user("bob", home, _perms(delete_dir=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.rmdir("adir")
    finally:
        _close(client, sftp)


# ───────────── transfer round-trip ─────────────

def test_upload_then_download_roundtrip_updates_byte_count(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    src = tmp_path / "src.bin"
    payload = b"round trip payload" * 100
    src.write_bytes(payload)
    dst = tmp_path / "dst.bin"
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        sftp.put(str(src), "f.bin")
        sftp.get("f.bin", str(dst))
        assert dst.read_bytes() == payload

        sessions = list(handle.service._sessions.values())
        assert len(sessions) == 1
        assert sessions[0]["bytes"] >= len(payload)
    finally:
        _close(client, sftp)


# ───────────── open-file attribute changes ─────────────

def test_open_file_chmod_reports_unsupported_and_leaves_mode(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "a.txt"
    target.write_bytes(b"data")
    before = target.stat().st_mode
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        f = sftp.open("a.txt", "r+")
        try:
            # Attribute change over the open handle must be refused, not
            # silently reported as done: the client sees an error and the
            # file's mode on disk is untouched.
            with pytest.raises(IOError):
                f.chmod(0o444)
        finally:
            f.close()
        assert target.stat().st_mode == before
    finally:
        _close(client, sftp)


def test_open_file_utime_reports_unsupported_and_leaves_mtime(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "a.txt"
    target.write_bytes(b"data")
    before = target.stat().st_mtime
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        f = sftp.open("a.txt", "r+")
        try:
            with pytest.raises(IOError):
                # A year-2000 timestamp, clearly different from the real one.
                f.utime((946684800, 946684800))
        finally:
            f.close()
        assert target.stat().st_mtime == before
    finally:
        _close(client, sftp)


# ───────────── lockout ─────────────

def test_lockout_blocks_then_clears(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    password = "correct horse battery staple"
    user = make_user("bob", home, _perms(), password=password)
    handle = sftp_server([user])

    for _ in range(LOCKOUT_THRESHOLD):
        with pytest.raises(paramiko.AuthenticationException):
            sftp_password(handle.port, "bob", "wrong password")

    # bob's account is now locked, but the address itself is still well
    # below the address-wide backstop, so the connection reaches the SSH
    # session and auth is rejected explicitly rather than the raw
    # connection being dropped.
    with pytest.raises(paramiko.AuthenticationException):
        sftp_password(handle.port, "bob", password)

    handle.service.lockout.clear("127.0.0.1", "bob")

    client, sftp = sftp_password(handle.port, "bob", password)
    _close(client, sftp)


# ───────────── cleanup ─────────────

def test_session_removed_after_disconnect(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    assert len(handle.service._sessions) == 1
    _close(client, sftp)

    deadline = time.time() + 2
    while time.time() < deadline and handle.service._sessions:
        time.sleep(0.05)
    assert handle.service._sessions == {}
