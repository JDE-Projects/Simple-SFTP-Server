"""Security boundary regression suite: runs a real SFTPService on a loopback
port and drives it with a real Paramiko client, covering auth, the jail that
confines every path to a user's home folder, the permission gates, transfer
byte counting, brute-force lockout, and session cleanup on disconnect.

This does not cover server-stop or account-revocation lifecycle behavior;
that is reserved for other test files.
"""

import os
import time

import paramiko
import pytest
from paramiko.sftp import CMD_FSETSTAT, CMD_SETSTAT

import app.server as server_module
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


def _upload(sftp, path):
    with sftp.open(path, "w") as f:
        f.write(b"data")


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


# ───────────── uploaded-file attribute changes ─────────────

def test_uploaded_file_utime_sets_mtime(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "uploaded.txt"
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])
    timestamp = 946684800

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        _upload(sftp, "uploaded.txt")
        sftp.utime("uploaded.txt", (timestamp, timestamp))
        assert target.stat().st_mtime == timestamp
    finally:
        _close(client, sftp)


def test_uploaded_file_utime_succeeds_after_rename(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "x"
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])
    timestamp = 946684800

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        _upload(sftp, "x.filepart")
        sftp.rename("x.filepart", "x")
        sftp.utime("x", (timestamp, timestamp))
        assert target.stat().st_mtime == timestamp
    finally:
        _close(client, sftp)


def test_utime_refuses_preexisting_file_and_leaves_mtime(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "existing.txt"
    target.write_bytes(b"data")
    timestamp = 946684800
    os.utime(target, (timestamp, timestamp))
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.utime("existing.txt", (timestamp + 1, timestamp + 1))
        assert target.stat().st_mtime == timestamp
    finally:
        _close(client, sftp)


def test_utime_refuses_folder_and_leaves_mtime(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "folder"
    target.mkdir()
    timestamp = 946684800
    os.utime(target, (timestamp, timestamp))
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.utime("folder", (timestamp + 1, timestamp + 1))
        assert target.stat().st_mtime == timestamp
    finally:
        _close(client, sftp)


def test_utime_refuses_path_outside_jail_and_leaves_mtime(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = tmp_path / "outside.txt"
    target.write_bytes(b"data")
    timestamp = 946684800
    os.utime(target, (timestamp, timestamp))
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.utime("../outside.txt", (timestamp + 1, timestamp + 1))
        assert target.stat().st_mtime == timestamp
    finally:
        _close(client, sftp)


def test_utime_refuses_user_without_upload_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "existing.txt"
    target.write_bytes(b"data")
    timestamp = 946684800
    os.utime(target, (timestamp, timestamp))
    user = make_user("bob", home, _perms(upload=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.utime("existing.txt", (timestamp + 1, timestamp + 1))
        assert target.stat().st_mtime == timestamp
    finally:
        _close(client, sftp)


def test_utime_refuses_file_uploaded_by_another_connection(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "uploaded.txt"
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])
    timestamp = 946684800

    first_client, first_sftp = sftp_password(handle.port, "bob", "pw")
    second_client, second_sftp = sftp_password(handle.port, "bob", "pw")
    try:
        _upload(first_sftp, "uploaded.txt")
        before = target.stat().st_mtime
        with pytest.raises(IOError):
            second_sftp.utime("uploaded.txt", (timestamp, timestamp))
        assert target.stat().st_mtime == before
    finally:
        _close(second_client, second_sftp)
        _close(first_client, first_sftp)


def test_utime_refuses_mixed_attributes_and_leaves_file_unchanged(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "uploaded.txt"
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])
    timestamp = 946684800

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        _upload(sftp, "uploaded.txt")
        before = target.stat()
        attr = paramiko.SFTPAttributes()
        attr.st_mode = 0o600
        attr.st_atime = timestamp
        attr.st_mtime = timestamp
        with pytest.raises(IOError):
            sftp._request(CMD_SETSTAT, "uploaded.txt", attr)
        after = target.stat()
        assert after.st_mtime == before.st_mtime
        assert after.st_mode == before.st_mode
    finally:
        _close(client, sftp)


def test_chmod_refuses_uploaded_file_and_leaves_mode(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "uploaded.txt"
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        _upload(sftp, "uploaded.txt")
        before = target.stat().st_mode
        with pytest.raises(IOError):
            sftp.chmod("uploaded.txt", 0o444)
        assert target.stat().st_mode == before
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


def test_open_upload_handle_utime_keeps_mtime_after_close(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "a.txt"
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])
    timestamp = 946684800

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        f = sftp.open("a.txt", "w")
        try:
            f.write(b"data")
            f.utime((timestamp, timestamp))
        finally:
            f.close()
        assert target.stat().st_mtime == timestamp
    finally:
        _close(client, sftp)


def test_open_upload_handle_refuses_mixed_attributes(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "a.txt"
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])
    timestamp = 946684800

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        f = sftp.open("a.txt", "w")
        try:
            f.write(b"data")
            before = target.stat()
            attr = paramiko.SFTPAttributes()
            attr.st_mode = 0o600
            attr.st_atime = timestamp
            attr.st_mtime = timestamp
            with pytest.raises(IOError):
                sftp._request(CMD_FSETSTAT, f.handle, attr)
        finally:
            f.close()
        after = target.stat()
        assert after.st_mtime != timestamp
        assert after.st_mode == before.st_mode
    finally:
        _close(client, sftp)


def test_open_read_handle_utime_is_refused(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "a.txt"
    target.write_bytes(b"data")
    before = 946684700
    timestamp = 946684800
    os.utime(target, (before, before))
    # Full permissions, so the refusal comes from the handle being read-only.
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        f = sftp.open("a.txt", "r")
        try:
            with pytest.raises(IOError):
                f.utime((timestamp, timestamp))
        finally:
            f.close()
        assert target.stat().st_mtime == before
    finally:
        _close(client, sftp)


def test_open_upload_handle_close_reports_second_utime_failure(tmp_path, sftp_server,
                                                                monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "a.txt"
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])
    timestamp = 946684800
    activity = []
    original_activity = handle.service.activity

    def record_activity(sid, verb, name):
        activity.append((sid, verb, name))
        original_activity(sid, verb, name)

    monkeypatch.setattr(handle.service, "activity", record_activity)
    original_utime = os.utime
    calls = 0

    def fail_second_target_utime(path, dates):
        nonlocal calls
        if os.fspath(path) == str(target):
            calls += 1
            if calls == 2:
                raise PermissionError("simulated close-time failure")
        original_utime(path, dates)

    monkeypatch.setattr(server_module.os, "utime", fail_second_target_utime)
    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        f = sftp.open("a.txt", "w")
        f.write(b"data")
        f.utime((timestamp, timestamp))
        f.close()
        assert calls == 2
        assert ("could not keep original date on", "a.txt") in [
            (verb, name) for _sid, verb, name in activity]
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
