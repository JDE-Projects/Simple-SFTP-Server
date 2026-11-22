"""Security boundary regression suite: runs a real SFTPService on a loopback
port and drives it with a real Paramiko client, covering auth, the jail that
confines every path to a user's home folder, the permission gates, transfer
byte counting, brute-force lockout, and session cleanup on disconnect.

This does not cover server-stop or account-revocation lifecycle behavior;
that is reserved for other test files.
"""

import os
import stat
import time

import paramiko
import pytest
from paramiko.sftp import CMD_DATA, CMD_FSETSTAT, CMD_READ, CMD_SETSTAT, int64

import app.server as server_module
from app.constants import LOCKOUT_THRESHOLD, MAX_READ_LENGTH
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


def test_key_auth_disabled_key_rejected(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    enabled_key = paramiko.RSAKey.generate(2048)
    disabled_key = paramiko.RSAKey.generate(2048)
    user = make_user("alice", home, _perms(), auth="key",
                     authorized_keys=[authorized_key_line(enabled_key)],
                     disabled_keys=[authorized_key_line(disabled_key)])
    handle = sftp_server([user])

    with pytest.raises(paramiko.AuthenticationException):
        sftp_key(handle.port, "alice", disabled_key)


def test_key_auth_enabled_key_connects_beside_disabled_key(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    enabled_key = paramiko.RSAKey.generate(2048)
    disabled_key = paramiko.RSAKey.generate(2048)
    user = make_user("alice", home, _perms(), auth="key",
                     authorized_keys=[authorized_key_line(enabled_key)],
                     disabled_keys=[authorized_key_line(disabled_key)])
    handle = sftp_server([user])

    client, sftp = sftp_key(handle.port, "alice", enabled_key)
    try:
        assert sftp.listdir(".") == []
    finally:
        _close(client, sftp)


def test_key_only_user_rejects_password_auth(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    client_key = paramiko.RSAKey.generate(2048)
    user = make_user("alice", home, _perms(), auth="key",
                      authorized_keys=[authorized_key_line(client_key)])
    handle = sftp_server([user])

    with pytest.raises(paramiko.AuthenticationException):
        sftp_password(handle.port, "alice", "some password")


def test_password_only_user_rejects_key_auth(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    client_key = paramiko.RSAKey.generate(2048)
    user = make_user("bob", home, _perms(), password="correct horse battery staple")
    # A key on file must still be refused while the account is password-only.
    user["authorized_keys"] = [authorized_key_line(client_key)]
    handle = sftp_server([user])

    with pytest.raises(paramiko.AuthenticationException):
        sftp_key(handle.port, "bob", client_key)


# ───────────── advertised sign-in methods ─────────────

class _AuthService:
    def __init__(self, users):
        self.lockout = server_module.Lockout()
        self._users = {u["username"]: u for u in users}

    def find_user(self, username):
        return self._users.get(username)


def test_every_username_is_offered_the_same_sign_in_methods(tmp_path):
    key_line = authorized_key_line(paramiko.RSAKey.generate(2048))
    users = [
        make_user("pw", tmp_path, _perms(), auth="password", password="pw-secret"),
        make_user("key", tmp_path, _perms(), auth="key", authorized_keys=[key_line]),
        make_user("either", tmp_path, _perms(), auth="both", password="pw-secret",
                  authorized_keys=[key_line]),
    ]
    iface = server_module.ServerIface(_AuthService(users), "127.0.0.1", 1)

    offered = {name: iface.get_allowed_auths(name)
               for name in ("pw", "key", "either", "no-such-user")}

    assert set(offered.values()) == {"publickey,password"}


def test_rejected_keys_do_not_lock_out_password_user(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    password = "correct horse battery staple"
    user = make_user("bob", home, _perms(), password=password)
    handle = sftp_server([user])
    stray_key = paramiko.RSAKey.generate(2048)

    # A client holding several keys offers each one before the password.
    for _ in range(LOCKOUT_THRESHOLD + 1):
        with pytest.raises(paramiko.AuthenticationException):
            sftp_key(handle.port, "bob", stray_key)

    client, sftp = sftp_password(handle.port, "bob", password)
    _close(client, sftp)


# ───────────── lockout is cleared only by a completed sign-in ─────────────

class _FakeTransport:
    def __init__(self, username=None):
        self.username = username

    def get_username(self):
        return self.username


def test_matching_public_key_without_proof_keeps_failure_count(tmp_path):
    client_key = paramiko.RSAKey.generate(2048)
    user = make_user("either", tmp_path, _perms(), auth="both", password="right-pw",
                     authorized_keys=[authorized_key_line(client_key)])
    service = _AuthService([user])
    iface = server_module.ServerIface(service, "127.0.0.1", 1, _FakeTransport())

    for _ in range(LOCKOUT_THRESHOLD - 1):
        assert iface.check_auth_password("either", "wrong-pw") == paramiko.AUTH_FAILED
    # Paramiko asks this before the client proves it holds the private key.
    assert iface.check_auth_publickey("either", client_key) == paramiko.AUTH_SUCCESSFUL
    assert iface.username is None
    iface.check_auth_password("either", "wrong-pw")

    assert service.lockout.is_locked("127.0.0.1", "either")


def test_session_uses_the_name_that_completed_sign_in(tmp_path):
    alice_key = paramiko.RSAKey.generate(2048)
    alice = make_user("alice", tmp_path, _perms(), auth="key",
                      authorized_keys=[authorized_key_line(alice_key)])
    bob = make_user("bob", tmp_path, _perms(), password="bob-pw")
    transport = _FakeTransport()
    iface = server_module.ServerIface(_AuthService([alice, bob]), "127.0.0.1", 1, transport)

    iface.check_auth_publickey("alice", alice_key)
    assert iface.check_auth_password("bob", "bob-pw") == paramiko.AUTH_SUCCESSFUL
    transport.username = "bob"

    assert iface.check_channel_request("session", 0) == paramiko.OPEN_SUCCEEDED
    assert iface.username == "bob"
    assert iface.user is bob


def test_key_sign_in_records_user_when_session_opens(tmp_path):
    client_key = paramiko.RSAKey.generate(2048)
    user = make_user("alice", tmp_path, _perms(), auth="key",
                     authorized_keys=[authorized_key_line(client_key)])
    service = _AuthService([user])
    service.lockout.record_fail("127.0.0.1", "alice")
    transport = _FakeTransport()
    iface = server_module.ServerIface(service, "127.0.0.1", 1, transport)

    iface.check_auth_publickey("alice", client_key)
    transport.username = "alice"

    assert iface.check_channel_request("session", 0) == paramiko.OPEN_SUCCEEDED
    assert iface.username == "alice"
    assert iface.user is user
    assert ("127.0.0.1", "alice") not in service.lockout._fails


def test_session_refused_when_no_sign_in_was_recorded(tmp_path):
    iface = server_module.ServerIface(_AuthService([]), "127.0.0.1", 1,
                                      _FakeTransport("ghost"))

    assert (iface.check_channel_request("session", 0)
            == paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)
    assert iface.username is None


def test_real_key_sign_in_still_clears_failures(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    password = "correct horse battery staple"
    client_key = paramiko.RSAKey.generate(2048)
    user = make_user("either", home, _perms(), auth="both", password=password,
                     authorized_keys=[authorized_key_line(client_key)])
    handle = sftp_server([user])

    for _ in range(LOCKOUT_THRESHOLD - 1):
        with pytest.raises(paramiko.AuthenticationException):
            sftp_password(handle.port, "either", "wrong password")
    client, sftp = sftp_key(handle.port, "either", client_key)
    _close(client, sftp)
    for _ in range(LOCKOUT_THRESHOLD - 1):
        with pytest.raises(paramiko.AuthenticationException):
            sftp_password(handle.port, "either", "wrong password")

    client, sftp = sftp_password(handle.port, "either", password)
    _close(client, sftp)


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


def test_concurrent_upload_cannot_overwrite_without_delete_permission(
        tmp_path, sftp_server, monkeypatch):
    # Another connection's upload creates the file in the gap between this
    # upload's checks and its open. That upload must be refused, and the
    # other connection's file must survive untouched.
    home = tmp_path / "home"
    home.mkdir()
    target = home / "race.txt"
    src = tmp_path / "src.txt"
    src.write_bytes(b"second upload")
    user = make_user("bob", home, _perms(delete=False), password="pw")
    handle = sftp_server([user])

    real_open = os.open
    fired = []

    def open_after_other_upload(path, flags, *args, **kwargs):
        if not fired and os.path.basename(str(path)) == "race.txt":
            fired.append(True)
            target.write_bytes(b"first upload")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(server_module.os, "open", open_after_other_upload)

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(PermissionError):
            sftp.put(str(src), "race.txt")
        assert fired
        assert target.read_bytes() == b"first upload"
    finally:
        _close(client, sftp)


def test_new_upload_allowed_without_delete_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    src = tmp_path / "src.txt"
    src.write_bytes(b"new file")
    user = make_user("bob", home, _perms(delete=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        sftp.put(str(src), "new.txt")
        assert (home / "new.txt").read_bytes() == b"new file"
    finally:
        _close(client, sftp)


def test_write_without_create_refused_without_delete_permission(tmp_path, sftp_server):
    # "r+" asks to write without creating, so it can only reach an existing
    # file: refused for an existing one, missing for an absent one.
    home = tmp_path / "home"
    home.mkdir()
    (home / "existing.txt").write_bytes(b"original")
    user = make_user("bob", home, _perms(delete=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(PermissionError):
            sftp.open("existing.txt", "r+")
        with pytest.raises(FileNotFoundError):
            sftp.open("absent.txt", "r+")
        assert (home / "existing.txt").read_bytes() == b"original"
        assert not (home / "absent.txt").exists()
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


def test_posix_rename_to_new_name(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    (home / "a.txt").write_bytes(b"data")
    user = make_user("bob", home, _perms(delete=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        sftp.posix_rename("a.txt", "b.txt")
        assert (home / "b.txt").read_bytes() == b"data"
        assert not (home / "a.txt").exists()
    finally:
        _close(client, sftp)


def test_posix_rename_replaces_file_with_delete_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    (home / "a.txt").write_bytes(b"new")
    (home / "b.txt").write_bytes(b"old")
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        sftp.posix_rename("a.txt", "b.txt")
        assert (home / "b.txt").read_bytes() == b"new"
        assert not (home / "a.txt").exists()
    finally:
        _close(client, sftp)


def test_posix_rename_refuses_existing_target_without_delete_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    (home / "a.txt").write_bytes(b"new")
    (home / "b.txt").write_bytes(b"old")
    user = make_user("bob", home, _perms(delete=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises((IOError, PermissionError)):
            sftp.posix_rename("a.txt", "b.txt")
        assert (home / "a.txt").read_bytes() == b"new"
        assert (home / "b.txt").read_bytes() == b"old"
    finally:
        _close(client, sftp)


def test_posix_rename_denied_without_rename_file_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    (home / "a.txt").write_bytes(b"data")
    user = make_user("bob", home, _perms(rename_file=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises((IOError, PermissionError)):
            sftp.posix_rename("a.txt", "b.txt")
        assert (home / "a.txt").read_bytes() == b"data"
        assert not (home / "b.txt").exists()
    finally:
        _close(client, sftp)


def test_posix_rename_dir_denied_without_rename_dir_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    (home / "adir").mkdir()
    user = make_user("bob", home, _perms(rename_dir=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises((IOError, PermissionError)):
            sftp.posix_rename("adir", "bdir")
        assert (home / "adir").is_dir()
        assert not (home / "bdir").exists()
    finally:
        _close(client, sftp)


@pytest.mark.parametrize("method", ["rename", "posix_rename"])
@pytest.mark.parametrize("outside_path_kind", ["parent", "absolute"])
@pytest.mark.parametrize("outside_is_source", [False, True])
def test_rename_refuses_paths_outside_jail(
    tmp_path, sftp_server, method, outside_path_kind, outside_is_source
):
    home = tmp_path / "home"
    home.mkdir()
    (home / "a.txt").write_bytes(b"data")
    outside = tmp_path / "outside.txt"
    outside_path = "../outside.txt" if outside_path_kind == "parent" else str(outside)
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises((IOError, PermissionError)):
            getattr(sftp, method)(
                outside_path if outside_is_source else "a.txt",
                "b.txt" if outside_is_source else outside_path,
            )
        assert (home / "a.txt").read_bytes() == b"data"
        assert not (home / "b.txt").exists()
        assert not outside.exists()
    finally:
        _close(client, sftp)


def test_posix_rename_target_appearing_mid_rename_is_not_overwritten(
    tmp_path, sftp_server, monkeypatch
):
    home = tmp_path / "home"
    home.mkdir()
    source = home / "a.txt"
    target = home / "b.txt"
    source.write_bytes(b"new")
    user = make_user("bob", home, _perms(delete=False), password="pw")
    handle = sftp_server([user])
    original_isdir = server_module.os.path.isdir

    def create_target_during_permission_check(path):
        if path == str(source):
            target.write_bytes(b"old")
        return original_isdir(path)

    monkeypatch.setattr(server_module.os.path, "isdir", create_target_during_permission_check)
    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises((IOError, PermissionError)):
            sftp.posix_rename("a.txt", "b.txt")
        assert source.read_bytes() == b"new"
        assert target.read_bytes() == b"old"
    finally:
        _close(client, sftp)


def test_rename_refuses_existing_target(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    (home / "a.txt").write_bytes(b"new")
    (home / "b.txt").write_bytes(b"old")
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with pytest.raises(IOError):
            sftp.rename("a.txt", "b.txt")
        assert (home / "a.txt").read_bytes() == b"new"
        assert (home / "b.txt").read_bytes() == b"old"
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


# ───────────── read request size ─────────────

class _RecordingFile:
    """Stands in for an open file and records every length asked of read()."""

    def __init__(self, content):
        self._content = content
        self._pos = 0
        self.read_lengths = []

    def seek(self, offset):
        self._pos = offset

    def read(self, length):
        self.read_lengths.append(length)
        data = self._content[self._pos:self._pos + length]
        self._pos += len(data)
        return data


class _QuietIface:
    def _progress(self, handle):
        pass


def _read_handle(content):
    h = server_module.JailedHandle(0, _QuietIface(), "f.bin", "down", len(content))
    h.readfile = _RecordingFile(content)
    return h


def test_oversized_read_length_never_reaches_the_file():
    content = bytes(range(256)) * 512  # 128 KiB
    h = _read_handle(content)

    data = h.read(0, 0xFFFFFFFF)

    assert h.readfile.read_lengths == [MAX_READ_LENGTH]
    assert data == content[:MAX_READ_LENGTH]


def test_normal_read_length_is_passed_through():
    content = bytes(range(256)) * 512
    h = _read_handle(content)

    data = h.read(100, 4096)

    assert h.readfile.read_lengths == [4096]
    assert data == content[100:4196]


def test_oversized_read_request_gets_short_reply_over_sftp(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    content = os.urandom(MAX_READ_LENGTH * 3)
    (home / "big.bin").write_bytes(content)
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with sftp.open("big.bin", "rb") as f:
            # Send the raw request, since Paramiko's own client never asks
            # for more than 32 KiB at once.
            t, msg = sftp._request(CMD_READ, f.handle, int64(0), 0xFFFFFFFF)
            assert t == CMD_DATA
            assert msg.get_string() == content[:MAX_READ_LENGTH]
            t, msg = sftp._request(CMD_READ, f.handle, int64(MAX_READ_LENGTH), 0xFFFFFFFF)
            assert t == CMD_DATA
            assert msg.get_string() == content[MAX_READ_LENGTH:MAX_READ_LENGTH * 2]
        # A normal whole-file download still arrives intact.
        dst = tmp_path / "dst.bin"
        sftp.get("big.bin", str(dst))
        assert dst.read_bytes() == content
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


def test_uploaded_file_utime_succeeds_after_posix_rename(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "x"
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])
    timestamp = 946684800

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        _upload(sftp, "x.filepart")
        sftp.posix_rename("x.filepart", "x")
        sftp.utime("x", (timestamp, timestamp))
        assert target.stat().st_mtime == timestamp
    finally:
        _close(client, sftp)


def test_uploaded_file_utime_succeeds_after_folder_rename(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "new" / "sub" / "x"
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])
    timestamp = 946684800

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        sftp.mkdir("old")
        sftp.mkdir("old/sub")
        _upload(sftp, "old/sub/x")
        sftp.rename("old", "new")
        sftp.utime("new/sub/x", (timestamp, timestamp))
        assert target.stat().st_mtime == timestamp
    finally:
        _close(client, sftp)


def test_folder_rename_drops_records_under_old_path(tmp_path, sftp_server):
    # A file someone else puts at the old path after the rename was not
    # uploaded by this connection, so its date cannot be set.
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])
    timestamp = 946684800

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        sftp.mkdir("old")
        _upload(sftp, "old/x")
        sftp.rename("old", "new")
        (home / "old").mkdir()
        replacement = home / "old" / "x"
        replacement.write_bytes(b"other")
        os.utime(replacement, (timestamp, timestamp))
        with pytest.raises(IOError):
            sftp.utime("old/x", (timestamp + 1, timestamp + 1))
        assert replacement.stat().st_mtime == timestamp
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


def test_chmod_to_current_mode_accepted_on_uploaded_file(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "uploaded.txt"
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        _upload(sftp, "uploaded.txt")
        before = target.stat()
        mode = stat.S_IMODE(before.st_mode)
        sftp.chmod("uploaded.txt", mode)
        after = target.stat()
        assert stat.S_IMODE(after.st_mode) == mode
        assert after.st_mtime == before.st_mtime
    finally:
        _close(client, sftp)


def test_chmod_to_current_mode_refused_on_preexisting_file(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "existing.txt"
    target.write_bytes(b"data")
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        mode = stat.S_IMODE(target.stat().st_mode)
        with pytest.raises(IOError):
            sftp.chmod("existing.txt", mode)
        assert stat.S_IMODE(target.stat().st_mode) == mode
    finally:
        _close(client, sftp)


def test_chmod_to_current_mode_refused_without_upload_permission(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "existing.txt"
    target.write_bytes(b"data")
    user = make_user("bob", home, _perms(upload=False), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        mode = stat.S_IMODE(target.stat().st_mode)
        with pytest.raises(IOError):
            sftp.chmod("existing.txt", mode)
        assert stat.S_IMODE(target.stat().st_mode) == mode
    finally:
        _close(client, sftp)


def test_chmod_to_current_mode_refused_on_folder(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        sftp.mkdir("folder")
        mode = stat.S_IMODE((home / "folder").stat().st_mode)
        with pytest.raises(IOError):
            sftp.chmod("folder", mode)
    finally:
        _close(client, sftp)


def test_chmod_to_current_mode_refused_outside_jail(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"data")
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        mode = stat.S_IMODE(outside.stat().st_mode)
        with pytest.raises(IOError):
            sftp.chmod("../outside.txt", mode)
        assert stat.S_IMODE(outside.stat().st_mode) == mode
    finally:
        _close(client, sftp)


def test_chmod_with_dates_still_refused_when_mode_matches(tmp_path, sftp_server):
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
        attr.st_mode = stat.S_IMODE(before.st_mode)
        attr.st_atime = timestamp
        attr.st_mtime = timestamp
        with pytest.raises(IOError):
            sftp._request(CMD_SETSTAT, "uploaded.txt", attr)
        after = target.stat()
        assert after.st_mtime == before.st_mtime
        assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)
    finally:
        _close(client, sftp)


def test_overwrite_with_matching_chmod_then_posix_rename_succeeds(tmp_path, sftp_server):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "b.txt"
    target.write_bytes(b"old")
    user = make_user("bob", home, _perms(), password="pw")
    handle = sftp_server([user])

    client, sftp = sftp_password(handle.port, "bob", "pw")
    try:
        with sftp.open(".b.txt.part", "w") as scratch:
            scratch.write(b"new")
        sftp.chmod(".b.txt.part", stat.S_IMODE(sftp.stat("b.txt").st_mode))
        sftp.posix_rename(".b.txt.part", "b.txt")
        with sftp.open("b.txt", "r") as result:
            assert result.read() == b"new"
        assert not (home / ".b.txt.part").exists()
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
