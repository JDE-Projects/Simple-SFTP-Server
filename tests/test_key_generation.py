"""cryptography 50 compatibility coverage for generated user keys, plus
overwrite safety, authorized-key validation on save, and the login match
that ties them together.
"""

import builtins
import os

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_ssh_private_key

from app import paths
from app.api import Api, _valid_authorized_key
from app.constants import DEFAULT_PORT
from app.server import DEFAULT_PERMISSIONS
from app.services.keygen import generate_keypair
from simple_sftp_server import APP_VERSION
from tests.sftp_helpers import make_user


def _perms(**overrides):
    p = {k: True for k in DEFAULT_PERMISSIONS}
    p.update(overrides)
    return p


def _api(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    api = Api(APP_VERSION)
    api._save_config({"settings": {"port": DEFAULT_PORT}, "users": []})
    return api


def test_generate_encrypted_ed25519_key(tmp_path):
    private_path = tmp_path / "id_ed25519"

    result = Api(APP_VERSION).generate_keypair(
        "Ed25519", str(private_path), "test-passphrase", "fixture-user"
    )

    assert result["ok"] is True
    assert result["private_path"] == str(private_path)
    private_key = load_ssh_private_key(private_path.read_bytes(), b"test-passphrase")
    assert isinstance(private_key, Ed25519PrivateKey)

    public_text = private_path.with_suffix(".pub").read_text(encoding="utf-8")
    assert public_text == result["public"] + "\n"
    assert public_text.startswith("ssh-ed25519 ")
    assert public_text.endswith(" fixture-user@simple-sftp-server\n")


def test_generate_rsa_key_round_trip(tmp_path):
    private_path = tmp_path / "id_rsa"

    result = Api(APP_VERSION).generate_keypair("RSA", str(private_path), "", "fixture-user")

    assert result["ok"] is True
    key = paramiko.RSAKey.from_private_key_file(str(private_path))
    assert key is not None
    public_text = private_path.with_suffix(".pub").read_text(encoding="utf-8")
    assert public_text.startswith("ssh-rsa ")


def test_overwrite_refused_by_default(tmp_path):
    private_path = tmp_path / "id_ed25519"

    first = Api(APP_VERSION).generate_keypair("Ed25519", str(private_path), "", "fixture-user")
    assert first["ok"] is True
    original_bytes = private_path.read_bytes()

    second = Api(APP_VERSION).generate_keypair("Ed25519", str(private_path), "", "fixture-user")
    assert second["ok"] is False
    assert second["exists"] is True
    assert private_path.read_bytes() == original_bytes


def test_overwrite_allowed_when_requested(tmp_path):
    private_path = tmp_path / "id_ed25519"

    first = Api(APP_VERSION).generate_keypair("Ed25519", str(private_path), "", "fixture-user")
    assert first["ok"] is True
    original_bytes = private_path.read_bytes()

    second = Api(APP_VERSION).generate_keypair(
        "Ed25519", str(private_path), "", "fixture-user", True
    )
    assert second["ok"] is True
    assert private_path.read_bytes() != original_bytes


def test_partial_write_failure_leaves_no_private_key(tmp_path, monkeypatch):
    private_path = tmp_path / "id_ed25519"
    pub_path = str(private_path) + ".pub"

    real_open = builtins.open

    def failing_open(path, *args, **kwargs):
        if str(path).startswith(pub_path + ".tmp-"):
            raise OSError("simulated failure writing .pub file")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("app.services.keygen.open", failing_open, raising=False)

    result = generate_keypair("Ed25519", str(private_path), "", "fixture-user")

    assert result["ok"] is False
    assert not private_path.exists()


def _write_existing_pair(private_path):
    private_path.write_bytes(b"old private key")
    private_path.with_suffix(".pub").write_bytes(b"old public key\n")


def _assert_no_keygen_staging_files(tmp_path):
    assert list(tmp_path.glob("*.tmp-*")) == []


def test_overwrite_public_write_failure_preserves_existing_pair(tmp_path, monkeypatch):
    private_path = tmp_path / "id_ed25519"
    pub_path = private_path.with_suffix(".pub")
    _write_existing_pair(private_path)
    old_private = private_path.read_bytes()
    old_public = pub_path.read_bytes()
    real_open = builtins.open

    def failing_open(path, *args, **kwargs):
        if str(path).startswith(str(pub_path) + ".tmp-"):
            raise OSError("simulated failure writing .pub file")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("app.services.keygen.open", failing_open, raising=False)

    result = generate_keypair("Ed25519", str(private_path), "", "fixture-user", True)

    assert result["ok"] is False
    assert private_path.read_bytes() == old_private
    assert pub_path.read_bytes() == old_public
    _assert_no_keygen_staging_files(tmp_path)


def test_overwrite_private_write_failure_preserves_existing_pair(tmp_path, monkeypatch):
    private_path = tmp_path / "id_ed25519"
    pub_path = private_path.with_suffix(".pub")
    _write_existing_pair(private_path)
    old_private = private_path.read_bytes()
    old_public = pub_path.read_bytes()
    real_open = builtins.open

    def failing_open(path, *args, **kwargs):
        if str(path).startswith(str(private_path) + ".tmp-"):
            raise OSError("simulated failure writing private key")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("app.services.keygen.open", failing_open, raising=False)

    result = generate_keypair("Ed25519", str(private_path), "", "fixture-user", True)

    assert result["ok"] is False
    assert private_path.read_bytes() == old_private
    assert pub_path.read_bytes() == old_public
    _assert_no_keygen_staging_files(tmp_path)


def test_overwrite_second_replace_failure_restores_existing_pair(tmp_path, monkeypatch):
    private_path = tmp_path / "id_ed25519"
    pub_path = private_path.with_suffix(".pub")
    _write_existing_pair(private_path)
    old_private = private_path.read_bytes()
    old_public = pub_path.read_bytes()
    real_replace = os.replace
    replace_calls = 0

    def failing_second_replace(source, destination):
        nonlocal replace_calls
        replace_calls += 1
        if replace_calls == 3:
            raise OSError("simulated failure replacing .pub file")
        return real_replace(source, destination)

    monkeypatch.setattr("app.services.keygen.os.replace", failing_second_replace)

    result = generate_keypair("Ed25519", str(private_path), "", "fixture-user", True)

    assert result["ok"] is False
    assert private_path.read_bytes() == old_private
    assert pub_path.read_bytes() == old_public
    _assert_no_keygen_staging_files(tmp_path)


def test_failed_restore_keeps_private_key_backup(tmp_path, monkeypatch):
    private_path = tmp_path / "id_ed25519"
    _write_existing_pair(private_path)
    old_private = private_path.read_bytes()
    real_replace = os.replace
    replace_calls = 0

    def failing_replace(source, destination):
        nonlocal replace_calls
        replace_calls += 1
        if replace_calls >= 3:
            raise OSError("simulated failure replacing and restoring")
        return real_replace(source, destination)

    monkeypatch.setattr("app.services.keygen.os.replace", failing_replace)

    result = generate_keypair("Ed25519", str(private_path), "", "fixture-user", True)

    assert result["ok"] is False
    backups = [p for p in tmp_path.glob("id_ed25519.tmp-*")
               if p.read_bytes() == old_private]
    assert len(backups) == 1


def test_successful_overwrite_replaces_pair_without_staging_files(tmp_path):
    private_path = tmp_path / "id_ed25519"
    pub_path = private_path.with_suffix(".pub")
    _write_existing_pair(private_path)

    result = generate_keypair("Ed25519", str(private_path), "", "fixture-user", True)

    assert result["ok"] is True
    private_key = load_ssh_private_key(private_path.read_bytes(), None)
    expected_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode()
    assert pub_path.read_text(encoding="utf-8").startswith(expected_public + " ")
    _assert_no_keygen_staging_files(tmp_path)


def test_save_user_rejects_malformed_authorized_key(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()

    r = api.save_user({
        "username": "alice", "home": str(home), "permissions": _perms(),
        "auth": "key", "authorized_keys": ["ssh-rsa not-real-base64!!!"],
    })
    assert r["ok"] is False

    cfg = api._load_config()
    assert cfg.get("users", []) == []


def test_save_user_rejects_mixed_valid_and_invalid_keys(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    valid = api.generate_keypair("Ed25519", str(tmp_path / "id_ed25519"), "", "alice")
    assert valid["ok"] is True
    invalid = "ssh-ed25519 mangled-public-key"

    result = api.save_user({
        "username": "alice", "home": str(home), "permissions": _perms(),
        "auth": "key", "authorized_keys": [valid["public"], invalid],
    })

    assert result == {
        "ok": False,
        "error": ('Key 2 is not a valid public key (starts with "ssh-ed25519 mangled-..."). '
                  "Paste the full contents of a .pub file (for example ssh-ed25519 AAAA... comment)."),
    }
    assert api._load_config().get("users", []) == []


def test_save_user_rejects_invalid_key_without_changing_existing_keys(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    first = api.generate_keypair("Ed25519", str(tmp_path / "id_ed25519"), "", "alice")
    second = api.generate_keypair("Ed25519", str(tmp_path / "id_ed25519_2"), "", "alice")
    assert first["ok"] is True
    assert second["ok"] is True
    original_keys = [first["public"], second["public"]]
    assert api.save_user({
        "username": "alice", "home": str(home), "permissions": _perms(),
        "auth": "key", "authorized_keys": original_keys,
    })["ok"] is True

    result = api.save_user({
        "username": "alice", "home": str(home), "permissions": _perms(),
        "auth": "key", "authorized_keys": original_keys + ["not-a-public-key"],
    })

    assert result["ok"] is False
    assert api._load_config()["users"][0]["authorized_keys"] == original_keys


def test_save_user_accepts_all_valid_public_keys(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    first = api.generate_keypair("Ed25519", str(tmp_path / "id_ed25519"), "", "alice")
    second = api.generate_keypair("Ed25519", str(tmp_path / "id_ed25519_2"), "", "alice")
    assert first["ok"] is True
    assert second["ok"] is True
    keys = [first["public"], second["public"]]

    result = api.save_user({
        "username": "alice", "home": str(home), "permissions": _perms(),
        "auth": "key", "authorized_keys": keys,
    })

    assert result["ok"] is True
    assert api._load_config()["users"][0]["authorized_keys"] == keys


def test_save_user_accepts_generated_public_key(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    private_path = tmp_path / "id_ed25519"
    keygen_result = api.generate_keypair("Ed25519", str(private_path), "", "alice")
    assert keygen_result["ok"] is True

    r = api.save_user({
        "username": "alice", "home": str(home), "permissions": _perms(),
        "auth": "key", "authorized_keys": [keygen_result["public"]],
    })
    assert r["ok"] is True

    cfg = api._load_config()
    saved = next(u for u in cfg["users"] if u["username"] == "alice")
    assert saved["authorized_keys"] == [keygen_result["public"]]


def test_valid_authorized_key_helper(tmp_path):
    result = generate_keypair("Ed25519", str(tmp_path / "id_ed25519"), "", "someone")
    assert _valid_authorized_key(result["public"]) is True
    assert _valid_authorized_key("ssh-ed25519 not-real-base64!!!") is False
    assert _valid_authorized_key("just-one-field") is False


def test_login_match_accepts_matching_key_rejects_other(tmp_path, sftp_server):
    home = tmp_path / "alice"
    home.mkdir()
    private_path = tmp_path / "id_ed25519"
    keygen_result = Api(APP_VERSION).generate_keypair("Ed25519", str(private_path), "", "alice")
    assert keygen_result["ok"] is True

    matching_key = paramiko.Ed25519Key.from_private_key_file(str(private_path))

    other_private_path = tmp_path / "other_id_ed25519"
    other_result = Api(APP_VERSION).generate_keypair("Ed25519", str(other_private_path), "", "mallory")
    assert other_result["ok"] is True
    other_key = paramiko.Ed25519Key.from_private_key_file(str(other_private_path))

    user = make_user("alice", home, _perms(), auth="key",
                      authorized_keys=[keygen_result["public"]])
    handle = sftp_server([user])

    from tests.sftp_helpers import sftp_key
    client, sftp = sftp_key(handle.port, "alice", matching_key)
    try:
        assert sftp.listdir(".") == []
    finally:
        sftp.close()
        client.close()

    with pytest.raises(paramiko.AuthenticationException):
        sftp_key(handle.port, "alice", other_key)
