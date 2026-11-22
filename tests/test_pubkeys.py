import base64
import builtins
import sys
from types import SimpleNamespace

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from app import paths
from app.api import Api
from app.constants import DEFAULT_PORT
from app.helpers import fingerprint_sha256
import app.server as server_module
from app.server import DEFAULT_PERMISSIONS
from app.services.pubkeys import (
    INVALID_KEY_MESSAGE,
    describe_key,
    key_identity,
    read_key_file,
    read_keys,
    read_keys_file,
    read_one_key,
)
from simple_sftp_server import APP_VERSION


def _public_line(private_key, comment=""):
    line = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return f"{line} {comment}".strip()


def _rfc4716_block(line, headers=(), line_ending="\n"):
    _, encoded, *_ = line.split()
    body = [encoded[index:index + 70] for index in range(0, len(encoded), 70)]
    return line_ending.join([
        "---- BEGIN SSH2 PUBLIC KEY ----", *headers, *body,
        "---- END SSH2 PUBLIC KEY ----",
    ])


def _api(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    api = Api(APP_VERSION)
    api._save_config({"settings": {"port": DEFAULT_PORT}, "users": []})
    return api


def _perms():
    return {name: True for name in DEFAULT_PERMISSIONS}


def _user_payload(home, key):
    return {"username": "alice", "home": str(home), "permissions": _perms(),
            "auth": "key", "public_key": key}


def test_read_one_key_normalizes_valid_ed25519_and_comment():
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "alice laptop")

    result, error = read_one_key("  " + line.replace(" ", "   ") + "  ")

    assert error is None
    assert result == line


def test_read_one_key_accepts_private_key_in_public_key_comment():
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "PRIVATE KEY")

    result, error = read_one_key(line)

    assert error is None
    assert result == line


def test_read_one_key_skips_blank_and_comment_lines():
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "alice")

    result, error = read_one_key("\n  # a comment\n\n" + line + "\n # another\n")

    assert (result, error) == (line, None)


def test_read_one_key_rejects_empty_multiple_and_garbage():
    line = _public_line(ed25519.Ed25519PrivateKey.generate())

    assert read_one_key("") == (None, "No public key found.")
    assert read_one_key(" \n\t ") == (None, "No public key found.")
    assert read_one_key(line + "\n" + line) == (
        None, "This holds more than one key. This app uses one key per user.")
    garbage = "definitely-not-a-key"
    assert read_one_key(garbage) == (None, INVALID_KEY_MESSAGE)
    assert garbage not in INVALID_KEY_MESSAGE


def test_read_one_key_rejects_private_and_converts_putty_format():
    private = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()).decode()
    private_message = "That is a private key. Choose the .pub file next to it instead."

    assert read_one_key(private) == (None, private_message)
    assert all(line not in private_message for line in private.splitlines())
    assert read_one_key("PuTTY-User-Key-File-3: ssh-ed25519") == (None, private_message)
    assert read_one_key("\n  PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none") == (
        None, private_message)
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "alice@laptop")
    putty = _rfc4716_block(line, ['Comment: "alice@laptop"'])
    assert read_one_key(putty) == (line, None)


@pytest.mark.parametrize("header", [
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
])
def test_read_one_key_rejects_pem_private_key_headers(header):
    private_message = "That is a private key. Choose the .pub file next to it instead."

    result, error = read_one_key(header + "\nprivate material")

    assert (result, error) == (None, private_message)
    assert header not in error


def test_read_one_key_converts_rfc4716_rsa_without_comment():
    line = _public_line(rsa.generate_private_key(public_exponent=65537, key_size=3072))

    assert read_one_key(_rfc4716_block(line)) == (line, None)


def test_read_one_key_converts_rfc4716_continued_comment_and_ignores_headers():
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "alice laptop")
    block = _rfc4716_block(line, ['Comment: "alice\\', ' laptop"', 'x-other: y'])

    assert read_one_key(block) == (line, None)


def test_read_one_key_converts_rfc4716_lowercase_comment_header():
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "alice@laptop")

    assert read_one_key(_rfc4716_block(line, ['comment: "alice@laptop"'])) == (line, None)


def test_read_one_key_rejects_invalid_rfc4716_blocks():
    line = _public_line(ed25519.Ed25519PrivateKey.generate())
    block = _rfc4716_block(line)
    multiple_message = "This holds more than one key. This app uses one key per user."

    assert read_one_key(block.rsplit("\n", 1)[0]) == (None, INVALID_KEY_MESSAGE)
    bad_body = "not+base64!"
    assert read_one_key(
        f"---- BEGIN SSH2 PUBLIC KEY ----\n{bad_body}\n---- END SSH2 PUBLIC KEY ----"
    ) == (None, INVALID_KEY_MESSAGE)
    assert bad_body not in INVALID_KEY_MESSAGE
    assert read_one_key(
        "---- BEGIN SSH2 PUBLIC KEY ----\nAAAAAXNzaA==\n---- END SSH2 PUBLIC KEY ----"
    ) == (None, INVALID_KEY_MESSAGE)
    assert read_one_key(block + "\n" + block) == (None, multiple_message)
    assert read_one_key(block + "\n" + line) == (None, multiple_message)


def test_read_key_file_converts_rfc4716_windows_line_endings(tmp_path):
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "alice@laptop")
    path = tmp_path / "id_ed25519.pub"
    path.write_text(
        _rfc4716_block(line, ['Comment: "alice@laptop"'], "\r\n"),
        encoding="utf-8", newline="",
    )

    assert read_key_file(path) == (line, None)


def test_describe_key_types_comments_and_fingerprint():
    ed25519_line = _public_line(ed25519.Ed25519PrivateKey.generate(), "alice laptop")
    rsa_line = _public_line(rsa.generate_private_key(public_exponent=65537, key_size=1024))
    ecdsa_line = _public_line(ec.generate_private_key(ec.SECP256R1()))

    assert describe_key(ed25519_line)["type"] == "ed25519"
    assert describe_key(ed25519_line)["comment"] == "alice laptop"
    assert describe_key(rsa_line)["type"] == "rsa"
    assert describe_key(rsa_line)["comment"] == ""
    assert describe_key(ecdsa_line)["type"] == "ecdsa"
    key_type, encoded, *_ = ed25519_line.split()
    loaded = paramiko.PKey.from_type_string(key_type, base64.b64decode(encoded, validate=True))
    assert describe_key(ed25519_line)["fingerprint"] == fingerprint_sha256(loaded)


def test_read_key_file_cases(tmp_path, monkeypatch):
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "alice")
    good = tmp_path / "id_ed25519.pub"
    good.write_text(line + "\n", encoding="utf-8")
    assert read_key_file(good) == (line, None)

    empty = tmp_path / "empty.pub"
    empty.write_text("", encoding="utf-8")
    assert read_key_file(empty) == (None, "No public key found.")

    oversized = tmp_path / "oversized.pub"
    oversized.write_bytes(b"x" * (64 * 1024 + 1))
    real_open = builtins.open

    def fail_open(*args, **kwargs):
        if args[0] == oversized:
            raise AssertionError("oversized key file was read")
        return real_open(*args, **kwargs)

    monkeypatch.setattr(builtins, "open", fail_open)
    assert read_key_file(oversized) == (None, "That file is too large to be a public key.")

    bad_encoding = tmp_path / "bad.pub"
    bad_encoding.write_bytes(b"\xff")
    assert read_key_file(bad_encoding) == (None, INVALID_KEY_MESSAGE)

    two_keys = tmp_path / "two.pub"
    two_keys.write_text(line + "\n" + line, encoding="utf-8")
    assert read_key_file(two_keys) == (
        None, "This holds more than one key. This app uses one key per user.")


def test_save_user_keeps_blank_key_and_rejects_private_key(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    first = _public_line(ed25519.Ed25519PrivateKey.generate())
    assert api.save_user(_user_payload(home, first))["ok"] is True
    assert api.save_user(_user_payload(home, ""), original="alice")["ok"] is True
    assert api._load_config()["users"][0]["authorized_keys"] == [first]

    private = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()).decode()
    result = api.save_user(_user_payload(home, private), original="alice")
    assert result == {"ok": False,
                      "error": "That is a private key. Choose the .pub file next to it instead."}
    assert all(line not in result["error"] for line in private.splitlines())
    assert api._load_config()["users"][0]["authorized_keys"] == [first]


def test_save_user_requires_key_when_none_is_stored(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()

    result = api.save_user(_user_payload(home, ""))

    assert result == {"ok": False,
                      "error": "Add at least one public key (or switch to password auth)."}
    assert api._load_config()["users"] == []


def test_pick_key_file_and_check_public_key(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "alice")
    key_file = tmp_path / "id_ed25519.pub"
    key_file.write_text(line, encoding="utf-8")
    bad_file = tmp_path / "bad.pub"
    bad_file.write_text("not a key", encoding="utf-8")
    webview = SimpleNamespace(FileDialog=SimpleNamespace(OPEN="open"))
    monkeypatch.setitem(sys.modules, "webview", webview)

    api._set_window(SimpleNamespace(create_file_dialog=lambda *args, **kwargs: None))
    assert api.pick_key_file() == {"ok": False}

    api._set_window(SimpleNamespace(create_file_dialog=lambda *args, **kwargs: [str(key_file)]))
    picked = api.pick_key_file()
    assert picked["ok"] is True
    assert picked["key"] == line
    assert picked["described"] == describe_key(line)

    api._set_window(SimpleNamespace(create_file_dialog=lambda *args, **kwargs: [str(bad_file)]))
    assert api.pick_key_file() == {"ok": False, "error": INVALID_KEY_MESSAGE}
    assert api.check_public_key(line)["key"] == line
    assert api.check_public_key("PuTTY-User-Key-File-3: ssh-ed25519") == {
        "ok": False, "error": "That is a private key. Choose the .pub file next to it instead."}


def test_public_users_include_key_description(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "alice laptop")
    users = api._public_users({"users": [
        {"username": "alice", "auth": "key", "authorized_keys": [line]},
        {"username": "bob", "auth": "password"},
    ]})

    assert users[0]["key"] == describe_key(line)
    assert users[0]["keys"] == [describe_key(line)]
    assert users[1]["key"] is None
    assert users[1]["keys"] == []


def test_public_users_skips_unusable_stored_keys(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "valid")

    users = api._public_users({"users": [{
        "username": "alice", "auth": "key", "authorized_keys": ["", None, "junk", line],
    }]})

    assert users[0]["keys"] == [describe_key(line)]
    assert users[0]["key"] == describe_key(line)


def test_public_users_returns_legacy_keys_in_stored_order(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    first = _public_line(ed25519.Ed25519PrivateKey.generate(), "first")
    second = _public_line(ed25519.Ed25519PrivateKey.generate(), "second")

    users = api._public_users({"users": [{
        "username": "alice", "auth": "key", "authorized_keys": [first, second],
    }]})

    assert users[0]["keys"] == [describe_key(first), describe_key(second)]
    assert users[0]["key"] == describe_key(first)


def test_describe_key_survives_damaged_stored_key():
    described = describe_key("ssh-ed25519 not-a-real-key hand@edited")

    assert described == {"type": "ed25519", "comment": "hand@edited", "fingerprint": ""}


def test_read_key_file_accepts_byte_order_mark(tmp_path):
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "notepad")
    path = tmp_path / "id_ed25519.pub"
    path.write_bytes(b"\xef\xbb\xbf" + line.encode() + b"\r\n")

    assert read_key_file(str(path)) == (line, None)


def test_read_keys_returns_every_key_in_order():
    lines = [
        _public_line(ed25519.Ed25519PrivateKey.generate(), "alice"),
        _public_line(rsa.generate_private_key(public_exponent=65537, key_size=1024), "bob"),
        _public_line(ec.generate_private_key(ec.SECP256R1()), "carol"),
    ]

    assert read_keys("\n".join(line.replace(" ", "  ") for line in lines)) == (lines, None)


def test_read_keys_skips_blank_and_comment_lines():
    first = _public_line(ed25519.Ed25519PrivateKey.generate(), "alice")
    second = _public_line(ed25519.Ed25519PrivateKey.generate(), "bob")

    assert read_keys(f"\n# notes\n{first}\n\n  # notes\n{second}\n") == ([first, second], None)


def test_read_keys_one_bad_line_returns_nothing_and_names_line():
    first = _public_line(ed25519.Ed25519PrivateKey.generate())
    second = _public_line(ed25519.Ed25519PrivateKey.generate())

    result, error = read_keys(f"{first}\n# notes\nnot-a-key SECRETTEXT\n{second}")

    assert result is None
    assert "Line 3" in error
    assert "SECRETTEXT" not in error


def test_read_keys_names_first_bad_line():
    line = _public_line(ed25519.Ed25519PrivateKey.generate())

    result, error = read_keys(f"{line}\nbad-first\n{line}\nbad-second")

    assert result is None
    assert "Line 2" in error


def test_read_keys_refuses_private_key_without_echo():
    public = _public_line(ed25519.Ed25519PrivateKey.generate())
    private_message = "That is a private key. Choose the .pub file next to it instead."
    pem_private = rsa.generate_private_key(public_exponent=65537, key_size=1024).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()
    openssh_private = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()).decode()
    putty_private = "PuTTY-User-Key-File-3: ssh-ed25519\nPrivate-MAC: secret"

    for private in (pem_private, openssh_private, putty_private):
        result, error = read_keys(public + "\n" + private)
        assert (result, error) == (None, private_message)
        assert all(part not in error for part in private.splitlines())


def test_read_keys_empty_text():
    for text in ("", " \n\t ", "# note\n  # another", None):
        assert read_keys(text) == (None, "No public key found.")


def test_read_keys_reads_one_ssh2_block():
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "alice@laptop")
    block = _rfc4716_block(line, ['Comment: "alice@laptop"'])

    assert read_keys(block) == ([read_one_key(block)[0]], None)


def test_read_keys_refuses_mixed_or_multiple_ssh2_blocks():
    line = _public_line(ed25519.Ed25519PrivateKey.generate())
    block = _rfc4716_block(line)

    for text in (block + "\n" + block, line + "\n" + block, block + "\n" + line):
        result, error = read_keys(text)
        assert result is None
        assert "one key per user" not in error


def test_key_identity_ignores_comment():
    line = _public_line(ed25519.Ed25519PrivateKey.generate())
    other = _public_line(ed25519.Ed25519PrivateKey.generate())
    key_type, encoded = line.split()

    assert key_identity(f"  {key_type}   {encoded}  a@pc") == key_identity(
        f"{line} b@laptop") == key_identity(line)
    assert key_identity(line) != key_identity(other)
    assert key_identity(None) is None
    assert key_identity(key_type) is None


def test_read_keys_keeps_duplicates_for_caller():
    line = _public_line(ed25519.Ed25519PrivateKey.generate())
    first = line + " a@pc"
    second = line + " b@laptop"

    result, error = read_keys(first + "\n" + second)

    assert (result, error) == ([first, second], None)
    assert key_identity(result[0]) == key_identity(result[1])


def test_read_keys_file_cases(tmp_path):
    first = _public_line(ed25519.Ed25519PrivateKey.generate(), "first")
    second = _public_line(ed25519.Ed25519PrivateKey.generate(), "second")
    good = tmp_path / "keys.pub"
    good.write_text(first + "\n" + second, encoding="utf-8")
    assert read_keys_file(good) == ([first, second], None)

    oversized = tmp_path / "oversized.pub"
    oversized.write_bytes(b"x" * (64 * 1024 + 1))
    assert read_keys_file(oversized) == (None, "That file is too large to be a public key.")

    empty = tmp_path / "empty.pub"
    empty.write_text("", encoding="utf-8")
    assert read_keys_file(empty) == (None, "No public key found.")

    missing_result, missing_error = read_keys_file(tmp_path / "missing.pub")
    assert missing_result is None
    assert "No such file" not in missing_error

    bad_encoding = tmp_path / "bad.pub"
    bad_encoding.write_bytes(b"\xff")
    assert read_keys_file(bad_encoding) == (None, INVALID_KEY_MESSAGE)

    bom = tmp_path / "bom.pub"
    bom.write_bytes(b"\xef\xbb\xbf" + first.encode())
    assert read_keys_file(bom) == ([first], None)


@pytest.mark.parametrize("text, marker", [
    ("not-a-key UNIQUE_BAD_LINE", "UNIQUE_BAD_LINE"),
    ("---- BEGIN SSH2 PUBLIC KEY ----\nUNIQUE_BAD_SSH2\n---- END SSH2 PUBLIC KEY ----", "UNIQUE_BAD_SSH2"),
    ("---- BEGIN SSH2 PUBLIC KEY ----\nAAAAAXNzaA==\n---- END SSH2 PUBLIC KEY ----\nUNIQUE_MIXED", "UNIQUE_MIXED"),
])
def test_read_keys_rejected_text_absent_from_errors(text, marker):
    result, error = read_keys(text)

    assert result is None
    assert marker not in error


def test_save_user_treats_non_text_key_as_blank(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()

    result = api.save_user(_user_payload(home, ["ssh-ed25519 AAAA"]))

    assert result == {"ok": False,
                      "error": "Add at least one public key (or switch to password auth)."}
    assert api._load_config().get("users", []) == []


def test_save_user_keeps_or_replaces_legacy_keys(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    first = _public_line(ed25519.Ed25519PrivateKey.generate(), "first")
    second = _public_line(ed25519.Ed25519PrivateKey.generate(), "second")
    replacement = _public_line(ed25519.Ed25519PrivateKey.generate(), "replacement")
    assert api.save_user(_user_payload(home, first))["ok"] is True
    cfg = api._load_config()
    cfg["users"][0]["authorized_keys"] = [first, second]
    assert api._save_config(cfg) is True

    assert api.save_user(_user_payload(home, ""), original="alice")["ok"] is True
    assert api._load_config()["users"][0]["authorized_keys"] == [first, second]
    assert api.save_user(_user_payload(home, replacement), original="alice")["ok"] is True
    assert api._load_config()["users"][0]["authorized_keys"] == [replacement]


def test_check_auth_publickey_skips_non_string_stored_keys():
    key = paramiko.RSAKey.generate(1024)
    user = {"username": "alice", "auth": "key", "authorized_keys": [None, key.get_name() + " " + key.get_base64()]}

    class AuthService:
        def __init__(self):
            self.lockout = server_module.Lockout()

        def find_user(self, username):
            return user if username == "alice" else None

    iface = server_module.ServerIface(AuthService(), "127.0.0.1", 1)

    assert iface.check_auth_publickey("alice", key) == paramiko.AUTH_SUCCESSFUL


def test_pick_key_file_filters_pass_pywebview_check(tmp_path, monkeypatch):
    # pywebview refuses a badly formed file filter when the dialog opens, which
    # a faked window would never show. Run the real filters through its check.
    from webview.util import parse_file_type

    api = _api(tmp_path, monkeypatch)
    seen = {}

    def dialog(*args, **kwargs):
        seen.update(kwargs)
        return None

    monkeypatch.setitem(sys.modules, "webview", SimpleNamespace(FileDialog=SimpleNamespace(OPEN="open")))
    api._set_window(SimpleNamespace(create_file_dialog=dialog))

    assert api.pick_key_file() == {"ok": False}
    assert [parse_file_type(f) for f in seen["file_types"]] == [
        ("Public key files", "*.pub"), ("All files", "*.*")]
