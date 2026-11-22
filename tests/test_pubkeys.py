import base64
import sys
from types import SimpleNamespace

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

import app.server as server_module
from app import paths
from app.api import Api
from app.constants import DEFAULT_PORT
from app.helpers import fingerprint_sha256
from app.server import DEFAULT_PERMISSIONS
from app.services.pubkeys import (
    INVALID_KEY_MESSAGE,
    clean_key_name,
    describe_key,
    is_valid_key,
    key_identity,
    key_name_problem,
    read_keys,
    read_keys_file,
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


def _user_payload(home, keys):
    return {"username": "alice", "home": str(home), "permissions": _perms(),
            "auth": "key", "authorized_keys": keys}


def test_clean_key_name_shortens_name_without_changing_identity():
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "x" * 150)

    cleaned, note = clean_key_name(line)

    assert cleaned.endswith(" " + "x" * 100)
    assert "shortened" in note
    assert key_identity(cleaned) == key_identity(line)


def test_clean_key_name_removes_control_and_format_characters():
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "a\x1bb\u202ec")

    cleaned, note = clean_key_name(line)

    assert cleaned.endswith(" abc")
    assert "Hidden characters" in note


def test_clean_key_name_leaves_clean_line_unchanged():
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "alice laptop")

    assert clean_key_name(line) == (line, None)


def test_key_name_problem_limits_and_hides_name():
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "x" * 100)

    assert key_name_problem(line) is None
    too_long = line.rsplit(" ", 1)[0] + " " + "y" * 101
    assert key_name_problem(too_long) is not None
    hidden = line.rsplit(" ", 1)[0] + " safe\u202ename"
    message = key_name_problem(hidden)
    assert message is not None
    assert "safe" not in message


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


def test_save_user_stores_full_list_and_removes_a_key(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    keys = [_public_line(ed25519.Ed25519PrivateKey.generate(), str(number)) for number in range(3)]

    assert api.save_user(_user_payload(home, keys))["ok"] is True
    assert api._load_config()["users"][0]["authorized_keys"] == keys
    assert api.save_user(_user_payload(home, keys[:2]), original="alice")["ok"] is True
    assert api._load_config()["users"][0]["authorized_keys"] == keys[:2]


def test_save_user_requires_key_when_none_is_stored(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()

    result = api.save_user(_user_payload(home, []))

    assert result == {"ok": False,
                      "error": "Add at least one public key (or switch to password auth)."}
    assert api._load_config()["users"] == []


def test_pick_key_file_and_check_public_key_return_every_key(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    lines = [_public_line(ed25519.Ed25519PrivateKey.generate(), "alice"),
             _public_line(ed25519.Ed25519PrivateKey.generate(), "x" * 150),
             _public_line(ed25519.Ed25519PrivateKey.generate(), "carol")]
    key_file = tmp_path / "id_ed25519.pub"
    key_file.write_text("\n".join(lines[:2]), encoding="utf-8")
    bad_file = tmp_path / "bad.pub"
    bad_file.write_text("not a key", encoding="utf-8")
    webview = SimpleNamespace(FileDialog=SimpleNamespace(OPEN="open"))
    monkeypatch.setitem(sys.modules, "webview", webview)

    api._set_window(SimpleNamespace(create_file_dialog=lambda *args, **kwargs: None))
    assert api.pick_key_file() == {"ok": False}

    api._set_window(SimpleNamespace(create_file_dialog=lambda *args, **kwargs: [str(key_file)]))
    picked = api.pick_key_file()
    assert picked["ok"] is True
    assert [key["key"] for key in picked["keys"]] == [lines[0], lines[1].rsplit(" ", 1)[0] + " " + "x" * 100]
    assert all(key["described"] for key in picked["keys"])
    assert "shortened" in picked["keys"][1]["note"]

    api._set_window(SimpleNamespace(create_file_dialog=lambda *args, **kwargs: [str(bad_file)]))
    assert api.pick_key_file()["error"].startswith("Line 1 is not a valid public key.")
    checked = api.check_public_key("\n".join(lines))
    assert [key["key"] for key in checked["keys"]] == [lines[0], lines[1].rsplit(" ", 1)[0] + " " + "x" * 100, lines[2]]
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
    assert users[0]["keys"] == [{"line": line, "valid": True, **describe_key(line), "name_problem": None}]
    assert users[0]["key_count"] == 1
    assert users[1]["key"] is None
    assert users[1]["keys"] == []


def test_public_users_returns_invalid_stored_key_in_order(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "valid")

    users = api._public_users({"users": [{
        "username": "alice", "auth": "key", "authorized_keys": ["", None, "junk", line],
    }]})

    assert users[0]["keys"] == [
        {"line": "junk", "valid": False, "type": "", "comment": "", "fingerprint": "", "name_problem": None},
        {"line": line, "valid": True, **describe_key(line), "name_problem": None},
    ]
    assert users[0]["key"] == describe_key(line)
    assert users[0]["key_count"] == 1


def test_public_users_returns_legacy_keys_in_stored_order(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    first = _public_line(ed25519.Ed25519PrivateKey.generate(), "first")
    second = _public_line(ed25519.Ed25519PrivateKey.generate(), "second")

    users = api._public_users({"users": [{
        "username": "alice", "auth": "key", "authorized_keys": [first, second],
    }]})

    assert [key["line"] for key in users[0]["keys"]] == [first, second]
    assert users[0]["key"] == describe_key(first)


def test_describe_key_survives_damaged_stored_key():
    described = describe_key("ssh-ed25519 not-a-real-key hand@edited")

    assert described == {"type": "ed25519", "comment": "hand@edited", "fingerprint": ""}


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

    assert read_keys(block) == ([line], None)


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


def test_save_user_refuses_malformed_lists_without_writing_config(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()

    before = (tmp_path / "server_config.json").read_bytes()
    for keys in (None, "not a list", [3]):
        result = api.save_user(_user_payload(home, keys))
        assert result["ok"] is False
        assert (tmp_path / "server_config.json").read_bytes() == before


def test_save_user_renames_and_deduplicates_keys(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    first = _public_line(ed25519.Ed25519PrivateKey.generate(), "first")
    renamed = first.rsplit(" ", 1)[0] + " renamed"
    assert api.save_user(_user_payload(home, [first]))["ok"] is True
    assert api.save_user(_user_payload(home, [renamed, first]), original="alice")["ok"] is True
    assert api._load_config()["users"][0]["authorized_keys"] == [renamed]
    assert is_valid_key(renamed)
    assert key_identity(renamed) == key_identity(first)


def test_save_user_rejects_invalid_stored_style_entry_without_writing(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    before = (tmp_path / "server_config.json").read_bytes()

    result = api.save_user(_user_payload(home, ["damaged stored key"]))

    assert result["ok"] is False
    assert "Key 1" in result["error"]
    assert "damaged stored key" not in result["error"]
    assert (tmp_path / "server_config.json").read_bytes() == before


def test_save_user_rejects_over_limit_name_without_writing(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    before = (tmp_path / "server_config.json").read_bytes()
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "x" * 101)

    result = api.save_user(_user_payload(home, [line]))

    assert result["ok"] is False
    assert "Key 1" in result["error"]
    assert (tmp_path / "server_config.json").read_bytes() == before


def test_save_user_refuses_more_than_25_new_keys(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    keys = [_public_line(ed25519.Ed25519PrivateKey.generate(), str(number)) for number in range(26)]

    result = api.save_user(_user_payload(home, keys))

    assert result == {"ok": False,
                      "error": "A user can have at most 25 keys. Remove one before adding another."}


def test_over_limit_existing_user_can_rename_or_remove_but_not_add(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    keys = [_public_line(ed25519.Ed25519PrivateKey.generate(), str(number)) for number in range(27)]
    cfg = api._load_config()
    cfg["users"] = [{"username": "alice", "home": str(home), "permissions": _perms(),
                     "auth": "key", "authorized_keys": keys}]
    assert api._save_config(cfg) is True

    assert api.save_user(_user_payload(home, keys), original="alice")["ok"] is True
    renamed = keys.copy()
    renamed[0] = renamed[0].rsplit(" ", 1)[0] + " renamed"
    assert api.save_user(_user_payload(home, renamed), original="alice")["ok"] is True
    assert api.save_user(_user_payload(home, renamed[:-1]), original="alice")["ok"] is True
    extra = _public_line(ed25519.Ed25519PrivateKey.generate(), "extra")
    result = api.save_user(_user_payload(home, renamed + [extra]), original="alice")
    assert result["ok"] is False
    assert "at most 25" in result["error"]


def test_public_users_reports_name_problem(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "x" * 101)

    user = api._public_users({"users": [{"username": "alice", "authorized_keys": [line]}]})[0]

    assert user["keys"][0]["name_problem"] is not None


def test_save_user_disconnects_only_when_access_changes(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    first = _public_line(ed25519.Ed25519PrivateKey.generate(), "first")
    second = _public_line(ed25519.Ed25519PrivateKey.generate(), "second")
    assert api.save_user(_user_payload(home, [first]))["ok"] is True
    calls = []
    monkeypatch.setattr(api._service, "disconnect_user", lambda name: (calls.append(name), 1)[1])

    renamed = first.rsplit(" ", 1)[0] + " renamed"
    for keys in ([renamed], [renamed]):
        result = api.save_user(_user_payload(home, keys), original="alice")
        assert result["access_changed"] is False
        assert result["disconnected"] == 0
    for payload in (
        _user_payload(home, [renamed, second]),
        _user_payload(home, [renamed]),
        {**_user_payload(home, [renamed]), "auth": "both", "password": "a password"},
        {**_user_payload(home, [renamed]), "permissions": {**_perms(), "download": False}},
    ):
        result = api.save_user(payload, original="alice")
        assert result["access_changed"] is True
        assert result["disconnected"] == 1
    assert calls == ["alice"] * 4


def test_save_user_stores_each_key_as_one_normalized_line(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    spaced = _public_line(ed25519.Ed25519PrivateKey.generate(), "spaced name")
    ssh2_line = _public_line(ed25519.Ed25519PrivateKey.generate(), "putty")
    block = _rfc4716_block(ssh2_line, ['Comment: "putty"'])

    result = api.save_user(_user_payload(home, ["  " + spaced.replace(" ", " \t "), block]))

    assert result["ok"] is True
    assert api._load_config()["users"][0]["authorized_keys"] == [spaced, ssh2_line]


def test_password_only_save_drops_authorized_keys(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = tmp_path / "alice"
    home.mkdir()
    line = _public_line(ed25519.Ed25519PrivateKey.generate(), "alice")
    assert api.save_user(_user_payload(home, [line]))["ok"] is True

    result = api.save_user({"username": "alice", "home": str(home), "permissions": _perms(),
                            "auth": "password", "password": "a password"}, original="alice")

    assert result["ok"] is True
    assert "authorized_keys" not in api._load_config()["users"][0]


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
