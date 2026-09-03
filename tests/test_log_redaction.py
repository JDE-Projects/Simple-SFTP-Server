"""Tests for the debug log's credential redaction backstop and for the
generated-password cleanup in new_password (Task 8).

The log is designed never to receive a password or private key. These tests
prove the backstop still blanks them out if one ever reaches a log entry, and
that new_password keeps no copy in backend memory.
"""

import json

from app import paths
from app.api import Api
from app.debug_log import DebugLog, _redact


# ---- _redact() ----

def test_redact_blanks_private_key_block():
    text = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAxyz\nmore-secret-bytes\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    out = _redact(text)
    assert "PRIVATE KEY" not in out
    assert "secret-bytes" not in out
    assert "[redacted]" in out


def test_redact_blanks_password_field_in_json():
    out = _redact(json.dumps({"user": "amy", "password": "hunter2"}))
    assert "hunter2" not in out
    # The key name is kept so the log still shows a secret was present.
    assert "password" in out
    assert "amy" in out


def test_redact_covers_secret_synonyms():
    for field, value in (
        ("passphrase", "opensesame"),
        ("secret", "s3cr3t"),
        ("token", "abc.def.ghi"),
        ("api_key", "AKIA123"),
        ("private_key", "-----INLINE-----"),
    ):
        out = _redact(f'"{field}": "{value}"')
        assert value not in out, field


def test_redact_leaves_public_keys_readable():
    line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI comment"
    assert _redact(line) == line


def test_redact_handles_empty():
    assert _redact("") == ""
    assert _redact(None) is None


# ---- log() writes redacted content ----

def test_log_write_redacts_secret(tmp_path, monkeypatch):
    monkeypatch.setattr("app.debug_log.exe_dir", lambda: str(tmp_path))
    log = DebugLog()
    assert log.set_enabled(True) is True
    log.log("auth attempt", {"user": "amy", "password": "hunter2"})
    written = (tmp_path).glob("Debug_Log_*.txt")
    body = next(written).read_text(encoding="utf-8")
    assert "hunter2" not in body
    assert "[redacted]" in body


# ---- new_password keeps no backend copy ----

def test_new_password_returns_without_retaining(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    api = Api()
    result = api.new_password()
    assert result["password"]
    assert len(result["password"]) == 20
    assert not hasattr(api, "_new_password")
