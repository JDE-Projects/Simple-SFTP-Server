"""cryptography 50 compatibility coverage for the server host key lifecycle."""

import pytest

from app import paths
from app.services.hostkey import HostKeyError, load_or_create_host_key


def test_ed25519_host_key_is_generated_and_reloaded_from_tmp_path(tmp_path, monkeypatch):
    host_key_path = tmp_path / "host_ed25519"
    monkeypatch.setattr(paths, "HOST_KEY_FILE", str(host_key_path))

    generated = load_or_create_host_key()
    assert host_key_path.exists()
    assert generated.get_name() == "ssh-ed25519"

    reloaded = load_or_create_host_key()
    assert reloaded.get_name() == "ssh-ed25519"
    assert reloaded.get_base64() == generated.get_base64()


def test_malformed_host_key_blocks_startup_and_is_left_untouched(tmp_path, monkeypatch):
    host_key_path = tmp_path / "host_ed25519"
    garbage = b"this is not a valid host key file"
    host_key_path.write_bytes(garbage)
    monkeypatch.setattr(paths, "HOST_KEY_FILE", str(host_key_path))

    with pytest.raises(HostKeyError):
        load_or_create_host_key()

    assert host_key_path.read_bytes() == garbage


def test_ed25519_generation_failure_propagates_without_writing_a_key(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import ed25519

    host_key_path = tmp_path / "host_ed25519"
    monkeypatch.setattr(paths, "HOST_KEY_FILE", str(host_key_path))

    def boom():
        raise RuntimeError("crypto backend broken")

    monkeypatch.setattr(ed25519.Ed25519PrivateKey, "generate", staticmethod(boom))

    # With no fallback key type, a generation failure surfaces honestly and
    # leaves nothing on disk for the next restart to choke on.
    with pytest.raises(RuntimeError):
        load_or_create_host_key()

    assert not host_key_path.exists()
    assert not list(tmp_path.glob(".host_ed25519.*"))


def test_stray_temp_file_does_not_affect_the_loaded_key(tmp_path, monkeypatch):
    host_key_path = tmp_path / "host_ed25519"
    monkeypatch.setattr(paths, "HOST_KEY_FILE", str(host_key_path))

    generated = load_or_create_host_key()
    generated_b64 = generated.get_base64()

    # a leftover temp file from an earlier, unfinished write should never be
    # mistaken for the real key on the next load.
    stray = tmp_path / ".host_ed25519.stray123"
    stray.write_bytes(b"not a real key")

    reloaded = load_or_create_host_key()
    assert reloaded.get_base64() == generated_b64
    assert host_key_path.read_bytes() != stray.read_bytes()
