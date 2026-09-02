"""cryptography 50 compatibility coverage for the server host key lifecycle."""

from app import paths
from app.services.hostkey import load_or_create_host_key


def test_ed25519_host_key_is_generated_and_reloaded_from_tmp_path(tmp_path, monkeypatch):
    host_key_path = tmp_path / "host_ed25519"
    monkeypatch.setattr(paths, "HOST_KEY_FILE", str(host_key_path))

    generated = load_or_create_host_key()
    assert host_key_path.exists()
    assert generated.get_name() == "ssh-ed25519"

    reloaded = load_or_create_host_key()
    assert reloaded.get_name() == "ssh-ed25519"
    assert reloaded.get_base64() == generated.get_base64()
