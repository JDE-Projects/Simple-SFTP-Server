"""cryptography 50 compatibility coverage for generated user keys."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_ssh_private_key

import simple_sftp_server as app


def test_generate_encrypted_ed25519_key(tmp_path):
    private_path = tmp_path / "id_ed25519"

    result = app.Api().generate_keypair(
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
