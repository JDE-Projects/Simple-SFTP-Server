import os

import paramiko

from app import paths
from app.debug_log import debug


# ───────────── host key ─────────────
def load_or_create_host_key():
    if os.path.exists(paths.HOST_KEY_FILE):
        try:
            return paramiko.Ed25519Key(filename=paths.HOST_KEY_FILE)
        except Exception as e:
            debug.log("host key load failed, regenerating", str(e))
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        k = Ed25519PrivateKey.generate()
        priv = k.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.OpenSSH,
                               serialization.NoEncryption())
        with open(paths.HOST_KEY_FILE, "wb") as f:
            f.write(priv)
        try:
            os.chmod(paths.HOST_KEY_FILE, 0o600)
        except OSError:
            pass
        return paramiko.Ed25519Key(filename=paths.HOST_KEY_FILE)
    except Exception as e:
        debug.log("ed25519 host key failed, using RSA", str(e))
        key = paramiko.RSAKey.generate(3072)
        key.write_private_key_file(paths.HOST_KEY_FILE)
        return key
