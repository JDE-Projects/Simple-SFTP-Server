import os
import tempfile

import paramiko

from app import paths
from app.debug_log import debug


class HostKeyError(Exception):
    """Raised when the host key file exists but cannot be loaded, so the
    server refuses to touch it rather than risk replacing the server's
    identity."""


def _chmod_owner_only(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _write_atomic(data):
    """Write data to a temp file next to HOST_KEY_FILE, then atomically
    replace HOST_KEY_FILE with it. Cleans up the temp file on failure."""
    directory = os.path.dirname(paths.HOST_KEY_FILE) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".host_ed25519.")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        _chmod_owner_only(tmp_path)
        os.replace(tmp_path, paths.HOST_KEY_FILE)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def _write_atomic_rsa(key):
    """Write an RSA key's private key bytes to a temp file next to
    HOST_KEY_FILE, then atomically replace HOST_KEY_FILE with it."""
    directory = os.path.dirname(paths.HOST_KEY_FILE) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".host_ed25519.")
    try:
        with os.fdopen(fd, "w") as f:
            key.write_private_key(f)
            f.flush()
            os.fsync(f.fileno())
        _chmod_owner_only(tmp_path)
        os.replace(tmp_path, paths.HOST_KEY_FILE)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


# ───────────── host key ─────────────
def load_or_create_host_key():
    if os.path.exists(paths.HOST_KEY_FILE):
        try:
            return paramiko.Ed25519Key(filename=paths.HOST_KEY_FILE)
        except Exception as e:
            debug.log("host key load failed", str(e))
            raise HostKeyError(
                f"host key file '{paths.HOST_KEY_FILE}' exists but could not be loaded"
            ) from e
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        k = Ed25519PrivateKey.generate()
        priv = k.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.OpenSSH,
                               serialization.NoEncryption())
        _write_atomic(priv)
        return paramiko.Ed25519Key(filename=paths.HOST_KEY_FILE)
    except Exception as e:
        debug.log("ed25519 host key failed, using RSA", str(e))
        key = paramiko.RSAKey.generate(3072)
        _write_atomic_rsa(key)
        return key
