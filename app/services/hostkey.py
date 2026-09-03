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
    # Only Ed25519 keys are ever written. This loader fails closed on a file it
    # cannot read, so writing an alternate key type would block the next
    # restart. Let a generation failure surface honestly rather than write a
    # key the server cannot reload.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.OpenSSH,
                           serialization.NoEncryption())
    _write_atomic(priv)
    return paramiko.Ed25519Key(filename=paths.HOST_KEY_FILE)
