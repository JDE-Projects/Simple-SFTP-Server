"""Shared building blocks for tests that drive the real SFTPService with a
real Paramiko client over a loopback socket. Import from here instead of
hand-rolling host keys, ports, or client connections in each test file.
"""

import os
import socket
import threading

import paramiko

from app.services.passwords import hash_password


class CountingApi:
    """Stands in for the real Api and counts every UI push by event type."""

    def __init__(self, user=None, users=None):
        self._user = user
        self._users = users
        self._lock = threading.Lock()
        self.counts = {}

    def emit(self, event, payload):
        with self._lock:
            self.counts[event] = self.counts.get(event, 0) + 1

    def total(self):
        with self._lock:
            return sum(self.counts.values())

    def status_payload(self):
        return {"running": True}

    def find_user(self, username):
        if self._users is not None:
            return self._users.get(username)
        if self._user is not None and username == self._user["username"]:
            return self._user
        return None


def free_port():
    """Return an unused TCP port on the loopback interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_host_key(dir_path):
    """Write a throwaway Ed25519 host key into dir_path and load it."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    k = Ed25519PrivateKey.generate()
    p = os.path.join(str(dir_path), "host_key")
    with open(p, "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.OpenSSH,
                                serialization.NoEncryption()))
    return paramiko.Ed25519Key(filename=p)


def make_user(username, home, permissions, auth="password", password=None,
              authorized_keys=None):
    """Build a user record in the shape SFTPService/ServerIface expect."""
    user = {
        "username": username,
        "home": str(home),
        "auth": auth,
        "permissions": dict(permissions),
    }
    if password is not None:
        user["password_hash"] = hash_password(password)
    if authorized_keys is not None:
        user["authorized_keys"] = list(authorized_keys)
    return user


def sftp_password(port, username, password, timeout=10):
    """Connect with password auth and return (ssh_client, sftp_client)."""
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect("127.0.0.1", port=port, username=username, password=password,
              allow_agent=False, look_for_keys=False, timeout=timeout)
    sftp = c.open_sftp()
    return c, sftp


def sftp_key(port, username, pkey, timeout=10):
    """Connect with public-key auth and return (ssh_client, sftp_client)."""
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect("127.0.0.1", port=port, username=username, pkey=pkey,
              allow_agent=False, look_for_keys=False, timeout=timeout)
    sftp = c.open_sftp()
    return c, sftp


def authorized_key_line(pkey):
    """Format a client public key the way authorized_keys entries are matched."""
    return "%s %s" % (pkey.get_name(), pkey.get_base64())


__all__ = [
    "CountingApi",
    "free_port",
    "make_host_key",
    "make_user",
    "sftp_password",
    "sftp_key",
    "authorized_key_line",
]
