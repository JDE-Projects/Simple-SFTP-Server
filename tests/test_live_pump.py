"""Task 1 regression: the live-view update path must not scale with file count.

Starts the real SFTPService on an ephemeral loopback port, connects a real
Paramiko client, transfers a large synthetic set of small files, and asserts the
number of UI pushes stays bounded by elapsed time (the coalescing pump rate),
not by the number of files moved. Before the fix each file fired 2-4 synchronous
cross-layer pushes, which took a production server down.
"""

import io
import math
import os
import socket
import threading
import time

import paramiko
import pytest

from app import server as server_mod
from app.server import SFTPService
from app.services.passwords import hash_password


class CountingApi:
    """Stands in for the real Api and counts every UI push by event type."""

    def __init__(self, user):
        self._user = user
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
        return self._user if username == self._user["username"] else None


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _make_host_key(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    k = Ed25519PrivateKey.generate()
    p = os.path.join(str(tmp_path), "host_key")
    with open(p, "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.OpenSSH,
                                serialization.NoEncryption()))
    return paramiko.Ed25519Key(filename=p)


def _connect(port, username, password):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect("127.0.0.1", port=port, username=username, password=password,
              allow_agent=False, look_for_keys=False, timeout=10)
    return c


def test_ui_pushes_stay_bounded_over_many_files(tmp_path):
    files = 400
    home = tmp_path / "home"
    home.mkdir()
    password = "correct horse battery staple"
    user = {"username": "bob", "home": str(home), "auth": "password",
            "password_hash": hash_password(password),
            "permissions": {k: True for k in server_mod.QUICK_PERMISSIONS}}

    api = CountingApi(user)
    service = SFTPService(api)
    service.host_key = _make_host_key(tmp_path)
    port = _free_port()

    r = service.start(port)
    assert r["ok"], r
    try:
        start = time.time()
        client = _connect(port, "bob", password)
        sftp = client.open_sftp()
        blob = b"x" * 64
        for i in range(files):
            sftp.putfo(io.BytesIO(blob), f"/f{i:05d}.bin")
        sftp.close()
        client.close()
        # Let the pump run one last window so any final push lands, then stop.
        time.sleep(server_mod.PUMP_INTERVAL * 2)
        duration = time.time() - start
    finally:
        service.stop()

    # Every file really was written.
    assert len(os.listdir(str(home))) == files

    total = api.total()
    # The pump pushes at most three events per tick (status, activity, transfer)
    # while something is dirty. Bound the pushes by the wall-clock window, not by
    # the number of files, with generous slack for connect/disconnect and jitter.
    ticks = math.ceil(duration / server_mod.PUMP_INTERVAL) + 2
    bound = ticks * 3 + 8
    assert total <= bound, f"{total} pushes for {files} files over {duration:.2f}s (bound {bound})"
    # And the headline property: pushes are far below one-per-file.
    assert total < files, f"{total} pushes still scales with {files} files"
