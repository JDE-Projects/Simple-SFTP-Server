"""ui_drive fixture for Simple SFTP Server's weak-key scenario.

Writes a config with one key user holding a saved 1024-bit RSA key (too weak)
and an Ed25519 key, into the throwaway app copy before the app launches. It
also prints a second 1024-bit RSA key line for the scenario to paste. The
user's folder sits in the run's output folder. Both are inside the run folder
ui_drive deletes afterwards. Nothing is written anywhere else.
"""

import json
import os
import sys
import time

sys.path.insert(0, os.getcwd())

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa  # noqa: E402

from app.server import DEFAULT_PERMISSIONS  # noqa: E402


def key_line(private_key, name):
    public = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode("ascii")
    return f"{public} {name}"


def weak_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


app_dir = os.environ["UI_DRIVE_APP_DIR"]
out_dir = os.environ["UI_DRIVE_OUT_DIR"]

home = os.path.join(out_dir, "fixture-share")
os.makedirs(home)
config = {
    "settings": {"port": 2222},
    "users": [{
        "username": "keyuser",
        "home": home,
        "permissions": dict(DEFAULT_PERMISSIONS),
        "auth": "key",
        "authorized_keys": [
            key_line(weak_rsa(), "old-laptop"),
            key_line(ed25519.Ed25519PrivateKey.generate(), "new-laptop"),
        ],
    }],
}
with open(os.path.join(app_dir, "server_config.json"), "x", encoding="utf-8") as f:
    json.dump(config, f, indent=2)

print(json.dumps({"user": "keyuser", "weak_paste": key_line(weak_rsa(), "paste-test")}), flush=True)
while True:
    time.sleep(60)
