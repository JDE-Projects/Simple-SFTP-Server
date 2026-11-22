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
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from app.server import DEFAULT_PERMISSIONS  # noqa: E402

# Two fixed 1024-bit RSA public keys, the size the app must refuse. They are
# public halves only, with no private key kept anywhere, so they hold nothing
# secret and no weak key is created at run time.
WEAK_SAVED = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC5SNwCCtVcxSFgA7kFk445+ZvoNdNvR3NZr29MIQnrrukUQEPkCtDw"
    "K850i+0bLf7d9fw9g5wS2M3EGccT3Onx8vgPUHXKXQemVDmcuHPPvhbToLTJDMTTgXz6oLeqWuT0MURTZMtinjlvrOGP"
    "cy8sak8Wzg1AmQK93HCdTnIt0Q==")
WEAK_PASTE = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCjW/NS+qkuAR/XFKRNs1+3xmB8WOuQFq8PZJzMxYeeJ4n72inswMn+"
    "7OEE3qei7mP4LTJLpioLYvBHR3vzPVGbAlMGrIuMLm1lQoQMiw9/ZWWrM3brb7dJqeOLawSdNBPoRs2mbuTNlwfvxvTt"
    "ta8vFxApowHwKadD/6m1axAnPw==")


def key_line(private_key, name):
    public = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode("ascii")
    return f"{public} {name}"


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
            WEAK_SAVED + " old-laptop",
            key_line(ed25519.Ed25519PrivateKey.generate(), "new-laptop"),
        ],
    }],
}
with open(os.path.join(app_dir, "server_config.json"), "x", encoding="utf-8") as f:
    json.dump(config, f, indent=2)

print(json.dumps({"user": "keyuser", "weak_paste": WEAK_PASTE + " paste-test"}), flush=True)
while True:
    time.sleep(60)
