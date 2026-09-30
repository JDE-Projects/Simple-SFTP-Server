"""ui_drive fixture for Simple SFTP Server's start-errors scenario.

Writes into the throwaway app copy, before the app launches:
- a config with one password user (a regular Start needs one), whose folder
  sits in the run's output folder;
- an RSA 2048 host key saved as host_ed25519, the kind versions up to 1.5.0
  could write.

It then keeps the config file open for the whole run. Windows refuses to
replace a file another program has open, so the app can read the config but
every save fails, which is the real "port could not be saved" path. The
handle closes when the run ends and kills this script.

Both files are inside the run folder ui_drive deletes afterwards. Nothing is
written anywhere else.
"""

import json
import os
import secrets
import sys
import time

sys.path.insert(0, os.getcwd())

import paramiko  # noqa: E402

from app.helpers import fingerprint_sha256  # noqa: E402
from app.server import DEFAULT_PERMISSIONS  # noqa: E402
from app.services.passwords import hash_password  # noqa: E402

app_dir = os.environ["UI_DRIVE_APP_DIR"]
out_dir = os.environ["UI_DRIVE_OUT_DIR"]

home = os.path.join(out_dir, "fixture-share")
os.makedirs(home)
config = {
    "settings": {"port": 2222},
    "users": [{
        "username": "fixtureuser",
        "home": home,
        "permissions": dict(DEFAULT_PERMISSIONS),
        "auth": "password",
        "password_hash": hash_password(secrets.token_urlsafe(24)),
    }],
}
config_path = os.path.join(app_dir, "server_config.json")
with open(config_path, "x", encoding="utf-8") as f:
    json.dump(config, f, indent=2)

key_path = os.path.join(app_dir, "host_ed25519")
if os.path.exists(key_path):
    raise SystemExit("host_ed25519 already exists in the app copy")
key = paramiko.RSAKey.generate(2048)
key.write_private_key_file(key_path)

held = open(config_path, "r", encoding="utf-8")

print(json.dumps({"fingerprint": fingerprint_sha256(key)}), flush=True)
while True:
    time.sleep(60)
