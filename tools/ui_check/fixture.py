"""ui_drive fixture for Simple SFTP Server's smoke scenario.

The app refuses a regular Start with no users, so this writes a config with
one password user into the throwaway app copy before the app launches. The
user's folder sits in the run's output folder. Both are inside the run
folder ui_drive deletes afterwards. Nothing is written anywhere else.
"""

import json
import os
import secrets
import sys
import time

sys.path.insert(0, os.getcwd())

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
with open(os.path.join(app_dir, "server_config.json"), "x", encoding="utf-8") as f:
    json.dump(config, f, indent=2)

print(json.dumps({"user": "fixtureuser"}), flush=True)
while True:
    time.sleep(60)
