"""ui_drive fixture for Simple SFTP Server's stale-save scenario.

Writes a config with one password user who may only list and download, into
the throwaway app copy before the app launches, so a permission change made
later is easy to see. It prints the user's name and the absolute path of that
copy's server_config.json, which the scenario edits by hand to mimic someone
changing the file while the Manage window is open. The user's folder sits in
the run's output folder. Both are inside the run folder ui_drive deletes
afterwards. Nothing is written anywhere else.
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
permissions = dict(DEFAULT_PERMISSIONS)
permissions.update({"list": True, "download": True, "upload": False})
config = {
    "settings": {"port": 2222},
    "users": [{
        "username": "fixtureuser",
        "home": home,
        "permissions": permissions,
        "auth": "password",
        "password_hash": hash_password(secrets.token_urlsafe(24)),
    }],
}
config_path = os.path.abspath(os.path.join(app_dir, "server_config.json"))
with open(config_path, "x", encoding="utf-8") as f:
    json.dump(config, f, indent=2)

print(json.dumps({"user": "fixtureuser", "config_path": config_path}), flush=True)
while True:
    time.sleep(60)
