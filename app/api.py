import json
import os
import shutil
import threading
import webbrowser
from datetime import datetime, timezone

from app import paths
from app.atomic import atomic_write_json
from app.constants import APP_VERSION, DEFAULT_PORT, GITHUB_REPO
from app.debug_log import debug
from app.helpers import fingerprint_sha256, friendly_error
from app.server import DEFAULT_PERMISSIONS, QUICK_PERMISSIONS, SFTPService, perms_for
from app.services.firewall import _firewall_status
from app.services.keygen import generate_keypair as _generate_keypair
from app.services.network import lan_ip, port_is_free, public_ip
from app.services.passwords import generate_password, hash_password
from app.services.prefs import load_prefs, save_prefs
from app.services.updates import check_update as _check_update
from app.services.usernames import validate_username


# ───────────── js api ─────────────
class Api:
    def __init__(self):
        self._window = None
        self.service = SFTPService(self)
        self._quick_user = None
        self._quick_password = ""
        self._new_password = ""
        self._firewall_state = None
        self._cfg_lock = threading.Lock()

    def set_window(self, w):
        self._window = w

    def emit(self, event, payload):
        if self._window:
            try:
                self._window.evaluate_js(
                    f"window.appEvent && window.appEvent({json.dumps(event)},{json.dumps(payload)})")
            except Exception as e:
                # Never let a failed UI push crash a worker thread, but leave a
                # trace when debug logging is on instead of vanishing silently.
                debug.log("emit failed", {"event": event, "error": str(e)})

    def get_meta(self):
        cfg = self._load_config()
        warning = getattr(self, "_config_warning", None)
        self._config_warning = None
        return {"version": APP_VERSION, "key_types": ["Ed25519", "RSA-4096"],
                "default_port": DEFAULT_PORT, "settings": cfg.get("settings", {}),
                "users": self._public_users(cfg), "config_warning": warning}

    def set_debug(self, on):
        ok = debug.set_enabled(on)
        debug.log("Debug enabled" if on and ok else "Debug disabled")
        return {"ok": ok, "enabled": debug.is_enabled()}

    # ---- theme persistence ----
    def get_theme(self):
        theme = load_prefs().get("theme")
        return theme if theme in ("dark", "light") else "dark"

    def save_theme(self, theme):
        if theme not in ("dark", "light"):
            return {"ok": False}
        prefs = load_prefs()
        prefs["theme"] = theme
        return {"ok": save_prefs(prefs)}

    # ---- config ----
    def _load_config(self):
        if not os.path.exists(paths.CONFIG_FILE):
            return {"settings": {"port": DEFAULT_PORT}, "users": []}
        try:
            with open(paths.CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                data.setdefault("settings", {"port": DEFAULT_PORT})
                data.setdefault("users", [])
                return data
        except Exception as e:
            # The file exists but can't be parsed. Preserve it rather than
            # silently discarding it: rename it aside and keep going with a
            # fresh, empty config so the app still opens.
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            corrupt_path = os.path.join(os.path.dirname(paths.CONFIG_FILE),
                                         f"server_config.corrupt-{stamp}.json")
            try:
                os.replace(paths.CONFIG_FILE, corrupt_path)
                debug.log("config unreadable, moved aside", {"from": paths.CONFIG_FILE,
                                                               "to": corrupt_path,
                                                               "error": str(e)})
                self._config_warning = (
                    "Your saved settings file could not be read. It was kept as "
                    f"{os.path.basename(corrupt_path)} and the app started with no "
                    "users. The original file was not deleted.")
            except Exception as e2:
                debug.log("config unreadable and could not be moved aside",
                          {"path": paths.CONFIG_FILE, "error": str(e2)})
                self._config_warning = (
                    "Your saved settings file could not be read and could not be "
                    "moved aside. The app started with no users; the original file "
                    "was left in place.")
        return {"settings": {"port": DEFAULT_PORT}, "users": []}

    def _save_config(self, cfg):
        try:
            cfg["_note"] = "Simple SFTP Server config. Passwords are bcrypt hashes, never plaintext."
            atomic_write_json(paths.CONFIG_FILE, cfg, indent=2)
            return True
        except Exception as e:
            debug.log("save config failed", str(e))
            return False

    def _public_users(self, cfg):
        out = []
        for u in cfg.get("users", []):
            out.append({"username": u.get("username"), "home": u.get("home"),
                        "permissions": perms_for(u),
                        "auth": u.get("auth", "password"),
                        "has_password": bool(u.get("password_hash")),
                        "key_count": len(u.get("authorized_keys", []))})
        return out

    def find_user(self, username):
        if self._quick_user and username == self._quick_user["username"]:
            return self._quick_user
        for u in self._load_config().get("users", []):
            if u.get("username") == username:
                return u
        return None

    # ---- folders ----
    def pick_folder(self):
        try:
            import webview
            try:
                dlg = webview.FileDialog.FOLDER
            except AttributeError:  # older pywebview
                dlg = webview.FOLDER_DIALOG
            res = self._window.create_file_dialog(dlg)
            if res:
                return {"ok": True, "path": res[0] if isinstance(res, (list, tuple)) else res}
            return {"ok": False}
        except Exception as e:
            return {"ok": False, "error": friendly_error(e)}

    def make_share_folder(self, username):
        ok, msg = validate_username(username)
        if not ok:
            return {"ok": False, "error": msg}
        path = os.path.join(paths.exe_dir(), f"{username}-share")
        try:
            os.makedirs(path, exist_ok=True)
            return {"ok": True, "path": path}
        except Exception as e:
            return {"ok": False, "error": friendly_error(e)}

    def reveal_folder(self, path):
        try:
            if path and os.path.isdir(path):
                os.startfile(path)  # noqa (Windows)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": friendly_error(e)}

    # ---- password generation ----
    def new_password(self):
        self._new_password = generate_password(20)
        return {"password": self._new_password}

    def validate_username(self, username):
        ok, msg = validate_username(username)
        return {"ok": ok, "error": msg}

    # ---- users ----
    def save_user(self, p, original=None):
        username = (p.get("username") or "").strip()
        ok, msg = validate_username(username)
        if not ok:
            return {"ok": False, "error": msg}
        home = (p.get("home") or "").strip()
        if not home:
            return {"ok": False, "error": "Choose a folder for this user."}
        if not os.path.isdir(home):
            try:
                os.makedirs(home, exist_ok=True)
            except Exception as e:
                return {"ok": False, "error": "Could not create that folder: " + friendly_error(e)}
        # permissions
        perms_in = p.get("permissions") or {}
        if not isinstance(perms_in, dict):
            perms_in = {}
        permissions = {k: bool(perms_in.get(k, False)) for k in DEFAULT_PERMISSIONS}
        # require at least one permission
        if not any(permissions.values()):
            return {"ok": False, "error": "Grant the user at least one permission."}
        auth = p.get("auth", "password")
        with self._cfg_lock:
            cfg = self._load_config()
            users = cfg.get("users", [])
            for u in users:
                if u.get("username") == username and username != (original or ""):
                    return {"ok": False, "error": "A user with that name already exists."}
            existing = next((u for u in users if u.get("username") == (original or username)), None)
            rec = existing or {}
            rec["username"] = username
            rec["home"] = home
            rec["permissions"] = permissions
            rec["auth"] = auth
            # remove legacy fields if present
            rec.pop("access", None)
            rec.pop("allow_delete", None)
            plain = p.get("password") or ""
            if auth in ("password", "both"):
                if plain:
                    rec["password_hash"] = hash_password(plain)
                elif not rec.get("password_hash"):
                    return {"ok": False, "error": "Set a password for this user (or switch to key auth)."}
            else:
                rec.pop("password_hash", None)
            if auth in ("key", "both"):
                keys = p.get("authorized_keys") or []
                cleaned = []
                for k in keys:
                    k = (k or "").strip()
                    if k and len(k.split()) >= 2 and k.split()[0].startswith(("ssh-", "ecdsa-")):
                        cleaned.append(k)
                if not cleaned and not rec.get("authorized_keys"):
                    return {"ok": False, "error": "Add at least one public key (or switch to password auth)."}
                if cleaned:
                    rec["authorized_keys"] = cleaned
            else:
                rec.pop("authorized_keys", None)
            if existing is None:
                users.append(rec)
            users.sort(key=lambda x: x.get("username", "").lower())
            cfg["users"] = users
            self._new_password = ""
            if not self._save_config(cfg):
                return {"ok": False, "error": "Could not write the config file."}
        debug.log("user saved", {"user": username, "permissions": permissions, "auth": auth})
        return {"ok": True, "users": self._public_users(cfg)}

    def delete_user(self, username, delete_folder=False):
        with self._cfg_lock:
            cfg = self._load_config()
            user_rec = next((u for u in cfg.get("users", []) if u.get("username") == username), None)
            cfg["users"] = [u for u in cfg.get("users", []) if u.get("username") != username]
            if not self._save_config(cfg):
                return {"ok": False, "error": "Could not write the config file."}
        warning = None
        if delete_folder and user_rec:
            home = user_rec.get("home", "")
            if home and os.path.isdir(home):
                try:
                    shutil.rmtree(home)
                    debug.log("user folder deleted", home)
                except Exception as e:
                    debug.log("user folder delete failed", str(e))
                    warning = "The user was removed but their folder could not be deleted: " + friendly_error(e)
        result = {"ok": True, "users": self._public_users(cfg)}
        if warning:
            result["warning"] = warning
        return result

    def generate_keypair(self, key_type, out_path, passphrase, username):
        return _generate_keypair(key_type, out_path, passphrase, username)

    def browse_save_key(self, suggested):
        try:
            import webview
            try:
                dlg = webview.FileDialog.SAVE
            except AttributeError:  # older pywebview
                dlg = webview.SAVE_DIALOG
            res = self._window.create_file_dialog(
                dlg, save_filename=suggested or "id_ed25519")
            return res[0] if isinstance(res, (list, tuple)) and res else (res or "")
        except Exception:
            return ""

    # ---- start / stop ----
    def _check_firewall_async(self, port):
        # Advisory only: runs on a daemon thread so it never delays startup, and a
        # failure inside _firewall_status is caught there and returns "unknown".
        def worker():
            self._firewall_state = _firewall_status(port)
            self.emit("status", self.status_payload())
        threading.Thread(target=worker, daemon=True).start()

    def start_server(self, port):
        with self._cfg_lock:
            cfg = self._load_config()
            if not cfg.get("users"):
                return {"ok": False, "error": "Add at least one user before starting (or use Quick Start)."}
            try:
                cfg.setdefault("settings", {})["port"] = int(port or DEFAULT_PORT)
                self._save_config(cfg)
            except Exception:
                pass
        use_port = int(port or DEFAULT_PORT)
        r = self.service.start(use_port, quick=False)
        if r.get("ok"):
            self.emit("status", self.status_payload())
            self._check_firewall_async(use_port)
        return r

    def stop_server(self, delete_folder=False):
        was_quick = self.service.is_quick
        quick_folder = paths.QUICK_FOLDER if was_quick else ""
        self.service.stop()
        self._firewall_state = None
        self._quick_user = None
        self._quick_password = ""
        if delete_folder and was_quick and quick_folder and os.path.isdir(quick_folder):
            try:
                shutil.rmtree(quick_folder)
                debug.log("quick folder deleted", quick_folder)
            except Exception as e:
                debug.log("quick folder delete failed", str(e))
        return {"ok": True, "status": self.status_payload()}

    def quick_start(self):
        if self.service.running:
            return {"ok": False, "error": "Stop the running server first."}
        try:
            os.makedirs(paths.QUICK_FOLDER, exist_ok=True)
        except Exception as e:
            return {"ok": False, "error": friendly_error(e)}
        self._quick_password = generate_password(20)
        self._quick_user = {"username": "quickstart", "home": paths.QUICK_FOLDER,
                            "permissions": QUICK_PERMISSIONS,
                            "auth": "password",
                            "password_hash": hash_password(self._quick_password)}
        cfg = self._load_config()
        port = int(cfg.get("settings", {}).get("port", DEFAULT_PORT))
        r = self.service.start(port, quick=True)
        if not r.get("ok"):
            self._quick_user = None
            self._quick_password = ""
            return r
        self.emit("status", self.status_payload())
        self._check_firewall_async(port)
        return {"ok": True, "port": port, "folder": paths.QUICK_FOLDER, "username": "quickstart"}

    def reveal_quick_password(self):
        if self.service.running and self.service.is_quick:
            return {"ok": True, "password": self._quick_password}
        return {"ok": False}

    # ---- status / network ----
    def status_payload(self):
        running = self.service.running
        return {"running": running, "quick": self.service.is_quick,
                "port": self.service.port,
                "lan": lan_ip() if running else "",
                "fingerprint": fingerprint_sha256(self.service.host_key) if self.service.host_key else "",
                "connections": self.service.connections() if running else [],
                "locked": self.service.lockout.locked_list(),
                "quick_folder": paths.QUICK_FOLDER if self.service.is_quick else "",
                "firewall": self._firewall_state if running else None}

    def get_status(self):
        return self.status_payload()

    def get_public_ip(self):
        ip = public_ip()
        return {"ok": bool(ip), "ip": ip}

    def check_port(self, port):
        return {"free": port_is_free(port)}

    # ---- lockout ----
    def unlock_ip(self, ip):
        self.service.lockout.clear(ip)
        return {"ok": True, "status": self.status_payload()}

    def unlock_all(self):
        self.service.lockout.clear_all()
        return {"ok": True, "status": self.status_payload()}

    # ---- update / misc ----
    def check_update(self):
        return _check_update(APP_VERSION, GITHUB_REPO)

    def open_url(self, url):
        try:
            webbrowser.open(url)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": friendly_error(e)}
