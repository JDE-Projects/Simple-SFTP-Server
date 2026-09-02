"""
Simple SFTP Server
A clean, single-window SFTP server: point at a folder, add users (each jailed to
their own folder), and bring it online to your LAN or the internet. Or hit Quick
Start for an instant server with a fresh random password.

Secure algorithms only (no weak/CVE'd fallbacks): a client that can only offer an
outdated algorithm set is refused rather than downgrading.

Passwords are never stored or shown after entry: only a bcrypt hash is kept, in
server_config.json next to the exe. Public-key users store only their key text.
The Quick Start password lives in memory only and is wiped when it stops.

Backend: paramiko (server side). Window: pywebview on the Qt backend, UI in
simple_sftp_server-UI.html.

Built with AI assistance, directed by JDE-Projects.
"""

import os
import sys
import io
import re
import ctypes
from ctypes import wintypes
import json
import time
import errno
import socket
import ssl
import base64
import hashlib
import secrets
import threading
import traceback
import shutil
import webbrowser
from datetime import datetime, timezone
from urllib.request import Request, urlopen
import urllib.error

import paramiko
import bcrypt

APP_VERSION = "1.4.3"
GITHUB_REPO = "JDE-Projects/Simple-SFTP-Server"
DEFAULT_PORT = 2222

DISABLED_ALGORITHMS = {
    "kex": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1"],
    "ciphers": ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
                "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128", "arcfour256"],
    "macs": ["hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-sha1"],
    "keys": ["ssh-dss"],
}

LOCKOUT_THRESHOLD = 5
LOCKOUT_SECONDS = 15 * 60


# ───────────── paths ─────────────
def resource_path(rel):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)


def exe_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


CONFIG_FILE = os.path.join(exe_dir(), "server_config.json")
HOST_KEY_FILE = os.path.join(exe_dir(), "host_ed25519")
QUICK_FOLDER = os.path.join(exe_dir(), "QuickStart-Share")


# ───────────── debug log ─────────────
class DebugLog:
    def __init__(self):
        self._on = False
        self._path = None
        self._lock = threading.Lock()

    def set_enabled(self, on):
        with self._lock:
            on = bool(on)
            if on and not self._path:
                stamp = datetime.now().strftime("%m%d%Y_%H%M%S")
                self._path = os.path.join(exe_dir(), f"Debug_Log_{stamp}.txt")
                try:
                    with open(self._path, "w", encoding="utf-8") as f:
                        f.write("=== Simple SFTP Server debug log ===\n")
                        f.write(f"Started: {datetime.now().isoformat()}\n" + "=" * 60 + "\n\n")
                except Exception:
                    self._path = None
                    self._on = False
                    return False
            self._on = on
            return True

    def is_enabled(self):
        return self._on

    def log(self, label, content=""):
        if not self._on or not self._path:
            return
        try:
            with self._lock, open(self._path, "a", encoding="utf-8") as f:
                ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                f.write(f"[{ts}] {label}\n")
                if content:
                    if isinstance(content, (dict, list)):
                        content = json.dumps(content, indent=2, default=str)
                    f.write(f"{content}\n")
                f.write("\n")
        except Exception:
            pass


debug = DebugLog()


# ───────────── helpers ─────────────
def human_size(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return (f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}")
        n /= 1024


def fingerprint_sha256(key):
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def friendly_error(e):
    try:
        debug.log("error detail", f"{type(e).__name__}: {e}")
    except Exception:
        pass
    if isinstance(e, PermissionError):
        return "Permission denied. Choose a folder this app can read and write."
    if isinstance(e, FileNotFoundError):
        return "That folder was not found."
    if isinstance(e, OSError):
        en = getattr(e, "errno", None)
        win = getattr(e, "winerror", None)
        if en == errno.EADDRINUSE or win == 10048:
            return "That port is already in use by another program. Pick a different port."
        if en == errno.EACCES or win == 10013:
            return "That port needs administrator rights (ports below 1024). Use 1024 or higher."
        if en == errno.EADDRNOTAVAIL:
            return "That address is not available on this machine."
        return (e.strerror or "The operation failed.")
    return "Something went wrong. Turn on the debug log for details."


# ───────────── passwords ─────────────
_SAFE_LOWER = "abcdefghijkmnpqrstuvwxyz"
_SAFE_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_SAFE_DIGIT = "23456789"
_SYMBOLS = "!@#$%^&*()"


def generate_password(length=20):
    length = max(16, int(length))
    pools = [_SAFE_LOWER, _SAFE_UPPER, _SAFE_DIGIT, _SYMBOLS]
    allchars = "".join(pools)
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(allchars) for _ in range(length - len(pools))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def hash_password(plain):
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(plain, hashed):
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("ascii"))
    except Exception:
        return False


# A precomputed bcrypt hash of a throwaway string, used only to burn roughly
# the same amount of time as a real password check when the username doesn't
# exist (or has no password set), so login failures don't leak which
# usernames are valid through response timing.
_DUMMY_PASSWORD_HASH = hash_password("simple-sftp-server-dummy-check")


# ───────────── usernames ─────────────
_RESERVED = {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}


def validate_username(u):
    u = (u or "").strip()
    if not u or len(u) > 32:
        return False, "Username must be 1 to 32 characters."
    if not re.fullmatch(r"[A-Za-z0-9._-]+", u):
        return False, "Use only letters, digits, dot, underscore or hyphen."
    if u.startswith(".") or u.endswith("."):
        return False, "Username cannot start or end with a dot."
    if u.lower() in _RESERVED:
        return False, "That name is reserved by Windows."
    return True, ""


# ───────────── network ─────────────
def lan_ip():
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"
    finally:
        if s:
            s.close()


def public_ip():
    for url in ("https://api.ipify.org", "https://checkip.amazonaws.com",
                "https://ifconfig.me/ip"):
        try:
            req = Request(url, headers={"User-Agent": "Simple-SFTP-Server"})
            with urlopen(req, timeout=6) as r:
                ip = r.read().decode().strip()
            if re.fullmatch(r"[0-9.]{7,15}", ip):
                return ip
        except Exception:
            continue
    return ""


def port_is_free(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", int(port)))
        return True
    except OSError:
        return False
    finally:
        s.close()


# ───────────── firewall detection (advisory, read-only, no admin) ─────────────
def _parse_firewall_rule(s):
    """Split a pipe-delimited Windows Firewall rule string into a dict with
    lowercased keys, e.g. 'Action=Allow|Dir=In|LocalPort=2222' -> {"action":"Allow",...}.
    Tolerant of malformed or empty segments; never raises."""
    out = {}
    if not s:
        return out
    for seg in str(s).split("|"):
        if "=" not in seg:
            continue
        k, _, v = seg.partition("=")
        k = k.strip().lower()
        if k:
            out[k] = v.strip()
    return out


def _port_in_localport(port, localport):
    """True if `port` matches a rule's LocalPort value: exact, 'Any', a comma list, or an 'a-b' range."""
    if not localport:
        return False
    localport = localport.strip()
    if localport.lower() == "any":
        return True
    port = str(port)
    for part in localport.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                if int(lo) <= int(port) <= int(hi):
                    return True
            except ValueError:
                continue
        elif part == port:
            return True
    return False


def _rule_allows(parsed, exe_norm, port):
    """True only for an ENABLED, INBOUND, ALLOW rule that clearly matches our exe path
    or our TCP port. Conservative on purpose: only a clear match returns True."""
    if not parsed:
        return False
    if (parsed.get("active", "TRUE") or "TRUE").upper() == "FALSE":
        return False
    if (parsed.get("action") or "").strip().lower() != "allow":
        return False
    if (parsed.get("dir") or "").strip().lower() != "in":
        return False
    app = parsed.get("app")
    if app:
        try:
            if os.path.normcase(os.path.realpath(app)) == exe_norm:
                return True
        except Exception:
            pass
    protocol = (parsed.get("protocol") or "").strip()
    if protocol == "6" and _port_in_localport(port, parsed.get("localport")):
        return True
    return False


def _decide_firewall(any_profile_enabled, has_allow):
    """Three-state decision: 'allowed' / 'blocked' / 'unknown'."""
    if has_allow:
        return "allowed"
    if any_profile_enabled is False:
        return "allowed"
    if any_profile_enabled is True:
        return "blocked"
    return "unknown"


def _firewall_status(port):
    """Advisory-only, read-only registry check. Any failure (missing key, permission,
    unexpected value) is logged and returns 'unknown'; this must never raise and must
    never affect whether the server runs."""
    try:
        import winreg
        policy = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        readable = False
        any_enabled = False
        for profile in ("StandardProfile", "PublicProfile", "DomainProfile"):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{policy}\\{profile}") as k:
                    val, _ = winreg.QueryValueEx(k, "EnableFirewall")
                readable = True
                if val == 1:
                    any_enabled = True
            except OSError:
                continue
        any_profile_enabled = any_enabled if readable else None

        exe_norm = os.path.normcase(os.path.realpath(
            sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)))

        # Known limitation (see roadmap.md "Firewall detection and messaging"): we treat
        # "any profile enabled" as a proxy for whichever profile is actually active,
        # since reliably determining the in-use profile without admin rights or COM is
        # not practical here. We also only see Windows Defender Firewall, never
        # third-party firewalls or the router. That is why the UI says connections
        # "may be" blocked rather than stating it as certain.
        has_allow = False
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{policy}\\FirewallRules") as k:
                i = 0
                while True:
                    try:
                        _name, value, _vtype = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    parsed = _parse_firewall_rule(value)
                    if _rule_allows(parsed, exe_norm, port):
                        has_allow = True
                        break
        except OSError:
            pass

        return _decide_firewall(any_profile_enabled, has_allow)
    except Exception as e:
        debug.log("firewall check failed", str(e))
        return "unknown"


# ───────────── host key ─────────────
def load_or_create_host_key():
    if os.path.exists(HOST_KEY_FILE):
        try:
            return paramiko.Ed25519Key(filename=HOST_KEY_FILE)
        except Exception as e:
            debug.log("host key load failed, regenerating", str(e))
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        k = Ed25519PrivateKey.generate()
        priv = k.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.OpenSSH,
                               serialization.NoEncryption())
        with open(HOST_KEY_FILE, "wb") as f:
            f.write(priv)
        try:
            os.chmod(HOST_KEY_FILE, 0o600)
        except OSError:
            pass
        return paramiko.Ed25519Key(filename=HOST_KEY_FILE)
    except Exception as e:
        debug.log("ed25519 host key failed, using RSA", str(e))
        key = paramiko.RSAKey.generate(3072)
        key.write_private_key_file(HOST_KEY_FILE)
        return key


# ───────────── lockout ─────────────
class Lockout:
    def __init__(self):
        self._lock = threading.Lock()
        self._fails = {}
        self._until = {}

    def is_locked(self, ip):
        with self._lock:
            u = self._until.get(ip)
            if u and time.time() < u:
                return True
            if u:
                self._until.pop(ip, None)
                self._fails.pop(ip, None)
            return False

    def record_fail(self, ip):
        with self._lock:
            n = self._fails.get(ip, 0) + 1
            self._fails[ip] = n
            if n >= LOCKOUT_THRESHOLD:
                self._until[ip] = time.time() + LOCKOUT_SECONDS

    def clear(self, ip):
        with self._lock:
            self._fails.pop(ip, None)
            self._until.pop(ip, None)

    def clear_all(self):
        with self._lock:
            self._fails.clear()
            self._until.clear()

    def locked_list(self):
        out = []
        now = time.time()
        with self._lock:
            for ip, u in list(self._until.items()):
                if u > now:
                    out.append({"ip": ip, "remaining": int(u - now)})
        return out


# ───────────── default permissions ─────────────
DEFAULT_PERMISSIONS = {
    "list": True,
    "download": False,
    "upload": False,
    "delete": False,
    "rename_file": False,
    "rename_dir": False,
    "mkdir": False,
    "delete_dir": False,
}

QUICK_PERMISSIONS = {
    "list": True,
    "download": True,
    "upload": True,
    "delete": True,
    "rename_file": True,
    "rename_dir": True,
    "mkdir": True,
    "delete_dir": True,
}


def perms_for(user):
    """Return the permission dict for a user record."""
    p = user.get("permissions")
    if isinstance(p, dict):
        # fill any missing keys with False
        return {k: bool(p.get(k, False)) for k in DEFAULT_PERMISSIONS}
    # fallback for any legacy record (should not occur in fresh installs)
    return dict(DEFAULT_PERMISSIONS)


# ───────────── jailed SFTP filesystem ─────────────
class JailedHandle(paramiko.SFTPHandle):
    def __init__(self, flags, iface, name, direction, total):
        super().__init__(flags)
        self._iface = iface
        self._name = name
        self._dir = direction
        self._total = total
        self._bytes = 0
        self._last_emit = 0.0
        self.readfile = None
        self.writefile = None

    def stat(self):
        try:
            f = self.readfile or self.writefile
            return paramiko.SFTPAttributes.from_stat(os.fstat(f.fileno()))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def chattr(self, attr):
        return paramiko.SFTP_OK

    def write(self, offset, data):
        if self.writefile is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            self.writefile.seek(offset)
            self.writefile.write(data)
        except (OSError, IOError) as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        self._bytes += len(data)
        self._iface._progress(self)
        return paramiko.SFTP_OK

    def read(self, offset, length):
        if self.readfile is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            self.readfile.seek(offset)
            data = self.readfile.read(length)
        except (OSError, IOError) as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        self._bytes += len(data)
        self._iface._progress(self)
        return data

    def close(self):
        try:
            super().close()
        finally:
            self._iface._finish(self)


class JailedSFTP(paramiko.SFTPServerInterface):
    def __init__(self, server, *largs, **kwargs):
        super().__init__(server, *largs, **kwargs)
        self.service = getattr(server, "service", None)
        self.user = getattr(server, "user", None)
        self.ip = getattr(server, "ip", "")
        self.sid = getattr(server, "sid", "")
        home = (self.user or {}).get("home", "")
        if home:
            try:
                self.root = os.path.realpath(home)
            except Exception:
                self.root = home
        else:
            # No home configured: fail closed rather than letting
            # os.path.realpath("") resolve to the current working directory.
            self.root = None
        self.perm = perms_for(self.user) if self.user else dict(DEFAULT_PERMISSIONS)

    def _progress(self, handle):
        if self.service:
            self.service._progress(handle)

    def _finish(self, handle):
        if self.service:
            self.service._finish(handle)

    def _real(self, path):
        if not self.root:
            return None
        p = path.replace("\\", "/")
        while p.startswith("/"):
            p = p[1:]
        full = os.path.realpath(os.path.join(self.root, p))
        if full == self.root or full.startswith(self.root + os.sep):
            return full
        return None

    def list_folder(self, path):
        if not self.perm["list"]:
            return paramiko.SFTP_PERMISSION_DENIED
        real = self._real(path)
        if real is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            out = []
            for name in os.listdir(real):
                try:
                    attr = paramiko.SFTPAttributes.from_stat(os.stat(os.path.join(real, name)))
                except OSError:
                    continue
                attr.filename = name
                out.append(attr)
            return out
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def stat(self, path):
        real = self._real(path)
        if real is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(real))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def lstat(self, path):
        real = self._real(path)
        if real is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            return paramiko.SFTPAttributes.from_stat(os.lstat(real))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def open(self, path, flags, attr):
        real = self._real(path)
        if real is None:
            return paramiko.SFTP_PERMISSION_DENIED
        if flags & os.O_WRONLY:
            reading, writing = False, True
        elif flags & os.O_RDWR:
            reading, writing = True, True
        else:
            reading, writing = True, False
        if writing and not self.perm["upload"]:
            return paramiko.SFTP_PERMISSION_DENIED
        if reading and not self.perm["download"]:
            return paramiko.SFTP_PERMISSION_DENIED
        # overwrite check: blocked unless user can delete files
        exists = os.path.exists(real)
        if writing and exists and not self.perm["delete"]:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            mode = getattr(attr, "st_mode", None) or 0o644
            fd = os.open(real, flags, mode)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        if flags & os.O_WRONLY:
            fstr = "ab" if (flags & os.O_APPEND) else "wb"
        elif flags & os.O_RDWR:
            fstr = "a+b" if (flags & os.O_APPEND) else "r+b"
        else:
            fstr = "rb"
        try:
            f = os.fdopen(fd, fstr)
        except OSError as e:
            os.close(fd)
            return paramiko.SFTPServer.convert_errno(e.errno)
        direction = "download" if (reading and not writing) else "upload"
        total = None
        if direction == "download":
            try:
                total = os.path.getsize(real)
            except OSError:
                total = None
        handle = JailedHandle(flags, self, os.path.basename(real), direction, total)
        handle.filename = real
        if reading and not writing:
            handle.readfile = f
        elif writing and not reading:
            handle.writefile = f
        else:
            handle.readfile = f
            handle.writefile = f
        if self.service:
            self.service.transfer_begin(self.sid, handle)
        return handle

    def remove(self, path):
        if not self.perm["delete"]:
            return paramiko.SFTP_PERMISSION_DENIED
        real = self._real(path)
        if real is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            os.remove(real)
            if self.service:
                self.service.activity(self.sid, "deleted", os.path.basename(real))
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def rename(self, oldpath, newpath):
        o = self._real(oldpath)
        n = self._real(newpath)
        if o is None or n is None:
            return paramiko.SFTP_PERMISSION_DENIED
        is_dir = os.path.isdir(o)
        if is_dir and not self.perm["rename_dir"]:
            return paramiko.SFTP_PERMISSION_DENIED
        if not is_dir and not self.perm["rename_file"]:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            os.rename(o, n)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def mkdir(self, path, attr):
        if not self.perm["mkdir"]:
            return paramiko.SFTP_PERMISSION_DENIED
        real = self._real(path)
        if real is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            os.mkdir(real)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def rmdir(self, path):
        if not self.perm["delete_dir"]:
            return paramiko.SFTP_PERMISSION_DENIED
        real = self._real(path)
        if real is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            os.rmdir(real)
            if self.service:
                self.service.activity(self.sid, "removed folder", os.path.basename(real))
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)


# ───────────── SSH server interface (auth) ─────────────
class ServerIface(paramiko.ServerInterface):
    def __init__(self, service, ip, sid):
        self.service = service
        self.ip = ip
        self.sid = sid
        self.username = None
        self.user = None

    def get_allowed_auths(self, username):
        u = self.service.find_user(username)
        methods = []
        if u:
            if u.get("auth") in ("password", "both") and u.get("password_hash"):
                methods.append("password")
            if u.get("auth") in ("key", "both") and u.get("authorized_keys"):
                methods.append("publickey")
        return ",".join(methods) if methods else "publickey,password"

    def check_auth_password(self, username, password):
        if self.service.lockout.is_locked(self.ip):
            return paramiko.AUTH_FAILED
        u = self.service.find_user(username)
        real_hash = u.get("password_hash") if (u and u.get("auth") in ("password", "both")) else None
        if real_hash:
            if verify_password(password, real_hash):
                self._win(username, u)
                return paramiko.AUTH_SUCCESSFUL
        else:
            # No real user/hash to check against: run a dummy bcrypt check
            # anyway and discard the result, so this path takes about as
            # long as the real one and doesn't leak valid usernames via timing.
            verify_password(password, _DUMMY_PASSWORD_HASH)
        self.service.lockout.record_fail(self.ip)
        debug.log("auth fail (password)", {"ip": self.ip, "user": username})
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if self.service.lockout.is_locked(self.ip):
            return paramiko.AUTH_FAILED
        u = self.service.find_user(username)
        if u and u.get("auth") in ("key", "both"):
            offered = key.get_base64()
            for ak in u.get("authorized_keys", []):
                parts = ak.split()
                if len(parts) >= 2 and parts[1] == offered:
                    self._win(username, u)
                    return paramiko.AUTH_SUCCESSFUL
        self.service.lockout.record_fail(self.ip)
        debug.log("auth fail (key)", {"ip": self.ip, "user": username})
        return paramiko.AUTH_FAILED

    def _win(self, username, user):
        self.username = username
        self.user = user
        self.service.lockout.clear(self.ip)

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request(self, channel, name):
        ok = (name == "sftp")
        return paramiko.ServerInterface.check_channel_subsystem_request(self, channel, name) if ok else False

    def check_channel_pty_request(self, *a, **k):
        return False

    def check_channel_shell_request(self, channel):
        return False

    def check_channel_exec_request(self, channel, command):
        return False


# ───────────── the server service ─────────────
class SFTPService:
    def __init__(self, api):
        self.api = api
        self.lockout = Lockout()
        self.host_key = None
        self.sock = None
        self.port = None
        self.running = False
        self.is_quick = False
        self._accept_thread = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._sessions = {}
        self._sid = 0

    def find_user(self, username):
        return self.api.find_user(username)

    def start(self, port, quick=False):
        if self.running:
            return {"ok": False, "error": "Server is already running."}
        port = int(port or DEFAULT_PORT)
        if self.host_key is None:
            self.host_key = load_or_create_host_key()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            s.listen(20)
        except OSError as e:
            s.close()
            return {"ok": False, "error": friendly_error(e)}
        self.sock = s
        self.port = port
        self.is_quick = quick
        self.running = True
        self._stop.clear()
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        debug.log("SERVER start", {"port": port, "quick": quick})
        return {"ok": True, "port": port}

    def stop(self):
        self._stop.set()
        self.running = False
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.sock = None
        with self._lock:
            self._sessions.clear()
        debug.log("SERVER stop")
        return {"ok": True}

    def _accept_loop(self):
        while not self._stop.is_set():
            sock = self.sock
            if sock is None:
                break
            try:
                sock.settimeout(1.0)
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _handle(self, conn, addr):
        ip = addr[0]
        if self.lockout.is_locked(ip):
            debug.log("rejected (locked)", ip)
            try:
                conn.close()
            except Exception:
                pass
            return
        with self._lock:
            self._sid += 1
            sid = self._sid
        t = None
        try:
            t = paramiko.Transport(conn, disabled_algorithms=DISABLED_ALGORITHMS)
            t.local_version = "SSH-2.0-SimpleSFTPServer"
            t.add_server_key(self.host_key)
            t.set_subsystem_handler("sftp", paramiko.SFTPServer, JailedSFTP)
            server = ServerIface(self, ip, sid)
            t.start_server(server=server)
            # Ping the client every 15s. If the link dies silently (a network
            # blip, a NAT/router timeout) the send fails, paramiko marks the
            # transport inactive, and the loop below drops the session. Without
            # this, dead sessions linger in the Live list until the OS TCP
            # timeout hours later, and reconnects pile up as ghost entries.
            t.set_keepalive(15)
            deadline = time.time() + 30
            chan = None
            while time.time() < deadline and not self._stop.is_set():
                chan = t.accept(1)
                if chan is not None:
                    break
                if not t.is_active():
                    break
            if not server.username or chan is None:
                return
            with self._lock:
                self._sessions[sid] = {"ip": ip, "user": server.username,
                                       "since": time.time(), "transfers": {}}
            debug.log("client connected", {"ip": ip, "user": server.username})
            self._emit_status()
            self.activity(sid, "connected", "")
            while t.is_active() and not self._stop.is_set():
                time.sleep(0.5)
        except paramiko.SSHException as e:
            debug.log("transport error", str(e))
        except Exception:
            debug.log("handle error", traceback.format_exc())
        finally:
            if t:
                try:
                    t.close()
                except Exception:
                    pass
            existed = False
            with self._lock:
                if sid in self._sessions:
                    existed = True
                    self._sessions.pop(sid, None)
            if existed:
                debug.log("client disconnected", {"ip": ip})
                self._emit_status()

    def transfer_begin(self, sid, handle):
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is not None:
                sess["transfers"][id(handle)] = handle

    def _progress(self, handle):
        now = time.time()
        if now - handle._last_emit < 0.3:
            return
        handle._last_emit = now
        pct = None
        if handle._total:
            pct = min(100, int(handle._bytes * 100 / handle._total))
        self.api.emit("transfer", {"name": handle._name, "dir": handle._dir,
                                   "bytes": handle._bytes, "human": human_size(handle._bytes),
                                   "pct": pct, "active": True})

    def _finish(self, handle):
        with self._lock:
            for sess in self._sessions.values():
                sess["transfers"].pop(id(handle), None)
        verb = "received" if handle._dir == "upload" else "sent"
        self.api.emit("transfer", {"name": handle._name, "dir": handle._dir,
                                   "bytes": handle._bytes, "human": human_size(handle._bytes),
                                   "pct": 100, "active": False})
        self.api.emit("activity", {"verb": verb, "name": handle._name,
                                   "human": human_size(handle._bytes)})

    def activity(self, sid, verb, name):
        self.api.emit("activity", {"verb": verb, "name": name, "human": ""})
        self._emit_status()

    def connections(self):
        out = []
        with self._lock:
            for _sid, s in self._sessions.items():
                out.append({"ip": s["ip"], "user": s["user"],
                            "since": int(time.time() - s["since"]),
                            "active": len(s["transfers"])})
        return out

    def _emit_status(self):
        self.api.emit("status", self.api.status_payload())


def _atomic_write_json(path, data, **kwargs):
    """Write JSON to a temp file in the same folder, then swap it onto the real
    path with os.replace(), so a crash mid-write can never leave a half-written
    file behind. Cleans up the temp file on any failure."""
    tmp = path + f".tmp-{os.getpid()}"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, **kwargs)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


# ───────────── prefs (theme + window geometry) ─────────────
def _pref_file():
    return os.path.join(exe_dir(), "simple_sftp_server.pref")


def load_prefs():
    try:
        with open(_pref_file(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_prefs(prefs):
    try:
        _atomic_write_json(_pref_file(), prefs)
        return True
    except Exception as e:
        debug.log("save prefs failed", str(e))
        return False


def _valid_geometry(geo):
    """Pure validation: a stored {x,y,width,height} dict -> a clamped dict, or {} if unusable."""
    if not isinstance(geo, dict):
        return {}
    x, y, w, h = geo.get("x"), geo.get("y"), geo.get("width"), geo.get("height")
    for v in (x, y, w, h):
        if not isinstance(v, int) or isinstance(v, bool):
            return {}
    w = max(980, min(w, 10000))   # min_size floor .. sane ceiling
    h = max(680, min(h, 10000))
    return {"x": x, "y": y, "width": w, "height": h}


def _restore_geometry():
    try:
        geo = _valid_geometry(load_prefs().get("window"))
        if not geo:
            return {}
        # Is a point in the title bar still on a connected monitor?
        point = wintypes.POINT(geo["x"] + 100, geo["y"] + 30)
        user32 = ctypes.windll.user32
        user32.MonitorFromPoint.argtypes = [wintypes.POINT, wintypes.DWORD]
        user32.MonitorFromPoint.restype = wintypes.HMONITOR
        if not user32.MonitorFromPoint(point, 0):   # MONITOR_DEFAULTTONULL
            return {}
        return geo
    except Exception:
        return {}


def _win32():
    """user32 with argtypes set for the window-geometry calls (64-bit HWND safe)."""
    u = ctypes.windll.user32
    u.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    u.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                               ctypes.c_int, ctypes.c_int, wintypes.UINT]
    return u


def _own_window_handle(title):
    """Return our visible top-level window with an exact title, or None."""
    try:
        u = ctypes.windll.user32
        WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        u.EnumWindows.argtypes = [WNDENUMPROC, wintypes.LPARAM]
        u.EnumWindows.restype = wintypes.BOOL
        u.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        u.GetWindowThreadProcessId.restype = wintypes.DWORD
        u.GetWindowTextLengthW.argtypes = [wintypes.HWND]
        u.GetWindowTextLengthW.restype = ctypes.c_int
        u.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        u.GetWindowTextW.restype = ctypes.c_int
        u.IsWindowVisible.argtypes = [wintypes.HWND]
        u.IsWindowVisible.restype = wintypes.BOOL

        own_pid = os.getpid()
        found = {"hwnd": None}

        def _callback(hwnd, _lparam):
            if not u.IsWindowVisible(hwnd):
                return True
            pid = wintypes.DWORD()
            u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value != own_pid:
                return True
            length = u.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return True
            buf = ctypes.create_unicode_buffer(length + 1)
            u.GetWindowTextW(hwnd, buf, length + 1)
            if buf.value != title:
                return True
            found["hwnd"] = hwnd
            return False

        proc = WNDENUMPROC(_callback)
        u.EnumWindows(proc, 0)
        return found["hwnd"]
    except Exception:
        return None


def _window_rect():
    """Our window's absolute frame rectangle via Win32 as {x, y, width, height} in
    physical pixels, or None. GetWindowRect and SetWindowPos share one frame-based
    physical coordinate space, so save and restore round-trip exactly on any monitor and
    at any DPI scaling. (pywebview's own window.x/window.move mix a client-origin read
    with a frame move in Qt's scaled, primary-relative space, which drifts each launch
    and lands on the wrong monitor.)"""
    try:
        u = _win32()
        hwnd = _own_window_handle("Simple SFTP Server")
        if not hwnd:
            return None
        r = wintypes.RECT()
        if not u.GetWindowRect(hwnd, ctypes.byref(r)):
            return None
        return {"x": r.left, "y": r.top, "width": r.right - r.left, "height": r.bottom - r.top}
    except Exception:
        return None


def _apply_window_rect(geo):
    """Place our window frame at an absolute rect saved by _window_rect. Windows-only."""
    try:
        u = _win32()
        hwnd = _own_window_handle("Simple SFTP Server")
        if not hwnd:
            return
        SWP_NOZORDER, SWP_NOACTIVATE = 0x0004, 0x0010
        u.SetWindowPos(hwnd, None, geo["x"], geo["y"], geo["width"], geo["height"],
                       SWP_NOZORDER | SWP_NOACTIVATE)
    except Exception:
        pass


def _save_geometry(win=None):
    try:
        geo = _window_rect()
        if not geo:
            return
        if geo["x"] <= -30000 or geo["y"] <= -30000:   # minimized sentinel, not a real spot
            return
        if geo["width"] < 200 or geo["height"] < 200:   # implausible; don't persist
            return
        prefs = load_prefs()
        prefs["window"] = geo
        save_prefs(prefs)
    except Exception:
        pass


# ───────────── js api ─────────────
def _update_error_reason(exc: BaseException) -> str:
    """Return a short, plain-language update-check failure reason.

    This is deliberately pure and network-free so each error branch can be
    tested without making an HTTP request.
    """
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 403:
            return "GitHub is rate-limiting update checks from this network. Try again later."
        if exc.code == 404:
            return "No published release was found."
        if 500 <= exc.code < 600:
            return f"GitHub is having trouble on its end (HTTP {exc.code})."
        return f"GitHub returned an error (HTTP {exc.code})."

    if isinstance(exc, json.JSONDecodeError):
        return "GitHub returned something unexpected. This often means a proxy or a guest wifi sign-in page answered instead."

    is_url_error = isinstance(exc, urllib.error.URLError)
    cause = exc.reason if is_url_error and exc.reason is not None else exc
    if isinstance(cause, ssl.SSLCertVerificationError):
        return "GitHub's certificate could not be verified. This usually means antivirus or a network filter is inspecting HTTPS traffic."
    if isinstance(cause, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
        return "The secure connection was cut off during the handshake with GitHub."
    if isinstance(cause, ssl.SSLError):
        return "The secure connection to GitHub failed."
    if isinstance(cause, socket.gaierror):
        return "The address for api.github.com could not be looked up. Check DNS or the internet connection."
    if isinstance(cause, (socket.timeout, TimeoutError)):
        return "GitHub didn't respond in time."
    if isinstance(cause, (ConnectionRefusedError, ConnectionResetError)):
        return "The connection was refused or reset. A firewall or proxy may be blocking it."
    if isinstance(cause, OSError) and getattr(cause, "errno", None) == errno.ENETUNREACH:
        return "No network connection."
    if is_url_error:
        return "Couldn't reach GitHub. Check the internet connection."

    text = f"{type(exc).__name__}: {exc}"
    return text if len(text) <= 120 else text[:117] + "..."


class Api:
    def __init__(self):
        self._window = None
        self.service = SFTPService(self)
        self._quick_user = None
        self._quick_password = ""
        self._new_password = ""
        self._firewall_state = None

    def set_window(self, w):
        self._window = w

    def emit(self, event, payload):
        if self._window:
            try:
                self._window.evaluate_js(
                    f"window.appEvent && window.appEvent({json.dumps(event)},{json.dumps(payload)})")
            except Exception:
                pass

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
        if not os.path.exists(CONFIG_FILE):
            return {"settings": {"port": DEFAULT_PORT}, "users": []}
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
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
            corrupt_path = os.path.join(os.path.dirname(CONFIG_FILE),
                                         f"server_config.corrupt-{stamp}.json")
            try:
                os.replace(CONFIG_FILE, corrupt_path)
                debug.log("config unreadable, moved aside", {"from": CONFIG_FILE,
                                                               "to": corrupt_path,
                                                               "error": str(e)})
                self._config_warning = (
                    "Your saved settings file could not be read. It was kept as "
                    f"{os.path.basename(corrupt_path)} and the app started with no "
                    "users. The original file was not deleted.")
            except Exception as e2:
                debug.log("config unreadable and could not be moved aside",
                          {"path": CONFIG_FILE, "error": str(e2)})
                self._config_warning = (
                    "Your saved settings file could not be read and could not be "
                    "moved aside. The app started with no users; the original file "
                    "was left in place.")
        return {"settings": {"port": DEFAULT_PORT}, "users": []}

    def _save_config(self, cfg):
        try:
            cfg["_note"] = "Simple SFTP Server config. Passwords are bcrypt hashes, never plaintext."
            _atomic_write_json(CONFIG_FILE, cfg, indent=2)
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
        path = os.path.join(exe_dir(), f"{username}-share")
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
        try:
            from cryptography.hazmat.primitives import serialization
            if not out_path:
                return {"ok": False, "error": "Choose where to save the private key."}
            enc = (serialization.BestAvailableEncryption(passphrase.encode())
                   if passphrase else serialization.NoEncryption())
            if (key_type or "").startswith("Ed25519"):
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                k = Ed25519PrivateKey.generate()
                priv = k.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.OpenSSH, enc)
                pub = k.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                   serialization.PublicFormat.OpenSSH)
            else:
                key = paramiko.RSAKey.generate(4096)
                buf = io.StringIO()
                key.write_private_key(buf, password=passphrase or None)
                priv = buf.getvalue().encode()
                pub = f"ssh-rsa {key.get_base64()}".encode()
            with open(out_path, "wb") as f:
                f.write(priv)
            try:
                os.chmod(out_path, 0o600)
            except OSError:
                pass
            label = f"{username}@simple-sftp-server" if username else "simple-sftp-server"
            pubtext = pub.decode().strip() + " " + label
            with open(out_path + ".pub", "w", encoding="utf-8") as f:
                f.write(pubtext + "\n")
            debug.log("KEYGEN", {"type": key_type, "path": out_path})
            return {"ok": True, "public": pubtext, "private_path": out_path}
        except PermissionError:
            return {"ok": False, "error": "Couldn't write there (permission denied). Pick a folder you can write to."}
        except Exception:
            return {"ok": False, "error": "Key generation failed. Check the type and passphrase."}

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
        quick_folder = QUICK_FOLDER if was_quick else ""
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
            os.makedirs(QUICK_FOLDER, exist_ok=True)
        except Exception as e:
            return {"ok": False, "error": friendly_error(e)}
        self._quick_password = generate_password(20)
        self._quick_user = {"username": "quickstart", "home": QUICK_FOLDER,
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
        return {"ok": True, "port": port, "folder": QUICK_FOLDER, "username": "quickstart"}

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
                "quick_folder": QUICK_FOLDER if self.service.is_quick else "",
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
        result = {"current": APP_VERSION, "version": None, "update": False, "offline": False}
        try:
            url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
            req = Request(url, headers={"User-Agent": "Simple-SFTP-Server",
                                        "Accept": "application/vnd.github+json"})
            with urlopen(req, timeout=10) as r:
                data = json.loads(r.read().decode())
            tag = (data.get("tag_name") or "").lstrip("v")
            result["version"] = tag
            result["update"] = bool(tag and self._is_newer(tag, APP_VERSION))
            debug.log("check_update", f"found v{tag}, current v{APP_VERSION}")
        except Exception as e:
            result["offline"] = True
            result["reason"] = _update_error_reason(e)
            debug.log("check_update failed", f"{type(e).__name__}: {e}")
        return result

    def _is_newer(self, latest, current):
        def parts(v):
            out = []
            for x in v.split("."):
                try:
                    out.append(int(x))
                except ValueError:
                    out.append(0)
            return out + [0] * (3 - len(out))
        try:
            return parts(latest) > parts(current)
        except Exception:
            return False

    def open_url(self, url):
        try:
            webbrowser.open(url)
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": friendly_error(e)}


# ───────────── main ─────────────
_mutex_handle = None   # module-level: must live for the process lifetime

def _acquire_single_instance(mutex_name: str) -> bool:
    # Name convention: "JDE_Simple{Thing}Tool_SingleInstance"
    # Session-local (no "Global\" prefix): each Windows session (e.g. RDP,
    # fast user switching) gets its own instance instead of colliding across users.
    global _mutex_handle
    try:
        # use_last_error=True: ctypes.windll's GetLastError() can be clobbered
        # by ctypes-internal calls, so read the error via ctypes.get_last_error() instead.
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _mutex_handle = kernel32.CreateMutexW(None, False, mutex_name)
        return ctypes.get_last_error() != 183   # ERROR_ALREADY_EXISTS
    except Exception:
        return True   # fail open: never block launch over a mutex error

def _prompt_second_instance(app_title: str) -> bool:
    # Native message box only: runs before pywebview/Qt exists, so no Qt dialog is available yet.
    try:
        text = f"{app_title} is already running.\n\nOpen a second instance?"
        MB_YESNO_ICONQUESTION = 0x00000024
        result = ctypes.windll.user32.MessageBoxW(None, text, app_title, MB_YESNO_ICONQUESTION)
        return result == 6   # IDYES
    except Exception:
        return True   # fail open: if the box can't be shown, launch proceeds


def main():
    try:
        import truststore
        truststore.inject_into_ssl()
    except Exception:
        pass
    if not _acquire_single_instance("JDE_SimpleSFTPServer_SingleInstance"):
        if not _prompt_second_instance("Simple SFTP Server"):
            sys.exit(0)
    import webview
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("JDEProjects.SimpleSFTPServer")
        except Exception:
            pass
    api = Api()
    geo = _restore_geometry()
    window = webview.create_window(
        "Simple SFTP Server", url=resource_path("simple_sftp_server-UI.html"),
        js_api=api, width=1180, height=820, min_size=(980, 680),
        background_color="#0a0e14")
    api.set_window(window)

    if geo:
        # Restore the exact saved window rectangle once the window exists, via Win32
        # (see _apply_window_rect) rather than create_window x/y or window.move: those use
        # Qt's scaled, primary-relative coordinates and drift across monitors and DPI.
        # SetWindowPos is symmetric with the Win32 save, so it round-trips exactly.
        def _restore_pos():
            _apply_window_rect(geo)
        window.events.shown += _restore_pos

    def _on_closing():
        _save_geometry(window)
        return True
    window.events.closing += _on_closing
    try:
        webview.start(gui="qt", icon=resource_path("simple_sftp_server.png"))
    except TypeError:
        webview.start(gui="qt")


if __name__ == "__main__":
    main()
