import base64
import errno
import hashlib

from app.debug_log import debug


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
