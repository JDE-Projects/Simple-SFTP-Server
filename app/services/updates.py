import errno
import json
import socket
import ssl
import urllib.error
from urllib.request import Request, urlopen

from app.debug_log import debug


# ───────────── update check ─────────────
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


def _is_newer(latest, current):
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


def check_update(app_version, github_repo):
    result = {"current": app_version, "version": None, "update": False, "offline": False}
    try:
        url = f"https://api.github.com/repos/{github_repo}/releases/latest"
        req = Request(url, headers={"User-Agent": "Simple-SFTP-Server",
                                    "Accept": "application/vnd.github+json"})
        with urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        tag = (data.get("tag_name") or "").lstrip("v")
        result["version"] = tag
        result["update"] = bool(tag and _is_newer(tag, app_version))
        debug.log("check_update", f"found v{tag}, current v{app_version}")
    except Exception as e:
        result["offline"] = True
        result["reason"] = _update_error_reason(e)
        debug.log("check_update failed", f"{type(e).__name__}: {e}")
    return result
