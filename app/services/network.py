import re
import socket
from urllib.request import Request, urlopen


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


def valid_port(value):
    """Validate a port number from user input (string or int).

    Returns a 3-tuple (ok, port, error): on success, port is the parsed int
    and error is None; on failure, port is None and error is a message
    describing what was wrong.
    """
    text = str(value).strip() if isinstance(value, str) else value
    if text == "" or text is None:
        return False, None, "Enter a port number (1-65535)."
    try:
        port = int(str(value).strip())
    except (ValueError, TypeError):
        return False, None, "Port must be a whole number between 1 and 65535."
    if port < 1 or port > 65535:
        return False, None, "Port must be between 1 and 65535."
    return True, port, None


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
