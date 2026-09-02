import os
import sys


# ───────────── paths ─────────────
def resource_path(rel):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, rel)


def exe_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


CONFIG_FILE = os.path.join(exe_dir(), "server_config.json")
HOST_KEY_FILE = os.path.join(exe_dir(), "host_ed25519")
QUICK_FOLDER = os.path.join(exe_dir(), "QuickStart-Share")


def pref_file():
    return os.path.join(exe_dir(), "simple_sftp_server.pref")
