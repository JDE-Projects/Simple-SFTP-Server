import ctypes
import json
import os
from ctypes import wintypes

from app import paths
from app.atomic import atomic_write_json
from app.debug_log import debug


# ───────────── prefs (theme + window geometry) ─────────────
def load_prefs():
    try:
        with open(paths.pref_file(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_prefs(prefs):
    try:
        atomic_write_json(paths.pref_file(), prefs)
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
