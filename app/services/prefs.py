import ctypes
import json
import os
import time
from ctypes import wintypes

from app import paths
from app.atomic import atomic_write_json
from app.debug_log import debug, describe_error


# ───────────── prefs (theme + window geometry) ─────────────
def load_prefs():
    """Full prefs dict. A missing file is a first run. A file that opens but
    will not parse is kept aside (renamed with a .corrupt- stamp) and logged,
    never wiped. A file that cannot be opened (locked, no access) is not
    damaged, so it is left in place and logged."""
    path = paths.pref_file()
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        return {}
    except OSError as e:
        debug._log("settings file not read", describe_error(e))
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
        if isinstance(data, dict):
            return data
        raise ValueError("prefs root is not an object")
    except Exception as e:
        reason = describe_error(e)
        try:
            os.replace(path, f"{path}.corrupt-{time.strftime('%Y%m%d-%H%M%S')}")
            debug._log("settings file unreadable, kept aside", reason)
        except Exception as move_error:
            debug._log("settings file unreadable, not kept aside",
                       {"error": reason, "move_error": describe_error(move_error)})
        return {}


def save_prefs(prefs):
    try:
        atomic_write_json(paths.pref_file(), prefs)
        return True
    except Exception as e:
        debug._log("save prefs failed", describe_error(e))
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
    """The saved window rect, validated, or {}. Read before the window exists; the
    on-screen check happens in _apply_window_rect, because until Qt makes the process
    DPI-aware Windows reports scaled-down screen coordinates and a spot near the right
    or bottom edge, or on a second monitor, would wrongly look off-screen."""
    try:
        return _valid_geometry(load_prefs().get("window"))
    except Exception:
        return {}


def _win32():
    """user32 with argtypes set for the window-geometry calls (64-bit HWND safe)."""
    u = ctypes.windll.user32
    u.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    u.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                               ctypes.c_int, ctypes.c_int, wintypes.UINT]
    return u


class _MONITORINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", wintypes.RECT),
        ("rcWork", wintypes.RECT),
        ("dwFlags", wintypes.DWORD),
    ]


def _monitor_work_area(hmonitor):
    """Return hmonitor's work area as (left, top, right, bottom), or None."""
    user32 = ctypes.windll.user32
    user32.GetMonitorInfoW.argtypes = [wintypes.HMONITOR, ctypes.POINTER(_MONITORINFO)]
    user32.GetMonitorInfoW.restype = wintypes.BOOL
    info = _MONITORINFO()
    info.cbSize = ctypes.sizeof(info)
    if not user32.GetMonitorInfoW(hmonitor, ctypes.byref(info)):
        return None
    work = info.rcWork
    return work.left, work.top, work.right, work.bottom


def _frame_insets(hwnd):
    """Return DWM frame insets for hwnd, or zero insets when unavailable."""
    try:
        frame = wintypes.RECT()
        if not _win32().GetWindowRect(hwnd, ctypes.byref(frame)):
            return 0, 0, 0, 0
        extended = wintypes.RECT()
        dwmapi = ctypes.windll.dwmapi
        dwmapi.DwmGetWindowAttribute.argtypes = [
            wintypes.HWND, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
        ]
        dwmapi.DwmGetWindowAttribute.restype = ctypes.c_long
        DWMWA_EXTENDED_FRAME_BOUNDS = 9
        if dwmapi.DwmGetWindowAttribute(
            hwnd, DWMWA_EXTENDED_FRAME_BOUNDS, ctypes.byref(extended), ctypes.sizeof(extended)
        ) != 0:
            return 0, 0, 0, 0
        return (
            max(0, extended.left - frame.left),
            max(0, extended.top - frame.top),
            max(0, frame.right - extended.right),
            max(0, frame.bottom - extended.bottom),
        )
    except Exception:
        return 0, 0, 0, 0


def fit_rect_to_work_area(x, y, w, h, work, insets):
    """Fit a frame rect so its DWM-visible rect remains in a monitor work area."""
    left, top, right, bottom = work
    inset_left, inset_top, inset_right, inset_bottom = insets
    visible_x = x + inset_left
    visible_y = y + inset_top
    visible_w = min(max(0, w - inset_left - inset_right), right - left)
    visible_h = min(max(0, h - inset_top - inset_bottom), bottom - top)

    if visible_x + visible_w > right:
        visible_x = right - visible_w
    if visible_y + visible_h > bottom:
        visible_y = bottom - visible_h
    if visible_x < left:
        visible_x = left
    if visible_y < top:
        visible_y = top
    return (
        visible_x - inset_left,
        visible_y - inset_top,
        visible_w + inset_left + inset_right,
        visible_h + inset_top + inset_bottom,
    )


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
    """Place our window frame at a rect saved by _window_rect, fitted to the work area
    of the monitor it lands on. A rect that already fits is applied exactly as saved.
    Wired to `shown`, which pywebview runs on a worker thread, so the settle wait
    below never blocks the window. Windows-only; never raises."""
    try:
        user32 = ctypes.windll.user32
        user32.MonitorFromPoint.argtypes = [wintypes.POINT, wintypes.DWORD]
        user32.MonitorFromPoint.restype = wintypes.HMONITOR
        MONITOR_DEFAULTTONULL, MONITOR_DEFAULTTONEAREST = 0, 2
        # Is a point in the title bar still on a connected monitor? NULL means no
        # (for example the saved monitor was unplugged), so keep the default spot.
        point = wintypes.POINT(geo["x"] + 100, geo["y"] + 30)
        hmonitor = user32.MonitorFromPoint(point, MONITOR_DEFAULTTONULL)
        if not hmonitor:
            return
        work = _monitor_work_area(hmonitor)
        if work is None:
            return
        u = _win32()
        hwnd = _own_window_handle("Simple SFTP Server")
        if not hwnd:
            return
        SWP_NOZORDER, SWP_NOACTIVATE = 0x0004, 0x0010
        rect = fit_rect_to_work_area(geo["x"], geo["y"], geo["width"], geo["height"],
                                     work, _frame_insets(hwnd))
        u.SetWindowPos(hwnd, None, *rect, SWP_NOZORDER | SWP_NOACTIVATE)

        # A move to a monitor with different scaling makes Qt resize the window
        # after it lands, so wait for that and fit once more.
        time.sleep(0.3)
        current = wintypes.RECT()
        if not u.GetWindowRect(hwnd, ctypes.byref(current)):
            return
        user32.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
        user32.MonitorFromWindow.restype = wintypes.HMONITOR
        hmonitor = user32.MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST)
        if not hmonitor:
            return
        work = _monitor_work_area(hmonitor)
        if work is None:
            return
        current_rect = (current.left, current.top,
                        current.right - current.left, current.bottom - current.top)
        fitted_rect = fit_rect_to_work_area(*current_rect, work, _frame_insets(hwnd))
        if fitted_rect != current_rect:
            u.SetWindowPos(hwnd, None, *fitted_rect, SWP_NOZORDER | SWP_NOACTIVATE)
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
