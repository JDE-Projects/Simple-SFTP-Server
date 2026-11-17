"""Shared fixture for the window-fit scenarios.

Plants a saved window rectangle before the app launches, then watches the
app's window (read-only Win32 calls only, nothing is moved or resized) and
writes where it ended up to window_fit_result.json in UI_DRIVE_OUT_DIR for the
scenario to check. The case ("oversized" or "offscreen") is chosen by the thin
wrapper files window_fit_oversized_fixture.py and window_fit_offscreen_fixture.py.
"""

import ctypes
import json
import os
import time
from ctypes import wintypes
from pathlib import Path

WINDOW_TITLE = "Simple SFTP Server"
PREF_FILE = "simple_sftp_server.pref"  # relative to UI_DRIVE_APP_DIR, where app/paths.py pref_file() resolves
RESULT_NAME = "window_fit_result.json"
MIN_SIZE_LOGICAL = (980, 680)  # min_size passed to create_window in the app
FIND_TIMEOUT_S = 90
STABLE_S = 2.0
SETTLE_TIMEOUT_S = 10
DWMWA_EXTENDED_FRAME_BOUNDS = 9
MONITOR_DEFAULTTOPRIMARY = 1
MONITOR_DEFAULTTONEAREST = 2

user32 = ctypes.windll.user32
dwmapi = ctypes.windll.dwmapi


class MONITORINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", wintypes.RECT),
        ("rcWork", wintypes.RECT),
        ("dwFlags", wintypes.DWORD),
    ]


def _setup_api() -> None:
    # Report physical pixels, the same units the app saves.
    try:
        user32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except Exception:
        pass
    user32.MonitorFromPoint.argtypes = [wintypes.POINT, wintypes.DWORD]
    user32.MonitorFromPoint.restype = wintypes.HMONITOR
    user32.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
    user32.MonitorFromWindow.restype = wintypes.HMONITOR
    user32.GetMonitorInfoW.argtypes = [wintypes.HMONITOR, ctypes.POINTER(MONITORINFO)]
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user32.GetDpiForWindow.argtypes = [wintypes.HWND]
    user32.GetDpiForWindow.restype = wintypes.UINT
    dwmapi.DwmGetWindowAttribute.argtypes = [
        wintypes.HWND, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]


def _work_area(hmonitor) -> dict:
    info = MONITORINFO()
    info.cbSize = ctypes.sizeof(MONITORINFO)
    if not user32.GetMonitorInfoW(hmonitor, ctypes.byref(info)):
        raise OSError("GetMonitorInfoW failed")
    r = info.rcWork
    return {"left": r.left, "top": r.top, "right": r.right, "bottom": r.bottom}


def _primary_work_area() -> dict:
    return _work_area(user32.MonitorFromPoint(wintypes.POINT(0, 0), MONITOR_DEFAULTTOPRIMARY))


def _find_window():
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def visit(hwnd, _lparam):
        if user32.IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(hwnd, buf, 256)
            if buf.value == WINDOW_TITLE:
                found.append(hwnd)
        return True

    user32.EnumWindows(visit, 0)
    return found[0] if found else None


def _rect_dict(r) -> dict:
    return {"left": r.left, "top": r.top, "right": r.right, "bottom": r.bottom}


def _planted_window(case: str, work: dict) -> dict:
    work_w = work["right"] - work["left"]
    work_h = work["bottom"] - work["top"]
    if case == "oversized":
        return {"x": work["left"] - 60, "y": work["top"] - 20,
                "width": work_w + 2000, "height": work_h + 1500}
    if case == "offscreen":
        # 1150x760, or larger on a scaled screen so it stays above the app's
        # minimum size (which grows with the scale and would otherwise resize it).
        dpi = user32.GetDpiForSystem() or 96
        min_w = round(MIN_SIZE_LOGICAL[0] * dpi / 96) + 120
        min_h = round(MIN_SIZE_LOGICAL[1] * dpi / 96) + 120
        return {"x": work["right"] - 300, "y": work["bottom"] - 200,
                "width": max(1150, min_w), "height": max(760, min_h)}
    raise ValueError(f"unknown case: {case}")


def _write_result(out_dir: Path, result: dict) -> None:
    tmp = out_dir / (RESULT_NAME + ".tmp")
    tmp.write_text(json.dumps(result), encoding="utf-8")
    os.replace(tmp, out_dir / RESULT_NAME)


def _wait_for_stable_frame(hwnd) -> list:
    """Wait until the window frame has not changed for STABLE_S seconds, giving
    up after SETTLE_TIMEOUT_S. The app applies the saved rectangle after the
    window is shown, and Qt can resize it again afterward, so a reading at one
    fixed moment can catch an in-between size. Returns each distinct frame
    seen, with seconds since the window was found, so a failed run shows
    whether the restore was late, undone, or never happened."""
    start = time.time()
    history = []
    last = None
    last_change = start
    while True:
        now = time.time()
        r = wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(r))
        frame = _rect_dict(r)
        if frame != last:
            history.append({"t": round(now - start, 2), **frame})
            last = frame
            last_change = now
        if now - last_change >= STABLE_S or now - start >= SETTLE_TIMEOUT_S:
            return history
        time.sleep(0.05)


def _measure(case: str, work: dict, planted: dict) -> dict:
    result = {"case": case, "primary_work": work, "planted": planted, "error": None}
    deadline = time.time() + FIND_TIMEOUT_S
    hwnd = None
    while time.time() < deadline:
        hwnd = _find_window()
        if hwnd:
            break
        time.sleep(0.1)
    if not hwnd:
        result["error"] = f"window titled '{WINDOW_TITLE}' did not appear within {FIND_TIMEOUT_S}s"
        return result
    result["frame_history"] = _wait_for_stable_frame(hwnd)
    visible = wintypes.RECT()
    hr = dwmapi.DwmGetWindowAttribute(
        hwnd, DWMWA_EXTENDED_FRAME_BOUNDS, ctypes.byref(visible), ctypes.sizeof(visible))
    if hr != 0:
        result["error"] = f"DwmGetWindowAttribute failed (HRESULT {hr})"
        return result
    frame = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(frame))
    result["visible"] = _rect_dict(visible)
    result["frame"] = _rect_dict(frame)
    result["work"] = _work_area(user32.MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST))
    dpi = user32.GetDpiForWindow(hwnd) or 96
    result["dpi"] = dpi
    min_w = round(MIN_SIZE_LOGICAL[0] * dpi / 96)
    min_h = round(MIN_SIZE_LOGICAL[1] * dpi / 96)
    result["min_size"] = {"width": min_w, "height": min_h}
    work_w = result["work"]["right"] - result["work"]["left"]
    work_h = result["work"]["bottom"] - result["work"]["top"]
    result["work_too_small"] = work_w < min_w or work_h < min_h
    return result


def run(case: str) -> None:
    app_dir = Path(os.environ["UI_DRIVE_APP_DIR"])
    out_dir = Path(os.environ["UI_DRIVE_OUT_DIR"])
    _setup_api()
    work = _primary_work_area()
    planted = _planted_window(case, work)
    pref = app_dir / PREF_FILE
    pref.parent.mkdir(parents=True, exist_ok=True)
    pref.write_text(json.dumps({"window": planted}), encoding="utf-8")
    print(json.dumps({"case": case, "work": work, "planted": planted,
                      "out_dir": str(out_dir), "result_file": RESULT_NAME}), flush=True)
    try:
        result = _measure(case, work, planted)
    except Exception as exc:
        result = {"case": case, "primary_work": work, "planted": planted,
                  "error": f"fixture measurement failed: {type(exc).__name__}: {exc}"}
    _write_result(out_dir, result)
    while True:
        time.sleep(60)
