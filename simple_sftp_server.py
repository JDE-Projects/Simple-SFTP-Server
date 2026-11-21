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

import ctypes
import os
import shlex
import sys
from ctypes import wintypes

from app.api import Api
from app.debug_log import debug
from app.paths import resource_path
from app.services.prefs import _apply_window_rect, _restore_geometry, _save_geometry

APP_VERSION = "1.10.0"


# Remove Qt's remote-debugging switches from a built app at startup, so the
# exe never opens Qt's remote-control port. Source runs are left alone because
# the Claude-driven smoke checks need that port.
def _is_remote_debugging_switch(token):
    # Chromium on Windows accepts "--", "-" or "/" before a switch name and
    # ignores its case, so every spelling is matched.
    for prefix in ("--", "-", "/"):
        if token.startswith(prefix):
            return token[len(prefix):].lower().startswith("remote-debugging-")
    return False


def _drop_remote_debugging(tokens):
    """Return tokens without remote-debugging switches, including a value
    given as the following token (--remote-debugging-port 9222)."""
    kept = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        index += 1
        if _is_remote_debugging_switch(token):
            if "=" not in token and index < len(tokens) and not tokens[index].startswith(("-", "/")):
                index += 1
        else:
            kept.append(token)
    return kept


def strip_remote_debugging(environ, argv, frozen):
    """Remove Qt remote-debugging controls from frozen application launches,
    so the built app never opens Qt's remote-control port. Source runs are
    left alone: the real-window smoke check depends on that port."""
    if not frozen:
        return

    environ.pop("QTWEBENGINE_REMOTE_DEBUGGING", None)

    flags = environ.get("QTWEBENGINE_CHROMIUM_FLAGS")
    if flags is not None:
        try:
            lexer = shlex.shlex(flags, posix=False)
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            # Unbalanced quote: split on spaces rather than fail at startup.
            tokens = flags.split()
        kept = _drop_remote_debugging(tokens)
        if kept:
            environ["QTWEBENGINE_CHROMIUM_FLAGS"] = " ".join(kept)
        else:
            del environ["QTWEBENGINE_CHROMIUM_FLAGS"]

    argv[1:] = _drop_remote_debugging(argv[1:])


# ───────────── single instance ─────────────
# Only one copy may run: two copies would read and replace the same config,
# preferences, and host-key files, and one would silently lose the other's
# changes. Every path below that cannot prove this is the only copy exits.
APP_TITLE = "Simple SFTP Server"
MUTEX_NAME = "JDE_SimpleSFTPServer_SingleInstance"
ERROR_ALREADY_EXISTS = 183
MB_ICONERROR = 0x10
MB_ICONINFORMATION = 0x40

_mutex_handle = None   # module-level: must live for the process lifetime


def _acquire_single_instance(mutex_name: str) -> bool:
    """True if this is the only copy, False if another copy holds the lock.
    Raises OSError if Windows cannot create the lock at all.

    Session-local (no "Global\\" prefix): each Windows session (e.g. RDP,
    fast user switching) gets its own copy instead of colliding across users.
    """
    global _mutex_handle
    # use_last_error=True: ctypes.windll's GetLastError() can be clobbered
    # by ctypes-internal calls, so read the error via ctypes.get_last_error().
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    handle = kernel32.CreateMutexW(None, False, mutex_name)
    error = ctypes.get_last_error()
    if not handle:
        raise ctypes.WinError(error)
    _mutex_handle = handle
    return error != ERROR_ALREADY_EXISTS


def _is_app_window_class(class_name: str) -> bool:
    # The Qt window's class is "Qt<version>QWindowIcon", e.g. Qt6112QWindowIcon.
    # Checking it stops a File Explorer window for a folder with the same name
    # from being taken for the app.
    return class_name.startswith("Qt") and class_name.endswith("QWindowIcon")


def _focus_existing_window(app_title: str) -> bool:
    """Bring the running copy's window to the front. True if it was found."""
    try:
        user32 = ctypes.windll.user32
        found = {"hwnd": None}
        enum_proc_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def _enum_proc(hwnd, lparam):
            if not user32.IsWindowVisible(hwnd):
                return True
            length = user32.GetWindowTextLengthW(hwnd)
            if length == 0:
                return True
            title = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, title, length + 1)
            # Exact match only: a prefix match could hit an unrelated window.
            if title.value != app_title:
                return True
            cls = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, cls, 256)
            if not _is_app_window_class(cls.value):
                return True
            found["hwnd"] = hwnd
            return False   # stop enumerating, match found

        user32.EnumWindows(enum_proc_type(_enum_proc), 0)
        hwnd = found["hwnd"]
        if not hwnd:
            return False
        SW_RESTORE = 9
        if user32.IsIconic(hwnd):
            user32.ShowWindow(hwnd, SW_RESTORE)
        user32.SetForegroundWindow(hwnd)
        return True
    except Exception:
        return False


def _show_message(app_title: str, text: str, icon: int) -> None:
    # Native message box only: runs before pywebview/Qt exists. If even this
    # fails there is nowhere left to report it; the caller still exits.
    try:
        ctypes.windll.user32.MessageBoxW(None, text, app_title, icon)
    except Exception:
        pass


def ensure_single_instance(app_title: str = APP_TITLE, mutex_name: str = MUTEX_NAME) -> None:
    """Return only if this is the only running copy; otherwise exit."""
    try:
        first = _acquire_single_instance(mutex_name)
    except Exception as e:
        _show_message(
            app_title,
            f"{app_title} could not check whether it is already running, so it "
            f"will not start.\n\nTry opening it again. If this keeps happening, "
            f"restart Windows.\n\nDetails: {e}",
            MB_ICONERROR)
        sys.exit(1)
    if first:
        return
    if not _focus_existing_window(app_title):
        # The window can be missing for a moment while the other copy starts.
        _show_message(app_title, f"{app_title} is already running.", MB_ICONINFORMATION)
    sys.exit(0)


def main():
    # Stops Qt leaving an empty %LOCALAPPDATA%\<exe name>\cache\qtpipelinecache-*
    # folder the uninstaller never removes. Must run before the window is created.
    os.environ.setdefault("QT_DISABLE_SHADER_DISK_CACHE", "1")
    strip_remote_debugging(os.environ, sys.argv, getattr(sys, "frozen", False))
    try:
        import truststore
        truststore.inject_into_ssl()
    except Exception:
        pass
    ensure_single_instance()
    import webview
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("JDEProjects.SimpleSFTPServer")
        except Exception:
            pass
    api = Api(APP_VERSION)
    debug.on_warning = api._on_debug_warning
    debug.prune()
    geo = _restore_geometry()
    window = webview.create_window(
        APP_TITLE, url=resource_path("simple_sftp_server-UI.html"),
        js_api=api, width=1180, height=820, min_size=(980, 680),
        background_color="#0a0e14")
    api._set_window(window)

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
