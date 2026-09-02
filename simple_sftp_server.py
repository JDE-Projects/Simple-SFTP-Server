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
import sys

from app.api import Api
from app.paths import resource_path
from app.services.prefs import _apply_window_rect, _restore_geometry, _save_geometry


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
