"""Tests for Phase 2 of folder-deletion hardening: the blocked_reason safety
gate and its wiring into Api.delete_user."""

import os
import sys

import pytest

from app import paths
from app.api import Api
from app.services.safety import blocked_reason


# ---- Group 1: blocked_reason ----

def test_blank_paths_are_blocked():
    assert blocked_reason("") is not None
    assert blocked_reason("   ") is not None


def test_drive_root_is_blocked(tmp_path):
    drive, _ = os.path.splitdrive(str(tmp_path))
    root = drive + "\\" if drive else "C:\\"
    assert blocked_reason(root) is not None


def test_exe_dir_and_parent_are_blocked(tmp_path, monkeypatch):
    exe_dir = str(tmp_path / "app")
    os.makedirs(exe_dir)
    monkeypatch.setattr(paths, "exe_dir", lambda: exe_dir)

    assert blocked_reason(paths.exe_dir()) is not None
    assert blocked_reason(os.path.dirname(paths.exe_dir())) is not None


def test_user_profile_and_documents_are_blocked():
    profile = os.path.expanduser("~")
    assert blocked_reason(profile) is not None
    assert blocked_reason(os.path.join(profile, "Documents")) is not None


def test_folder_inside_exe_dir_is_allowed(tmp_path, monkeypatch):
    exe_dir = str(tmp_path / "app")
    os.makedirs(exe_dir)
    monkeypatch.setattr(paths, "exe_dir", lambda: exe_dir)

    share = str(tmp_path / "app" / "bob-share")
    os.makedirs(share)
    assert blocked_reason(share) is None


def test_ordinary_folder_elsewhere_is_allowed(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "exe_dir", lambda: str(tmp_path / "app"))
    share = str(tmp_path / "elsewhere" / "share")
    os.makedirs(share)
    assert blocked_reason(share) is None


# ---- Group 1b: folders INSIDE a system tree are blocked at any depth ----

def test_inside_windows_is_blocked():
    windir = os.environ.get("WINDIR") or os.environ.get("SystemRoot")
    if not windir:
        import pytest as _pytest
        _pytest.skip("no Windows directory in environment")
    assert blocked_reason(os.path.join(windir, "System32")) is not None


def test_inside_program_files_is_blocked():
    pf = os.environ.get("ProgramFiles")
    if not pf:
        import pytest as _pytest
        _pytest.skip("no Program Files in environment")
    assert blocked_reason(os.path.join(pf, "SomeVendorApp")) is not None


def test_inside_programdata_is_blocked():
    pd = os.environ.get("ProgramData")
    if not pd:
        import pytest as _pytest
        _pytest.skip("no ProgramData in environment")
    assert blocked_reason(os.path.join(pd, "SomeVendorApp")) is not None


def test_inside_appdata_stays_deletable():
    # AppData is the user's own per-app data, same category as the rest of the
    # profile: deletable behind the UI warning, not a hard block.
    appdata = os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "SFTP-Shares-xyz")
    assert blocked_reason(appdata) is None


def test_share_inside_app_dir_under_program_files_is_allowed(tmp_path, monkeypatch):
    # The app itself is installed inside a protected tree (Program Files), but
    # its own shares under the app folder must stay deletable.
    fake_pf = str(tmp_path / "ProgramFiles")
    exe_dir = os.path.join(fake_pf, "SimpleSFTP")
    os.makedirs(exe_dir)
    monkeypatch.setenv("ProgramFiles", fake_pf)
    monkeypatch.setattr(paths, "exe_dir", lambda: exe_dir)

    share = os.path.join(exe_dir, "bob-share")
    os.makedirs(share)
    assert blocked_reason(share) is None

    # A different app's folder in the same tree is still blocked.
    other = os.path.join(fake_pf, "OtherApp")
    os.makedirs(other)
    assert blocked_reason(other) is not None


def test_ordinary_profile_subfolder_stays_deletable(tmp_path, monkeypatch):
    # Not a system tree and not a standard profile folder: a share the user
    # placed in their own profile remains deletable (behind the UI warning).
    monkeypatch.setattr(paths, "exe_dir", lambda: str(tmp_path / "app"))
    target = os.path.join(os.path.expanduser("~"), "SFTP-Shares-xyz")
    assert blocked_reason(target) is None


# ---- Group 2: delete_user integration ----

def _api(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    monkeypatch.setattr(paths, "exe_dir", lambda: str(tmp_path / "app"))
    return Api()


def test_delete_user_removes_safe_unprotected_folder(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = str(tmp_path / "elsewhere" / "alice-home")
    os.makedirs(home)
    with open(os.path.join(home, "file.txt"), "w") as f:
        f.write("hello")

    cfg = {"settings": {"port": 2222},
           "users": [{"username": "alice", "home": home,
                      "permissions": {"list": True}, "auth": "password",
                      "password_hash": "x"}]}
    api._save_config(cfg)

    result = api.delete_user("alice", delete_folder=True)

    assert result["ok"] is True
    assert "warning" not in result or "kept because" not in (result.get("warning") or "")
    assert not os.path.isdir(home)


def test_delete_user_refuses_to_delete_protected_folder(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = paths.exe_dir()
    os.makedirs(home, exist_ok=True)

    cfg = {"settings": {"port": 2222},
           "users": [{"username": "bob", "home": home,
                      "permissions": {"list": True}, "auth": "password",
                      "password_hash": "x"}]}
    api._save_config(cfg)

    result = api.delete_user("bob", delete_folder=True)

    assert result["ok"] is True
    assert "warning" in result
    assert os.path.isdir(home)


# ---- Group 3: stop_server (Quick Start folder delete) ----

def _quick_api(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    api.service.is_quick = True
    monkeypatch.setattr(api.service, "stop", lambda: None)
    return api


def test_stop_server_deletes_safe_quick_folder(tmp_path, monkeypatch):
    quick_folder = str(tmp_path / "QuickStart-Share")
    monkeypatch.setattr(paths, "QUICK_FOLDER", quick_folder)
    os.makedirs(quick_folder)
    with open(os.path.join(quick_folder, "file.txt"), "w") as f:
        f.write("hello")

    api = _quick_api(tmp_path, monkeypatch)

    result = api.stop_server(delete_folder=True)

    assert result["ok"] is True
    assert "warning" not in result
    assert not os.path.isdir(quick_folder)


def test_stop_server_keeps_protected_quick_folder(tmp_path, monkeypatch):
    quick_folder = os.path.expanduser("~")
    monkeypatch.setattr(paths, "QUICK_FOLDER", quick_folder)

    api = _quick_api(tmp_path, monkeypatch)

    result = api.stop_server(delete_folder=True)

    assert result["ok"] is True
    assert "warning" in result
    assert os.path.isdir(quick_folder)


def test_stop_server_warns_when_delete_is_incomplete(tmp_path, monkeypatch):
    quick_folder = str(tmp_path / "QuickStart-Share")
    monkeypatch.setattr(paths, "QUICK_FOLDER", quick_folder)
    os.makedirs(quick_folder)
    with open(os.path.join(quick_folder, "file.txt"), "w") as f:
        f.write("hello")

    api = _quick_api(tmp_path, monkeypatch)
    monkeypatch.setattr("app.api.shutil.rmtree", lambda *a, **k: None)

    result = api.stop_server(delete_folder=True)

    assert result["ok"] is True
    assert "warning" in result
    assert "fully removed" in result["warning"]
    assert os.path.isdir(quick_folder)


def test_stop_server_leaves_folder_when_delete_not_requested(tmp_path, monkeypatch):
    quick_folder = str(tmp_path / "QuickStart-Share")
    monkeypatch.setattr(paths, "QUICK_FOLDER", quick_folder)
    os.makedirs(quick_folder)
    with open(os.path.join(quick_folder, "file.txt"), "w") as f:
        f.write("hello")

    api = _quick_api(tmp_path, monkeypatch)

    result = api.stop_server(delete_folder=False)

    assert result["ok"] is True
    assert "warning" not in result
    assert os.path.isdir(quick_folder)


# ---- Group 4: Phase 4 gap-fill (partial failure, open handles, managed end-to-end) ----

def test_delete_user_warns_when_rmtree_fails(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = str(tmp_path / "elsewhere" / "greg-home")
    os.makedirs(home)

    cfg = {"settings": {"port": 2222},
           "users": [{"username": "greg", "home": home,
                      "permissions": {"list": True}, "auth": "password",
                      "password_hash": "x"}]}
    api._save_config(cfg)

    def boom(*a, **k):
        raise OSError("simulated delete failure")
    monkeypatch.setattr("app.api.shutil.rmtree", boom)

    result = api.delete_user("greg", delete_folder=True)

    # The account is still removed, but the folder failure is surfaced, not swallowed.
    assert result["ok"] is True
    assert "warning" in result
    assert "could not be deleted" in result["warning"]
    assert os.path.isdir(home)
    assert not any(u["username"] == "greg" for u in api._load_config()["users"])


@pytest.mark.skipif(sys.platform != "win32",
                    reason="POSIX allows unlinking an open file, so the delete would succeed there")
def test_delete_user_warns_when_a_file_handle_is_open(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = str(tmp_path / "elsewhere" / "hanna-home")
    os.makedirs(home)
    locked = os.path.join(home, "locked.txt")

    cfg = {"settings": {"port": 2222},
           "users": [{"username": "hanna", "home": home,
                      "permissions": {"list": True}, "auth": "password",
                      "password_hash": "x"}]}
    api._save_config(cfg)

    # An open handle inside the folder blocks recursive deletion on Windows.
    handle = open(locked, "w")
    handle.write("in use")
    handle.flush()
    try:
        result = api.delete_user("hanna", delete_folder=True)
    finally:
        handle.close()

    assert result["ok"] is True
    assert "warning" in result
    assert os.path.isfile(locked)


def test_managed_share_folder_deletes_end_to_end(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)

    r = api.make_share_folder("frank")
    assert r["ok"] is True
    with open(os.path.join(r["path"], "data.txt"), "w") as f:
        f.write("payload")

    saved = api.save_user({
        "username": "frank",
        "home": r["path"],
        "permissions": {"list": True, "download": True},
        "auth": "password",
        "password": "Sup3rSecretPass!",
    })
    assert saved["ok"] is True
    rec = next(u for u in api._load_config()["users"] if u["username"] == "frank")
    assert rec.get("managed_folder") is True

    result = api.delete_user("frank", delete_folder=True)

    assert result["ok"] is True
    assert "kept because" not in (result.get("warning") or "")
    assert not os.path.isdir(r["path"])
