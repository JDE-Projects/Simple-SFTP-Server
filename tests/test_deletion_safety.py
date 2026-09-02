"""Tests for Phase 2 of folder-deletion hardening: the blocked_reason safety
gate and its wiring into Api.delete_user."""

import os

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
