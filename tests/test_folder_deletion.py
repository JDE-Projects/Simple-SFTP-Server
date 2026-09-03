"""Tests for Phase 1 of folder-deletion hardening: tracking only, no
deletion behavior. Verifies that only folders created by make_share_folder
(or Quick Start) are ever marked managed_folder."""

import os

from app import paths
from app.api import Api


def _api(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    monkeypatch.setattr(paths, "exe_dir", lambda: str(tmp_path))
    return Api()


def _save(api, username, home, password="Sup3rSecretPass!"):
    return api.save_user({
        "username": username,
        "home": home,
        "permissions": {"list": True, "download": True},
        "auth": "password",
        "password": password,
    })


def test_make_share_folder_new_then_save_user_is_managed(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)

    r = api.make_share_folder("alice")
    assert r["ok"] is True
    assert os.path.isdir(r["path"])

    result = _save(api, "alice", r["path"])
    assert result["ok"] is True

    cfg = api._load_config()
    rec = next(u for u in cfg["users"] if u["username"] == "alice")
    assert rec.get("managed_folder") is True

    public = api._public_users(cfg)
    pub_rec = next(u for u in public if u["username"] == "alice")
    assert pub_rec["managed_folder"] is True


def test_make_share_folder_preexisting_is_unmanaged(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)

    path = os.path.join(str(tmp_path), "bob-share")
    os.makedirs(path)  # pre-exists before make_share_folder is ever called

    r = api.make_share_folder("bob")
    assert r["ok"] is True
    assert r["path"] == path

    result = _save(api, "bob", path)
    assert result["ok"] is True

    cfg = api._load_config()
    rec = next(u for u in cfg["users"] if u["username"] == "bob")
    assert not rec.get("managed_folder")


def test_save_user_auto_created_home_is_unmanaged(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)

    home = str(tmp_path / "typed-path" / "carol-home")
    assert not os.path.isdir(home)

    result = _save(api, "carol", home)
    assert result["ok"] is True
    assert os.path.isdir(home)

    cfg = api._load_config()
    rec = next(u for u in cfg["users"] if u["username"] == "carol")
    assert not rec.get("managed_folder")


def test_edit_managed_user_without_home_change_stays_managed(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)

    r = api.make_share_folder("dave")
    assert r["ok"] is True
    _save(api, "dave", r["path"])

    # Edit without changing home: bump a permission.
    result = api.save_user({
        "username": "dave",
        "home": r["path"],
        "permissions": {"list": True, "download": True, "upload": True},
        "auth": "password",
        "password": "",
    }, original="dave")
    assert result["ok"] is True

    cfg = api._load_config()
    rec = next(u for u in cfg["users"] if u["username"] == "dave")
    assert rec.get("managed_folder") is True


def test_edit_managed_user_changing_home_drops_managed(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)

    r = api.make_share_folder("erin")
    assert r["ok"] is True
    _save(api, "erin", r["path"])

    new_home = str(tmp_path / "erin-manual-path")
    result = api.save_user({
        "username": "erin",
        "home": new_home,
        "permissions": {"list": True, "download": True},
        "auth": "password",
        "password": "",
    }, original="erin")
    assert result["ok"] is True

    cfg = api._load_config()
    rec = next(u for u in cfg["users"] if u["username"] == "erin")
    assert not rec.get("managed_folder")


def test_quick_start_marks_folder_it_creates(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    quick_folder = str(tmp_path / "QuickStart-Share")
    monkeypatch.setattr(paths, "QUICK_FOLDER", quick_folder)
    monkeypatch.setattr(api.service, "start", lambda *a, **k: {"ok": True})

    r = api.quick_start()
    assert r["ok"] is True
    assert os.path.isdir(quick_folder)
    assert api._quick_user["managed_folder"] is True


def test_quick_start_does_not_mark_preexisting_folder(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    quick_folder = str(tmp_path / "QuickStart-Share")
    os.makedirs(quick_folder)
    monkeypatch.setattr(paths, "QUICK_FOLDER", quick_folder)
    monkeypatch.setattr(api.service, "start", lambda *a, **k: {"ok": True})

    r = api.quick_start()
    assert r["ok"] is True
    assert "managed_folder" not in api._quick_user


def test_legacy_user_without_managed_field_reports_false(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    home = str(tmp_path / "legacy-home")
    os.makedirs(home)
    cfg = {"settings": {"port": 2222},
           "users": [{"username": "legacy", "home": home,
                      "permissions": {"list": True}, "auth": "password",
                      "password_hash": "x"}]}

    public = api._public_users(cfg)
    rec = next(u for u in public if u["username"] == "legacy")
    assert rec["managed_folder"] is False
