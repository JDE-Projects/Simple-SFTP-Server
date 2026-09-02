"""Tests for the review-fixes branch: config write safety, empty-home
lockdown, and auth timing equalization."""

import glob
import json
import os

import paramiko

from app import paths
from app.api import Api
from app.constants import DEFAULT_PORT
from app.server import JailedSFTP, Lockout, ServerIface, perms_for


def _api(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    return Api()


# ---- FIX 1: delete_user must not silently ignore a failed config write ----

def test_delete_user_reports_config_write_failure(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    api._load_config = lambda: {"settings": {"port": DEFAULT_PORT},
                                 "users": [{"username": "bob", "home": str(tmp_path)}]}
    monkeypatch.setattr(api, "_save_config", lambda cfg: False)

    result = api.delete_user("bob", delete_folder=False)

    assert result["ok"] is False
    assert "error" in result


# ---- FIX 2: atomic config writes + preserving an unreadable config ----

def test_save_config_round_trips_and_leaves_no_temp_file(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    cfg = {"settings": {"port": 2222}, "users": [{"username": "alice"}]}

    ok = api._save_config(dict(cfg))
    assert ok is True

    with open(paths.CONFIG_FILE, "r", encoding="utf-8") as f:
        on_disk = json.load(f)
    assert on_disk["settings"] == cfg["settings"]
    assert on_disk["users"] == cfg["users"]

    leftovers = glob.glob(paths.CONFIG_FILE + ".tmp-*")
    assert leftovers == []


def test_load_config_missing_file_returns_default_without_corrupt_file(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    assert not os.path.exists(paths.CONFIG_FILE)

    cfg = api._load_config()

    assert cfg == {"settings": {"port": DEFAULT_PORT}, "users": []}
    corrupt_files = glob.glob(str(tmp_path / "server_config.corrupt-*.json"))
    assert corrupt_files == []


def test_load_config_corrupt_file_is_renamed_aside_and_preserved(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    original_text = "{ not valid json at all"
    with open(paths.CONFIG_FILE, "w", encoding="utf-8") as f:
        f.write(original_text)

    cfg = api._load_config()

    assert cfg == {"settings": {"port": DEFAULT_PORT}, "users": []}
    assert not os.path.exists(paths.CONFIG_FILE)
    corrupt_files = glob.glob(str(tmp_path / "server_config.corrupt-*.json"))
    assert len(corrupt_files) == 1
    with open(corrupt_files[0], "r", encoding="utf-8") as f:
        assert f.read() == original_text


# ---- FIX 3: an empty home must fail closed ----

def test_jailed_sftp_empty_home_rejects_every_path():
    class DummyServer:
        service = None
        user = {"username": "nohome", "home": ""}
        ip = ""
        sid = ""

    sftp = JailedSFTP.__new__(JailedSFTP)
    sftp.service = None
    sftp.user = DummyServer.user
    sftp.ip = ""
    sftp.sid = ""
    home = (sftp.user or {}).get("home", "")
    if home:
        sftp.root = os.path.realpath(home)
    else:
        sftp.root = None
    sftp.perm = perms_for(sftp.user)

    assert sftp.root is None
    assert sftp._real("/") is None
    assert sftp._real("") is None
    assert sftp._real("some/file.txt") is None


# ---- FIX 5: unknown usernames must still fail authentication ----

def test_check_auth_password_unknown_username_fails():
    class FakeService:
        def __init__(self):
            self.lockout = Lockout()

        def find_user(self, username):
            return None

    server = ServerIface(FakeService(), "127.0.0.1", 1)
    result = server.check_auth_password("no-such-user", "whatever")
    assert result == paramiko.AUTH_FAILED


# ---- FIX 2 (UI notice): a corrupt config surfaces a one-time startup warning ----

def test_get_meta_surfaces_corrupt_config_warning_once(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    with open(paths.CONFIG_FILE, "w", encoding="utf-8") as f:
        f.write("{ broken json")

    first = api.get_meta()
    assert first["config_warning"]

    # The bad file has been moved aside, so a later load is a clean fresh
    # start and the warning is not shown again.
    second = api.get_meta()
    assert second["config_warning"] is None
