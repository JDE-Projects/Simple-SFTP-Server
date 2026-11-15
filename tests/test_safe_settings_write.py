"""Settings files survive failed writes, damaged contents, and locks."""
import builtins
import json
import os
from pathlib import Path

import pytest

from app import atomic, debug_log, paths
from app.atomic import atomic_write_json
from app.debug_log import DebugLog
from app.services import prefs


@pytest.fixture
def private_log(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log = DebugLog(str(log_dir), "Test App", redact=debug_log._redact)
    assert log.set_enabled(True)
    for module in (atomic, prefs):
        monkeypatch.setattr(module, "debug", log)
    return log


@pytest.fixture
def pref_path(tmp_path, monkeypatch):
    path = tmp_path / "simple_sftp_server.pref"
    monkeypatch.setattr(paths, "pref_file", lambda: str(path))
    return path


def _read_log(log):
    return Path(log._path).read_text(encoding="utf-8")


def _leftovers(folder, name):
    return [p.name for p in folder.iterdir() if p.name.startswith(name + ".")]


# ---- atomic_write_json ----

def test_write_forces_data_to_disk_before_swap(tmp_path, monkeypatch):
    target = tmp_path / "data.json"
    order = []
    real_fsync, real_replace = os.fsync, os.replace
    monkeypatch.setattr(atomic.os, "fsync",
                        lambda fd: (order.append("fsync"), real_fsync(fd))[1])
    monkeypatch.setattr(atomic.os, "replace",
                        lambda a, b: (order.append("replace"), real_replace(a, b))[1])

    atomic_write_json(str(target), {"a": 1})

    assert order == ["fsync", "replace"]
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": 1}
    assert _leftovers(tmp_path, "data.json") == []


def test_failed_write_leaves_existing_file_unchanged(tmp_path, monkeypatch):
    target = tmp_path / "data.json"
    target.write_text('{"keep": true}', encoding="utf-8")

    def fail(_fd):
        raise OSError(28, "disk full")
    monkeypatch.setattr(atomic.os, "fsync", fail)

    with pytest.raises(OSError):
        atomic_write_json(str(target), {"keep": False})

    assert target.read_text(encoding="utf-8") == '{"keep": true}'
    assert _leftovers(tmp_path, "data.json") == []


def test_failed_swap_leaves_existing_file_unchanged(tmp_path, monkeypatch):
    target = tmp_path / "data.json"
    target.write_text('{"keep": true}', encoding="utf-8")

    def fail(_a, _b):
        raise PermissionError(13, "locked")
    monkeypatch.setattr(atomic.os, "replace", fail)

    with pytest.raises(PermissionError):
        atomic_write_json(str(target), {"keep": False})

    assert target.read_text(encoding="utf-8") == '{"keep": true}'
    assert _leftovers(tmp_path, "data.json") == []


def test_save_prefs_reports_failure_and_keeps_old_settings(pref_path, monkeypatch, private_log):
    pref_path.write_text('{"theme": "light"}', encoding="utf-8")

    def fail(_fd):
        raise OSError(28, "zzmarkerdisk C:\\Users\\bob")
    monkeypatch.setattr(atomic.os, "fsync", fail)

    assert prefs.save_prefs({"theme": "dark"}) is False
    assert json.loads(pref_path.read_text(encoding="utf-8")) == {"theme": "light"}
    written = _read_log(private_log)
    assert "save prefs failed" in written
    assert "ENOSPC" in written
    assert "zzmarkerdisk" not in written
    assert "bob" not in written


# ---- load_prefs ----

def test_missing_prefs_file_is_first_run(pref_path, private_log):
    assert prefs.load_prefs() == {}
    assert not pref_path.exists()


def test_valid_prefs_file_loads(pref_path):
    pref_path.write_text('{"theme": "light"}', encoding="utf-8")
    assert prefs.load_prefs() == {"theme": "light"}


@pytest.mark.parametrize("content", [b"{not json", b"[1, 2]", b"\xff\xfe\x00junk"])
def test_damaged_prefs_file_is_kept_aside(pref_path, private_log, content):
    pref_path.write_bytes(content)

    assert prefs.load_prefs() == {}

    assert not pref_path.exists()
    kept = [p for p in pref_path.parent.iterdir()
            if p.name.startswith(pref_path.name + ".corrupt-")]
    assert len(kept) == 1
    assert kept[0].read_bytes() == content
    written = _read_log(private_log)
    assert "settings file unreadable, kept aside" in written
    assert str(pref_path.parent) not in written


def test_damaged_prefs_file_that_cannot_move_is_logged(pref_path, monkeypatch, private_log):
    pref_path.write_text("{not json", encoding="utf-8")

    def fail(_a, _b):
        raise PermissionError(13, "zzmarkermove")
    monkeypatch.setattr(prefs.os, "replace", fail)

    assert prefs.load_prefs() == {}

    assert pref_path.read_text(encoding="utf-8") == "{not json"
    written = _read_log(private_log)
    assert "settings file unreadable, not kept aside" in written
    assert "zzmarkermove" not in written


def test_locked_prefs_file_is_left_in_place(pref_path, monkeypatch, private_log):
    pref_path.write_text('{"theme": "light"}', encoding="utf-8")
    real_open = builtins.open

    def locked_open(file, *args, **kwargs):
        if str(file) == str(pref_path):
            raise PermissionError(13, "zzmarkerlock C:\\Users\\bob")
        return real_open(file, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", locked_open)

    assert prefs.load_prefs() == {}

    monkeypatch.setattr(builtins, "open", real_open)
    assert pref_path.read_text(encoding="utf-8") == '{"theme": "light"}'
    assert [p.name for p in pref_path.parent.iterdir() if ".corrupt-" in p.name] == []
    written = _read_log(private_log)
    assert "settings file not read" in written
    assert "EACCES" in written
    assert "zzmarkerlock" not in written
