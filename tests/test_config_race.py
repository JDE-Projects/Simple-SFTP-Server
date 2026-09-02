"""Regression test for the config read-modify-write race: pywebview dispatches
every JS->Python API call on its own thread with no serialization, so two
overlapping config changes (e.g. two user deletes) could silently lose one of
them. This proves both deletions persist when they race."""

import json
import threading

from app import paths
from app.api import Api
from app.constants import DEFAULT_PORT


def _api(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    return Api()


def test_concurrent_delete_user_does_not_lose_a_deletion(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    seed = {"settings": {"port": DEFAULT_PORT},
            "users": [{"username": "alice", "home": str(tmp_path / "alice")},
                      {"username": "bob", "home": str(tmp_path / "bob")}]}
    assert api._save_config(seed)

    # Force both delete_user calls to reach the save step at (roughly) the same
    # time, so a stale in-memory read (the bug) is reproduced deterministically.
    # If the caller holds a lock across the whole load-then-save sequence (the
    # fix), only one thread can ever reach this point at once: the barrier then
    # times out harmlessly and each call proceeds on its own.
    barrier = threading.Barrier(2)
    real_save_config = api._save_config

    def racy_save_config(cfg):
        try:
            barrier.wait(timeout=1.0)
        except threading.BrokenBarrierError:
            pass
        return real_save_config(cfg)

    monkeypatch.setattr(api, "_save_config", racy_save_config)

    results = {}

    def run(username):
        results[username] = api.delete_user(username, delete_folder=False)

    t1 = threading.Thread(target=run, args=("alice",))
    t2 = threading.Thread(target=run, args=("bob",))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert not t1.is_alive()
    assert not t2.is_alive()
    assert results.get("alice", {}).get("ok") is True
    assert results.get("bob", {}).get("ok") is True

    with open(paths.CONFIG_FILE, "r", encoding="utf-8") as f:
        on_disk = json.load(f)
    usernames = {u.get("username") for u in on_disk.get("users", [])}
    assert usernames == set()
