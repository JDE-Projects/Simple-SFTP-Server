"""Lockout table bounding: fail/lockout records for the account layer
(ip, username) and the address layer (ip) now age out and each table has a
hard ceiling, so an account or address that fails a few times and never
returns (or gets locked out and never reconnects) does not leave a
permanent entry behind. These tests drive the clock explicitly via the
`now` parameter rather than sleeping.
"""

from app.constants import (FAIL_RECORD_TTL_SECONDS, IP_LOCKOUT_THRESHOLD, LOCKOUT_PRUNE_INTERVAL,
                            LOCKOUT_SECONDS, LOCKOUT_THRESHOLD)
from app.server import Lockout


def _lock_out(lockout, ip, username, now):
    for _ in range(LOCKOUT_THRESHOLD):
        lockout.record_fail(ip, username, now=now)


def test_stale_fail_record_below_threshold_is_forgotten_after_ttl():
    lockout = Lockout()
    t0 = 1_000_000.0
    ip = "10.0.0.1"
    key = (ip, "bob")

    lockout.record_fail(ip, "bob", now=t0)
    lockout.record_fail(ip, "bob", now=t0)
    assert lockout.is_locked(ip, "bob", now=t0) is False

    later = t0 + FAIL_RECORD_TTL_SECONDS + 1
    assert lockout.is_locked(ip, "bob", now=later) is False
    assert key not in lockout._fails
    assert key not in lockout._last
    assert key not in lockout._until
    assert ip not in lockout._ip_fails
    assert ip not in lockout._ip_last


def test_expired_lockout_is_pruned_even_if_ip_never_reconnects():
    lockout = Lockout()
    t0 = 1_000_000.0
    ip = "10.0.0.2"
    other_ip = "10.0.0.3"
    key = (ip, "bob")

    _lock_out(lockout, ip, "bob", t0)
    assert lockout.is_locked(ip, "bob", now=t0) is True

    sweep_time = t0 + LOCKOUT_SECONDS + LOCKOUT_PRUNE_INTERVAL + 1
    # Trigger the throttled sweep via a different ip's call, exactly as it
    # would happen when a different attacker connects later.
    lockout.record_fail(other_ip, "eve", now=sweep_time)

    assert key not in lockout._until
    assert key not in lockout._fails
    assert key not in lockout._last


def test_still_locked_account_is_not_pruned_before_expiry():
    lockout = Lockout()
    t0 = 1_000_000.0
    ip = "10.0.0.4"
    key = (ip, "bob")

    _lock_out(lockout, ip, "bob", t0)
    assert lockout.is_locked(ip, "bob", now=t0) is True

    mid_point = t0 + LOCKOUT_SECONDS / 2
    assert lockout.is_locked(ip, "bob", now=mid_point) is True
    assert key in lockout._until
    assert key in lockout._fails


def test_cap_eviction_drops_oldest_nonlocked_first(monkeypatch):
    import app.server as server_module

    monkeypatch.setattr(server_module, "MAX_TRACKED_IPS", 5)

    lockout = Lockout()
    t0 = 1_000_000.0

    ips = ["10.0.1.%d" % i for i in range(8)]
    keys = [(ip, "user") for ip in ips]
    for i, ip in enumerate(ips):
        # one fail each, well below LOCKOUT_THRESHOLD, so none get locked
        lockout.record_fail(ip, "user", now=t0 + i)

    # Force a full sweep so the cap is enforced deterministically.
    lockout._prune(t0 + len(ips))

    assert len(lockout._fails) <= 5
    # The earliest-timestamped accounts should have been evicted first.
    for key in keys[:3]:
        assert key not in lockout._fails
    for key in keys[-3:]:
        assert key in lockout._fails


def test_locked_entries_survive_cap_eviction(monkeypatch):
    import app.server as server_module

    monkeypatch.setattr(server_module, "MAX_TRACKED_IPS", 5)

    lockout = Lockout()
    t0 = 1_000_000.0

    locked_ips = ["10.0.2.%d" % i for i in range(5)]
    locked_keys = [(ip, "user") for ip in locked_ips]
    for i, ip in enumerate(locked_ips):
        _lock_out(lockout, ip, "user", t0 + i)
        assert lockout.is_locked(ip, "user", now=t0 + i) is True

    extra_ips = ["10.0.2.%d" % i for i in range(100, 103)]
    for i, ip in enumerate(extra_ips):
        lockout.record_fail(ip, "user", now=t0 + 10 + i)

    lockout._prune(t0 + 200)

    # The cap may be exceeded here since every entry is locked, but no
    # locked account should ever be dropped to make room.
    for key in locked_keys:
        assert key in lockout._until
        assert key in lockout._fails
        assert key in lockout._last


def test_is_locked_accuracy_independent_of_prune_timing():
    lockout = Lockout()
    t0 = 1_000_000.0
    ip = "10.0.3.1"

    _lock_out(lockout, ip, "bob", t0)
    lockout._last_prune = t0  # simulate a stale sweep timestamp

    # Well before expiry, and before the prune interval would trigger a
    # fresh sweep: the per-account check must still be accurate.
    assert lockout.is_locked(ip, "bob", now=t0 + 5) is True


# ───────────── two-tier account / address behavior ─────────────

def test_account_isolation_between_usernames_on_shared_ip():
    lockout = Lockout()
    t0 = 1_000_000.0
    ip = "10.0.4.1"

    _lock_out(lockout, ip, "bob", t0)
    assert lockout.is_locked(ip, "bob", now=t0) is True
    assert lockout.is_locked(ip, "alice", now=t0) is False


def test_clear_with_username_does_not_touch_other_accounts_on_same_ip():
    lockout = Lockout()
    t0 = 1_000_000.0
    ip = "10.0.4.2"

    # bob is built up to just below the lockout threshold from a shared ip
    for _ in range(LOCKOUT_THRESHOLD - 1):
        lockout.record_fail(ip, "bob", now=t0)

    # alice logs in successfully from the same (shared/NAT) address
    lockout.clear(ip, "alice")

    # bob's fail count and lock state must be untouched
    assert lockout._fails.get((ip, "bob")) == LOCKOUT_THRESHOLD - 1
    assert lockout.is_locked(ip, "bob", now=t0) is False

    # one more failure locks bob out, proving the count really survived
    lockout.record_fail(ip, "bob", now=t0)
    assert lockout.is_locked(ip, "bob", now=t0) is True


def test_address_backstop_locks_whole_ip_on_username_spray():
    lockout = Lockout()
    t0 = 1_000_000.0
    ip = "10.0.4.3"

    for i in range(IP_LOCKOUT_THRESHOLD):
        lockout.record_fail(ip, "user%d" % i, now=t0)

    assert lockout._ip_fails[ip] == IP_LOCKOUT_THRESHOLD
    assert lockout.is_locked(ip, now=t0) is True


def test_single_account_lockout_does_not_trip_address_backstop():
    lockout = Lockout()
    t0 = 1_000_000.0
    ip = "10.0.4.4"

    _lock_out(lockout, ip, "bob", t0)

    assert lockout.is_locked(ip, "bob", now=t0) is True
    assert lockout.is_locked(ip, now=t0) is False


def test_admin_clear_without_username_clears_address_and_all_accounts():
    lockout = Lockout()
    t0 = 1_000_000.0
    ip = "10.0.4.5"

    _lock_out(lockout, ip, "bob", t0)
    lockout.record_fail(ip, "alice", now=t0)

    lockout.clear(ip)

    assert lockout.is_locked(ip, now=t0) is False
    assert lockout.is_locked(ip, "bob", now=t0) is False
    assert (ip, "bob") not in lockout._fails
    assert (ip, "alice") not in lockout._fails
    assert ip not in lockout._ip_fails
