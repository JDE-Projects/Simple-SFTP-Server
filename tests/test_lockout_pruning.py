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


def test_all_locked_tables_stay_at_ceiling_via_record_fail_and_prune(monkeypatch):
    import app.server as server_module

    monkeypatch.setattr(server_module, "MAX_TRACKED_IPS", 2)

    lockout = Lockout()
    t0 = 1_000_000.0

    for i in range(3):
        ip = "10.0.2.%d" % i
        _lock_out(lockout, ip, "user", t0 + i)
    assert len(lockout._fails) <= 2
    assert len(lockout._last) <= 2
    assert len(lockout._until) <= 2

    for i in range(3):
        ip = "10.0.3.%d" % i
        for username in range(IP_LOCKOUT_THRESHOLD):
            lockout.record_fail(ip, "user%d" % username, now=t0 + 10 + i)
    assert len(lockout._ip_fails) <= 2
    assert len(lockout._ip_last) <= 2
    assert len(lockout._ip_until) <= 2

    lockout._fails = {("10.0.4.%d" % i, "user"): LOCKOUT_THRESHOLD for i in range(3)}
    lockout._last = {key: t0 for key in lockout._fails}
    lockout._until = {key: t0 + LOCKOUT_SECONDS + i for i, key in enumerate(lockout._fails)}
    lockout._ip_fails = {"10.0.5.%d" % i: IP_LOCKOUT_THRESHOLD for i in range(3)}
    lockout._ip_last = {ip: t0 for ip in lockout._ip_fails}
    lockout._ip_until = {ip: t0 + LOCKOUT_SECONDS + i for i, ip in enumerate(lockout._ip_fails)}
    lockout._prune(t0 + 1)

    assert len(lockout._fails) <= 2
    assert len(lockout._last) <= 2
    assert len(lockout._until) <= 2
    assert len(lockout._ip_fails) <= 2
    assert len(lockout._ip_last) <= 2
    assert len(lockout._ip_until) <= 2


def test_unlocked_records_are_evicted_before_locked_records(monkeypatch):
    import app.server as server_module

    monkeypatch.setattr(server_module, "MAX_TRACKED_IPS", 2)
    lockout = Lockout()
    t0 = 1_000_000.0
    locked_key = ("10.0.6.1", "user")
    unlocked_key = ("10.0.6.2", "user")
    newer_unlocked_key = ("10.0.6.3", "user")
    lockout._fails = {locked_key: LOCKOUT_THRESHOLD, unlocked_key: 1, newer_unlocked_key: 1}
    lockout._last = {locked_key: t0 + 2, unlocked_key: t0, newer_unlocked_key: t0 + 1}
    lockout._until = {locked_key: t0 + LOCKOUT_SECONDS}

    lockout._prune(t0 + 3)

    assert locked_key in lockout._fails
    assert unlocked_key not in lockout._fails
    assert newer_unlocked_key in lockout._fails


def test_earliest_expiring_locked_record_is_evicted_and_no_longer_locked(monkeypatch):
    import app.server as server_module

    monkeypatch.setattr(server_module, "MAX_TRACKED_IPS", 2)
    lockout = Lockout()
    t0 = 1_000_000.0
    ips = ["10.0.7.%d" % i for i in range(3)]
    keys = [(ip, "user") for ip in ips]
    lockout._fails = {key: LOCKOUT_THRESHOLD for key in keys}
    lockout._last = {key: t0 for key in keys}
    lockout._until = {keys[0]: t0 + 10, keys[1]: t0 + 20, keys[2]: t0 + 30}

    lockout._prune(t0 + 1)

    assert keys[0] not in lockout._fails
    assert keys[0] not in lockout._last
    assert keys[0] not in lockout._until
    assert lockout.is_locked(ips[0], "user", now=t0 + 1) is False
    for ip in ips[1:]:
        assert lockout.is_locked(ip, "user", now=t0 + 1) is True


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
