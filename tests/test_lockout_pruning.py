"""Phase 2 lockout table bounding: fail/lockout records for a source IP now
age out and the table has a hard ceiling, so an address that fails a few
times and never returns (or gets locked out and never reconnects) does not
leave a permanent entry behind. These tests drive the clock explicitly via
the `now` parameter rather than sleeping.
"""

from app.constants import FAIL_RECORD_TTL_SECONDS, LOCKOUT_PRUNE_INTERVAL, LOCKOUT_SECONDS, LOCKOUT_THRESHOLD
from app.server import Lockout


def _lock_out(lockout, ip, now):
    for _ in range(LOCKOUT_THRESHOLD):
        lockout.record_fail(ip, now=now)


def test_stale_fail_record_below_threshold_is_forgotten_after_ttl():
    lockout = Lockout()
    t0 = 1_000_000.0
    ip = "10.0.0.1"

    lockout.record_fail(ip, now=t0)
    lockout.record_fail(ip, now=t0)
    assert lockout.is_locked(ip, now=t0) is False

    later = t0 + FAIL_RECORD_TTL_SECONDS + 1
    assert lockout.is_locked(ip, now=later) is False
    assert ip not in lockout._fails
    assert ip not in lockout._last
    assert ip not in lockout._until


def test_expired_lockout_is_pruned_even_if_ip_never_reconnects():
    lockout = Lockout()
    t0 = 1_000_000.0
    ip = "10.0.0.2"
    other_ip = "10.0.0.3"

    _lock_out(lockout, ip, t0)
    assert lockout.is_locked(ip, now=t0) is True

    sweep_time = t0 + LOCKOUT_SECONDS + LOCKOUT_PRUNE_INTERVAL + 1
    # Trigger the throttled sweep via a different ip's call, exactly as it
    # would happen when a different attacker connects later.
    lockout.record_fail(other_ip, now=sweep_time)

    assert ip not in lockout._until
    assert ip not in lockout._fails
    assert ip not in lockout._last


def test_still_locked_ip_is_not_pruned_before_expiry():
    lockout = Lockout()
    t0 = 1_000_000.0
    ip = "10.0.0.4"

    _lock_out(lockout, ip, t0)
    assert lockout.is_locked(ip, now=t0) is True

    mid_point = t0 + LOCKOUT_SECONDS / 2
    assert lockout.is_locked(ip, now=mid_point) is True
    assert ip in lockout._until
    assert ip in lockout._fails


def test_cap_eviction_drops_oldest_nonlocked_first(monkeypatch):
    import app.server as server_module

    monkeypatch.setattr(server_module, "MAX_TRACKED_IPS", 5)

    lockout = Lockout()
    t0 = 1_000_000.0

    ips = ["10.0.1.%d" % i for i in range(8)]
    for i, ip in enumerate(ips):
        # one fail each, well below LOCKOUT_THRESHOLD, so none get locked
        lockout.record_fail(ip, now=t0 + i)

    # Force a full sweep so the cap is enforced deterministically.
    lockout._prune(t0 + len(ips))

    assert len(lockout._fails) <= 5
    # The earliest-timestamped ips should have been evicted first.
    for ip in ips[:3]:
        assert ip not in lockout._fails
    for ip in ips[-3:]:
        assert ip in lockout._fails


def test_locked_entries_survive_cap_eviction(monkeypatch):
    import app.server as server_module

    monkeypatch.setattr(server_module, "MAX_TRACKED_IPS", 5)

    lockout = Lockout()
    t0 = 1_000_000.0

    locked_ips = ["10.0.2.%d" % i for i in range(5)]
    for i, ip in enumerate(locked_ips):
        _lock_out(lockout, ip, t0 + i)
        assert lockout.is_locked(ip, now=t0 + i) is True

    extra_ips = ["10.0.2.%d" % i for i in range(100, 103)]
    for i, ip in enumerate(extra_ips):
        lockout.record_fail(ip, now=t0 + 10 + i)

    lockout._prune(t0 + 200)

    # The cap may be exceeded here since every entry is locked, but no
    # locked ip should ever be dropped to make room.
    for ip in locked_ips:
        assert ip in lockout._until
        assert ip in lockout._fails
        assert ip in lockout._last


def test_is_locked_accuracy_independent_of_prune_timing():
    lockout = Lockout()
    t0 = 1_000_000.0
    ip = "10.0.3.1"

    _lock_out(lockout, ip, t0)
    lockout._last_prune = t0  # simulate a stale sweep timestamp

    # Well before expiry, and before the prune interval would trigger a
    # fresh sweep: the per-ip check must still be accurate.
    assert lockout.is_locked(ip, now=t0 + 5) is True
