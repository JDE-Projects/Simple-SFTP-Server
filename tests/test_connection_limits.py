"""Phase 1 connection admission: SFTPService bounds concurrent connections so a
flood of clients that never finish logging in cannot spawn handler threads
without limit. These tests exercise the admission bookkeeping (_admit /
_release) directly, with no real sockets involved.
"""

from unittest.mock import Mock

from app.constants import MAX_PER_IP_CONNECTIONS, MAX_TOTAL_CONNECTIONS
from app.server import SFTPService


def _service():
    return SFTPService(Mock())


def test_global_cap_rejects_after_max_total_connections():
    service = _service()
    for i in range(MAX_TOTAL_CONNECTIONS):
        assert service._admit("10.0.0.%d" % (i % 250)) is not None
    assert service._admit("10.0.9.9") is None


def test_per_ip_cap_rejects_same_ip_but_allows_other_ip():
    service = _service()
    ip = "10.0.0.1"
    for _ in range(MAX_PER_IP_CONNECTIONS):
        assert service._admit(ip) is not None
    assert service._admit(ip) is None
    assert service._admit("10.0.0.2") is not None


def test_release_frees_a_per_ip_slot_and_clears_dead_ip_entry():
    service = _service()
    ip = "10.0.0.1"
    generations = [service._admit(ip) for _ in range(MAX_PER_IP_CONNECTIONS)]
    assert all(gen is not None for gen in generations)
    assert service._admit(ip) is None

    service._release(ip, generations.pop())
    assert service._admit(ip) is not None

    # Drain the ip back to zero and confirm the dict entry is dropped, not
    # left behind at 0, so a long-lived server does not accumulate dead ips.
    for gen in generations:
        service._release(ip, gen)
    service._release(ip, service._generation)
    assert ip not in service._ip_counts


def test_global_release_frees_a_slot_for_a_new_connection():
    service = _service()
    generations = [service._admit("10.0.0.%d" % (i % 250))
                   for i in range(MAX_TOTAL_CONNECTIONS)]
    assert all(gen is not None for gen in generations)
    assert service._admit("10.0.9.9") is None

    service._release("10.0.0.0", generations[0])
    assert service._admit("10.0.9.9") is not None


def test_old_generation_release_does_not_reduce_restarted_connection_counts():
    service = _service()
    ip = "10.0.0.1"
    old_generation = service._admit(ip)
    assert old_generation == 0

    with service._lock:
        service._conn_count = 0
        service._ip_counts.clear()
        service._generation += 1

    new_generation = service._admit(ip)
    assert new_generation == 1
    assert service._conn_count == 1
    assert service._ip_counts == {ip: 1}

    service._release(ip, old_generation)
    assert service._conn_count == 1
    assert service._ip_counts == {ip: 1}


def test_current_generation_release_frees_a_slot():
    service = _service()
    ip = "10.0.0.1"
    generation = service._admit(ip)
    assert generation == 0

    service._release(ip, generation)
    assert service._conn_count == 0
    assert ip not in service._ip_counts
