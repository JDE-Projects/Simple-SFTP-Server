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
        assert service._admit("10.0.0.%d" % (i % 250)) is True
    assert service._admit("10.0.9.9") is False


def test_per_ip_cap_rejects_same_ip_but_allows_other_ip():
    service = _service()
    ip = "10.0.0.1"
    for _ in range(MAX_PER_IP_CONNECTIONS):
        assert service._admit(ip) is True
    assert service._admit(ip) is False
    assert service._admit("10.0.0.2") is True


def test_release_frees_a_per_ip_slot_and_clears_dead_ip_entry():
    service = _service()
    ip = "10.0.0.1"
    for _ in range(MAX_PER_IP_CONNECTIONS):
        assert service._admit(ip) is True
    assert service._admit(ip) is False

    service._release(ip)
    assert service._admit(ip) is True

    # Drain the ip back to zero and confirm the dict entry is dropped, not
    # left behind at 0, so a long-lived server does not accumulate dead ips.
    for _ in range(MAX_PER_IP_CONNECTIONS):
        service._release(ip)
    assert ip not in service._ip_counts


def test_global_release_frees_a_slot_for_a_new_connection():
    service = _service()
    for i in range(MAX_TOTAL_CONNECTIONS):
        assert service._admit("10.0.0.%d" % (i % 250)) is True
    assert service._admit("10.0.9.9") is False

    service._release("10.0.0.0")
    assert service._admit("10.0.9.9") is True
