"""Connection admission: SFTPService bounds concurrent connections so a
flood of clients that never finish logging in cannot spawn handler threads
without limit. Most tests exercise the admission bookkeeping (_admit /
_release) directly, with no real sockets involved; the restart test uses a
real loopback server.
"""

from unittest.mock import Mock

from app.constants import MAX_PER_IP_CONNECTIONS, MAX_TOTAL_CONNECTIONS
from app.server import SFTPService


def _service():
    return SFTPService(Mock())


def test_global_cap_rejects_after_max_total_connections():
    service = _service()
    for i in range(MAX_TOTAL_CONNECTIONS):
        assert service._admit("10.0.0.%d" % (i % 250), service._generation) is not None
    assert service._admit("10.0.9.9", service._generation) is None


def test_per_ip_cap_rejects_same_ip_but_allows_other_ip():
    service = _service()
    ip = "10.0.0.1"
    for _ in range(MAX_PER_IP_CONNECTIONS):
        assert service._admit(ip, service._generation) is not None
    assert service._admit(ip, service._generation) is None
    assert service._admit("10.0.0.2", service._generation) is not None


def test_release_frees_a_per_ip_slot_and_clears_dead_ip_entry():
    service = _service()
    ip = "10.0.0.1"
    generations = [service._admit(ip, service._generation) for _ in range(MAX_PER_IP_CONNECTIONS)]
    assert all(gen is not None for gen in generations)
    assert service._admit(ip, service._generation) is None

    service._release(ip, generations.pop())
    assert service._admit(ip, service._generation) is not None

    # Drain the ip back to zero and confirm the dict entry is dropped, not
    # left behind at 0, so a long-lived server does not accumulate dead ips.
    for gen in generations:
        service._release(ip, gen)
    service._release(ip, service._generation)
    assert ip not in service._ip_counts


def test_global_release_frees_a_slot_for_a_new_connection():
    service = _service()
    generations = [service._admit("10.0.0.%d" % (i % 250), service._generation)
                   for i in range(MAX_TOTAL_CONNECTIONS)]
    assert all(gen is not None for gen in generations)
    assert service._admit("10.0.9.9", service._generation) is None

    service._release("10.0.0.0", generations[0])
    assert service._admit("10.0.9.9", service._generation) is not None


def test_old_generation_release_does_not_reduce_restarted_connection_counts():
    service = _service()
    ip = "10.0.0.1"
    old_generation = service._admit(ip, service._generation)
    assert old_generation == 0

    with service._lock:
        service._conn_count = 0
        service._ip_counts.clear()
        service._generation += 1

    new_generation = service._admit(ip, service._generation)
    assert new_generation == 1
    assert service._conn_count == 1
    assert service._ip_counts == {ip: 1}

    service._release(ip, old_generation)
    assert service._conn_count == 1
    assert service._ip_counts == {ip: 1}


def test_restart_clears_a_slot_admitted_after_a_slow_stop(sftp_server):
    handle = sftp_server([])
    service = handle.service
    ip = "10.0.0.1"
    service.stop()

    # An accept loop that outlived Stop's time limit admits one more
    # connection after Stop has already cleared the counts.
    stray_generation = service._admit(ip, service._generation)
    assert service._conn_count == 1

    r = service.start(handle.port)
    assert r["ok"], r
    assert service._conn_count == 0
    assert service._ip_counts == {}

    # The stray connection's later release belongs to the old run and is
    # ignored, so it cannot push the new run's counts out of step either.
    service._release(ip, stray_generation)
    assert service._conn_count == 0
    assert service._ip_counts == {}


def test_current_generation_release_frees_a_slot():
    service = _service()
    ip = "10.0.0.1"
    generation = service._admit(ip, service._generation)
    assert generation == 0

    service._release(ip, generation)
    assert service._conn_count == 0
    assert ip not in service._ip_counts


def test_admit_refuses_an_accept_loop_from_an_earlier_run():
    service = _service()
    old_generation = service._generation
    with service._lock:
        service._generation += 1

    assert service._admit("10.0.0.1", old_generation) is None
    assert service._conn_count == 0
    assert service._ip_counts == {}
