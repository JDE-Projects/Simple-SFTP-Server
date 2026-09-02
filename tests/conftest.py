"""Pytest fixtures for tests that need a real, running SFTPService. Kept
separate from the root conftest.py (which only sets up sys.path).
"""

import pytest

from app.server import SFTPService
from tests.sftp_helpers import CountingApi, free_port, make_host_key


class _ServerHandle:
    def __init__(self, service, port):
        self.service = service
        self.port = port


@pytest.fixture
def sftp_server(tmp_path):
    """Factory fixture: start(users) starts a real SFTPService on a free
    loopback port with the given list of user records, and returns a handle
    with .port and .service. Every service started this way is stopped when
    the test ends.
    """
    started = []

    def start(users, quick=False):
        by_name = {u["username"]: u for u in users}
        api = CountingApi(users=by_name)
        service = SFTPService(api)
        service.host_key = make_host_key(tmp_path)
        port = free_port()
        r = service.start(port, quick=quick)
        assert r["ok"], r
        started.append(service)
        return _ServerHandle(service, port)

    yield start

    for service in started:
        service.stop()
