"""Tests for the per-connection activity readout: op/path tracking, running
counts, and the connections() reporting shape."""

import time

from app.server import SFTPService


class FakeApi:
    """Minimal stand-in for the real Api: no-op the methods SFTPService touches."""

    def emit(self, event, payload):
        pass

    def status_payload(self):
        return {}

    def find_user(self, username):
        return None


def _service_with_session(sid=1):
    service = SFTPService(FakeApi())
    service._sessions[sid] = {
        "ip": "127.0.0.1", "user": "bob", "since": time.time(), "transfers": {},
        "op": "", "path": "", "lists": 0, "stats": 0, "bytes": 0,
    }
    return service


def test_note_op_increments_counts_every_call_no_throttle():
    service = _service_with_session()

    for _ in range(5):
        service.note_op(1, "listing folder", "/photos", count_key="lists")

    sess = service._sessions[1]
    assert sess["lists"] == 5
    assert sess["op"] == "listing folder"
    assert sess["path"] == "/photos"


def test_connections_reports_new_activity_fields():
    service = _service_with_session()
    service.note_op(1, "listing folder", "/photos", count_key="lists")
    service.note_op(1, "reading file details", "/photos/a.jpg", count_key="stats")
    service._sessions[1]["bytes"] = 2048

    conns = service.connections()

    assert len(conns) == 1
    c = conns[0]
    assert c["op"] == "reading file details"
    assert c["path"] == "/photos/a.jpg"
    assert c["lists"] == 1
    assert c["stats"] == 1
    assert c["bytes"] == 2048
    assert c["human"] == "2.0 KB"


def test_note_op_missing_sid_does_not_raise():
    service = _service_with_session()

    service.note_op(999, "listing folder", "/nowhere", count_key="lists")

    # unrelated session untouched
    assert service._sessions[1]["lists"] == 0
