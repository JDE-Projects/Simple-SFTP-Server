"""Network-free tests for the update-check error reason helper."""

import errno
import json
import socket
import ssl
import urllib.error

import pytest

from app.services.updates import _update_error_reason


@pytest.mark.parametrize(
    ("exc", "expected"),
    [
        (urllib.error.HTTPError("url", 403, "Forbidden", {}, None), "rate-limiting"),
        (urllib.error.HTTPError("url", 404, "Not Found", {}, None), "No published release was found."),
        (urllib.error.HTTPError("url", 500, "Error", {}, None), "trouble on its end"),
        (urllib.error.HTTPError("url", 418, "Error", {}, None), "GitHub returned an error (HTTP 418)."),
        (json.JSONDecodeError("bad JSON", "not json", 0), "returned something unexpected"),
        (urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed")), "certificate could not be verified"),
        (urllib.error.URLError(ssl.SSLEOFError("EOF")), "cut off during the handshake"),
        (urllib.error.URLError(ssl.SSLError("TLS failed")), "secure connection to GitHub failed"),
        (urllib.error.URLError(socket.gaierror("not found")), "could not be looked up"),
        (urllib.error.URLError(socket.timeout("timed out")), "didn't respond in time"),
        (urllib.error.URLError(ConnectionRefusedError("refused")), "refused or reset"),
        (urllib.error.URLError(OSError(errno.ENETUNREACH, "network unreachable")), "No network connection."),
        (urllib.error.URLError(OSError("unclassified")), "Couldn't reach GitHub. Check the internet connection."),
        (ValueError("unexpected value"), "ValueError: unexpected value"),
    ],
)
def test_update_error_reason_branches(exc, expected):
    assert expected in _update_error_reason(exc)


def test_update_error_reason_truncates_unknown_exception():
    reason = _update_error_reason(ValueError("x" * 200))
    assert len(reason) == 120
    assert reason.endswith("...")
