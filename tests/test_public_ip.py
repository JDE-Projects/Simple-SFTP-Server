"""Network-free tests for the public IP lookup."""

import pytest

from app.services import network


class _Response:
    def __init__(self, body):
        self._body = body.encode()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self):
        return self._body


def _fake_urlopen(responses, calls):
    iterator = iter(responses)

    def fake_urlopen(request, timeout):
        calls.append((request.full_url, request.get_header("User-agent"), timeout))
        response = next(iterator)
        if isinstance(response, Exception):
            raise response
        return _Response(response)

    return fake_urlopen


def test_public_ip_services_are_ipify_then_amazon():
    assert network.PUBLIC_IP_SERVICES == (
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
    )


def test_public_ip_accepts_global_ipv4_with_trailing_newline(monkeypatch):
    calls = []
    monkeypatch.setattr(
        network, "urlopen", _fake_urlopen(["8.8.8.8\n"], calls)
    )

    assert network.public_ip() == "8.8.8.8"
    assert calls == [(network.PUBLIC_IP_SERVICES[0], "Simple-SFTP-Server", 6)]


@pytest.mark.parametrize(
    "reply",
    [
        "999.999.999.999",
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "127.0.0.1",
        "100.64.0.1",
        "0.0.0.0",
        "2001:4860:4860::8888",
        "<html>not an IP</html>",
        "",
    ],
)
def test_public_ip_rejects_invalid_or_non_global_replies(monkeypatch, reply):
    calls = []
    monkeypatch.setattr(
        network, "urlopen", _fake_urlopen([reply, reply], calls)
    )

    assert network.public_ip() == ""
    assert [url for url, _user_agent, _timeout in calls] == list(network.PUBLIC_IP_SERVICES)


@pytest.mark.parametrize("first_response", [OSError("offline"), "not an IP"])
def test_public_ip_uses_amazon_after_ipify_error_or_bad_reply(monkeypatch, first_response):
    calls = []
    monkeypatch.setattr(
        network, "urlopen", _fake_urlopen([first_response, "1.1.1.1\n"], calls)
    )

    assert network.public_ip() == "1.1.1.1"
    assert [url for url, _user_agent, _timeout in calls] == list(network.PUBLIC_IP_SERVICES)
    assert all("ifconfig.me" not in url for url, _user_agent, _timeout in calls)


def test_public_ip_returns_empty_when_all_services_error(monkeypatch):
    calls = []
    monkeypatch.setattr(
        network, "urlopen", _fake_urlopen([OSError("offline")] * 2, calls)
    )

    assert network.public_ip() == ""
    assert [url for url, _user_agent, _timeout in calls] == list(network.PUBLIC_IP_SERVICES)
