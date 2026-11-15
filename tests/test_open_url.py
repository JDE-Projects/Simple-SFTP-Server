"""The open_url bridge opens the JDE-Projects website and nothing else."""
from pathlib import Path

import pytest

from app import api as api_module
from app import debug_log, paths
from app.api import Api, _is_allowed_url
from app.debug_log import DebugLog
from simple_sftp_server import APP_VERSION


@pytest.fixture
def private_log(tmp_path, monkeypatch):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log = DebugLog(str(log_dir), "Test App", redact=debug_log._redact)
    assert log.set_enabled(True)
    monkeypatch.setattr(api_module, "debug", log)
    return log


@pytest.fixture
def opened(monkeypatch):
    calls = []
    monkeypatch.setattr(api_module.webbrowser, "open", lambda url: calls.append(url))
    return calls


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    return Api(APP_VERSION)


ALLOWED = [
    "https://jde-projects.com",
    "https://jde-projects.com/",
    "https://jde-projects.com/privacy",
    "https://jde-projects.com/support/#commercial-licensing",
    "https://jde-projects.com/page?x=1",
]

REFUSED = [
    "http://jde-projects.com",
    "javascript:alert(1)",
    "file:///C:/Windows/System32/calc.exe",
    "ftp://jde-projects.com",
    "https://jde-projects.com.evil.example",
    "https://evil.example/jde-projects.com",
    "https://www.jde-projects.com",
    "https://JDE-Projects.com",
    "https://jde-projects.com:8443/",
    "https://user@jde-projects.com/",
    "https://evil.example@jde-projects.com/",
    "https://jde-projects.com /x",
    "https://jde-projects.com/\nx",
    "https://jde-projects.com/\x00",
    "https://[jde-projects.com",
    "https://github.com/JDE-Projects/Simple-SFTP-Server",
    "jde-projects.com",
    "",
    None,
    123,
    ["https://jde-projects.com"],
]


@pytest.mark.parametrize("url", ALLOWED)
def test_allowed_website_pages(url):
    assert _is_allowed_url(url) is True


@pytest.mark.parametrize("url", REFUSED)
def test_refused_hosts_and_schemes(url):
    assert _is_allowed_url(url) is False


def test_open_url_opens_allowed_page(api, opened):
    assert api.open_url("https://jde-projects.com/privacy") == {"ok": True}
    assert opened == ["https://jde-projects.com/privacy"]


@pytest.mark.parametrize("url", REFUSED)
def test_open_url_refuses_without_opening_browser(api, opened, private_log, url):
    result = api.open_url(url)

    assert result == {"ok": False, "error": "That link isn't allowed."}
    assert opened == []
    written = Path(private_log._path).read_text(encoding="utf-8")
    assert "open_url refused an address outside the allowed site" in written
    if isinstance(url, str) and url:
        assert url not in written
