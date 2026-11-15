import ast
import re
from pathlib import Path

import pytest

from app import api as api_module
from app import debug_log, helpers, paths, server
from app.api import Api
from app.debug_log import DebugLog, describe_error, describe_failure
from app.server import Lockout, ServerIface
from app.services import firewall, hostkey, keygen, prefs, updates
from simple_sftp_server import APP_VERSION


def _read_log(log):
    return Path(log._path).read_text(encoding="utf-8")


@pytest.fixture
def private_log(tmp_path, monkeypatch):
    log = DebugLog(str(tmp_path), "Test App", redact=debug_log._redact)
    assert log.set_enabled(True)
    for module in (debug_log, api_module, helpers, server, firewall, hostkey, keygen, prefs, updates):
        monkeypatch.setattr(module, "debug", log)
    return log


def test_describe_error_omits_message():
    class NamedOSError(OSError):
        pass

    description = describe_error(NamedOSError(2, "secret-path C:\\Users\\bob\\x"))
    assert "OSError" in description
    assert "ENOENT" in description
    assert "secret-path" not in description
    assert "bob" not in description


def test_describe_error_winerror():
    error = OSError(5, "access denied", None, 5)
    assert "WinError 5" in describe_error(error)


def test_describe_error_plain_exception():
    assert describe_error(ValueError("typed-marker")) == "ValueError"


def test_describe_failure_location():
    api = Api(APP_VERSION)

    def fail(_port):
        raise ValueError("typed-marker")

    api._start_server = fail
    with pytest.raises(ValueError) as caught:
        api.start_server("2222")

    description = describe_failure(caught.value)
    assert re.fullmatch(r"ValueError at api\.py:\d+", description)
    assert "typed-marker" not in description
    assert "/" not in description and "\\" not in description


def test_describe_failure_no_app_frame():
    try:
        raise ValueError("typed-marker")
    except ValueError as error:
        description = describe_failure(error)
    assert description == "ValueError"


def test_save_user_username_not_logged(tmp_path, monkeypatch, private_log):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    api = Api(APP_VERSION)
    home = tmp_path / "home"
    home.mkdir()

    result = api.save_user({
        "username": "zzmarkeruser", "home": str(home),
        "permissions": {"list": True}, "auth": "password", "password": "secret",
    })

    assert result["ok"] is True
    written = _read_log(private_log)
    assert "user saved" in written
    assert "zzmarkeruser" not in written


def test_auth_fail_username_not_logged(private_log):
    class FakeService:
        def __init__(self):
            self.lockout = Lockout()

        def find_user(self, _username):
            return None

    iface = ServerIface(FakeService(), "127.0.0.1", 1)
    iface.check_auth_password("zzmarkerattacker", "wrong")

    written = _read_log(private_log)
    assert "auth fail (password)" in written
    assert "127.0.0.1" in written
    assert "zzmarkerattacker" not in written


def test_save_config_error_text_not_logged(tmp_path, monkeypatch, private_log):
    monkeypatch.setattr(paths, "CONFIG_FILE", str(tmp_path / "server_config.json"))
    monkeypatch.setattr(
        api_module, "atomic_write_json",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError(13, "zzmarkerpath C:\\Users\\bob")),
    )
    api = Api(APP_VERSION)

    assert api._save_config({}) is False
    written = _read_log(private_log)
    assert "save config failed" in written
    assert "EACCES" in written
    assert "zzmarkerpath" not in written
    assert "bob" not in written


def test_start_failure_logs_kind_and_location_only(private_log):
    api = Api(APP_VERSION)

    def fail(_port):
        raise RuntimeError("zzmarkertrace")

    api._start_server = fail
    with pytest.raises(RuntimeError):
        api.start_server("2222")

    written = _read_log(private_log)
    assert "RuntimeError at " in written
    assert "zzmarkertrace" not in written
    assert "Traceback" not in written


def test_keygen_path_not_logged(tmp_path, private_log):
    out_path = tmp_path / "zzmarkerkeydir" / "id_ed25519"
    out_path.parent.mkdir()

    result = keygen.generate_keypair("Ed25519", str(out_path), "", "user")

    assert result["ok"] is True
    written = _read_log(private_log)
    assert "KEYGEN" in written
    assert "zzmarkerkeydir" not in written


def _unsafe_log_calls(source):
    tree = ast.parse(source)
    unsafe = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "_log":
            continue
        rendered = " ".join(ast.unparse(argument) for argument in node.args)
        if any(marker in rendered for marker in ("str(e", "{e}", "{e2}", "format_exc", ".strerror")):
            unsafe.append(rendered)
    return unsafe


def test_no_str_e_in_log_calls():
    root = Path(__file__).resolve().parent.parent
    sources = [root / "simple_sftp_server.py", *(root / "app").rglob("*.py")]
    assert len(sources) > 10
    for source in sources:
        assert _unsafe_log_calls(source.read_text(encoding="utf-8")) == []
    assert _unsafe_log_calls('debug._log("bad", str(e))')


def test_log_method_is_private():
    assert hasattr(DebugLog, "_log")
    assert not hasattr(DebugLog, "log")
