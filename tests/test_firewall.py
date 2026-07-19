"""Tests for the pure firewall-detection helpers: _parse_firewall_rule,
_rule_allows, and _decide_firewall. See simple_sftp_server.py, "firewall
detection (advisory, read-only, no admin)" section. The registry-reading
wrapper (_firewall_status) does real I/O and is covered by the manual smoke
test instead, per roadmap.md."""

import os

from simple_sftp_server import _decide_firewall, _parse_firewall_rule, _rule_allows

PORT = 2222
APP_PATH = r"C:\Program Files\Simple SFTP Server\Simple SFTP Server.exe"
EXE_NORM = os.path.normcase(os.path.realpath(APP_PATH))


def rule(s):
    return _parse_firewall_rule(s)


# ---------- _parse_firewall_rule ----------

def test_parse_basic_rule_lowercases_keys():
    s = f"Action=Allow|Dir=In|Protocol=6|LocalPort={PORT}|App={APP_PATH}|Active=TRUE"
    parsed = rule(s)
    assert parsed["action"] == "Allow"
    assert parsed["dir"] == "In"
    assert parsed["protocol"] == "6"
    assert parsed["localport"] == str(PORT)
    assert parsed["app"] == APP_PATH
    assert parsed["active"] == "TRUE"


def test_parse_empty_string_returns_empty_dict():
    assert rule("") == {}
    assert rule(None) == {}


def test_parse_malformed_record_handled_gracefully():
    # Segments without "=" are skipped rather than raising; a trailing "|" and
    # stray whitespace should not blow up the parser.
    s = "Action=Allow|garbage-segment-no-equals|Dir=In| Protocol = 6 |LocalPort=2222|"
    parsed = rule(s)
    assert parsed["action"] == "Allow"
    assert parsed["dir"] == "In"
    assert parsed["protocol"] == "6"
    assert parsed["localport"] == "2222"
    assert "garbage-segment-no-equals" not in parsed


# ---------- _rule_allows ----------

def test_allow_rule_matches_by_app_path():
    s = f"Action=Allow|Dir=In|Protocol=6|LocalPort=9999|App={APP_PATH}|Active=TRUE"
    assert _rule_allows(rule(s), EXE_NORM, PORT) is True


def test_allow_rule_matches_by_port():
    s = f"Action=Allow|Dir=In|Protocol=6|LocalPort={PORT}|App=C:\\other\\app.exe|Active=TRUE"
    assert _rule_allows(rule(s), EXE_NORM, PORT) is True


def test_allow_rule_matches_localport_any():
    s = "Action=Allow|Dir=In|Protocol=6|LocalPort=Any|Active=TRUE"
    assert _rule_allows(rule(s), EXE_NORM, PORT) is True


def test_allow_rule_matches_port_in_comma_list():
    s = f"Action=Allow|Dir=In|Protocol=6|LocalPort=80,443,{PORT}|Active=TRUE"
    assert _rule_allows(rule(s), EXE_NORM, PORT) is True


def test_allow_rule_matches_port_in_range():
    s = "Action=Allow|Dir=In|Protocol=6|LocalPort=2000-2300|Active=TRUE"
    assert _rule_allows(rule(s), EXE_NORM, PORT) is True


def test_allow_rule_does_not_match_unrelated_port_or_app():
    s = "Action=Allow|Dir=In|Protocol=6|LocalPort=9999|App=C:\\other\\app.exe|Active=TRUE"
    assert _rule_allows(rule(s), EXE_NORM, PORT) is False


def test_disabled_rule_does_not_match():
    s = f"Action=Allow|Dir=In|Protocol=6|LocalPort={PORT}|Active=FALSE"
    assert _rule_allows(rule(s), EXE_NORM, PORT) is False


def test_block_rule_does_not_match():
    s = f"Action=Block|Dir=In|Protocol=6|LocalPort={PORT}|Active=TRUE"
    assert _rule_allows(rule(s), EXE_NORM, PORT) is False


def test_outbound_rule_does_not_match():
    s = f"Action=Allow|Dir=Out|Protocol=6|LocalPort={PORT}|Active=TRUE"
    assert _rule_allows(rule(s), EXE_NORM, PORT) is False


def test_malformed_record_does_not_match_and_does_not_raise():
    parsed = rule("this is not a valid rule string at all")
    assert _rule_allows(parsed, EXE_NORM, PORT) is False


def test_empty_parsed_dict_does_not_match():
    assert _rule_allows({}, EXE_NORM, PORT) is False


# ---------- _decide_firewall ----------

def test_decide_allowed_when_has_allow_rule_regardless_of_profile_state():
    assert _decide_firewall(True, True) == "allowed"
    assert _decide_firewall(False, True) == "allowed"
    assert _decide_firewall(None, True) == "allowed"


def test_decide_allowed_when_firewall_off_and_no_allow_rule():
    assert _decide_firewall(False, False) == "allowed"


def test_decide_blocked_when_firewall_on_and_no_allow_rule():
    assert _decide_firewall(True, False) == "blocked"


def test_decide_unknown_when_profile_state_could_not_be_read():
    assert _decide_firewall(None, False) == "unknown"
