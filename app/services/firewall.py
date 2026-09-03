import os
import sys

from app.debug_log import debug


# ───────────── firewall detection (advisory, read-only, no admin) ─────────────
def _parse_firewall_rule(s):
    """Split a pipe-delimited Windows Firewall rule string into a dict with
    lowercased keys, e.g. 'Action=Allow|Dir=In|LocalPort=2222' -> {"action":"Allow",...}.
    Tolerant of malformed or empty segments; never raises."""
    out = {}
    if not s:
        return out
    for seg in str(s).split("|"):
        if "=" not in seg:
            continue
        k, _, v = seg.partition("=")
        k = k.strip().lower()
        if k:
            out[k] = v.strip()
    return out


def _port_in_localport(port, localport):
    """True if `port` matches a rule's LocalPort value: exact, 'Any', a comma list, or an 'a-b' range."""
    if not localport:
        return False
    localport = localport.strip()
    if localport.lower() == "any":
        return True
    port = str(port)
    for part in localport.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                if int(lo) <= int(port) <= int(hi):
                    return True
            except ValueError:
                continue
        elif part == port:
            return True
    return False


def _rule_allows(parsed, exe_norm, port):
    """True only for an ENABLED, INBOUND, ALLOW rule that clearly matches our exe path
    or our TCP port. Conservative on purpose: only a clear match returns True."""
    if not parsed:
        return False
    if (parsed.get("active", "TRUE") or "TRUE").upper() == "FALSE":
        return False
    if (parsed.get("action") or "").strip().lower() != "allow":
        return False
    if (parsed.get("dir") or "").strip().lower() != "in":
        return False
    app = parsed.get("app")
    if app:
        try:
            if os.path.normcase(os.path.realpath(app)) == exe_norm:
                return True
        except Exception:
            pass
    protocol = (parsed.get("protocol") or "").strip()
    if protocol == "6" and _port_in_localport(port, parsed.get("localport")):
        return True
    return False


def _decide_firewall(any_profile_enabled, has_allow):
    """Three-state decision: 'allowed' / 'blocked' / 'unknown'."""
    if has_allow:
        return "allowed"
    if any_profile_enabled is False:
        return "allowed"
    if any_profile_enabled is True:
        return "blocked"
    return "unknown"


def _firewall_status(port):
    """Advisory-only, read-only registry check. Any failure (missing key, permission,
    unexpected value) is logged and returns 'unknown'; this must never raise and must
    never affect whether the server runs."""
    try:
        import winreg
        policy = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
        readable = False
        any_enabled = False
        for profile in ("StandardProfile", "PublicProfile", "DomainProfile"):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{policy}\\{profile}") as k:
                    val, _ = winreg.QueryValueEx(k, "EnableFirewall")
                readable = True
                if val == 1:
                    any_enabled = True
            except OSError:
                continue
        any_profile_enabled = any_enabled if readable else None

        exe_norm = os.path.normcase(os.path.realpath(
            sys.executable if getattr(sys, "frozen", False)
            else os.path.abspath(sys.modules["__main__"].__file__)))

        # Known limitation: we treat "any profile enabled" as a proxy for
        # whichever profile is actually active,
        # since reliably determining the in-use profile without admin rights or COM is
        # not practical here. We also only see Windows Defender Firewall, never
        # third-party firewalls or the router. That is why the UI says connections
        # "may be" blocked rather than stating it as certain.
        has_allow = False
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{policy}\\FirewallRules") as k:
                i = 0
                while True:
                    try:
                        _name, value, _vtype = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    parsed = _parse_firewall_rule(value)
                    if _rule_allows(parsed, exe_norm, port):
                        has_allow = True
                        break
        except OSError:
            pass

        return _decide_firewall(any_profile_enabled, has_allow)
    except Exception as e:
        debug.log("firewall check failed", str(e))
        return "unknown"
