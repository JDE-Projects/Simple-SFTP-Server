import re


# ───────────── usernames ─────────────
_RESERVED = {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}


def validate_username(u):
    u = (u or "").strip()
    if not u or len(u) > 32:
        return False, "Username must be 1 to 32 characters."
    if not re.fullmatch(r"[A-Za-z0-9._-]+", u):
        return False, "Use only letters, digits, dot, underscore or hyphen."
    if u.startswith(".") or u.endswith("."):
        return False, "Username cannot start or end with a dot."
    if u.lower() in _RESERVED:
        return False, "That name is reserved by Windows."
    return True, ""
