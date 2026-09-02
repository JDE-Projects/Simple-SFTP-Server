import secrets

import bcrypt


# ───────────── passwords ─────────────
_SAFE_LOWER = "abcdefghijkmnpqrstuvwxyz"
_SAFE_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_SAFE_DIGIT = "23456789"
_SYMBOLS = "!@#$%^&*()"


def generate_password(length=20):
    length = max(16, int(length))
    pools = [_SAFE_LOWER, _SAFE_UPPER, _SAFE_DIGIT, _SYMBOLS]
    allchars = "".join(pools)
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(allchars) for _ in range(length - len(pools))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def hash_password(plain):
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(plain, hashed):
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("ascii"))
    except Exception:
        return False


# A precomputed bcrypt hash of a throwaway string, used only to burn roughly
# the same amount of time as a real password check when the username doesn't
# exist (or has no password set), so login failures don't leak which
# usernames are valid through response timing.
_DUMMY_PASSWORD_HASH = hash_password("simple-sftp-server-dummy-check")
