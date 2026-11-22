import base64
import binascii
import os
import re
import unicodedata

import paramiko

from app.constants import MIN_RSA_KEY_BITS
from app.helpers import fingerprint_sha256, friendly_error

INVALID_KEY_MESSAGE = (
    "That is not a valid public key. Use the full contents of a .pub file "
    "(for example ssh-ed25519 AAAA... name@computer)."
)


def is_valid_key(line):
    """Return whether line is a complete, valid OpenSSH authorized key."""
    parts = line.split()
    if len(parts) < 2:
        return False
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        key = paramiko.PKey.from_type_string(parts[0], blob)
        return key.get_base64() == parts[1]
    except Exception:  # noqa: BLE001 - paramiko raises several key-format exceptions
        return False


def weak_key_bits(key):
    """Return the bit length when an RSA key is below the minimum."""
    if isinstance(key, paramiko.RSAKey) and key.get_bits() < MIN_RSA_KEY_BITS:
        return key.get_bits()
    return None


def weak_line_bits(line):
    """Return the bit length when a key line holds an RSA key below the minimum.

    Anything that is not a valid key line returns None: validity is
    is_valid_key's job, and a hand-edited config must not break a save."""
    if not isinstance(line, str) or not is_valid_key(line):
        return None
    try:
        return weak_key_bits(_load_key(line))
    except Exception:  # noqa: BLE001 - malformed saved keys are handled elsewhere
        return None


def key_strength_problem(line):
    """Return a user-facing message when a public key is too weak."""
    bits = weak_line_bits(line)
    if bits is None:
        return None
    return (f"This is a {bits}-bit RSA key, which is too weak. Use an RSA key of "
            f"{MIN_RSA_KEY_BITS} bits or more, or an Ed25519 key.")


def _read_rfc4716_key(text):
    """Convert one RFC 4716 public-key block to an OpenSSH key line."""
    lines = text.splitlines()
    begin = "---- BEGIN SSH2 PUBLIC KEY ----"
    end = "---- END SSH2 PUBLIC KEY ----"
    begin_indexes = [index for index, line in enumerate(lines) if line.strip() == begin]
    if len(begin_indexes) > 1:
        return None, "This SSH2 key block cannot be combined with other keys."

    begin_index = begin_indexes[0]
    end_index = next(
        (index for index in range(begin_index + 1, len(lines)) if lines[index].strip() == end),
        None,
    )
    if end_index is None:
        return None, INVALID_KEY_MESSAGE

    for line in lines[:begin_index] + lines[end_index + 1:]:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return None, "This SSH2 key block cannot be combined with other keys."

    headers = {}
    body = []
    continued_header = None
    for line in lines[begin_index + 1:end_index]:
        if continued_header is not None:
            value = line
            if value.endswith("\\"):
                headers[continued_header] += " " + value[:-1]
            else:
                headers[continued_header] += " " + value
                continued_header = None
            continue

        match = re.match(r"^([^:\s][^:]*):\s*(.*)$", line)
        if match:
            name, value = match.groups()
            name = name.lower()
            if value.endswith("\\"):
                headers[name] = value[:-1]
                continued_header = name
            else:
                headers[name] = value
        else:
            body.append(line)

    try:
        blob = base64.b64decode("".join("".join(body).split()).encode("ascii"), validate=True)
        if len(blob) < 4:
            raise ValueError
        key_type_length = int.from_bytes(blob[:4], "big")
        key_type = blob[4:4 + key_type_length].decode("ascii")
        if not key_type or len(blob) < 4 + key_type_length:
            raise ValueError
    except (binascii.Error, UnicodeEncodeError, UnicodeDecodeError, ValueError):
        return None, INVALID_KEY_MESSAGE

    comment = headers.get("comment", "").strip()
    if len(comment) >= 2 and comment.startswith('"') and comment.endswith('"'):
        comment = comment[1:-1]
    comment = " ".join(comment.split())
    line = f"{key_type} {base64.b64encode(blob).decode('ascii')}"
    if comment:
        line += f" {comment}"
    if not is_valid_key(line):
        return None, INVALID_KEY_MESSAGE
    return line, None


def read_keys(text):
    """Read valid OpenSSH public-key lines from text in their input order."""
    text = text if isinstance(text, str) else ""
    private_key_message = "That is a private key. Choose the .pub file next to it instead."
    if any(re.fullmatch(r"-----BEGIN(?: [A-Za-z]+)* PRIVATE KEY-----", line.strip())
           or line.strip().startswith("PuTTY-User-Key-File-")
           for line in text.splitlines()):
        return None, private_key_message

    ssh2_begin = "---- BEGIN SSH2 PUBLIC KEY ----"
    ssh2_indexes = [index for index, line in enumerate(text.splitlines())
                    if line.strip() == ssh2_begin]
    if ssh2_indexes:
        ssh2_message = "Text with a PuTTYgen (SSH2) key can hold only that one key. Add other keys separately."
        if len(ssh2_indexes) > 1:
            return None, ssh2_message
        line, error = _read_rfc4716_key(text)
        if error == INVALID_KEY_MESSAGE:
            return None, error
        if error is not None:
            return None, ssh2_message
        return [line], None

    keys = []
    for number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        line = " ".join(stripped.split())
        if not is_valid_key(line):
            return None, f"Line {number} is not a valid public key. Use the full contents of a .pub file (for example ssh-ed25519 AAAA... name@computer)."
        keys.append(line)
    if not keys:
        return None, "No public key found."
    return keys, None


def key_identity(line):
    """Return a key line's type and encoded key data, excluding its comment."""
    if not isinstance(line, str):
        return None
    parts = line.split()
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def _key_name(line):
    """Return the comment portion of an OpenSSH key line."""
    if not isinstance(line, str):
        return ""
    parts = line.split(maxsplit=2)
    return parts[2] if len(parts) == 3 else ""


def clean_key_name(line):
    """Remove unsafe characters and normalize the name in a key line."""
    match = re.match(r"^(\S+\s+\S+)(?:\s+(.*))?$", line)
    if not match:
        return line, None
    prefix, name = match.groups()
    name = name or ""
    without_controls = "".join(
        char for char in name if unicodedata.category(char) not in {"Cc", "Cf"})
    cleaned = " ".join(without_controls.split())
    hidden_removed = without_controls != name
    shortened = len(cleaned) > 100
    if shortened:
        cleaned = cleaned[:100].rstrip()
    if not hidden_removed and not shortened and cleaned == name:
        return line, None
    note_parts = []
    if hidden_removed:
        note_parts.append("Hidden characters were removed from the name.")
    if shortened:
        note_parts.append("The name was shortened to 100 characters.")
    return prefix + (f" {cleaned}" if cleaned else ""), " ".join(note_parts) or "The name was cleaned."


def key_name_problem(line):
    """Return a safe error when a key name cannot be stored."""
    name = _key_name(line)
    if any(unicodedata.category(char) in {"Cc", "Cf"} for char in name):
        return "The key name contains hidden characters."
    if len(" ".join(name.split())) > 100:
        return "The key name can be at most 100 characters."
    return None


def _load_key(line):
    key_type, encoded, *_ = line.split()
    return paramiko.PKey.from_type_string(key_type, base64.b64decode(encoded, validate=True))


def describe_key(line):
    """Return the display details for a validated OpenSSH public-key line."""
    if not isinstance(line, str):
        return None
    parts = line.split()
    if len(parts) < 2:
        return None
    key_type = parts[0]
    if key_type.startswith("ecdsa-sha2-"):
        display_type = "ecdsa"
    elif key_type.startswith("ssh-"):
        display_type = key_type.removeprefix("ssh-")
    else:
        display_type = key_type
    try:
        fingerprint = fingerprint_sha256(_load_key(line))
    except Exception:  # noqa: BLE001 - a hand-edited config must not break the user list
        fingerprint = ""
    return {
        "type": display_type,
        "comment": " ".join(parts[2:]),
        "fingerprint": fingerprint,
    }


def read_keys_file(path):
    """Read a small UTF-8 file containing one or more public keys."""
    try:
        if os.path.getsize(path) > 64 * 1024:
            return None, "That file is too large to be a public key."
        with open(path, "r", encoding="utf-8-sig") as f:
            text = f.read()
    except UnicodeDecodeError:
        return None, INVALID_KEY_MESSAGE
    except OSError as e:
        return None, friendly_error(e)
    return read_keys(text)
