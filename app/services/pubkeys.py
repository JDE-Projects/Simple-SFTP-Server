import base64
import binascii
import os
import re

import paramiko

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


def _read_rfc4716_key(text):
    """Convert one RFC 4716 public-key block to an OpenSSH key line."""
    lines = text.splitlines()
    begin = "---- BEGIN SSH2 PUBLIC KEY ----"
    end = "---- END SSH2 PUBLIC KEY ----"
    begin_indexes = [index for index, line in enumerate(lines) if line.strip() == begin]
    if len(begin_indexes) > 1:
        return None, "This holds more than one key. This app uses one key per user."

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
            return None, "This holds more than one key. This app uses one key per user."

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


def read_one_key(text):
    """Read exactly one OpenSSH public-key line without exposing rejected text."""
    text = text if isinstance(text, str) else ""
    if any(re.fullmatch(r"-----BEGIN(?: [A-Za-z]+)* PRIVATE KEY-----", line.strip())
           for line in text.splitlines()) or text.lstrip().startswith("PuTTY-User-Key-File-"):
        return None, "That is a private key. Choose the .pub file next to it instead."
    if any(line.strip() == "---- BEGIN SSH2 PUBLIC KEY ----" for line in text.splitlines()):
        return _read_rfc4716_key(text)

    lines = [line.strip() for line in text.splitlines()
             if line.strip() and not line.strip().startswith("#")]
    if not lines:
        return None, "No public key found."
    if len(lines) > 1:
        return None, "This holds more than one key. This app uses one key per user."

    line = " ".join(lines[0].split())
    if not is_valid_key(line):
        return None, INVALID_KEY_MESSAGE
    return line, None


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


def read_key_file(path):
    """Read a small UTF-8 public-key file, keeping its contents out of errors."""
    try:
        if os.path.getsize(path) > 64 * 1024:
            return None, "That file is too large to be a public key."
        with open(path, "r", encoding="utf-8-sig") as f:
            text = f.read()
    except UnicodeDecodeError:
        return None, INVALID_KEY_MESSAGE
    except OSError as e:
        return None, friendly_error(e)
    return read_one_key(text)
