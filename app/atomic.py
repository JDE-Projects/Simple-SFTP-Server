import json
import os
import uuid

from app.debug_log import debug, describe_error


class ConfigWriteConflict(Exception):
    """The file changed after its contents were loaded for an update."""


FILE_MISSING = object()
_EXPECTED_BYTES_UNSET = object()


def _current_bytes(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return FILE_MISSING


def atomic_write_json(path, data, *, expected_bytes=_EXPECTED_BYTES_UNSET, **kwargs):
    """Write JSON to a temp file in the same folder, force it onto the disk,
    then swap it onto the real path with os.replace(), so a crash or power loss
    mid-write can never leave a half-written or empty file behind. The temp
    file is removed on any failure, and the original error is raised."""
    tmp = path + f".tmp-{os.getpid()}-{uuid.uuid4().hex}"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, **kwargs)
            f.flush()
            os.fsync(f.fileno())
        if expected_bytes is not _EXPECTED_BYTES_UNSET:
            try:
                if _current_bytes(path) != expected_bytes:
                    raise ConfigWriteConflict()
            except ConfigWriteConflict:
                raise
            except OSError as e:
                raise ConfigWriteConflict() from e
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError as e:
                debug._log("temp file not removed", describe_error(e))
