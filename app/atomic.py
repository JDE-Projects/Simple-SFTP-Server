import json
import os
import uuid

from app.debug_log import debug, describe_error


def atomic_write_json(path, data, **kwargs):
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
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError as e:
                debug._log("temp file not removed", describe_error(e))
