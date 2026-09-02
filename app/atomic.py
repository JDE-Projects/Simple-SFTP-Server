import json
import os
import uuid


def atomic_write_json(path, data, **kwargs):
    """Write JSON to a temp file in the same folder, then swap it onto the real
    path with os.replace(), so a crash mid-write can never leave a half-written
    file behind. Cleans up the temp file on any failure."""
    tmp = path + f".tmp-{os.getpid()}-{uuid.uuid4().hex}"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, **kwargs)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass
