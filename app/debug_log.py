import json
import os
import re
import threading
from datetime import datetime

from app.paths import exe_dir


# ───────────── credential redaction ─────────────
# Nothing in this app is meant to log a password or private key. This scrubber
# is a backstop that runs on every write, so the README's promise ("no passwords
# or key material") holds even if a future log line, or a captured traceback,
# ever carries one. Public keys are not secrets and are left readable.
_REDACTED = "[redacted]"

# A private key block in PEM form, e.g. -----BEGIN OPENSSH PRIVATE KEY----- ...
_PEM_KEY = re.compile(
    r"-----BEGIN [^\n-]*PRIVATE KEY-----.*?-----END [^\n-]*PRIVATE KEY-----",
    re.DOTALL,
)
# A JSON-ish "field": "value" pair whose name looks like a secret. Matches the
# double-quoted form json.dumps produces and a plain form. The key name is kept
# so the log still shows a secret was present; only the value is blanked.
_SECRET_FIELD = re.compile(
    r'("?(?:password|passwd|passphrase|secret|token|api_?key|private_?key)"?'
    r'\s*[:=]\s*)(".*?"|\'.*?\'|[^\s,}]+)',
    re.IGNORECASE,
)


def _redact(text):
    if not text:
        return text
    text = _PEM_KEY.sub(_REDACTED, text)
    text = _SECRET_FIELD.sub(lambda m: m.group(1) + '"' + _REDACTED + '"', text)
    return text


# ───────────── debug log ─────────────
class DebugLog:
    def __init__(self):
        self._on = False
        self._path = None
        self._lock = threading.Lock()

    def set_enabled(self, on):
        with self._lock:
            on = bool(on)
            if on and not self._path:
                stamp = datetime.now().strftime("%m%d%Y_%H%M%S")
                self._path = os.path.join(exe_dir(), f"Debug_Log_{stamp}.txt")
                try:
                    with open(self._path, "w", encoding="utf-8") as f:
                        f.write("=== Simple SFTP Server debug log ===\n")
                        f.write(f"Started: {datetime.now().isoformat()}\n" + "=" * 60 + "\n\n")
                except Exception:
                    self._path = None
                    self._on = False
                    return False
            self._on = on
            return True

    def is_enabled(self):
        return self._on

    def log(self, label, content=""):
        if not self._on or not self._path:
            return
        try:
            with self._lock, open(self._path, "a", encoding="utf-8") as f:
                ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
                f.write(f"[{ts}] {_redact(str(label))}\n")
                if content:
                    if isinstance(content, (dict, list)):
                        content = json.dumps(content, indent=2, default=str)
                    f.write(f"{_redact(str(content))}\n")
                f.write("\n")
        except Exception:
            pass


debug = DebugLog()
