import os

from app import paths


# Last line of defense before a recursive folder delete (shutil.rmtree). This
# module never deletes anything itself, it only decides whether a delete is
# allowed to happen. It must fail closed: if anything about the path can't be
# resolved cleanly, it blocks rather than risking a mistake.


def _contains(parent, child):
    # True if child is strictly inside parent (already normcase, realpath'd).
    try:
        return parent != child and os.path.commonpath([parent, child]) == parent
    except ValueError:
        return False  # different drives, not related


def _protected_paths():
    profile = os.path.expanduser("~")
    candidates = [
        paths.exe_dir(),
        profile,
        os.path.dirname(profile),
    ]
    for name in ("Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos", "OneDrive"):
        candidates.append(os.path.join(profile, name))
    for var in ("WINDIR", "SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "PUBLIC"):
        val = os.environ.get(var)
        if val:
            candidates.append(val)
    system_drive = os.environ.get("SystemDrive", "")
    if system_drive:
        candidates.append(system_drive + os.sep)

    protected = set()
    for c in candidates:
        if not c:
            continue
        try:
            nc = os.path.normcase(os.path.realpath(c))
        except Exception:
            continue
        if nc:
            protected.add(nc)
    return protected


def blocked_reason(path):
    """Return a short human reason string if recursively deleting `path`
    must be refused, or None if deletion is allowed. Security gate: this
    is the last line before shutil.rmtree, so it must fail closed."""
    if not path or not str(path).strip():
        return "no folder was recorded"

    try:
        real = os.path.realpath(path)
    except Exception:
        return "the folder path could not be resolved"

    nc = os.path.normcase(real)

    # Drive or filesystem root.
    if os.path.dirname(real) == real or os.path.splitdrive(real)[1].strip("\\/") == "":
        return "a drive root"

    protected = _protected_paths()

    if nc in protected:
        return "a protected system, profile, or application folder"

    for p in protected:
        if _contains(nc, p):
            return "a folder that contains protected system or application files"

    return None
