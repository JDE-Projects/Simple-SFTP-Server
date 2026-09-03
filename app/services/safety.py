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


def _norm(path):
    # Resolve to a real, case-folded path for comparison, or None if it cannot
    # be resolved or is blank. Symlinks and junctions are followed so a link
    # cannot disguise its true target.
    if not path:
        return None
    try:
        nc = os.path.normcase(os.path.realpath(path))
    except Exception:
        return None
    return nc or None


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
        candidates.append(os.environ.get(var))
    system_drive = os.environ.get("SystemDrive", "")
    if system_drive:
        candidates.append(system_drive + os.sep)

    protected = set()
    for c in candidates:
        nc = _norm(c)
        if nc:
            protected.add(nc)
    return protected


def _system_trees():
    # Folders whose entire subtree is off limits at any depth, not just the
    # folder itself. These are the operating system and the all-users software
    # install locations, where nothing inside is ever a legitimate user share,
    # so no descendant may be recursively deleted. The app's own folder is
    # exempted separately in blocked_reason so app-created shares still work
    # even when the app lives under Program Files. Note: the user profile and
    # its AppData and Public folders are deliberately NOT here. Those are the
    # user's own data, deletable behind the stronger UI warning; only their
    # top-level roots are protected, through _protected_paths.
    candidates = []
    for var in ("WINDIR", "SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
        candidates.append(os.environ.get(var))

    trees = set()
    for c in candidates:
        nc = _norm(c)
        if nc:
            trees.add(nc)
    return trees


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

    # Strip Windows extended-length prefixes so an extended path is judged the
    # same as its plain form (\\?\C:\Windows becomes c:\windows). Otherwise the
    # prefix would hide a system path from every comparison below.
    if nc.startswith("\\\\?\\unc\\"):
        nc = "\\\\" + nc[len("\\\\?\\unc\\"):]
    elif nc.startswith("\\\\?\\"):
        nc = nc[len("\\\\?\\"):]

    # Network (UNC) paths reach namespaces the app cannot reason about safely
    # (admin shares like \\host\C$ map straight onto a system drive). The app
    # only ever creates and deletes local folders, so refuse any UNC target
    # outright rather than risk a hidden system path.
    drive = os.path.splitdrive(nc)[0]
    if drive.startswith("\\\\") or nc.startswith("\\\\"):
        return "a network path, which the app does not delete"

    # Drive or filesystem root.
    if os.path.dirname(nc) == nc or os.path.splitdrive(nc)[1].strip("\\/") == "":
        return "a drive root"

    protected = _protected_paths()

    if nc in protected:
        return "a protected system, profile, or application folder"

    for p in protected:
        if _contains(nc, p):
            return "a folder that contains protected system or application files"

    # Refuse anything inside a system or other-application tree, at any depth.
    # The app's own folder is the one exception: shares the app created live
    # under it, and they stay deletable even if the app was installed under a
    # protected tree like Program Files. That exception is denied if the app
    # folder somehow resolves to a tree root itself, so it can never open a
    # whole system tree.
    trees = _system_trees()
    exe_nc = _norm(paths.exe_dir())
    inside_app = (exe_nc is not None and exe_nc not in trees
                  and (nc == exe_nc or _contains(exe_nc, nc)))
    if not inside_app:
        for t in trees:
            if nc == t or _contains(t, nc):
                return "inside a protected system or application folder"

    return None
