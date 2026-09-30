"""ui_drive fixture for Simple SFTP Server's debug-log scenario.

Writes five dated debug logs and two similarly named files into the throwaway
app copy before the app launches. It holds the oldest valid log open without
delete sharing, so launch-time pruning warns when Windows refuses to delete it.

After the app creates its live debug log, this fixture holds that file open
without sharing. A later debug write then fails through the app's normal
logging path. Both held handles close when ui_drive ends this script.

All files are inside the run folder ui_drive deletes afterwards. Nothing is
written anywhere else.
"""

import ctypes
import json
import os
import time


app_dir = os.environ["UI_DRIVE_APP_DIR"]
out_dir = os.environ["UI_DRIVE_OUT_DIR"]

planted_names = [
    f"Debug_Log_010{day}2026_010000.txt"
    for day in range(1, 6)
]
locked_name = planted_names[0]
jan2_name = planted_names[1]

for name in planted_names:
    with open(os.path.join(app_dir, name), "x", encoding="utf-8") as f:
        f.write("fixture log\n")

for name in ("Debug_Log_notes.txt", "notes.txt"):
    with open(os.path.join(app_dir, name), "x", encoding="utf-8") as f:
        f.write("leave alone\n")

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.CreateFileW.argtypes = [
    ctypes.c_wchar_p,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_void_p,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_void_p,
]
kernel32.CreateFileW.restype = ctypes.c_void_p

GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def lock_without_sharing(path):
    handle = kernel32.CreateFileW(
        path,
        GENERIC_READ,
        0,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        error = ctypes.get_last_error()
        raise OSError(error, f"CreateFileW failed for {path}")
    return handle


locked_handles = [lock_without_sharing(os.path.join(app_dir, locked_name))]
print(json.dumps({"locked_file": locked_name}), flush=True)

reported_prune = False
live_log_name = None
first_seen = None
deadline = time.monotonic() + 90
prune_deadline = time.monotonic() + 30

while time.monotonic() < deadline:
    jan2_deleted = not os.path.exists(os.path.join(app_dir, jan2_name))
    if not reported_prune and (jan2_deleted or time.monotonic() >= prune_deadline):
        names = sorted(
            name for name in os.listdir(app_dir)
            if name.startswith("Debug_Log_") or name == "notes.txt"
        )
        with open(os.path.join(out_dir, "prune_report.json"), "x", encoding="utf-8") as f:
            json.dump({"files": names, "jan2_deleted": jan2_deleted}, f)
        reported_prune = True

    if live_log_name is None:
        for name in os.listdir(app_dir):
            if (
                name.startswith("Debug_Log_")
                and name.endswith(".txt")
                and name not in planted_names
                and name != "Debug_Log_notes.txt"
            ):
                path = os.path.join(app_dir, name)
                # Wait a second after the file appears, so the app's own
                # "Debug enabled" line lands before the lock and only the
                # scenario's second switch-on hits the failing write.
                first_seen = first_seen or time.monotonic()
                if time.monotonic() - first_seen >= 1 and os.path.getsize(path) > 0:
                    locked_handles.append(lock_without_sharing(path))
                    live_log_name = name
                    with open(os.path.join(out_dir, "lock_report.json"), "a", encoding="utf-8") as f:
                        f.write(json.dumps({"locked_file": live_log_name}) + "\n")
                    break

    time.sleep(0.1)
