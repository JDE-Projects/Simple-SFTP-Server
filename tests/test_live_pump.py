"""Task 1 regression: the live-view update path must not scale with file count.

Starts the real SFTPService on an ephemeral loopback port, connects a real
Paramiko client, transfers a large synthetic set of small files, and asserts the
number of UI pushes stays bounded by elapsed time (the coalescing pump rate),
not by the number of files moved. Before the fix each file fired 2-4 synchronous
cross-layer pushes, which took a production server down.
"""

import io
import math
import os
import time

from app import server as server_mod
from app.server import SFTPService
from tests.sftp_helpers import CountingApi, free_port, make_host_key, make_user, sftp_password


def test_ui_pushes_stay_bounded_over_many_files(tmp_path):
    files = 400
    home = tmp_path / "home"
    home.mkdir()
    password = "correct horse battery staple"
    permissions = {k: True for k in server_mod.QUICK_PERMISSIONS}
    user = make_user("bob", home, permissions, password=password)

    api = CountingApi(user)
    service = SFTPService(api)
    service.host_key = make_host_key(tmp_path)
    port = free_port()

    r = service.start(port)
    assert r["ok"], r
    try:
        start = time.time()
        client, sftp = sftp_password(port, "bob", password)
        blob = b"x" * 64
        for i in range(files):
            sftp.putfo(io.BytesIO(blob), f"/f{i:05d}.bin")
        sftp.close()
        client.close()
        # Let the pump run one last window so any final push lands, then stop.
        time.sleep(server_mod.PUMP_INTERVAL * 2)
        duration = time.time() - start
    finally:
        service.stop()

    # Every file really was written.
    assert len(os.listdir(str(home))) == files

    total = api.total()
    # The pump pushes at most three events per tick (status, activity, transfer)
    # while something is dirty. Bound the pushes by the wall-clock window, not by
    # the number of files, with generous slack for connect/disconnect and jitter.
    ticks = math.ceil(duration / server_mod.PUMP_INTERVAL) + 2
    bound = ticks * 3 + 8
    assert total <= bound, f"{total} pushes for {files} files over {duration:.2f}s (bound {bound})"
    # And the headline property: pushes are far below one-per-file.
    assert total < files, f"{total} pushes still scales with {files} files"
