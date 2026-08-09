#!/usr/bin/env python3
"""Regenerate screenshots/sftp-light-dark.png from the real browser UI.

The desktop app has no browser backend. This script stages only the UI assets in
a temporary folder, seeds wholly fake data through the UI's normal rendering
functions, captures both themes, and removes the temporary files afterwards.

    python tools/screenshot/make_screenshot.py
    python tools/screenshot/make_screenshot.py --build-tools ..\build-tools
    python tools/screenshot/make_screenshot.py --keep
"""

import http.server
import json
import os
import re
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import scene  # noqa: E402

OUT_IMAGE = os.path.join(REPO_ROOT, "screenshots", "sftp-light-dark.png")
LAYOUT_WIDTH = 1800
LAYOUT_HEIGHT = 1160
CAPTURE_SCALE = 0.5


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_app_version():
    path = os.path.join(REPO_ROOT, "simple_sftp_server.py")
    with open(path, encoding="utf-8") as file:
        match = re.search(r'APP_VERSION\s*=\s*"([^"]+)"', file.read())
    if not match:
        fail(f"could not find APP_VERSION in {path}")
    return match.group(1)


def stage_ui(temp_dir):
    shutil.copy2(os.path.join(REPO_ROOT, "simple_sftp_server-UI.html"),
                 os.path.join(temp_dir, "index.html"))
    shutil.copy2(os.path.join(REPO_ROOT, "simple_sftp_server.png"), temp_dir)
    shutil.copytree(os.path.join(REPO_ROOT, "fonts"), os.path.join(temp_dir, "fonts"))


def build_setup_script(version):
    """Seed the UI's own data structures and call its native render seam."""
    meta = {"version": version, "key_types": ["Ed25519", "RSA-4096"],
            "default_port": 2222, "settings": {"port": 2222}, "users": scene.USERS}
    return (
        f"meta={json.dumps(meta)};users=meta.users;"
        f"document.getElementById('verLabel').textContent='v'+{json.dumps(version)};"
        "document.getElementById('port').value=meta.settings.port;"
        "const kg=document.getElementById('kgType');"
        "meta.key_types.forEach(t=>{const o=document.createElement('option');o.value=t;o.textContent=t;kg.appendChild(o);});"
        "if(typeof renderUsers==='function')renderUsers();"
        f"if(typeof applyStatus==='function')applyStatus({json.dumps(scene.STATUS)});"
        "if(typeof onActivity==='function'){"
        "onActivity({verb:'UPLOAD',name:'nightly-archive.zip',human:'842 MB'});"
        "onActivity({verb:'DOWNLOAD',name:'vendor-manifest.csv',human:'64 KB'});"
        "}"
    )


def write_capture_config(temp_dir, port, version):
    config = {
        "url": f"http://127.0.0.1:{port}/index.html", "width": LAYOUT_WIDTH,
        "height": LAYOUT_HEIGHT, "scale": CAPTURE_SCALE,
        "outDir": os.path.join(temp_dir, "shots"),
        "waitFor": "typeof applyStatus === 'function' && typeof renderUsers === 'function'",
        "setup": build_setup_script(version), "settleMs": 500,
        "shots": [{"name": "light", "script": "applyTheme('light')"},
                  {"name": "dark", "script": "applyTheme('dark')"}],
    }
    path = os.path.join(temp_dir, "shots.json")
    with open(path, "w", encoding="utf-8") as file:
        json.dump(config, file, indent=2)
    return path


def run(command, label):
    if subprocess.run(command, cwd=REPO_ROOT).returncode:
        fail(f"{label} failed")


def main(argv):
    keep = "--keep" in argv
    build_tools = os.path.join(os.path.dirname(REPO_ROOT), "build-tools")
    if "--build-tools" in argv:
        index = argv.index("--build-tools") + 1
        if index == len(argv):
            fail("--build-tools needs a path")
        build_tools = argv[index]
    capture = os.path.join(build_tools, "screenshot", "capture.mjs")
    compose = os.path.join(build_tools, "screenshot", "compose.py")
    if not os.path.isfile(capture) or not os.path.isfile(compose):
        fail("missing Build-Tools screenshot engine; pass --build-tools PATH")

    temp_dir = tempfile.mkdtemp(prefix="sftp-server-screenshot-")
    httpd = None
    try:
        stage_ui(temp_dir)

        class Handler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=temp_dir, **kwargs)

        httpd = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        config = write_capture_config(temp_dir, port, read_app_version())
        run(["node", capture, config], "capture")
        run([sys.executable, compose, OUT_IMAGE,
             os.path.join(temp_dir, "shots", "light.png"),
             os.path.join(temp_dir, "shots", "dark.png")], "compose")
    finally:
        if httpd:
            httpd.shutdown()
        if keep:
            print(f"temp folder kept at {temp_dir}")
        else:
            shutil.rmtree(temp_dir, ignore_errors=True)
            if os.path.exists(temp_dir):
                print(f"WARNING: could not remove {temp_dir}", file=sys.stderr)

    print(f"updated {OUT_IMAGE} from APP_VERSION v{read_app_version()}")


if __name__ == "__main__":
    main(sys.argv[1:])
