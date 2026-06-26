# Simple SFTP Server

A clean, personal SFTP server for Windows: pick a folder, add a user (or hit
Quick Start), and hand someone a ready-to-paste connection card. Each user is
locked to their own folder, sign-in is by password or key, and you watch
connections and transfers live. Secure connections only.

Built by [JDE-Projects](https://github.com/JDE-Projects).

If you enjoyed this project and would like to buy me a coffee, check out my [Ko-fi](https://ko-fi.com/jdeprojects).

## Highlights
- Quick Start: one click brings a full-access share live with a fresh random
  password, shown in an on-screen connection card you can copy and send.
- Users with a per-user folder (a real folder picker, or "Make folder"), and a
  jail so each user only ever sees inside their own folder.
- Three access modes per user: read-only, read & write, or upload-only
  (a drop box). Deleting and renaming is off unless you allow it.
- Sign-in by password, public key, or both, with a built-in generator for
  Ed25519 (default) or RSA-4096 key pairs to hand to a user who has none.
- Connection card: LAN address, on-demand public IP, port, and the host-key
  fingerprint, all copyable for first-connection verification.
- Live panel: connected clients, in-flight transfers, a recent-activity feed,
  and locked-out IP addresses with one-click Unlock and Unlock all.
- Brute-force lockout: five failed logins from an address are blocked for
  fifteen minutes, with a manual override.
- Default port 2222 (no admin needed), with a plain-language message if a port
  is already in use, plus a pre-flight port check.
- Built-in check for updates against GitHub Releases.
- Optional debug log, off by default, with credentials redacted.
- Secure transport only: weak or vulnerable algorithms are disabled, so the
  server runs securely or fails with a clear message (no unsafe fallback).

## How it works
- Backend: paramiko over SSH/SFTP, one jailed session per connection.
- Config: `server_config.json` next to the app (usernames, folders, settings,
  and one-way bcrypt password hashes; never a plaintext password).
- Host identity: an Ed25519 host key generated on first run and kept next to
  the app, so its fingerprint stays stable for clients to trust.
- Window: pywebview on the Qt backend, UI in `simple_sftp_server-UI.html`.

## Download and run
Two ways to get it from the [Releases](../../releases) page - pick one:

- **Installer (recommended):** download `SimpleSFTPServer-vX.Y.Z-setup.exe` and
  run it. It installs the app, adds a Start menu shortcut, and can be removed
  later from Add or Remove Programs. Installs just for you by default (no admin
  needed); you can choose all users during setup.
- **Portable .zip:** download `SimpleSFTPServer-vX.Y.Z.zip`, extract it, and run
  `Simple SFTP Server.exe` from inside the extracted folder. No install - good
  for a locked-down PC or a USB stick. Keep the folder together; the exe needs
  the files next to it.

Either way: Windows only, no Python or setup required. Unsigned, so SmartScreen
may warn the first time: More info > Run anyway. On first connection a client
also needs your firewall to allow the port, and for access from outside your
network, a port-forward to this machine.

## Verify this download (optional)
This release was built on GitHub from this public source - not on a personal
machine - and is signed with a build-provenance attestation. To confirm a
download is genuine, install the [GitHub CLI](https://cli.github.com) and run:

```
gh attestation verify SimpleSFTPServer-vX.Y.Z.zip \
  --repo JDE-Projects/Simple-SFTP-Server \
  --signer-repo JDE-Projects/Build-Tools
```

A `Verification succeeded!` line means the file was built by the published
pipeline from this repo. You can also check the file against the published
`.sha256`.

## Build from source (optional)
- Python 3 on PATH.
- `pip install -r requirements.txt` (pinned versions: PySide6, pywebview,
  paramiko, cryptography, bcrypt, and PyInstaller)
- Keep `simple_sftp_server.py`, `simple_sftp_server-UI.html`, the `fonts/`
  folder, the `.ico`, `.png`, and `-splash.png` together.
- Run from source: `python simple_sftp_server.py`
- Build the .exe: `Build_Simple_SFTP_Server.bat` -> `dist\Simple SFTP Server\Simple SFTP Server.exe`

## Using it
1. Quick Start for an instant share: click it, reveal the password, and send
   the connection card. The share folder is `QuickStart-Share` next to the app,
   with full access (read, write, delete, rename).
2. For anything narrower, add a user instead: set a username, a folder, an
   access mode, and a password or public key. That user is locked to that
   folder.
3. Press Start (or Quick Start) and give the other person the address, port,
   and their sign-in details from the connection card. Have them verify the
   host-key fingerprint on first connection.
4. Watch the Live panel for who is connected and what is transferring. Unlock
   an address if it gets locked out after failed logins.
5. Generate an Ed25519 or RSA key pair for a user who needs one, hand them the
   private key, and the public key is added to their account automatically.

## Security and privacy
- Saved-user passwords are stored only as a one-way bcrypt hash and are never
  shown again after you save them. Public-key users store only their public
  key text. No plaintext password is ever written to disk.
- The Quick Start password lives in memory only, is revealable as often as you
  like while it runs, and is wiped when you stop it; every launch makes a new
  one.
- Generated passwords use a cryptographic random source: 20 characters, no
  look-alikes, with letters, digits, and symbols guaranteed.
- Each user is jailed to their folder; paths that try to escape it are refused.
- Failed logins are rate-limited per address (five strikes, fifteen-minute
  lockout) with a manual unlock.
- Only modern, secure key-exchange, ciphers, and MACs are offered; known-weak
  algorithms are disabled. There is no "compatibility" downgrade.
- The host key persists next to the app so its fingerprint is stable; treat
  that file as private and do not commit it.
- The optional debug log is off by default; when on it writes
  `Debug_Log_MMDDYYYY_HHMMSS.txt` next to the app with credentials redacted.

## Updating
The "Check for updates" button in the bottom-right corner compares your
version to the latest GitHub Release and shows the result inline in the
bottom bar. If a newer version exists, a persistent link appears so you
can view the release. Otherwise a brief "No update" message shows and
fades on its own. The check is silent when you are offline.

To update: download the latest release from the
[Releases](../../releases) page and replace the existing exe, or re-run
the installer.

## A note on how this was built
This project was built with AI assistance. The design decisions, feature
direction, and real-world testing were directed by me. The code was written
and revised with an AI assistant against that direction.

## License
Released under the PolyForm Noncommercial License 1.0.0 (see
[LICENSE](LICENSE)). Personal and any noncommercial use, modification, and
noncommercial redistribution are permitted; commercial use is not. Keep the
copyright notice; no warranty. This tool bundles third-party code; see
[THIRD-PARTY-LICENSES.txt](THIRD-PARTY-LICENSES.txt).

For commercial licensing, open a [GitHub issue](https://github.com/JDE-Projects/Simple-SFTP-Server/issues) with the title "Commercial License Inquiry".
