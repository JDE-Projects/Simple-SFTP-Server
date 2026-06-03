# Simple SFTP Server

A clean, personal SFTP server for Windows: pick a folder, add a user (or hit
Quick Start), and hand someone a ready-to-paste connection card. Each user is
locked to their own folder, sign-in is by password or key, and you watch
connections and transfers live. Secure connections only.

Built by [JDE-Projects](https://github.com/JDE-Projects).

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
Grab the latest `Simple SFTP Server.exe` from the Releases page and
double-click it. No Python or setup required. Windows only.
Unsigned, so SmartScreen may warn the first time: More info > Run anyway.
On first connection a client also needs your firewall to allow the port, and
for access from outside your network, a port-forward to this machine.

## Build from source (optional)
- Python 3 on PATH.
- `pip install pywebview PySide6 paramiko` (bcrypt and cryptography come with
  paramiko).
- Keep `simple_sftp_server.py`, `simple_sftp_server-UI.html`, the `fonts/`
  folder, the `.ico`, `.png`, and `-splash.png` together.
- Run from source: `python simple_sftp_server.py`
- Build the .exe: `Build_Simple_SFTP_Server.bat` -> `dist\Simple SFTP Server.exe`

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

## Updates
Use Check for Updates to compare your version against the latest GitHub
Release. If a newer version exists, the app shows a banner linking to the
Releases page to download it. The check is silent if you're offline.

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
