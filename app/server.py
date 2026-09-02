import os
import socket
import threading
import time
import traceback

import paramiko

from app.constants import DEFAULT_PORT, DISABLED_ALGORITHMS, LOCKOUT_SECONDS, LOCKOUT_THRESHOLD
from app.debug_log import debug
from app.helpers import friendly_error, human_size
from app.services.hostkey import load_or_create_host_key
from app.services.passwords import _DUMMY_PASSWORD_HASH, verify_password


# How often the live view is refreshed. All per-file state is recorded in memory
# by the transfer threads and pushed to the window from one timer at this rate,
# so UI push volume stays bounded no matter how many files a client moves.
PUMP_INTERVAL = 0.25   # seconds between coalesced UI pushes (about 4 per second)
ACTIVITY_MAX = 40      # the window keeps only the last 40 activity lines
SHUTDOWN_TIMEOUT = 5.0 # seconds Stop will wait for all threads to finish


# ───────────── lockout ─────────────
class Lockout:
    def __init__(self):
        self._lock = threading.Lock()
        self._fails = {}
        self._until = {}

    def is_locked(self, ip):
        with self._lock:
            u = self._until.get(ip)
            if u and time.time() < u:
                return True
            if u:
                self._until.pop(ip, None)
                self._fails.pop(ip, None)
            return False

    def record_fail(self, ip):
        with self._lock:
            n = self._fails.get(ip, 0) + 1
            self._fails[ip] = n
            if n >= LOCKOUT_THRESHOLD:
                self._until[ip] = time.time() + LOCKOUT_SECONDS

    def clear(self, ip):
        with self._lock:
            self._fails.pop(ip, None)
            self._until.pop(ip, None)

    def clear_all(self):
        with self._lock:
            self._fails.clear()
            self._until.clear()

    def locked_list(self):
        out = []
        now = time.time()
        with self._lock:
            for ip, u in list(self._until.items()):
                if u > now:
                    out.append({"ip": ip, "remaining": int(u - now)})
        return out


# ───────────── default permissions ─────────────
DEFAULT_PERMISSIONS = {
    "list": True,
    "download": False,
    "upload": False,
    "delete": False,
    "rename_file": False,
    "rename_dir": False,
    "mkdir": False,
    "delete_dir": False,
}

QUICK_PERMISSIONS = {
    "list": True,
    "download": True,
    "upload": True,
    "delete": True,
    "rename_file": True,
    "rename_dir": True,
    "mkdir": True,
    "delete_dir": True,
}


def perms_for(user):
    """Return the permission dict for a user record."""
    p = user.get("permissions")
    if isinstance(p, dict):
        # fill any missing keys with False
        return {k: bool(p.get(k, False)) for k in DEFAULT_PERMISSIONS}
    # fallback for any legacy record (should not occur in fresh installs)
    return dict(DEFAULT_PERMISSIONS)


# ───────────── jailed SFTP filesystem ─────────────
class JailedHandle(paramiko.SFTPHandle):
    def __init__(self, flags, iface, name, direction, total):
        super().__init__(flags)
        self._iface = iface
        self._name = name
        self._dir = direction
        self._total = total
        self._bytes = 0
        self._last_emit = 0.0
        self.readfile = None
        self.writefile = None

    def stat(self):
        try:
            f = self.readfile or self.writefile
            return paramiko.SFTPAttributes.from_stat(os.fstat(f.fileno()))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def chattr(self, attr):
        return paramiko.SFTP_OK

    def write(self, offset, data):
        if self.writefile is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            self.writefile.seek(offset)
            self.writefile.write(data)
        except (OSError, IOError) as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        self._bytes += len(data)
        self._iface._progress(self)
        return paramiko.SFTP_OK

    def read(self, offset, length):
        if self.readfile is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            self.readfile.seek(offset)
            data = self.readfile.read(length)
        except (OSError, IOError) as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        self._bytes += len(data)
        self._iface._progress(self)
        return data

    def close(self):
        try:
            super().close()
        finally:
            self._iface._finish(self)


class JailedSFTP(paramiko.SFTPServerInterface):
    def __init__(self, server, *largs, **kwargs):
        super().__init__(server, *largs, **kwargs)
        self.service = getattr(server, "service", None)
        self.user = getattr(server, "user", None)
        self.ip = getattr(server, "ip", "")
        self.sid = getattr(server, "sid", "")
        home = (self.user or {}).get("home", "")
        if home:
            try:
                self.root = os.path.realpath(home)
            except Exception:
                self.root = home
        else:
            # No home configured: fail closed rather than letting
            # os.path.realpath("") resolve to the current working directory.
            self.root = None
        self.perm = perms_for(self.user) if self.user else dict(DEFAULT_PERMISSIONS)

    def _progress(self, handle):
        if self.service:
            self.service._progress(handle)

    def _finish(self, handle):
        if self.service:
            self.service._finish(handle)

    def _real(self, path):
        if not self.root:
            return None
        p = path.replace("\\", "/")
        while p.startswith("/"):
            p = p[1:]
        full = os.path.realpath(os.path.join(self.root, p))
        if full == self.root or full.startswith(self.root + os.sep):
            return full
        return None

    def list_folder(self, path):
        if self.service:
            self.service.note_op(self.sid, "listing folder", path, count_key="lists")
        if not self.perm["list"]:
            return paramiko.SFTP_PERMISSION_DENIED
        real = self._real(path)
        if real is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            out = []
            for name in os.listdir(real):
                try:
                    attr = paramiko.SFTPAttributes.from_stat(os.stat(os.path.join(real, name)))
                except OSError:
                    continue
                attr.filename = name
                out.append(attr)
            return out
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def stat(self, path):
        if self.service:
            self.service.note_op(self.sid, "reading file details", path, count_key="stats")
        real = self._real(path)
        if real is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(real))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def lstat(self, path):
        if self.service:
            self.service.note_op(self.sid, "reading file details", path, count_key="stats")
        real = self._real(path)
        if real is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            return paramiko.SFTPAttributes.from_stat(os.lstat(real))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def open(self, path, flags, attr):
        real = self._real(path)
        if real is None:
            return paramiko.SFTP_PERMISSION_DENIED
        if flags & os.O_WRONLY:
            reading, writing = False, True
        elif flags & os.O_RDWR:
            reading, writing = True, True
        else:
            reading, writing = True, False
        if writing and not self.perm["upload"]:
            return paramiko.SFTP_PERMISSION_DENIED
        if reading and not self.perm["download"]:
            return paramiko.SFTP_PERMISSION_DENIED
        # overwrite check: blocked unless user can delete files
        exists = os.path.exists(real)
        if writing and exists and not self.perm["delete"]:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            mode = getattr(attr, "st_mode", None) or 0o644
            fd = os.open(real, flags, mode)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        if flags & os.O_WRONLY:
            fstr = "ab" if (flags & os.O_APPEND) else "wb"
        elif flags & os.O_RDWR:
            fstr = "a+b" if (flags & os.O_APPEND) else "r+b"
        else:
            fstr = "rb"
        try:
            f = os.fdopen(fd, fstr)
        except OSError as e:
            os.close(fd)
            return paramiko.SFTPServer.convert_errno(e.errno)
        direction = "download" if (reading and not writing) else "upload"
        if self.service:
            self.service.note_op(self.sid, "downloading" if direction == "download" else "uploading", path)
        total = None
        if direction == "download":
            try:
                total = os.path.getsize(real)
            except OSError:
                total = None
        handle = JailedHandle(flags, self, os.path.basename(real), direction, total)
        handle.filename = real
        if reading and not writing:
            handle.readfile = f
        elif writing and not reading:
            handle.writefile = f
        else:
            handle.readfile = f
            handle.writefile = f
        if self.service:
            self.service.transfer_begin(self.sid, handle)
        return handle

    def remove(self, path):
        if self.service:
            self.service.note_op(self.sid, "deleting", path)
        if not self.perm["delete"]:
            return paramiko.SFTP_PERMISSION_DENIED
        real = self._real(path)
        if real is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            os.remove(real)
            if self.service:
                self.service.activity(self.sid, "deleted", os.path.basename(real))
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def rename(self, oldpath, newpath):
        if self.service:
            self.service.note_op(self.sid, "renaming", oldpath)
        o = self._real(oldpath)
        n = self._real(newpath)
        if o is None or n is None:
            return paramiko.SFTP_PERMISSION_DENIED
        is_dir = os.path.isdir(o)
        if is_dir and not self.perm["rename_dir"]:
            return paramiko.SFTP_PERMISSION_DENIED
        if not is_dir and not self.perm["rename_file"]:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            os.rename(o, n)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def mkdir(self, path, attr):
        if self.service:
            self.service.note_op(self.sid, "making folder", path)
        if not self.perm["mkdir"]:
            return paramiko.SFTP_PERMISSION_DENIED
        real = self._real(path)
        if real is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            os.mkdir(real)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def rmdir(self, path):
        if self.service:
            self.service.note_op(self.sid, "removing folder", path)
        if not self.perm["delete_dir"]:
            return paramiko.SFTP_PERMISSION_DENIED
        real = self._real(path)
        if real is None:
            return paramiko.SFTP_PERMISSION_DENIED
        try:
            os.rmdir(real)
            if self.service:
                self.service.activity(self.sid, "removed folder", os.path.basename(real))
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)


# ───────────── SSH server interface (auth) ─────────────
class ServerIface(paramiko.ServerInterface):
    def __init__(self, service, ip, sid):
        self.service = service
        self.ip = ip
        self.sid = sid
        self.username = None
        self.user = None

    def get_allowed_auths(self, username):
        u = self.service.find_user(username)
        methods = []
        if u:
            if u.get("auth") in ("password", "both") and u.get("password_hash"):
                methods.append("password")
            if u.get("auth") in ("key", "both") and u.get("authorized_keys"):
                methods.append("publickey")
        return ",".join(methods) if methods else "publickey,password"

    def check_auth_password(self, username, password):
        if self.service.lockout.is_locked(self.ip):
            return paramiko.AUTH_FAILED
        u = self.service.find_user(username)
        real_hash = u.get("password_hash") if (u and u.get("auth") in ("password", "both")) else None
        if real_hash:
            if verify_password(password, real_hash):
                self._win(username, u)
                return paramiko.AUTH_SUCCESSFUL
        else:
            # No real user/hash to check against: run a dummy bcrypt check
            # anyway and discard the result, so this path takes about as
            # long as the real one and doesn't leak valid usernames via timing.
            verify_password(password, _DUMMY_PASSWORD_HASH)
        self.service.lockout.record_fail(self.ip)
        debug.log("auth fail (password)", {"ip": self.ip, "user": username})
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if self.service.lockout.is_locked(self.ip):
            return paramiko.AUTH_FAILED
        u = self.service.find_user(username)
        if u and u.get("auth") in ("key", "both"):
            offered = key.get_base64()
            for ak in u.get("authorized_keys", []):
                parts = ak.split()
                if len(parts) >= 2 and parts[1] == offered:
                    self._win(username, u)
                    return paramiko.AUTH_SUCCESSFUL
        self.service.lockout.record_fail(self.ip)
        debug.log("auth fail (key)", {"ip": self.ip, "user": username})
        return paramiko.AUTH_FAILED

    def _win(self, username, user):
        self.username = username
        self.user = user
        self.service.lockout.clear(self.ip)

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request(self, channel, name):
        ok = (name == "sftp")
        return paramiko.ServerInterface.check_channel_subsystem_request(self, channel, name) if ok else False

    def check_channel_pty_request(self, *a, **k):
        return False

    def check_channel_shell_request(self, channel):
        return False

    def check_channel_exec_request(self, channel, command):
        return False


# ───────────── the server service ─────────────
class SFTPService:
    def __init__(self, api):
        self.api = api
        self.lockout = Lockout()
        self.host_key = None
        self.sock = None
        self.port = None
        self.running = False
        self.is_quick = False
        self._accept_thread = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._sessions = {}
        self._sid = 0
        self._generation = 0
        # Registry of every live Paramiko transport, including half-open
        # handshakes that have not finished auth, keyed by sid and removed on
        # disconnect. Later phases use this to close transports and wait for
        # teardown.
        self._conns = {}
        # Coalescing pump state, all guarded by self._lock. Transfer threads only
        # record here; the pump thread reads and pushes to the window.
        self._pending_activity = []      # activity lines not yet flushed
        self._latest_transfer = None     # newest progress snapshot for the bar
        self._transfer_dirty = False     # a new transfer snapshot is waiting
        self._status_dirty = False       # a status push is waiting
        self._pump_thread = None

    def find_user(self, username):
        return self.api.find_user(username)

    def start(self, port, quick=False):
        if self.running:
            return {"ok": False, "error": "Server is already running."}
        port = int(port or DEFAULT_PORT)
        if self.host_key is None:
            self.host_key = load_or_create_host_key()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            s.listen(20)
        except OSError as e:
            s.close()
            return {"ok": False, "error": friendly_error(e)}
        self.sock = s
        self.port = port
        self.is_quick = quick
        self.running = True
        self._stop.clear()
        with self._lock:
            self._generation += 1
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        self._pump_thread = threading.Thread(target=self._pump_loop, daemon=True)
        self._pump_thread.start()
        debug.log("SERVER start", {"port": port, "quick": quick})
        return {"ok": True, "port": port}

    def stop(self):
        self._stop.set()
        self.running = False
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.sock = None
        # One shared budget bounds the whole teardown so Stop can never hang.
        deadline = time.time() + SHUTDOWN_TIMEOUT

        def _remaining():
            return max(0.0, deadline - time.time())

        # Wait for the accept loop to exit first so no new handler threads can
        # start while we tear the rest down.
        accept_thread = self._accept_thread
        if accept_thread and accept_thread is not threading.current_thread():
            accept_thread.join(timeout=_remaining())
        self._accept_thread = None
        # Snapshot the live connections, then close every transport outside the
        # lock so blocked handler threads unblock at once instead of waiting out
        # their poll interval.
        with self._lock:
            entries = list(self._conns.values())
        for e in entries:
            try:
                e["transport"].close()
            except Exception:
                pass
        # Wait for the handler threads to finish under the shared budget.
        for e in entries:
            th = e.get("thread")
            if not th or th is threading.current_thread():
                continue
            th.join(timeout=_remaining())
        # Wait for the live-view pump thread too.
        pump_thread = self._pump_thread
        if pump_thread and pump_thread is not threading.current_thread():
            pump_thread.join(timeout=_remaining())
        self._pump_thread = None
        lingering = sum(1 for e in entries
                        if e.get("thread") and e["thread"].is_alive())
        with self._lock:
            self._sessions.clear()
            self._conns.clear()
            # Drop any buffered live-view state so a restart starts clean.
            self._pending_activity = []
            self._latest_transfer = None
            self._transfer_dirty = False
            self._status_dirty = False
        # The transports are already closed, so a thread that outlived the budget
        # cannot corrupt the next run; note it but still report stopped.
        if lingering:
            debug.log("SERVER stop: threads still winding down", {"count": lingering})
        debug.log("SERVER stop")
        return {"ok": True}

    def _accept_loop(self):
        while not self._stop.is_set():
            sock = self.sock
            if sock is None:
                break
            try:
                sock.settimeout(1.0)
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _handle(self, conn, addr):
        ip = addr[0]
        if self.lockout.is_locked(ip):
            debug.log("rejected (locked)", ip)
            try:
                conn.close()
            except Exception:
                pass
            return
        with self._lock:
            self._sid += 1
            sid = self._sid
            gen = self._generation
        t = None
        try:
            t = paramiko.Transport(conn, disabled_algorithms=DISABLED_ALGORITHMS)
            with self._lock:
                self._conns[sid] = {"transport": t, "thread": threading.current_thread(),
                                    "gen": gen, "ip": ip, "user": ""}
            t.local_version = "SSH-2.0-SimpleSFTPServer"
            t.add_server_key(self.host_key)
            t.set_subsystem_handler("sftp", paramiko.SFTPServer, JailedSFTP)
            server = ServerIface(self, ip, sid)
            t.start_server(server=server)
            # Ping the client every 15s. If the link dies silently (a network
            # blip, a NAT/router timeout) the send fails, paramiko marks the
            # transport inactive, and the loop below drops the session. Without
            # this, dead sessions linger in the Live list until the OS TCP
            # timeout hours later, and reconnects pile up as ghost entries.
            t.set_keepalive(15)
            deadline = time.time() + 30
            chan = None
            while time.time() < deadline and not self._stop.is_set():
                chan = t.accept(1)
                if chan is not None:
                    break
                if not t.is_active():
                    break
            if not server.username or chan is None:
                return
            with self._lock:
                self._sessions[sid] = {"ip": ip, "user": server.username,
                                       "since": time.time(), "transfers": {},
                                       "op": "", "path": "", "lists": 0,
                                       "stats": 0, "bytes": 0}
                if sid in self._conns:
                    self._conns[sid]["user"] = server.username
            debug.log("client connected", {"ip": ip, "user": server.username})
            self.activity(sid, "connected", "")
            while t.is_active() and not self._stop.is_set():
                time.sleep(0.5)
        except paramiko.SSHException as e:
            debug.log("transport error", str(e))
        except Exception:
            debug.log("handle error", traceback.format_exc())
        finally:
            if t:
                try:
                    t.close()
                except Exception:
                    pass
            existed = False
            with self._lock:
                if sid in self._sessions:
                    existed = True
                    self._sessions.pop(sid, None)
                self._conns.pop(sid, None)
            if existed:
                debug.log("client disconnected", {"ip": ip})
                self._emit_status()

    def transfer_begin(self, sid, handle):
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is not None:
                sess["transfers"][id(handle)] = handle

    def _progress(self, handle):
        # Called on every read/write chunk. Record the newest progress snapshot
        # only; the pump decides when to push it. Keep the cheap per-handle
        # throttle so a fast transfer does not thrash the shared state.
        now = time.time()
        if now - handle._last_emit < 0.3:
            return
        handle._last_emit = now
        pct = None
        if handle._total:
            pct = min(100, int(handle._bytes * 100 / handle._total))
        snap = {"name": handle._name, "dir": handle._dir,
                "bytes": handle._bytes, "human": human_size(handle._bytes),
                "pct": pct, "active": True}
        with self._lock:
            self._latest_transfer = snap
            self._transfer_dirty = True
            self._status_dirty = True

    def _finish(self, handle):
        verb = "received" if handle._dir == "upload" else "sent"
        snap = {"name": handle._name, "dir": handle._dir,
                "bytes": handle._bytes, "human": human_size(handle._bytes),
                "pct": 100, "active": False}
        item = {"verb": verb, "name": handle._name, "human": human_size(handle._bytes)}
        with self._lock:
            for sess in self._sessions.values():
                if sess["transfers"].pop(id(handle), None) is not None:
                    sess["bytes"] += handle._bytes
                    break
            self._latest_transfer = snap
            self._transfer_dirty = True
            self._pending_activity.append(item)
            self._status_dirty = True

    def activity(self, sid, verb, name):
        with self._lock:
            self._pending_activity.append({"verb": verb, "name": name, "human": ""})
            self._status_dirty = True

    def note_op(self, sid, op, path=None, count_key=None):
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is None:
                return
            sess["op"] = op
            if path is not None:
                sess["path"] = path
            if count_key:
                sess[count_key] = sess.get(count_key, 0) + 1
            self._status_dirty = True

    def connections(self):
        out = []
        with self._lock:
            for _sid, s in self._sessions.items():
                out.append({"ip": s["ip"], "user": s["user"],
                            "since": int(time.time() - s["since"]),
                            "active": len(s["transfers"]),
                            "op": s["op"], "path": s["path"],
                            "lists": s["lists"], "stats": s["stats"],
                            "bytes": s["bytes"], "human": human_size(s["bytes"])})
        return out

    def active_conns(self, generation=None):
        """Snapshot of tracked connection entries, optionally only those from
        the given server generation. Entries reference live transport/thread
        objects for later phases to act on."""
        with self._lock:
            return [dict(e) for e in self._conns.values()
                    if generation is None or e["gen"] == generation]

    def conns_for_user(self, username):
        """Snapshot of tracked connection entries for one authenticated user."""
        with self._lock:
            return [dict(e) for e in self._conns.values() if e["user"] == username]

    def _pump_loop(self):
        # One low-rate timer drives every live-view push. It sleeps on the same
        # stop event the rest of the server uses, so Stop ends it promptly.
        while not self._stop.is_set():
            self._stop.wait(PUMP_INTERVAL)
            try:
                self._flush()
            except Exception:
                debug.log("live pump flush error", traceback.format_exc())

    def _flush(self):
        with self._lock:
            acts = self._pending_activity[-ACTIVITY_MAX:] if self._pending_activity else None
            self._pending_activity = []
            trans = self._latest_transfer if self._transfer_dirty else None
            had_trans = self._transfer_dirty
            self._transfer_dirty = False
            status = self._status_dirty
            self._status_dirty = False
        # At most three pushes per tick regardless of how many files moved.
        if status:
            self._emit_status()
        if acts:
            self.api.emit("activity", acts)
        if had_trans:
            self.api.emit("transfer", trans)

    def _emit_status(self):
        self.api.emit("status", self.api.status_payload())
