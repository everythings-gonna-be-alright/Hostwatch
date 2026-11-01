#!/usr/bin/env python3
"""
Hostwatch collector (prototype).

Sources:
  exec  - Apple's eslogger (Endpoint Security) `exec` events  -> new processes,
          with the command line (obvious secrets masked)
  file  - Apple's eslogger `open` events                      -> newly opened files
  net   - (Endpoint Security has no TCP/UDP connect event, so three sources, deduplicated)
          * TCP SYNs from pktap packet capture with process metadata (tcpdump)
          * periodic `lsof -i` snapshot diff: UDP, incoming, and anything capture misses
          * `nettop` traffic stats backstop: a new process with TCP traffic nobody reported
            (e.g. flows taken over by a security product's network extension) gets an
            inferred event, destination taken from its command line + recent DNS answers
          Each connection is labelled with a hostname: the DNS name that resolved to the IP
          (DNS answers read passively from the same capture), else reverse DNS (PTR).

Events are republished as compact JSON lines on a Unix socket, /var/run/hostwatch/collector.sock:
the folder is root-owned (nobody else can create or replace the socket), the socket belongs to the
client user with mode 0600, and each connection is checked: only the Hostwatch app that launched the
collector (--owner-pid) is accepted, or, when started by hand, the user who ran sudo.
Each client may send JSON config lines back:
  {"exclude": ["pattern", ...], "kinds": ["exec", "net", "file"], "top": true}
and only receives events that pass its filter. With "top", it also gets a "top" message every 5 s:
the busiest processes by CPU and memory (all users, including root) and total disk throughput.

Exclusion pattern syntax (case-insensitive; glob if it contains * or ?,
otherwise substring):
  mdworker            hide every event from a process whose name/path matches
  proc:/usr/libexec/* hide process-spawn events whose executable matches
  file:/System/*      hide file-open events whose file path matches
  net:*:53            hide connections whose remote endpoint matches

Apple says eslogger output is not a stable API; this is a prototype adapter.
"""
import argparse
import concurrent.futures
import ctypes
import fnmatch
import ipaddress
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from datetime import datetime

SOCKET_PATH = "/var/run/hostwatch/collector.sock"
SOL_LOCAL, LOCAL_PEERCRED, LOCAL_PEERPID = 0, 1, 2      # <sys/un.h>: peer credentials on Unix sockets
ALL_KINDS = ("exec", "net", "file")
SCOPE_FOR_KIND = {"exec": "proc", "net": "net", "file": "file"}

STOP = threading.Event()
SHUTDOWN_HOOKS = []          # callables run once when the agent should exit
SHUTDOWN_TOKEN = None        # secret a client must present to stop the agent
SELF_PID = os.getpid()
IGNORED_PIDS = {SELF_PID}

# Hostwatch's own activity is not reported: the app that started us (verified by pid), any other run
# of the very same executable (e.g. the MCP server Claude Code starts), and their children. Only the
# exact executable of the verified owner counts, and pids leave the set when they exit, so this is
# no hiding place for other programs.
OWN_EXE = ""
OUR_TREE = set()
OUR_TREE_LOCK = threading.Lock()


def is_ours_pid(pid):
    if pid in IGNORED_PIDS:
        return True
    with OUR_TREE_LOCK:
        return pid in OUR_TREE


def note_exec(pid, ppid, path):
    """Called for every exec: True if it belongs to Hostwatch (and remembers it)."""
    with OUR_TREE_LOCK:
        ours = ppid in OUR_TREE or ppid in IGNORED_PIDS or (bool(OWN_EXE) and path == OWN_EXE)
        if ours:
            OUR_TREE.add(pid)
        else:
            OUR_TREE.discard(pid)          # a reused pid now running something else
        return ours


def note_exit(pid):
    with OUR_TREE_LOCK:
        OUR_TREE.discard(pid)


def adopt_own_processes(owner_pid):
    """At start: the owner app, our launcher, and Hostwatch processes already running."""
    global OWN_EXE
    OWN_EXE = pid_path(owner_pid) if owner_pid else ""
    with OUR_TREE_LOCK:
        if owner_pid:
            OUR_TREE.add(owner_pid)
        OUR_TREE.add(os.getppid())         # Hostwatch --collector-launcher
    if not OWN_EXE or _LIBPROC is None:
        return
    count = _LIBPROC.proc_listallpids(None, 0)
    pids = (ctypes.c_int * (count + 64))()
    count = _LIBPROC.proc_listallpids(pids, ctypes.sizeof(pids))
    buf = ctypes.create_string_buffer(4096)
    for pid in pids[:max(count, 0)]:
        if pid > 0 and _LIBPROC.proc_pidpath(pid, buf, ctypes.c_uint32(4096)) > 0:
            if buf.value.decode("utf-8", "replace") == OWN_EXE:
                with OUR_TREE_LOCK:
                    OUR_TREE.add(pid)

# pid -> executable path, learned from ES events, used to label net events.
PID_PATHS = OrderedDict()
PID_PATHS_LOCK = threading.Lock()


def now_hms():
    return time.strftime("%H:%M:%S")


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


PID_PARENTS = OrderedDict()   # pid -> ppid, from exec events (packets carry no ppid)


def remember_pid(pid, path, ppid=0):
    if not pid or not path:
        return
    with PID_PATHS_LOCK:
        PID_PATHS[pid] = path
        PID_PATHS.move_to_end(pid)
        while len(PID_PATHS) > 8192:
            PID_PATHS.popitem(last=False)
        if ppid:
            PID_PARENTS[pid] = ppid
            PID_PARENTS.move_to_end(pid)
            while len(PID_PARENTS) > 8192:
                PID_PARENTS.popitem(last=False)


def pid_parent(pid):
    with PID_PATHS_LOCK:
        cached = PID_PARENTS.get(pid, 0)
    if cached or not _LIBPROC:
        return cached
    # struct proc_bsdinfo: pbi_ppid is the 4th uint32 (flags, status, xstatus, pid, ppid).
    info = ctypes.create_string_buffer(136)
    if _LIBPROC.proc_pidinfo(int(pid), 3, ctypes.c_uint64(0), info, 136) >= 20:
        return int.from_bytes(info.raw[16:20], "little")
    return 0


try:
    _LIBPROC = ctypes.CDLL("/usr/lib/libproc.dylib")
except OSError:
    _LIBPROC = None


def pid_path(pid):
    with PID_PATHS_LOCK:
        cached = PID_PATHS.get(pid, "")
    if cached or not _LIBPROC:
        return cached
    # Not seen via Endpoint Security yet: ask the kernel for the executable path.
    buf = ctypes.create_string_buffer(4096)
    if _LIBPROC.proc_pidpath(int(pid), buf, ctypes.c_uint32(4096)) > 0:
        path = buf.value.decode("utf-8", "replace")
        remember_pid(pid, path)
        return path
    return ""


# ---------------------------------------------------------------- filtering

def compile_rules(lines):
    rules = []
    for line in lines or []:
        s = str(line).strip()
        if not s or s.startswith("#"):
            continue
        scope = None
        for prefix in ("proc:", "net:", "file:"):
            if s.lower().startswith(prefix):
                scope = prefix[:-1]
                s = s[len(prefix):].strip()
                break
        if s:
            rules.append((scope, s.lower(), "*" in s or "?" in s))
    return rules


def _match(pattern, is_glob, value):
    if not value:
        return False
    v = value.lower()
    return fnmatch.fnmatchcase(v, pattern) if is_glob else pattern in v


def is_excluded(rules, ev):
    kind_scope = SCOPE_FOR_KIND[ev["kind"]]
    for scope, pattern, is_glob in rules:
        if scope is None:
            fields = (ev["name"], ev["proc"])
        elif scope != kind_scope:
            continue
        elif scope == "proc":
            fields = (ev["name"], ev["target"])
        else:
            port = ev["target"].rsplit(":", 1)[-1]
            fields = (ev["target"], f'{ev["host"]}:{port}' if ev.get("host") else "")
        if any(_match(pattern, is_glob, f) for f in fields):
            return True
    return False


def request_shutdown():
    STOP.set()
    for hook in SHUTDOWN_HOOKS:
        try:
            hook()
        except Exception:
            pass


# ------------------------------------------------------------------ socket

def pid_uid(pid):
    """Real user id of a running process (proc_bsdinfo.pbi_uid), or None."""
    if not _LIBPROC:
        return None
    info = ctypes.create_string_buffer(136)
    if _LIBPROC.proc_pidinfo(int(pid), 3, ctypes.c_uint64(0), info, 136) >= 24:
        return int.from_bytes(info.raw[20:24], "little")
    return None


def peer_identity(sock):
    """(pid, uid) of the process on the other end of a Unix socket, from the kernel."""
    pid = sock.getsockopt(SOL_LOCAL, LOCAL_PEERPID)
    cred = sock.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, 76)      # struct xucred
    uid = int.from_bytes(cred[4:8], "little")
    return pid, uid


def peer_allowed(pid, uid, owner_pid, client_uid):
    """Launched by the app: only that app process. Started by hand: only the user who ran sudo."""
    if owner_pid:
        return pid == owner_pid and uid == client_uid
    return uid == client_uid


def create_server_socket(path, client_uid):
    """Binds `path` inside a folder only root can write, so no other process can create or replace
    the socket; the socket itself belongs to `client_uid` with mode 0600 (only that user can connect)."""
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o755, exist_ok=True)
    st = os.lstat(folder)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
        raise RuntimeError(f"{folder} is not a folder owned by us; refusing to use it")
    os.chmod(folder, 0o755)                              # no group/other write
    try:
        if stat.S_ISSOCK(os.lstat(path).st_mode):
            os.unlink(path)                              # stale socket from a crashed collector
        else:
            raise RuntimeError(f"{path} exists and is not a socket; refusing to replace it")
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)                                # created as 0600, never briefly wider
    try:
        server.bind(path)
    finally:
        os.umask(old)
    if client_uid is not None and client_uid != os.geteuid():
        os.chown(path, client_uid, -1)
    os.chmod(path, 0o600)
    server.listen(8)
    server.settimeout(1.0)
    SHUTDOWN_HOOKS.append(lambda: os.path.exists(path) and os.unlink(path))
    return server


def watch_owner(pid):
    """Exit when the app that launched us goes away."""
    while not STOP.wait(2.0):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            print(f"owner PID {pid} exited; stopping", flush=True)
            request_shutdown()
            return
        except PermissionError:
            pass


# ------------------------------------------------------------------ clients

class Client:
    FILE_RATE = 40  # max file events per second per client

    def __init__(self, sock):
        self.sock = sock
        self.rules = []
        self.kinds = set(ALL_KINDS)
        self.rate_limit = True
        self.top = False           # wants the 5-second "top" process samples
        self.window = 0
        self.file_count = 0
        self.lock = threading.Lock()

    def configure(self, cfg):
        if "exclude" in cfg:
            self.rules = compile_rules(cfg.get("exclude"))
        if "kinds" in cfg:
            self.kinds = {k for k in cfg.get("kinds") or [] if k in ALL_KINDS}
        if "top" in cfg:
            self.top = bool(cfg.get("top"))
        if "rate_limit" in cfg:
            # History recorders want every event, not the 40/s display cap.
            self.rate_limit = bool(cfg.get("rate_limit"))

    def wants(self, ev):
        if ev["kind"] == "top":
            return self.top
        if ev["kind"] not in self.kinds or is_excluded(self.rules, ev):
            return False
        if ev["kind"] == "file" and self.rate_limit:
            sec = int(time.monotonic())
            if sec != self.window:
                self.window, self.file_count = sec, 0
            self.file_count += 1
            if self.file_count > self.FILE_RATE:
                return False
        return True


CLIENTS = set()
CLIENTS_LOCK = threading.Lock()


def drop_client(client):
    with CLIENTS_LOCK:
        CLIENTS.discard(client)
    try:
        client.sock.close()
    except OSError:
        pass


def publish(ev):
    ev.setdefault("ts", now_iso())
    payload = (json.dumps(ev, separators=(",", ":")) + "\n").encode("utf-8")
    with CLIENTS_LOCK:
        clients = list(CLIENTS)
    for client in clients:
        with client.lock:
            if not client.wants(ev):
                continue
            try:
                client.sock.sendall(payload)
            except OSError:
                drop_client(client)


def client_reader(client):
    buf = b""
    while not STOP.is_set():
        try:
            data = client.sock.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            break
        if not data:
            break
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            try:
                cfg = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(cfg, dict):
                continue
            if cfg.get("cmd") == "shutdown":
                if SHUTDOWN_TOKEN and cfg.get("token") == SHUTDOWN_TOKEN:
                    print("shutdown requested by client", flush=True)
                    request_shutdown()
                continue
            with client.lock:
                client.configure(cfg)
    drop_client(client)


def accept_clients(server, owner_pid=0, client_uid=None):
    while not STOP.is_set():
        try:
            sock, _ = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            pid, uid = peer_identity(sock)
        except OSError:
            sock.close()
            continue
        if not peer_allowed(pid, uid, owner_pid, client_uid):
            print(f"rejected connection from pid {pid} (uid {uid}, {pid_path(pid) or '?'})", flush=True)
            sock.close()
            continue
        sock.settimeout(2.0)
        client = Client(sock)
        with CLIENTS_LOCK:
            CLIENTS.add(client)
        threading.Thread(target=client_reader, args=(client,), daemon=True).start()


# ------------------------------------------------------- eslogger: exec/open

def _exe(proc):
    return (((proc or {}).get("executable") or {}).get("path")) or ""


def _pid(proc):
    token = (proc or {}).get("audit_token") or {}
    return int(token.get("pid") or (proc or {}).get("pid") or 0)


def _is_ours(proc):
    return is_ours_pid(_pid(proc)) or int((proc or {}).get("ppid") or 0) == SELF_PID


_SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization:\s*(?:bearer|basic|token)?\s*)[^\s'\x22]+"), r"\1***"),
    (re.compile(r"(?i)\b((?:password|passwd|pwd|token|secret|api[-_]?key|access[-_]?key|auth|session)[=:]\s*)[^\s'\x22&]+"), r"\1***"),
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@"), r"\1***@"),
    (re.compile(r"\b(gh[pousr]_|glpat-|xox[abp]-|sk-|AKIA)[A-Za-z0-9_-]{8,}"), r"\1***"),
]


def format_args(args, limit=400):
    """argv -> one shell-like line with obvious secrets masked (it is stored in history)."""
    parts = []
    for a in (args or [])[:64]:
        a = str(a)
        parts.append(f"'{a}'" if (not a or any(c in a for c in " \t\"'")) else a)
    line = " ".join(parts)
    for rx, repl in _SECRET_PATTERNS:
        line = rx.sub(repl, line)
    return line if len(line) <= limit else line[:limit] + "…"


class RecentSet:
    """Remembers keys for `ttl` seconds so repeated opens are reported once."""

    def __init__(self, ttl=120.0, maxsize=50000):
        self.ttl, self.maxsize, self.data = ttl, maxsize, OrderedDict()

    def seen(self, key):
        now = time.monotonic()
        ts = self.data.get(key)
        if ts is not None and now - ts < self.ttl:
            return True
        self.data[key] = now
        self.data.move_to_end(key)
        while len(self.data) > self.maxsize:
            self.data.popitem(last=False)
        return False


RECENT_OPENS = RecentSet()


class LockedRecentSet(RecentSet):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lock = threading.Lock()

    def seen(self, key):
        with self.lock:
            return super().seen(key)


# A connection is reported once, by whichever source sees it first (packet capture or lsof).
SEEN_CONNS = LockedRecentSet(ttl=600.0)


def normalize(raw):
    event = raw.get("event") or {}
    caller = raw.get("process") or {}
    if "exit" in event:
        note_exit(_pid(caller))
        return None
    if _is_ours(caller) and "exec" not in event:
        return None

    if "exec" in event:
        target = (event.get("exec") or {}).get("target") or {}
        path = _exe(target)
        if not path:
            return None
        pid = _pid(target)
        ppid = int(target.get("ppid") or caller.get("ppid") or 0)
        remember_pid(pid, path, ppid)
        if note_exec(pid, ppid, path) or _pid(caller) in IGNORED_PIDS:
            return None
        args = format_args((event.get("exec") or {}).get("args"))
        remember_args(pid, args)
        return {
            "kind": "exec", "time": now_hms(), "pid": pid,
            "ppid": ppid,
            "name": os.path.basename(path) or path, "proc": path, "target": path,
            # Image that called exec, i.e. the program that spawned this one.
            "parent": _exe(caller),
            "args": args,
        }

    if "open" in event:
        op = event.get("open") or {}
        fpath = ((op.get("file") or {}).get("path")) or ""
        if not fpath:
            return None
        pid = _pid(caller)
        exe = _exe(caller)
        remember_pid(pid, exe)
        if RECENT_OPENS.seen((pid, fpath)):
            return None
        fflag = int(op.get("fflag") or 0)
        mode = {1: "r", 2: "w", 3: "rw"}.get(fflag & 3, "r")
        return {
            "kind": "file", "time": now_hms(), "pid": pid,
            "ppid": int(caller.get("ppid") or 0),
            "name": os.path.basename(exe) or "?", "proc": exe,
            "target": fpath, "extra": mode,
        }
    return None


def run_eslogger(kinds):
    # "exit" only keeps the set of Hostwatch's own pids exact; it is never published.
    events = ["exec", "exit"] + (["open"] if "file" in kinds else [])
    # New session: eslogger suppresses events from its own process group,
    # which would otherwise hide the user's Terminal session.
    proc = subprocess.Popen(
        ["/usr/bin/eslogger", *events],
        stdout=subprocess.PIPE, stderr=sys.stderr,
        text=True, bufsize=1, start_new_session=True,
    )
    IGNORED_PIDS.add(proc.pid)
    print(f"eslogger {' '.join(events)} started (PID {proc.pid})", flush=True)
    return proc


# ------------------------------------------------------- hostnames for IPs

# ip -> name that was asked for (from DNS answers seen on the wire).
DNS_NAMES = OrderedDict()
DNS_LOCK = threading.Lock()
DNS_MAX = 50000
# ip -> reverse-DNS name ("" = none), resolved lazily.
PTR_NAMES = OrderedDict()
PTR_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="ptr")

_DNS_QUESTION = re.compile(r" q: \S+\? (\S+?)\.? ")
_DNS_ANSWER = re.compile(r"(?:^|[ ,])\S+? (?:\[\S+\] )?(A|AAAA) ([0-9a-fA-F:.]+?)(?=[, ]|\s*\(|$)")


def parse_dns_line(line):
    """'... q: A? www.google.com. 2/0/0 www.google.com. A 1.2.3.4, ...' -> ('www.google.com', ['1.2.3.4'])."""
    q = _DNS_QUESTION.search(line)
    if not q:
        return None, []
    answers = line[q.end():]
    ips = [m.group(2) for m in _DNS_ANSWER.finditer(answers)]
    return q.group(1).rstrip(".").lower(), ips


DNS_BY_NAME = OrderedDict()   # name -> (ips, monotonic time), to resolve names from command lines


def remember_dns(name, ips):
    with DNS_LOCK:
        DNS_BY_NAME[name] = (list(ips), time.monotonic())
        DNS_BY_NAME.move_to_end(name)
        while len(DNS_BY_NAME) > 5000:
            DNS_BY_NAME.popitem(last=False)
        for ip in ips:
            DNS_NAMES[ip] = name
            DNS_NAMES.move_to_end(ip)
        while len(DNS_NAMES) > DNS_MAX:
            DNS_NAMES.popitem(last=False)


_META = re.compile(r"\(([^()]*\b(?:proc|pid) [^()]*)\)")
_META_PROC = re.compile(r"\bproc ([^,:)]+?):(\d+)")
_META_PID = re.compile(r"\bpid (\d+)")
_SYN = re.compile(r"(\S+)\.(\d+) > (\S+)\.(\d+): Flags \[S\]")

# DNS answers + connection-opening TCP SYNs (IPv4, and IPv6 without extension headers).
_PCAP_FILTER = ("(udp src port 53 or tcp src port 53)"
                " or (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)"
                " or (ip6 and ip6[6] == 6 and ip6[53] & 0x12 == 0x02)")


def _lsof_addr(ip, port):
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def parse_syn(line, meta):
    """SYN line + packet metadata -> (pid, meta_name, remote, outgoing) or None."""
    m = _SYN.search(line)
    if not m:
        return None
    src, sport, dst, dport = m.groups()
    pm = _META_PROC.search(meta)
    pid = int(pm.group(2)) if pm else int((_META_PID.search(meta) or [0, 0])[1] or 0)
    if not pid:
        return None
    outgoing = not re.search(r"(^|[ ,])in([ ,]|$)", meta)
    remote = _lsof_addr(dst, dport) if outgoing else _lsof_addr(src, sport)
    return pid, (pm.group(1).strip() if pm else ""), remote, outgoing


def publish_connection(pid, remote, proto, name_hint="", budget=0.3):
    """Publishes a net event unless this (pid, remote) was already reported."""
    if is_ours_pid(pid) or SEEN_CONNS.seen((pid, remote)):
        return
    mark_net_pid(pid)
    exe = pid_path(pid)
    ip = _strip_host(remote)
    ev = {
        "kind": "net", "time": now_hms(), "pid": pid, "ppid": pid_parent(pid),
        "name": os.path.basename(exe) or name_hint or "?", "proc": exe,
        "target": remote, "extra": proto,
    }
    host = resolve_hosts([ip], budget=budget).get(ip)
    if host:
        ev["host"], ev["host_src"] = host
    publish(ev)


def run_packet_sniffer(capture_connects):
    """One tcpdump (needs root) for both DNS answers and TCP SYNs, so a DNS answer is always
    handled before the connection it led to. pktap adds the owning process to each packet,
    which catches connections too short for the lsof poll (e.g. `curl google.com`).
    Falls back to DNS-only capture where pktap metadata is unavailable."""
    attempts = []
    if capture_connects:
        attempts.append((["-i", "pktap,all", "-k", "NPD"], _PCAP_FILTER, True))
    attempts += [(["-i", "any"], "udp src port 53 or tcp src port 53", False),
                 ([], "udp src port 53 or tcp src port 53", False)]
    choice, failures = 0, 0
    while not STOP.is_set():
        args, bpf, connects = attempts[choice]
        cmd = ["/usr/sbin/tcpdump", "-l", "-n", "-vv", "-s", "0", *args, bpf]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, errors="replace", start_new_session=True)
        except OSError as exc:
            print(f"packet capture disabled: {exc}", file=sys.stderr, flush=True)
            return
        IGNORED_PIDS.add(proc.pid)
        SHUTDOWN_HOOKS.append(proc.terminate)
        print(f"packet capture: {' '.join(args) or 'default'}"
              f" ({'DNS + connections' if connects else 'DNS only'})", flush=True)
        started, parsed, meta = time.monotonic(), 0, ""
        header, unparsed_logged, syn_ok = "", 0, 0
        assert proc.stdout is not None
        for line in proc.stdout:
            if STOP.is_set():
                break
            parsed += 1
            # Metadata "(en0, proc curl:123, out, …)" sits on the packet's first line;
            # with -vv the addresses may be on the next one.
            if line[:1].isdigit():
                header = line
                mm = _META.search(line)
                meta = mm.group(1) if mm else ""
            name, ips = parse_dns_line(line)
            if name and ips:
                remember_dns(name, ips)
                continue
            if connects:
                syn = parse_syn(line, meta)
                # Self-diagnosis: log the raw format of the first outgoing SYNs we cannot attribute.
                if "Flags [S]" in line and not syn and "(in)" not in header and unparsed_logged < 3:
                    unparsed_logged += 1
                    print(f"packet capture: unattributed SYN; header={header.strip()[:300]!r} "
                          f"line={line.strip()[:200]!r}", flush=True)
                if syn:
                    syn_ok += 1
                if syn and syn[3]:          # outgoing only; incoming is left to lsof
                    pid, hint, remote, _ = syn
                    try:
                        publish_connection(pid, remote, "TCP", hint)
                    except Exception as exc:   # never let one bad packet stop capture
                        print(f"connection event failed: {exc}", file=sys.stderr, flush=True)
        proc.wait()
        IGNORED_PIDS.discard(proc.pid)
        if STOP.is_set():
            return
        if time.monotonic() - started < 3 and parsed == 0:
            choice += 1                     # unsupported here: try the next mode
            failures += 1
            if choice >= len(attempts) or failures >= 6:
                print("packet capture disabled: tcpdump keeps failing", file=sys.stderr, flush=True)
                return
        STOP.wait(2)


def _strip_host(remote):
    """'[2a00::1]:443' / '1.2.3.4:80' -> ip."""
    host = remote.rsplit(":", 1)[0] if remote.count(":") == 1 or remote.startswith("[") else remote
    return host.strip("[]")


def _public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified)


def _ptr(ip):
    try:
        return socket.gethostbyaddr(ip)[0].rstrip(".").lower()
    except (OSError, UnicodeError):
        return ""


def resolve_hosts(ips, budget=0.8):
    """ip -> (name, source) for the given IPs. DNS names are instant; reverse DNS runs in
    parallel for at most `budget` seconds so a slow resolver never stalls the event stream."""
    out, pending = {}, {}
    for ip in set(ips):
        with DNS_LOCK:
            name = DNS_NAMES.get(ip)
        if name:
            out[ip] = (name, "dns")
        elif ip in PTR_NAMES:
            if PTR_NAMES[ip]:
                out[ip] = (PTR_NAMES[ip], "ptr")
        elif _public(ip):
            pending[PTR_POOL.submit(_ptr, ip)] = ip
    if pending:
        done, _ = concurrent.futures.wait(pending, timeout=budget)
        for fut in done:
            ip = pending[fut]
            PTR_NAMES[ip] = fut.result()
            if PTR_NAMES[ip]:
                out[ip] = (PTR_NAMES[ip], "ptr")
        for fut in set(pending) - done:   # finish in the background for next time
            fut.add_done_callback(lambda f, ip=pending[fut]: PTR_NAMES.__setitem__(ip, f.result()))
        while len(PTR_NAMES) > DNS_MAX:
            PTR_NAMES.popitem(last=False)
    return out


# ------------------------------------------- nettop: connections nobody saw

# Some security products (traffic-scanning network extensions) take over TCP flows in the
# kernel, so a short connection never shows up as a packet from its process, and closes before
# the next lsof poll. The kernel's network statistics (nettop) still count the process's traffic,
# so a new process with TCP traffic that nothing else reported gets an inferred event.

PID_ARGS = OrderedDict()       # pid -> command line, from exec events
NET_PIDS = OrderedDict()       # pid -> monotonic time a connection was reported for it
NET_LOCK = threading.Lock()

_HOSTISH = re.compile(r"(?:\b([a-z][a-z0-9+.-]*)://)?(?:[^\s/@'\x22]+@)?"
                      r"((?:[a-z0-9-]+\.)+[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?", re.I)
_SCHEME_PORTS = {"http": "80", "https": "443", "ws": "80", "wss": "443", "ftp": "21", "ssh": "22", "git": "9418"}


def remember_args(pid, args):
    if not pid:
        return
    with NET_LOCK:
        PID_ARGS[pid] = args
        PID_ARGS.move_to_end(pid)
        while len(PID_ARGS) > 8192:
            PID_ARGS.popitem(last=False)


def mark_net_pid(pid):
    with NET_LOCK:
        NET_PIDS[pid] = time.monotonic()
        NET_PIDS.move_to_end(pid)
        while len(NET_PIDS) > 8192:
            NET_PIDS.popitem(last=False)


def infer_destination(args):
    """'curl https://google.ua/x' -> ('142.251.110.94:443', 'google.ua', 'dns').
    Prefers names whose DNS answer was just seen; falls back to the name itself."""
    fallback = None
    for scheme, host, port in _HOSTISH.findall(args or ""):
        host = host.lower().rstrip(".")
        if host.endswith((".plist", ".json", ".txt", ".log", ".sh", ".py", ".app")):
            continue
        web_tool = os.path.basename((args or "").split(" ", 1)[0]).lower() in ("curl", "wget", "http", "https")
        port = port or _SCHEME_PORTS.get(scheme.lower(), "80" if not scheme and web_tool else "?")
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            return f"{host}:{port}", "", ""
        with DNS_LOCK:
            hit = DNS_BY_NAME.get(host)
        if hit and time.monotonic() - hit[1] < 120 and hit[0]:
            return _lsof_addr(hit[0][0], port), host, "dns"
        fallback = fallback or (f"{host}:{port}", host, "args")
    return fallback or ("?:?", "", "")


def parse_nettop_line(line):
    """'05:28:30.5,curl.44636,,,10053,343,…' -> ('curl', 44636, 10053, 343); None for headers/flows.
    Process names may contain dots ('com.apple.WebKit.Networking.812'): the pid is after the last."""
    parts = line.rstrip("\n").split(",")
    if len(parts) < 6 or parts[0] == "time" or "." not in parts[1] or " " in parts[1].split(".")[-1]:
        return None
    name, _, pid_text = parts[1].rpartition(".")
    try:
        return name, int(pid_text), int(parts[4] or 0), int(parts[5] or 0)
    except ValueError:
        return None


def run_nettop_backstop(settle=1.5):
    cmd = ["/usr/bin/nettop", "-L", "0", "-s", "1", "-m", "tcp", "-n", "-x", "-P"]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, errors="replace", start_new_session=True)
    except OSError as exc:
        print(f"nettop backstop disabled: {exc}", file=sys.stderr, flush=True)
        return
    IGNORED_PIDS.add(proc.pid)
    SHUTDOWN_HOOKS.append(proc.terminate)
    print("nettop backstop: watching for connections that close before they can be seen", flush=True)
    started = time.monotonic()
    known, pending = set(), {}
    assert proc.stdout is not None
    for line in proc.stdout:
        if STOP.is_set():
            break
        parsed = parse_nettop_line(line)
        if not parsed:
            continue
        name, pid, rx, tx = parsed
        now = time.monotonic()
        if pid not in known and rx + tx > 0:
            known.add(pid)
            if now - started > 3 and not is_ours_pid(pid):   # first samples = baseline
                pending[pid] = (now, name, rx, tx)
        # Anything lsof or packet capture did not report within `settle` seconds gets inferred.
        for p, (seen, pname, prx, ptx) in list(pending.items()):
            if now - seen < settle:
                continue
            del pending[p]
            with NET_LOCK:
                reported = p in NET_PIDS
                args = PID_ARGS.get(p, "")
            if reported:
                continue
            target, host, src = infer_destination(args)
            exe = pid_path(p)
            ev = {
                "kind": "net", "time": now_hms(), "pid": p, "ppid": pid_parent(p),
                "name": os.path.basename(exe) or pname or "?", "proc": exe,
                "target": target, "extra": "TCP", "inferred": True,
                "note": f"closed before it could be read; {prx} B in / {ptx} B out",
            }
            if host:
                ev["host"], ev["host_src"] = host, src
            mark_net_pid(p)
            publish(ev)
        if len(known) > 50000:
            known.clear()
    proc.wait()


# --------------------------------------------------------------- lsof: net

def lsof_snapshot():
    out = subprocess.run(
        ["/usr/sbin/lsof", "-nP", "-i", "-R", "+c", "0", "-F", "pcRPn"],
        capture_output=True, text=True, timeout=20,
    ).stdout
    conns = {}
    pid, ppid, cmd, proto = 0, 0, "", ""
    for line in out.splitlines():
        if not line:
            continue
        tag, val = line[0], line[1:]
        if tag == "p":
            pid, ppid, cmd, proto = int(val or 0), 0, "", ""
        elif tag == "c":
            cmd = val
        elif tag == "R":
            ppid = int(val or 0)
        elif tag == "P":
            proto = val
        elif tag == "n" and "->" in val:
            local, remote = val.split("->", 1)
            conns[(pid, proto, local, remote)] = (ppid, cmd)
    return conns


def poll_network(interval):
    previous = None
    while not STOP.is_set():
        try:
            current = lsof_snapshot()
        except (subprocess.SubprocessError, OSError, ValueError) as exc:
            print(f"lsof failed: {exc}", file=sys.stderr, flush=True)
            STOP.wait(interval * 4)
            continue
        if previous is not None:
            new = [k for k in current.keys() - previous.keys()
                   if not is_ours_pid(k[0]) and not SEEN_CONNS.seen((k[0], k[3]))]
            hosts = resolve_hosts([_strip_host(k[3]) for k in new]) if new else {}
            for key in new:
                pid, proto, _local, remote = key
                ppid, cmd = current[key]
                mark_net_pid(pid)
                exe = pid_path(pid)
                ev = {
                    "kind": "net", "time": now_hms(), "pid": pid, "ppid": ppid,
                    "name": cmd or os.path.basename(exe) or "?", "proc": exe,
                    "target": remote, "extra": proto,
                }
                host = hosts.get(_strip_host(remote))
                if host:
                    ev["host"], ev["host_src"] = host
                publish(ev)
        previous = current
        STOP.wait(interval)


# -------------------------------------------------------------------- main

# --- Top processes (CPU, memory, disk) -------------------------------------------------

class RUsageInfoV2(ctypes.Structure):
    """<libproc.h> rusage_info_v2: CPU times in mach ticks, memory and disk I/O in bytes."""
    _fields_ = [("uuid", ctypes.c_uint8 * 16), ("user_time", ctypes.c_uint64), ("system_time", ctypes.c_uint64),
                ("pkg_idle_wkups", ctypes.c_uint64), ("interrupt_wkups", ctypes.c_uint64),
                ("pageins", ctypes.c_uint64), ("wired_size", ctypes.c_uint64), ("resident_size", ctypes.c_uint64),
                ("phys_footprint", ctypes.c_uint64), ("proc_start_abstime", ctypes.c_uint64),
                ("proc_exit_abstime", ctypes.c_uint64), ("child_user_time", ctypes.c_uint64),
                ("child_system_time", ctypes.c_uint64), ("child_pkg_idle_wkups", ctypes.c_uint64),
                ("child_interrupt_wkups", ctypes.c_uint64), ("child_pageins", ctypes.c_uint64),
                ("child_elapsed_abstime", ctypes.c_uint64), ("diskio_bytesread", ctypes.c_uint64),
                ("diskio_byteswritten", ctypes.c_uint64)]


class Timebase(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


def process_snapshot(libproc, tick_ns):
    """{(pid, start): (cpu_ns, footprint, read, written)} for every process."""
    count = libproc.proc_listallpids(None, 0)
    pids = (ctypes.c_int * (count + 64))()
    count = libproc.proc_listallpids(pids, ctypes.sizeof(pids))
    out = {}
    info = RUsageInfoV2()
    for pid in pids[:max(count, 0)]:
        if pid <= 0 or libproc.proc_pid_rusage(pid, 2, ctypes.byref(info)) != 0:
            continue
        cpu = (info.user_time + info.system_time) * tick_ns
        out[(pid, info.proc_start_abstime)] = (cpu, info.phys_footprint, info.diskio_bytesread, info.diskio_byteswritten)
    return out


def top_from_snapshots(before, after, seconds, limit=5):
    """Busiest processes between two snapshots: [(pid, cpu %, footprint, read B/s, write B/s)] by CPU,
    plus the biggest by memory; and total disk read/write per second."""
    rows, disk_read, disk_write = [], 0.0, 0.0
    for key, (cpu, mem, rd, wr) in after.items():
        prev = before.get(key)
        if prev is None:
            continue                      # started during the interval: no baseline yet
        dcpu, drd, dwr = max(0, cpu - prev[0]), max(0, rd - prev[2]), max(0, wr - prev[3])
        disk_read += drd
        disk_write += dwr
        rows.append((key[0], 100.0 * dcpu / (seconds * 1e9), mem, drd / seconds, dwr / seconds))
    by_cpu = sorted(rows, key=lambda r: r[1], reverse=True)[:limit]
    by_mem = [r for r in sorted(rows, key=lambda r: r[2], reverse=True)[:3] if r not in by_cpu]
    return by_cpu + by_mem, disk_read / seconds, disk_write / seconds


def run_top_sampler(interval=5.0):
    """Every `interval` s, while a client asked for it: publish the busiest processes."""
    libproc = _LIBPROC
    try:
        timebase = Timebase()
        ctypes.CDLL(None).mach_timebase_info(ctypes.byref(timebase))
        tick_ns = timebase.numer / timebase.denom
    except (OSError, AttributeError) as exc:
        print(f"top sampler unavailable: {exc}", flush=True)
        return
    if libproc is None:
        return
    before, started = None, time.monotonic()
    while not STOP.wait(interval):
        with CLIENTS_LOCK:
            wanted = any(c.top for c in CLIENTS)
        if not wanted:
            before = None
            continue
        now = time.monotonic()
        snap = process_snapshot(libproc, tick_ns)
        if before is not None:
            rows, disk_read, disk_write = top_from_snapshots(before, snap, now - started)
            procs = []
            for pid, cpu, mem, rd, wr in rows:
                path = pid_path(pid) or ""
                procs.append({"pid": pid, "name": os.path.basename(path) or str(pid), "path": path,
                              "cpu": round(cpu, 1), "mem": mem, "read": round(rd), "write": round(wr)})
            publish({"kind": "top", "procs": procs, "disk_read": round(disk_read), "disk_write": round(disk_write)})
        before, started = snap, now


def main():
    parser = argparse.ArgumentParser(description="Hostwatch collector")
    parser.add_argument("--no-files", action="store_true", help="do not subscribe to file-open events")
    parser.add_argument("--no-net", action="store_true", help="do not poll network connections")
    parser.add_argument("--net-interval", type=float, default=1.0, help="seconds between lsof snapshots")
    parser.add_argument("--socket", default=SOCKET_PATH, help="Unix socket path (its folder must be root-owned)")
    parser.add_argument("--owner-pid", type=int, default=0, help="exit when this process exits")
    parser.add_argument("--token-file", default="", help="file holding the shutdown token")
    args = parser.parse_args()

    global SHUTDOWN_TOKEN
    if args.token_file:
        try:
            with open(args.token_file, encoding="utf-8") as fh:
                SHUTDOWN_TOKEN = fh.read().strip() or None
        except OSError as exc:
            print(f"cannot read token file: {exc}", file=sys.stderr, flush=True)

    if os.geteuid() != 0:
        print("Run this collector with sudo.", file=sys.stderr)
        return 1
    if not os.path.exists("/usr/bin/eslogger"):
        print("This macOS installation does not provide /usr/bin/eslogger.", file=sys.stderr)
        return 1

    kinds = set(ALL_KINDS)
    if args.no_files:
        kinds.discard("file")
    if args.no_net:
        kinds.discard("net")

    # Who may connect: the app that launched us, or (started by hand) the user who ran sudo.
    client_uid = pid_uid(args.owner_pid) if args.owner_pid else int(os.environ.get("SUDO_UID", "0"))
    try:
        server = create_server_socket(args.socket, client_uid)
    except (OSError, RuntimeError) as exc:
        print(f"cannot create the collector socket: {exc}", file=sys.stderr, flush=True)
        return 1
    threading.Thread(target=accept_clients, args=(server, args.owner_pid, client_uid), daemon=True).start()

    adopt_own_processes(args.owner_pid)        # before events flow: Hostwatch's own processes
    proc = run_eslogger(kinds)
    SHUTDOWN_HOOKS.append(proc.terminate)
    if args.owner_pid:
        threading.Thread(target=watch_owner, args=(args.owner_pid,), daemon=True).start()
    threading.Thread(target=run_top_sampler, daemon=True).start()
    if "net" in kinds:
        threading.Thread(target=run_packet_sniffer, args=(True,), daemon=True).start()
        threading.Thread(target=run_nettop_backstop, daemon=True).start()
        threading.Thread(target=poll_network, args=(args.net_interval,), daemon=True).start()
    print(f"Hostwatch agent listening on {args.socket} for "
          f"{'pid ' + str(args.owner_pid) if args.owner_pid else 'uid ' + str(client_uid)} "
          f"({', '.join(sorted(kinds))})", flush=True)

    def stop_handler(_signum, _frame):
        request_shutdown()

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if STOP.is_set():
                break
            try:
                ev = normalize(json.loads(line))
            except (json.JSONDecodeError, TypeError, ValueError, AttributeError):
                continue
            if ev:
                publish(ev)
    finally:
        STOP.set()
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            server.close()
        except OSError:
            pass
        with CLIENTS_LOCK:
            for client in list(CLIENTS):
                try:
                    client.sock.close()
                except OSError:
                    pass
            CLIENTS.clear()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
