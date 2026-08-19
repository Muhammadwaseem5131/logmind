#!/usr/bin/env python3
"""LogMind live watch - tail logs, analyse continuously, report. Never blocks.

Runs on one machine that can see the log files. Keeps a rolling window of
recent events, runs the same ten detectors over it every few seconds, prints
what is normal and alerts on what is not.

  python watch.py /var/log/auth.log
  python watch.py "C:/logs/*.log" --port 8000        # + live dashboard
  journalctl -f | python watch.py -                  # anything on stdin
  Get-WinEvent -LogName Security -MaxEvents 50 | ... | python watch.py -
  python watch.py --test

Options:
  --port N        also serve the live dashboard on localhost:N
  --window MIN    rolling analysis window          (default 15)
  --interval SEC  how often detectors run          (default 10)
  --cooldown MIN  silence for a repeated finding   (default 10)
  --status MIN    how often the baseline prints    (default 15)
  --webhook URL   POST alerts as JSON {"text": ...} (Slack/Discord shaped)
  --from-start    read existing file content first, not just new lines
"""
import glob
import json
import os
import queue
import sys
import threading
import time
import urllib.request
from collections import Counter, deque
from datetime import datetime

from logmind import analyze, parse

def _color_ok():
    """Colour only where it renders: a real terminal, and on Windows only if
    the console accepts ANSI. Otherwise the escapes print as literal junk."""
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            # 7 = ENABLE_PROCESSED_OUTPUT | WRAP_AT_EOL | VIRTUAL_TERMINAL_PROCESSING
            return bool(k.SetConsoleMode(k.GetStdHandle(-11), 7))
        except Exception:
            return False
    return True


if _color_ok():
    RESET, DIM = "\033[0m", "\033[2m"
    COLOR = {"High": "\033[91m", "Medium": "\033[93m", "Low": "\033[92m"}
else:
    RESET = DIM = ""
    COLOR = {}


# Log files worth watching if this machine happens to have them. Checked for
# existence and read permission, never opened blindly.
CANDIDATES = [
    "/var/log/auth.log", "/var/log/secure",          # linux ssh / sudo
    "/var/log/syslog", "/var/log/messages",
    "/var/log/nginx/access.log", "/var/log/apache2/access.log",
    "/var/log/system.log",                           # macos
    r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log",
]


def discover():
    """Readable log files on this machine. Empty is a normal answer - most
    desktops keep nothing a user can read without elevation."""
    return [p for p in CANDIDATES
            if os.path.isfile(p) and os.access(p, os.R_OK)]


# ------------------------------------------------------------------ input --

class FileSource:
    """Tail one file. Survives rotation, truncation, and partial last lines."""

    def __init__(self, path, from_start=False):
        self.path = path
        self.buf = b""
        self.pos = 0 if from_start else self._size()
        self.id = self._id()

    def _size(self):
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def _id(self):
        """Identity of the file behind the path. Inode + device only: on Linux
        st_ctime changes on every append, so including it would make each new
        line look like a rotation and re-read the whole file."""
        try:
            st = os.stat(self.path)
            return (st.st_ino, st.st_dev)
        except OSError:
            return None

    def read(self):
        now_id, size = self._id(), self._size()
        if now_id is None:
            return []
        if size < self.pos or now_id != self.id:    # rotated or truncated
            self.pos, self.buf, self.id = 0, b"", now_id
        if size == self.pos:
            return []
        with open(self.path, "rb") as f:
            f.seek(self.pos)
            data = self.buf + f.read()
            self.pos = f.tell()
        # a writer can be mid-line: hold the tail back until its newline lands
        if not data.endswith(b"\n"):
            data, _, self.buf = data.rpartition(b"\n")
        else:
            self.buf = b""
        return data.decode("utf-8", "replace").splitlines()


def is_admin():
    """True when this process can read privileged logs."""
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


class CommandSource:
    """Lines from a long-running command - used for logs that are not files,
    like the Windows Security event log behind winlogs.ps1."""

    def __init__(self, argv):
        import subprocess
        self.argv = argv
        self.q = queue.Queue()
        self.proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, text=True,
                                     encoding="utf-8", errors="replace",
                                     bufsize=1)
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.proc.stdout:
            self.q.put(line.rstrip("\n"))

    def read(self):
        out = []
        while True:
            try:
                out.append(self.q.get_nowait())
            except queue.Empty:
                return [ln for ln in out if ln.strip()]


class StdinSource:
    """Anything piped in: journalctl -f, tail -f, a PowerShell exporter."""

    def __init__(self, *_):
        self.q = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in sys.stdin:
            self.q.put(line.rstrip("\n"))

    def read(self):
        out = []
        while True:
            try:
                out.append(self.q.get_nowait())
            except queue.Empty:
                return out


# ----------------------------------------------------------------- state ---

class Window:
    """Events from the last `minutes`, keyed on arrival rather than on the
    timestamp in the line - a log can carry old or wrong times."""

    def __init__(self, minutes=15):
        self.span = minutes * 60
        self.items = deque()
        self.lock = threading.Lock()
        self.total = 0

    def add(self, events, now):
        with self.lock:
            for e in events:
                self.items.append((now, e))
            self.total += len(events)
            self._prune(now)

    def _prune(self, now):
        while self.items and now - self.items[0][0] > self.span:
            self.items.popleft()

    def events(self, now=None):
        with self.lock:
            self._prune(now or time.time())
            return [e for _, e in self.items]


class Alerter:
    """One alert per distinct finding per cooldown - a brute force lasting ten
    minutes must not print two hundred times."""

    def __init__(self, cooldown=600):
        self.cooldown = cooldown
        self.seen = {}

    @staticmethod
    def key(f):
        return (f["cat"], tuple(f["ips"]), tuple(f["users"]))

    def fresh(self, f, now):
        k = self.key(f)
        last = self.seen.get(k)
        if last is not None and now - last < self.cooldown:
            return False
        self.seen[k] = now
        return True


# ---------------------------------------------------------------- output ---

def stamp():
    return datetime.now().strftime("%H:%M:%S")


def show(f):
    c = COLOR.get(f["severity"], "")
    print(f'\n{c}[{stamp()}] {f["severity"].upper():6}{RESET} {f["title"]}')
    print(f'  {f["what"]}')
    if f["mitre"]:
        print(f'  {DIM}ATT&CK: {f["mitre"]}{RESET}')
    for line in f["evidence"][:2]:
        print(f'  {DIM}| {line[:150]}{RESET}')
    for a in f["actions"][:3]:
        print(f'  -> {a}')
    sys.stdout.flush()


def baseline(win, findings, now, quiet_for):
    """What normal looks like right now - the counterweight to the alerts."""
    evs = win.events(now)
    if not evs:
        print(f'[{stamp()}] {DIM}quiet - no events in the window{RESET}')
        return
    fails = sum(1 for e in evs if e.kind == "fail")
    ips = {e.ip for e in evs if e.ip}
    users = {e.user for e in evs if e.user}
    rate = len(evs) / max(win.span / 60, 1)
    state = (f'{len(findings)} open finding(s)' if findings
             else f'nothing abnormal for {quiet_for // 60}m')
    print(f'[{stamp()}] {DIM}normal: {rate:.1f} events/min, {fails} failed '
          f'({fails * 100 // max(len(evs), 1)}%), {len(ips)} source IPs, '
          f'{len(users)} accounts | {state}{RESET}')
    sys.stdout.flush()


def notify(url, f):
    """Fire-and-forget webhook. A dead endpoint must never stop the watch."""
    body = json.dumps({"text": f'[{f["severity"]}] {f["title"]}\n{f["what"]}\n'
                               f'Actions: ' + "; ".join(f["actions"][:2])}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"content-type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10).close()
    except Exception as exc:
        print(f'[{stamp()}] {DIM}webhook failed: {exc}{RESET}')


# ------------------------------------------------------------------ loop ---

def watch(paths, port=None, window=15, interval=10, cooldown=10, status=15,
          webhook=None, from_start=False):
    sources = [StdinSource() if p == "-" else FileSource(p, from_start)
               for p in paths]
    win, alerter = Window(window), Alerter(cooldown * 60)
    latest = {"report": None}

    if port:
        threading.Thread(target=live_server, args=(port, win, latest),
                         daemon=True).start()

    print(f'LogMind watching {len(sources)} source(s): {", ".join(paths)}')
    print(f'window {window}m | detectors every {interval}s | alert cooldown '
          f'{cooldown}m | notify only, nothing is ever blocked\n')

    last_status = last_finding = time.time()
    while True:
        now = time.time()
        lines = [ln for s in sources for ln in s.read()]
        if lines:
            events = parse("\n".join(lines))
            for e in events:
                if not e.real_ts:       # no timestamp in the line: it is now
                    e.ts = datetime.now()
            win.add(events, now)

        rep = analyze("\n".join(e.raw for e in win.events(now)))
        latest["report"] = rep
        for f in rep["findings"]:
            if alerter.fresh(f, now):
                last_finding = now
                show(f)
                if webhook:
                    threading.Thread(target=notify, args=(webhook, f),
                                     daemon=True).start()
        if now - last_status >= status * 60:
            baseline(win, rep["findings"], now, int(now - last_finding))
            last_status = now
        time.sleep(interval)


def live_server(port, win, latest):
    """The existing dashboard, pointed at the rolling window."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from logmind import page, render_results

    REFRESH = ('<script>setTimeout(()=>{const t=document.querySelector("#log");'
               'if(!t||!t.value)location.reload()},10000)</script>')

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            rep = latest["report"]
            body = page("", (render_results(rep) if rep and rep["stats"]["total"]
                             else '<p class="note">Watching. No events in the '
                                  'window yet.</p>') + REFRESH).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    print(f'live dashboard -> http://localhost:{port}\n')
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()


# ----------------------------------------------------------------- check ---

def test():
    import tempfile
    d = tempfile.mkdtemp()
    p = os.path.join(d, "t.log")
    open(p, "w", encoding="utf-8").close()
    src = FileSource(p)
    assert len(src._id()) == 2,         "file identity must be inode+device only - a timestamp in it makes "         "every append look like a rotation on Linux"
    assert src.read() == [], "a quiet file must yield nothing"

    with open(p, "a", encoding="utf-8") as f:
        f.write("line one\nline two\n")
    assert src.read() == ["line one", "line two"], "appended lines missed"
    assert src.read() == [], "lines must not be re-read"

    with open(p, "a", encoding="utf-8") as f:                     # writer caught mid-line
        f.write("partial")
    assert src.read() == [], "a partial line must be held back"
    with open(p, "a", encoding="utf-8") as f:
        f.write(" now complete\n")
    assert src.read() == ["partial now complete"], "held line never completed"

    open(p, "w", encoding="utf-8").close()                        # rotation / truncation
    with open(p, "a", encoding="utf-8") as f:
        f.write("after rotate\n")
    assert src.read() == ["after rotate"], "rotation not detected"

    w = Window(minutes=1)
    evs = parse("Aug 10 09:00:00 h sshd: Failed password for bob from 10.0.0.5")
    w.add(evs, 1000.0)
    assert len(w.events(1000.0)) == 1
    assert w.events(1090.0) == [], "events older than the window must drop"

    a = Alerter(cooldown=600)
    f1 = {"cat": "failed_burst", "ips": ["1.2.3.4"], "users": []}
    assert a.fresh(f1, 0) is True
    assert a.fresh(f1, 300) is False, "repeat inside the cooldown must be muted"
    assert a.fresh(f1, 700) is True, "cooldown must expire"
    assert a.fresh({**f1, "ips": ["9.9.9.9"]}, 300) is True, \
        "a different source is a different alert"
    print("ok - tail, rotation, partial lines, window expiry, alert cooldown")


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
    elif args[0] == "--test":
        test()
    else:
        opts, paths = {}, []
        i = 0
        while i < len(args):
            a = args[i]
            if a == "--from-start":
                opts["from_start"] = True
            elif a.startswith("--"):
                opts[a[2:]] = args[i + 1]
                i += 1
            else:
                paths += glob.glob(a) or [a]    # glob for shells that do not
            i += 1
        for k in ("port", "window", "interval", "cooldown", "status"):
            if k in opts:
                opts[k] = int(opts[k])
        missing = [p for p in paths if p != "-" and not os.path.exists(p)]
        if missing:
            sys.exit(f"no such file: {', '.join(missing)}")
        if not paths:
            sys.exit("give at least one log file, or - to read stdin")
        try:
            watch(paths, **opts)
        except KeyboardInterrupt:
            print("\nstopped")
