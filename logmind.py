#!/usr/bin/env python3
"""LogMind - AI Security Log Anomaly Explainer.

Detects anomalies in security logs, explains them in plain language, maps them
to MITRE ATT&CK, and recommends actions. Standard library only, no installs.

  python logmind.py                    # dashboard on http://localhost:8000
  python logmind.py 8137               # ... on another port
  python logmind.py samples/brute_force.log    # text report
  python logmind.py --json samples/brute_force.log
  python logmind.py --live             # dashboard + watch this machine's logs
  python logmind.py --test             # self-check
"""
import html
import json
import os
import re
import statistics
import sys
import threading
import time
import urllib.request
import webbrowser
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples")
MAX_BYTES = 5 * 1024 * 1024     # reject bigger uploads instead of eating RAM
MAX_LINES = 50_000              # analyse a prefix of huge logs, and say so
AI_TIMEOUT = 20                 # seconds before the report ships without a summary

# ---------------------------------------------------------------- parsing ---

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_RE = re.compile(r"\bfor (?:invalid user )?([\w.-]+)|\buser[= ]([\w.-]+)"
                     r"|^\w+ \d+ [\d:]+ \S+ sudo:\s+([\w.-]+) :", re.I)
FAIL_RE = re.compile(
    r"failed password|authentication failure|failed login|login failed"
    r"|invalid user|access denied|auth failure|\b401\b|\b403\b", re.I)
OK_RE = re.compile(
    r"accepted password|accepted publickey|login success|session opened"
    r"|authentication success|logged in", re.I)
TS_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r"|(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})"
    r"|([A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2})")
TS_FORMATS = ("%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S", "%Y %b %d %H:%M:%S")


class Event:
    __slots__ = ("ts", "ip", "user", "kind", "raw", "real_ts")

    def __init__(self, ts, ip, user, kind, raw, real_ts):
        self.ts, self.ip, self.user = ts, ip, user
        self.kind, self.raw, self.real_ts = kind, raw, real_ts


def parse(text):
    """Raw log text -> events. Lines with no parseable timestamp get a
    synthetic one 1s apart, so windowed checks still work; real_ts=False
    marks them so wall-clock checks (off-hours, gaps) skip them."""
    base = datetime(2000, 1, 1)
    events = []
    for i, line in enumerate(text.splitlines()[:MAX_LINES]):
        line = line.strip()
        if not line:
            continue
        ts, real = None, True
        m = TS_RE.search(line)
        if m:
            for group, fmt in zip(m.groups(), TS_FORMATS):
                if group:
                    s = re.sub(r" +", " ", group.replace("T", " "))
                    if fmt.startswith("%Y %b"):     # syslog carries no year
                        s = "%d %s" % (datetime.now().year, s)
                    try:
                        ts = datetime.strptime(s, fmt)
                    except ValueError:
                        pass
                    break
        if ts is None:
            ts, real = base + timedelta(seconds=i), False
        ip = IP_RE.search(line)
        u = USER_RE.search(line)
        kind = ("fail" if FAIL_RE.search(line) else
                "ok" if OK_RE.search(line) else "other")
        events.append(Event(ts, ip.group(0) if ip else None,
                            next((g for g in u.groups() if g), None) if u else None,
                            kind, line, real))
    return events


def group(events, kind=None):
    d = defaultdict(list)
    for e in events:
        if e.ip and (kind is None or e.kind == kind):
            d[e.ip].append(e)
    return d


def max_in_window(times, seconds=60):
    """Largest number of timestamps inside any window of `seconds`."""
    times = sorted(times)
    best = j = 0
    for i, t in enumerate(times):
        while (t - times[j]).total_seconds() > seconds:
            j += 1
        best = max(best, i - j + 1)
    return best


HTTP_RE = re.compile(r'"(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH) ')


def is_http(raw):
    return bool(HTTP_RE.search(raw))


def F(cat, sev, title, what, evidence, actions, mitre="", ips=(), users=()):
    return dict(cat=cat, severity=sev, title=title, what=what, mitre=mitre,
                evidence=[getattr(e, "raw", e) for e in evidence][:4],
                actions=list(actions), ips=sorted(set(ips)), users=sorted(set(users)))


# -------------------------------------------------------------- detectors ---

SENSITIVE = [
    (r"/etc/shadow|/etc/passwd|\.ssh/id_rsa", "credential file access",
     "T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow"),
    (r"\buseradd\b|\badduser\b|usermod -aG (sudo|wheel)", "new account or privilege grant",
     "T1136.001 Create Account: Local Account"),
    (r"chmod (777|\+s)\b|chown root", "permission weakening",
     "T1222 File and Directory Permissions Modification"),
    (r"(curl|wget)[^|]*\|\s*(ba)?sh", "remote script piped to a shell",
     "T1059.004 Command and Scripting Interpreter: Unix Shell"),
    (r"history -c|shred |\brm -rf /(?!home)", "destructive or anti-forensic command",
     "T1070 Indicator Removal"),
    (r"iptables -F|ufw disable|systemctl stop (auditd|rsyslog|firewalld)",
     "security service disabled", "T1562.001 Impair Defenses: Disable or Modify Tools"),
    (r"nc -l|/dev/tcp/|bash -i >&", "possible reverse shell",
     "T1059.004 Command and Scripting Interpreter: Unix Shell"),
]

WEB_ATTACKS = [
    (r"\.\./|%2e%2e|/etc/passwd HTTP", "path traversal", "T1190 Exploit Public-Facing Application"),
    (r"union\s+select|' or '1'='1|sleep\(\d|information_schema|--%20|or%201=1",
     "SQL injection", "T1190 Exploit Public-Facing Application"),
    (r"<script>|%3Cscript|onerror=|javascript:", "cross-site scripting",
     "T1190 Exploit Public-Facing Application"),
    (r"/\.env|/\.git/|/wp-login|/phpmyadmin|/admin\.php|shell\.php|/config\.php",
     "sensitive path probing", "T1595.003 Active Scanning: Wordlist Scanning"),
    (r"\bcmd=|\bexec=|\beval\(|\$\{jndi:", "command or template injection",
     "T1190 Exploit Public-Facing Application"),
]

TAMPER_RE = re.compile(
    r"logs? cleared|log file cleared|wtmp begins|audit log.*(clear|delet)"
    r"|rsyslog.*stopped|auditd.*stopped|journal.*vacuum", re.I)


def d_brute_force_success(events):
    """The finding that matters: failures then a success from the same IP."""
    out, fails, oks = [], group(events, "fail"), group(events, "ok")
    for ip, evs in sorted(fails.items()):
        start = min(e.ts for e in evs)
        win = next((o for o in oks.get(ip, []) if o.ts >= start), None)
        if win and len(evs) >= 5:
            out.append(F(
                "brute_force_success", "High",
                f"Successful login after repeated failures ({ip})",
                f"{ip} failed {len(evs)} times, then logged in successfully as "
                f"'{win.user or 'unknown'}'. That is the shape of a brute-force "
                f"attempt that worked. Treat the account as compromised until "
                f"you can prove otherwise.",
                evs[:3] + [win],
                ["Force a password reset and end active sessions for the account",
                 f"Block {ip} at the firewall",
                 "Review every command and file touched after the login time",
                 "Enable MFA on this account"],
                "T1110 Brute Force", [ip], [win.user] if win.user else []))
    return out


def d_failed_burst(events):
    out, oks = [], group(events, "ok")
    for ip, evs in sorted(group(events, "fail").items()):
        burst = max_in_window([e.ts for e in evs])
        start = min(e.ts for e in evs)
        if any(o.ts >= start for o in oks.get(ip, [])) and len(evs) >= 5:
            continue                                   # already reported as worse
        if burst >= 5:
            web = sum(is_http(e.raw) for e in evs) > len(evs) / 2
            noun = "rejected web requests" if web else "failed logins"
            out.append(F(
                "failed_burst", "High" if burst >= 15 else "Medium",
                f"{'Rejected request' if web else 'Failed login'} burst from {ip}",
                f"{burst} {noun} from {ip} inside one minute "
                f"({len(evs)} in total). "
                + ("Normal clients do not collect that many 401/403 answers - "
                   "something is walking the site." if web else
                   f"A person mistypes a password two or three times, not {burst}. "
                   f"This is automated."),
                evs[:3],
                [f"Rate-limit or block {ip}",
                 "Confirm no login from this IP ever succeeded",
                 "Check that account lockout is switched on"],
                "T1110.001 Brute Force: Password Guessing", [ip]))
    return out


def d_account_probing(events):
    out = []
    for ip, evs in sorted(group(events, "fail").items()):
        users = sorted({e.user for e in evs if e.user})
        if len(users) >= 3:
            out.append(F(
                "account_probing", "High" if len(users) >= 6 else "Medium",
                f"One source probing many accounts ({ip})",
                f"{ip} tried {len(users)} different usernames "
                f"({', '.join(users[:6])}{'...' if len(users) > 6 else ''}). "
                f"Spreading attempts across accounts is password spraying or "
                f"credential stuffing - it is designed to stay under the "
                f"lockout threshold on any single account.",
                evs[:3],
                [f"Block {ip} and check its reputation before unblocking",
                 "Check each named account for a successful login",
                 "Ban the usernames that do not exist on this host at the edge"],
                "T1110.003 Brute Force: Password Spraying", [ip], users))
    return out


def d_distributed_attack(events):
    """Many sources, one account: spraying seen from the target's side."""
    out, per_user = [], defaultdict(list)
    for e in events:
        if e.kind == "fail" and e.user and e.ip:
            per_user[e.user].append(e)
    for user, evs in sorted(per_user.items()):
        ips = sorted({e.ip for e in evs})
        if len(ips) >= 3 and len(evs) >= 6:
            got_in = any(o.kind == "ok" and o.user == user for o in events)
            out.append(F(
                "distributed_attack", "High" if got_in else "Medium",
                f"Account '{user}' attacked from {len(ips)} different IPs",
                f"{len(evs)} failed logins for '{user}' arrived from {len(ips)} "
                f"source addresses ({', '.join(ips[:4])}). One person does not "
                f"log in from four networks at once - this is a botnet or proxy "
                f"pool spreading attempts to dodge per-IP blocking."
                + (" A successful login for this account also appears in the log."
                   if got_in else ""),
                evs[:3],
                [f"Reset the password for '{user}' and enable MFA",
                 "Block the source range, not just single IPs",
                 "Check whether the same IPs appear against other accounts"],
                "T1110.003 Brute Force: Password Spraying", ips, [user]))
    return out


def d_volume_spike(events):
    per_min = Counter(e.ts.replace(second=0, microsecond=0) for e in events)
    if len(per_min) < 5:
        return []
    median = statistics.median(per_min.values())
    peak_min, peak = max(per_min.items(), key=lambda kv: kv[1])
    if peak < 10 or peak <= 3 * max(median, 1):
        return []
    return [F(
        "volume_spike", "Medium",
        f"Event volume spike at {peak_min:%H:%M}",
        f"{peak} events in a single minute against a typical {median:g}. A "
        f"sudden flood usually means a scan, a service failing in a loop, or "
        f"someone generating noise to bury the events that matter.",
        [e for e in events
         if e.ts.replace(second=0, microsecond=0) == peak_min][:3],
        ["Identify what produced the spike (source IP, service, error text)",
         "Compare the rate against a normal day for this host",
         "Check for other alerts inside the same minute"],
        "T1499 Endpoint Denial of Service (possible)")]


def d_off_hours(events):
    late = [e for e in events if e.real_ts and e.kind == "ok"
            and (e.ts.hour >= 22 or e.ts.hour < 5)]
    if not late or not any(e.real_ts and e.kind == "ok" and 8 <= e.ts.hour < 19
                           for e in events):
        return []      # no daytime baseline -> batch host, not worth alerting
    users = sorted({e.user for e in late if e.user})
    return [F(
        "off_hours", "Medium" if len(late) >= 3 else "Low",
        f"{len(late)} successful login(s) outside working hours",
        f"Logins succeeded between 22:00 and 05:00 for {', '.join(users) or 'unknown users'}. "
        f"Attackers use stolen credentials when nobody is watching. Legitimate "
        f"night work exists - confirm it with the account owner rather than "
        f"assuming either way.",
        late[:3],
        ["Confirm the activity with the account owner",
         "Compare against that user's normal login hours and source IPs",
         "Alert on out-of-hours logins for privileged accounts"],
        "T1078 Valid Accounts", [e.ip for e in late if e.ip], users)]


def d_sensitive_command(events):
    out = []
    for pattern, label, mitre in SENSITIVE:
        # HTTP request lines are the web detector's job, not host activity
        hits = [e for e in events
                if re.search(pattern, e.raw, re.I) and not is_http(e.raw)]
        if hits:
            users = sorted({e.user for e in hits if e.user})
            out.append(F(
                "sensitive_command", "High",
                f"Sensitive activity: {label}",
                f"{len(hits)} log line(s) show {label}"
                + (f" by {', '.join(users)}" if users else "") +
                ". On a normal day this appears during planned admin work and "
                "nowhere else. Outside a change window it is one of the "
                "strongest signals that someone is already inside.",
                hits[:3],
                ["Match this against an approved change or ticket",
                 "Ask the account owner directly - do not assume it was them",
                 "If unexplained, isolate the host and preserve the logs now"],
                mitre, [e.ip for e in hits if e.ip], users))
    return out


def d_web_attack(events):
    out = []
    for pattern, label, mitre in WEB_ATTACKS:
        hits = [e for e in events if re.search(pattern, e.raw, re.I)]
        if hits:
            ips = sorted({e.ip for e in hits if e.ip})
            # status code sits right after the closing quote of the request line
            hit_200 = [e for e in hits if re.search(r'"\s+2\d\d\b', e.raw)]
            out.append(F(
                "web_attack", "High" if hit_200 else "Medium",
                f"Web attack pattern: {label}",
                f"{len(hits)} request(s) from {', '.join(ips[:3]) or 'unknown source'} "
                f"carry {label} payloads. These are not typos in a URL, they are "
                f"crafted probes."
                + (" At least one returned a success status, so the target may "
                   "have answered the probe - treat as a possible breach."
                   if hit_200 else " All appear to have been rejected."),
                hits[:3],
                ["Block the source IPs at the WAF or edge",
                 "Check the application logs for what those requests returned",
                 "Patch or virtual-patch the endpoint being probed"],
                mitre, ips))
    return out


def d_user_enumeration(events):
    invalid = [e for e in events if re.search(r"invalid user", e.raw, re.I)]
    users = {e.user for e in invalid if e.user}
    ips = {e.ip for e in invalid if e.ip}
    if len(users) < 8 or len(ips) < 2:
        return []           # single-source case is already covered by probing
    return [F(
        "user_enumeration", "Medium",
        f"Username enumeration campaign ({len(users)} names, {len(ips)} sources)",
        f"{len(users)} usernames that do not exist on this host were tried from "
        f"{len(ips)} different IPs. Attackers do this first to learn which "
        f"accounts are real before spending attempts on passwords.",
        invalid[:3],
        ["Make failed logins respond identically for real and fake users",
         "Block the sources and watch for follow-up attempts on real accounts",
         "Alert when invalid-user failures exceed a daily baseline"],
        "T1087 Account Discovery", sorted(ips), sorted(users))]


def d_log_tampering(events):
    hits = [e for e in events if TAMPER_RE.search(e.raw)]
    real = [e for e in events if e.real_ts]
    out = []
    if hits:
        out.append(F(
            "log_tampering", "High", "Log clearing or logging service stopped",
            "The log records its own truncation or a logging service being "
            "stopped. This is what an intruder does after acting, and it means "
            "the events you are looking at are probably incomplete.",
            hits[:3],
            ["Preserve a copy of the current logs before anything else",
             "Pull the same period from your central log server, not this host",
             "Treat the host as untrusted until reviewed"],
            "T1070.002 Indicator Removal: Clear Linux or Mac System Logs",
            [e.ip for e in hits if e.ip]))
    if len(real) >= 20:
        pairs = sorted(zip(real, real[1:]),
                       key=lambda p: (p[1].ts - p[0].ts).total_seconds())
        a, b = pairs[-1]
        gap = (b.ts - a.ts).total_seconds()
        runner_up = (pairs[-2][1].ts - pairs[-2][0].ts).total_seconds()
        median = statistics.median(
            (y.ts - x.ts).total_seconds() for x, y in zip(real, real[1:])) or 1
        # Only meaningful in a continuously-written log, and only when the gap
        # is a lone outlier: in a sparse log an hour of quiet is lunch, and a
        # log with many hour-long gaps has a duty cycle, not a deletion.
        if (median <= 60 and gap >= 1800 and gap > 20 * median
                and gap > 4 * max(runner_up, 1)):
            out.append(F(
                "log_gap", "Low",
                f"Logging gap of {gap/60:.0f} minutes",
                f"Nothing was logged between {a.ts:%H:%M} and {b.ts:%H:%M}, while "
                f"the rest of the file averages an event every {median:.0f}s. "
                f"Usually a collector outage - occasionally deleted lines.",
                [a, b],
                ["Check whether the log shipper or host was down in that window",
                 "Compare with a second log source covering the same period"],
                "T1070.002 Indicator Removal (possible)"))
    return out


DETECTORS = [d_brute_force_success, d_failed_burst, d_account_probing,
             d_distributed_attack, d_volume_spike, d_off_hours,
             d_sensitive_command, d_web_attack, d_user_enumeration,
             d_log_tampering]

SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2}
SEV_WEIGHT = {"High": 35, "Medium": 12, "Low": 4}


def analyze(text):
    events = parse(text)
    findings = []
    for d in DETECTORS:
        try:
            findings += d(events)
        except Exception as exc:            # one bad detector must not lose the report
            findings.append(F("detector_error", "Low", f"{d.__name__} failed",
                              str(exc), [], ["Report this log sample as a bug"]))
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["title"]))
    risk = next((s for s in ("High", "Medium", "Low")
                 if any(f["severity"] == s for f in findings)), "Low")
    score = min(100, sum(SEV_WEIGHT[f["severity"]] for f in findings))
    return dict(events=events, findings=findings, risk=risk if findings else "Low",
                score=score, stats=summarize(events, findings))


def summarize(events, findings):
    flagged = {ip for f in findings if f["severity"] in ("High", "Medium")
               for ip in f["ips"]}
    per_ip = Counter(e.ip for e in events if e.ip)
    fails = Counter(e.ip for e in events if e.ip and e.kind == "fail")
    users = defaultdict(set)
    for e in events:
        if e.ip and e.user:
            users[e.ip].add(e.user)
    span = ""
    if events:
        secs = (max(e.ts for e in events) - min(e.ts for e in events)).total_seconds()
        h, m = divmod(int(secs) // 60, 60)
        span = f"{h}h {m}m" if h else f"{m}m"
    return dict(
        total=len(events), failed=sum(1 for e in events if e.kind == "fail"),
        ok=sum(1 for e in events if e.kind == "ok"), ips=len(per_ip), span=span,
        truncated=len(events) >= MAX_LINES,
        talkers=[dict(ip=ip, events=n, failed=fails[ip], users=len(users[ip]),
                      flagged=ip in flagged)
                 for ip, n in per_ip.most_common(8)])


# ------------------------------------------------------------ AI summary ----

def ai_summary(findings, key=None):
    """Optional analyst-voice summary.

    The key comes from the user - the dashboard field, an X-Api-Key header, or
    ANTHROPIC_API_KEY as a fallback. It is used for this one request and never
    stored, logged, echoed back into a page, or written into a report.
    """
    key = (key or "").strip() or os.environ.get("ANTHROPIC_API_KEY")
    if not key or not findings:
        return None
    prompt = ("You are a SOC analyst briefing a junior admin. In at most 4 "
              "sentences of plain English, say what these log findings mean "
              "together and what to do first:\n\n" +
              json.dumps([{k: f[k] for k in ("severity", "title", "what")}
                          for f in findings], indent=1))
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps({"model": "claude-sonnet-5", "max_tokens": 400,
                         "messages": [{"role": "user", "content": prompt}]}).encode(),
        headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                 "content-type": "application/json"})

    def call():
        with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as r:
            return json.load(r)["content"][0]["text"]

    # Hard deadline in a worker thread: a slow DNS lookup or a hung proxy can
    # outlast urlopen's own timeout, and the report must never wait on it.
    pool = ThreadPoolExecutor(1)
    try:
        return pool.submit(call).result(timeout=AI_TIMEOUT + 2)
    except FuturesTimeout:
        return (f"AI summary unavailable: no response within {AI_TIMEOUT}s. "
                f"The findings below are unaffected.")
    except Exception as exc:        # never let the network kill the report
        msg = str(exc)
        if "401" in msg or "403" in msg:
            msg = "the API key was rejected"
        elif "429" in msg:
            msg = "rate limited - try again shortly"
        return f"AI summary unavailable ({msg}). The findings below are unaffected."
    finally:
        pool.shutdown(wait=False)   # don't block the response on a dead socket


# --------------------------------------------------------------- rendering --

ICONS = {  # inline SVG strokes - no icon font, no emoji
    "shield": "M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3z",
    "alert": "M12 2 1 21h22L12 2zm0 15h.01M12 9v5",
    "clock": "M12 2a10 10 0 100 20 10 10 0 000-20zm0 5v5l3 2",
    "globe": "M12 2a10 10 0 100 20 10 10 0 000-20zM2 12h20M12 2a15 15 0 010 20 15 15 0 010-20z",
    "x": "M18 6 6 18M6 6l12 12",
    "check": "M20 6 9 17l-5-5",
    "lock": "M5 11h14v10H5zM8 11V7a4 4 0 018 0v4",
    "users": "M17 21v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2M9.5 7a3.5 3.5 0 107 0 3.5 3.5 0 10-7 0M23 21v-2a4 4 0 00-3-3.9",
    "activity": "M22 12h-4l-3 9L9 3l-3 9H2",
    "terminal": "M4 17l6-6-6-6M12 19h8",
    "search": "M11 3a8 8 0 100 16 8 8 0 000-16zM21 21l-4.35-4.35",
    "eraser": "M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14",
    "bolt": "M13 2 3 14h9l-1 8 10-12h-9z",
    "download": "M12 3v12m0 0l-4-4m4 4l4-4M4 21h16",
    "copy": "M9 9h10v12H9zM5 15V3h10",
    "printer": "M6 9V3h12v6M6 18H4v-6h16v6h-2M8 14h8v7H8z",
    "filter": "M3 4h18l-7 8v6l-4 2v-8z",
    "upload": "M12 16V4m0 0L8 8m4-4l4 4M4 20h16",
}

CAT_ICON = {
    "brute_force_success": "lock", "failed_burst": "lock",
    "account_probing": "users", "distributed_attack": "globe",
    "volume_spike": "activity", "off_hours": "clock",
    "sensitive_command": "terminal", "web_attack": "bolt",
    "user_enumeration": "search", "log_tampering": "eraser",
    "log_gap": "eraser",
}

DEMO_BLURBS = {
    "brute_force.log": ("SSH brute force", "15 failed logins then a success, "
                        "plus password spraying and a botnet spreading attempts"),
    "web_attack.log": ("Web application attack", "Scanner sweep, SQL injection, "
                       "and a path traversal that came back 200"),
    "insider.log": ("Insider / post-compromise", "Off-hours login, credential "
                    "file reads, a backdoor account, then the log cleared"),
}


def icon(name, cls="ic"):
    return (f'<svg class="{cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor"'
            f' stroke-width="2" stroke-linecap="round" stroke-linejoin="round"'
            f' aria-hidden="true"><path d="{ICONS[name]}"/></svg>')


KEY_TERMS = re.compile(
    r"Failed password|Accepted password|Accepted publickey|invalid user"
    r"|authentication failure|session opened|COMMAND=\S+|\"(?:GET|POST) [^\"]{0,60}"
    r"|\b(?:401|403|404|500|200)\b|log file cleared", re.I)


def highlight(line, terms):
    """Escape a log line, then mark the entities this finding is about, so the
    reader can see *why* the line was picked without reading all of it."""
    out = html.escape(line)
    for t in sorted({t for t in terms if t}, key=len, reverse=True):
        out = out.replace(html.escape(t), f"<mark>{html.escape(t)}</mark>")
    return KEY_TERMS.sub(lambda m: f'<b>{m.group(0)}</b>', out)


def svg_gauge(score, risk):
    """Semicircular risk gauge. Length of a 46px-radius half arc = pi*46."""
    arc = 3.14159 * 46
    return (
        f'<svg class="gauge" viewBox="0 0 120 74" role="img" '
        f'aria-label="Risk score {score} of 100, level {risk}">'
        f'<path d="M14 62a46 46 0 0192 0" fill="none" stroke="var(--card-2)" '
        f'stroke-width="11" stroke-linecap="round"/>'
        f'<path d="M14 62a46 46 0 0192 0" fill="none" stroke="currentColor" '
        f'stroke-width="11" stroke-linecap="round" stroke-dasharray="{arc:.1f}" '
        f'stroke-dashoffset="{arc * (1 - score / 100):.1f}"/>'
        f'<text x="60" y="54" class="g-num">{score}</text>'
        f'<text x="60" y="70" class="g-lab">{html.escape(risk.upper())} RISK</text>'
        f'</svg>')


def svg_timeline(events):
    """Stacked per-bucket bars: failed / successful / other. Server-rendered,
    no chart library, tooltips via <title> and a text summary for screen
    readers (never colour alone)."""
    if len(events) < 2:
        return ""
    t0, t1 = min(e.ts for e in events), max(e.ts for e in events)
    span = (t1 - t0).total_seconds()
    step = next((s for s in (60, 300, 900, 3600, 21600, 86400)
                 if span / s <= 48), 86400)
    buckets = defaultdict(lambda: [0, 0, 0])          # fail, ok, other
    for e in events:
        idx = int((e.ts - t0).total_seconds() // step)
        buckets[idx][{"fail": 0, "ok": 1}.get(e.kind, 2)] += 1
    n = max(buckets) + 1
    peak = max(sum(v) for v in buckets.values()) or 1
    w, h, gap = 100 / n, 96, 0.14
    bars = []
    for i in range(n):
        f, o, x = buckets.get(i, [0, 0, 0])
        total = f + o + x
        if not total:
            continue
        label = (t0 + timedelta(seconds=i * step)).strftime(
            "%H:%M" if step < 86400 else "%b %d")
        y = h
        parts = []
        for count, cls in ((x, "b-other"), (o, "b-ok"), (f, "b-fail")):
            if count:
                bh = count / peak * h
                y -= bh
                parts.append(f'<rect class="{cls}" x="{i*w+gap:.3f}" y="{y:.2f}" '
                             f'width="{w-gap*2:.3f}" height="{bh:.2f}" rx="0.15"/>')
        bars.append(f'<g><title>{label} - {total} events '
                    f'({f} failed, {o} accepted)</title>{"".join(parts)}</g>')
    unit = f'{step//60 if step < 86400 else step//86400}{"min" if step < 86400 else "d"}'
    axis = (f'<span>{t0:%b %d %H:%M}</span><span>1 bar = {unit}</span>'
            f'<span>{t1:%b %d %H:%M}</span>')
    rows = "".join(
        f'<tr><td class="mono">'
        f'{(t0 + timedelta(seconds=i*step)):%b %d %H:%M}</td>'
        f'<td>{v[0]}</td><td>{v[1]}</td><td>{v[2]}</td><td>{sum(v)}</td></tr>'
        for i, v in sorted(buckets.items()))
    return (f'<figure class="chart"><figcaption><span class="cap">'
            f'{icon("activity")}Event timeline</span>'
            f'<span class="legend"><i class="k-fail"></i>failed'
            f'<i class="k-ok"></i>accepted<i class="k-other"></i>other</span>'
            f'</figcaption>'
            f'<svg viewBox="0 0 100 {h}" preserveAspectRatio="none" role="img" '
            f'aria-label="Event volume over time, peak {peak} events per {unit}">'
            f'{"".join(bars)}</svg><div class="axis">{axis}</div>'
            f'<details class="datatable"><summary>Show the numbers</summary>'
            f'<div class="scroll"><table><thead><tr><th>Time</th><th>Failed</th>'
            f'<th>Accepted</th><th>Other</th><th>Total</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div></details></figure>')


def render_hero():
    cards = []
    for f in demo_files():
        title, blurb = DEMO_BLURBS.get(f, (f[:-4].replace("_", " ").title(), ""))
        cards.append(f'<a class="demo" href="/demo?f={html.escape(f)}">'
                     f'<span class="d-ic">{icon("upload")}</span>'
                     f'<strong>{html.escape(title)}</strong>'
                     f'<span>{html.escape(blurb)}</span>'
                     f'<span class="d-go">Load this log {icon("bolt")}</span></a>')
    steps = [("upload", "1. Give it a log",
              "Paste lines, drop a file, or open one of the demo logs below."),
             ("search", "2. Ten checks run",
              "Brute force, spraying, scanners, privilege abuse, log tampering, "
              "volume and timing anomalies."),
             ("shield", "3. Read plain English",
              "Every finding says what happened, why it matters, which ATT&CK "
              "technique it maps to, and what to do next.")]
    return (
        '<section class="hero">'
        '<h1>Understand your security logs in seconds</h1>'
        '<p class="lede">LogMind finds the patterns that matter in raw log '
        'files and explains them the way a analyst would - with a risk level, '
        'the evidence, and the next action. Runs locally, no account, no '
        'dependencies.</p>'
        '<ul class="facts"><li><strong>10</strong> detectors</li>'
        '<li><strong>MITRE</strong> ATT&amp;CK mapped</li>'
        '<li><strong>0</strong> dependencies</li>'
        '<li><strong>3</strong> demo attacks</li></ul>'
        '</section>'
        '<section class="steps">' +
        "".join(f'<div class="step">{icon(i, "ic step-ic")}'
                f'<strong>{t}</strong><span>{d}</span></div>'
                for i, t, d in steps) +
        '</section>'
        '<h2 class="section-h">Try a demo attack log</h2>'
        f'<section class="demos">{"".join(cards)}</section>')


def render_results(rep, ai=None, static=False, idx=""):
    s, fs = rep["stats"], rep["findings"]
    sev_counts = Counter(f["severity"] for f in fs)
    risk_cls = f'risk-{rep["risk"].lower()}'
    out = [f'<div id="results{idx}" tabindex="-1">',
           f'<div class="statusbar"><span class="pill {risk_cls}">'
           f'{icon("shield")}{rep["risk"]} risk</span>'
           f'<span class="sb-item"><b>{len(fs)}</b> findings</span>'
           f'<span class="sb-item"><b>{s["total"]:,}</b> events</span>'
           f'<span class="sb-item"><b>{s["failed"]:,}</b> failed</span>'
           f'<span class="sb-item"><b>{s["ips"]}</b> source IPs</span>'
           f'<span class="sb-item">{html.escape(s["span"] or "")}</span></div>']

    if s["truncated"]:
        out.append(f'<p class="note">Only the first {MAX_LINES:,} lines were analysed.</p>')

    out.append(svg_timeline(rep["events"]))

    if ai:
        out.append(f'<div class="card ai"><header><span class="sev">'
                   f'{icon("shield")}AI</span><h3>Analyst summary</h3></header>'
                   f'<p>{html.escape(ai)}</p></div>')

    out.append('<div class="grid">')
    out.append('<div class="col-main">')
    if not static:      # filters assume one live report per page
        out.append('<div class="toolbar"><div class="chips" role="group" '
                   'aria-label="Filter findings by severity">')
        for sev in ("All", "High", "Medium", "Low"):
            n = len(fs) if sev == "All" else sev_counts[sev]
            dis = "" if n else " disabled"
            out.append(f'<button class="chip{" on" if sev == "All" else ""}" '
                       f'data-sev="{sev}" aria-pressed="{str(sev == "All").lower()}"'
                       f'{dis}>{sev} <span class="cnt">{n}</span></button>')
        out.append('</div></div>')

    if not fs:
        out.append(f'<div class="card sev-Low"><header><span class="sev">'
                   f'{icon("check")}Clear</span><h3>No anomalies found</h3></header>'
                   f'<p>Failed logins are scattered rather than clustered, no '
                   f'single source is probing multiple accounts, and event volume '
                   f'is steady. That is what a quiet day looks like - it is not '
                   f'proof that nothing happened, only that these ten checks '
                   f'found nothing.</p></div>')
    for i, f in enumerate(fs):
        terms = f["ips"] + f["users"]
        ev = "\n".join(highlight(line, terms) for line in f["evidence"])
        acts = "".join(f"<li>{html.escape(a)}</li>" for a in f["actions"])
        chips = "".join(f'<span class="tag">{html.escape(x)}</span>'
                        for x in (f["ips"][:3] + f["users"][:3]))
        mitre = (f'<a class="mitre" target="_blank" rel="noopener" '
                 f'href="https://attack.mitre.org/techniques/'
                 f'{f["mitre"].split()[0].replace(".", "/")}/" '
                 f'title="Open this technique on attack.mitre.org">'
                 f'{html.escape(f["mitre"])}</a>' if f["mitre"] else "")
        out.append(
            f'<article class="card sev-{f["severity"]}" data-sev="{f["severity"]}"'
            f' style="--i:{i}">'
            f'<header><span class="sev">{icon(CAT_ICON.get(f["cat"], "alert"))}'
            f'{f["severity"]}</span><h3>{html.escape(f["title"])}</h3></header>'
            f'<p>{html.escape(f["what"])}</p>'
            + (f'<pre><code>{ev}</code></pre>' if ev else "") +
            f'<div class="actions"><h4>{icon("check")}Recommended actions</h4>'
            f'<ol>{acts}</ol></div>'
            f'<footer>{chips}{mitre}</footer></article>')
    out.append('</div>')                                        # /col-main

    bars = "".join(
        f'<div class="brow"><span class="blab {"risk-" + sev.lower()}">{sev}</span>'
        f'<span class="btrack"><i class="bfill sev-bg-{sev}" '
        f'style="width:{(sev_counts[sev] / max(len(fs), 1)) * 100:.0f}%"></i></span>'
        f'<b>{sev_counts[sev]}</b></div>' for sev in ("High", "Medium", "Low"))
    talkers = "".join(
        f'<tr><td class="mono">{html.escape(t["ip"])}</td><td>{t["events"]}</td>'
        f'<td>{t["failed"]}</td>'
        f'<td><span class="verdict {"bad" if t["flagged"] else "good"}">'
        f'{icon("x") if t["flagged"] else icon("check")}'
        f'{"flagged" if t["flagged"] else "ok"}</span></td></tr>'
        for t in s["talkers"])
    out.append(
        f'<aside class="side" aria-label="Summary and export">'
        f'<div class="card gauge-card {risk_cls}">{svg_gauge(rep["score"], rep["risk"])}'
        f'<div class="bars">{bars}</div></div>'
        f'<div class="card"><h3>{icon("globe")}Top sources</h3>'
        f'<div class="scroll"><table class="mini"><thead><tr><th>IP</th>'
        f'<th>Ev</th><th>Fail</th><th></th></tr></thead><tbody>{talkers}</tbody>'
        f'</table></div></div>'
        + ('' if static else
           f'<div class="card"><h3>{icon("download")}Export</h3><div class="exports">'
           f'<button id="copyMd" class="btn ghost">{icon("copy")}Copy report</button>'
           f'<button id="dlJson" class="btn ghost">{icon("download")}JSON</button>'
           f'<button onclick="print()" class="btn ghost">{icon("printer")}Print</button>'
           f'</div></div>') + '</aside>')
    out.append('</div>')                                        # /grid

    if not static:
        payload = json.dumps(report_json(rep, ai))
        out.append(f'<script type="application/json" id="reportJson">'
                   f'{html.escape(payload)}</script>')
        out.append(f'<script type="text/plain" id="reportMd">'
                   f'{html.escape(markdown_report(rep, ai))}</script>')
    out.append('</div>')
    return "\n".join(out)


def report_json(rep, ai=None):
    return dict(risk=rep["risk"], score=rep["score"],
                stats={k: v for k, v in rep["stats"].items()},
                ai_summary=ai, findings=rep["findings"])


def markdown_report(rep, ai=None):
    s = rep["stats"]
    L = [f'# LogMind report', "",
         f'- Risk: **{rep["risk"]}** (score {rep["score"]}/100)',
         f'- Events: {s["total"]} over {s["span"] or "n/a"}, '
         f'{s["failed"]} failed logins from {s["ips"]} source IPs',
         f'- Findings: {len(rep["findings"])}', ""]
    if ai:
        L += ["## AI analyst summary", ai, ""]
    for f in rep["findings"]:
        L += [f'## [{f["severity"]}] {f["title"]}',
              f'*{f["mitre"]}*' if f["mitre"] else "", f["what"], "",
              "```", *f["evidence"], "```", "**Actions**",
              *[f'- {a}' for a in f["actions"]], ""]
    return "\n".join(L)


def text_report(rep):
    s = rep["stats"]
    L = ["", f'LogMind report - risk {rep["risk"]} (score {rep["score"]}/100)',
         f'{s["total"]} events over {s["span"] or "n/a"}, {s["failed"]} failed '
         f'logins, {s["ips"]} source IPs', "=" * 68]
    for f in rep["findings"]:
        L += ["", f'[{f["severity"].upper()}] {f["title"]}',
              f'  {f["mitre"]}' if f["mitre"] else "", f'  {f["what"]}']
        L += [f'  evidence: {e}' for e in f["evidence"][:2]]
        L += [f'  action:   {a}' for a in f["actions"]]
    if not rep["findings"]:
        L.append("No anomalies detected.")
    return "\n".join(x for x in L if x is not None)


# -------------------------------------------------------------- live mode ---

LIVE = {"thread": None, "window": None, "sources": [], "started": None,
        "admin": False, "sim": None}


def live_start():
    """Begin watching this machine's readable logs, from the dashboard. Falls
    back to demo.log so the button always does something visible."""
    if LIVE["thread"] and LIVE["thread"].is_alive():
        return LIVE["sources"]
    import watch                              # imported late: watch imports us
    # demo.log is always watched: it is where the Simulate button writes, and
    # an absent file costs nothing to poll.
    paths = watch.discover() + [os.path.join(HERE, "demo.log")]
    sources = [watch.FileSource(p) for p in paths]

    # With administrator rights the Windows Security log is readable too - the
    # one that actually records logons, RDP attempts and new accounts.
    LIVE["admin"] = watch.is_admin()
    script = os.path.join(HERE, "winlogs.ps1")
    if LIVE["admin"] and os.name == "nt" and os.path.isfile(script):
        try:
            sources.append(watch.CommandSource(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-File", script]))
            paths = paths + ["Windows Security event log"]
        except Exception as exc:
            print(f"could not read the Security log: {exc}")

    window = watch.Window(minutes=15)

    def loop():
        while LIVE["thread"] is threading.current_thread():
            lines = [ln for s in sources for ln in s.read()]
            if lines:
                events = parse("\n".join(lines))
                for e in events:
                    if not e.real_ts:          # no timestamp in the line: now
                        e.ts = datetime.now()
                window.add(events, time.time())
            time.sleep(3)

    LIVE.update(window=window, sources=paths, started=datetime.now())
    LIVE["thread"] = threading.Thread(target=loop, daemon=True)
    LIVE["thread"].start()
    return paths


def live_simulate(name="brute"):
    """Write a fake attack into demo.log from the dashboard. Demo only - it
    writes log lines, it does not attack anything."""
    if LIVE["sim"] and LIVE["sim"].is_alive():
        return
    if not (LIVE["thread"] and LIVE["thread"].is_alive()):
        live_start()
    import simulate                          # imports evaluate, which imports us

    def run():
        try:
            simulate.simulate(name, os.path.join(HERE, "demo.log"), speed=0.3)
        except Exception as exc:
            print(f"simulation failed: {exc}")

    LIVE["sim"] = threading.Thread(target=run, daemon=True)
    LIVE["sim"].start()


def live_stop():
    LIVE["thread"] = None                     # the loop sees this and exits


def live_page(fragment=False):
    win = LIVE["window"]
    running = bool(LIVE["thread"] and LIVE["thread"].is_alive())
    srcs = "".join(f'<span class="tag">{html.escape(p)}</span>'
                   for p in LIVE["sources"])
    head = (
        f'<div class="statusbar"><span class="pill '
        f'{"risk-low" if running else ""}">{icon("activity")}'
        f'{"Live - watching" if running else "Stopped"}</span>'
        f'<span class="sb-item"><b>{len(LIVE["sources"])}</b> source(s)</span>'
        f'<span class="sb-item">since '
        f'{LIVE["started"]:%H:%M:%S}</span>' if LIVE["started"] else
        '<div class="statusbar"><span class="pill">Stopped</span>')
    head += ('<span class="spacer"></span>'
             '<form method="post" action="/live/stop" style="margin:0">'
             '<button class="btn ghost">Stop</button></form>'
             if running else
             '<form method="post" action="/live/start" style="margin:0">'
             '<button class="btn">Start monitoring</button></form>')
    head += f'</div><p class="note">Watching: {srcs or "nothing yet"}</p>'

    # Demo control: writes a known attack into demo.log so a live audience can
    # watch a finding appear. Labelled as a demo, because that is what it is.
    import simulate
    running_sim = bool(LIVE["sim"] and LIVE["sim"].is_alive())
    opts = "".join(f'<option value="{k}">{k} &mdash; {html.escape(b)}</option>'
                   for k, (_, b) in simulate.SCENARIOS.items())
    head += (
        f'<form class="simbar" method="post" action="/live/simulate">'
        f'<span class="simlabel">{icon("bolt")}Demo</span>'
        f'<select name="s" aria-label="Attack scenario">{opts}</select>'
        f'<button class="btn"{" disabled" if running_sim else ""}>'
        f'{"Writing attack..." if running_sim else "Simulate attack"}</button>'
        f'<span class="hint">Writes fake log lines into demo.log. Nothing is '
        f'attacked.</span></form>')
    if running and not LIVE["admin"]:
        head += (
            '<p class="note">Running without administrator rights, so the logs '
            'that record logons are not readable. On Windows, close this and '
            'right-click <b>start.bat</b> &rarr; <b>Run as administrator</b> to '
            'include the Security event log. On Linux, add your user to the '
            '<code>adm</code> group, or run with <code>sudo</code>.</p>')

    body = ""
    if win:
        evs = win.events()
        body = (render_results(analyze("\n".join(e.raw for e in evs)))
                if evs else
                '<p class="note">Connected and waiting. Nothing has been '
                'written to these files yet - findings appear here on their '
                'own.</p>')
    if fragment:
        return head + body

    # Poll for a new fragment and swap it in place. A full page reload would
    # throw away the reader's scroll position every few seconds.
    poll = """
<script>
(() => {
  const wrap = document.getElementById('liveWrap');
  let last = wrap.innerHTML;
  const tick = async () => {
    try {
      const html = await (await fetch('/live/data', {cache: 'no-store'})).text();
      if (html !== last) { wrap.innerHTML = html; last = html; }
    } catch (e) { /* server stopped: keep showing the last state */ }
  };
  setInterval(tick, 5000);
})();
</script>"""
    return f'<div id="liveWrap">{head}{body}</div>{poll}'


# ------------------------------------------------------------------ server --

def demo_files():
    return sorted(f for f in os.listdir(SAMPLES) if f.endswith(".log")) \
        if os.path.isdir(SAMPLES) else []


def read_text(path):
    """Always UTF-8. The default encoding is the machine's locale - cp1252 on
    a European Windows, cp949 on a Korean one - and a log written elsewhere
    would fail to open at all."""
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def page(log="", results=""):
    tpl = read_text(os.path.join(HERE, "ui.html"))
    opts = "".join(f'<option value="{html.escape(f)}">'
                   f'{html.escape(DEMO_BLURBS.get(f, (f[:-4], ""))[0])}</option>'
                   for f in demo_files())
    return (tpl.replace("{{LOG}}", html.escape(log))
               .replace("{{RESULTS}}", results)
               .replace("{{HERO}}", "" if results else render_hero())
               .replace("{{DEMOS}}", opts))


def serve(port=8000, live=False):
    # Threading matters: browsers open speculative connections they never send
    # a request on, and a single-threaded server serves them one at a time -
    # every real request then waits behind an idle socket.
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, urlparse

    class H(BaseHTTPRequestHandler):
        server_version = "LogMind"

        def send(self, body, ctype="text/html; charset=utf-8", code=200):
            body = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def body(self):
            n = int(self.headers.get("Content-Length", 0))
            if n > MAX_BYTES:
                self.send(f"Log too large (limit {MAX_BYTES//1024//1024} MB).",
                          "text/plain", 413)
                return None
            return self.rfile.read(n).decode("utf-8", "replace")

        def do_GET(self):
            u = urlparse(self.path)
            if u.path in ("/", "/index.html"):
                return self.send(page())
            if u.path == "/live":
                return self.send(page("", live_page()))
            if u.path == "/live/data":          # fragment for in-place refresh
                return self.send(live_page(fragment=True))
            if u.path == "/demo":
                want = parse_qs(u.query).get("f", [""])[0]
                if want not in demo_files():          # whitelist, no path games
                    return self.send(page())
                return self.send(page(read_text(os.path.join(SAMPLES, want))))
            self.send("Not found", "text/plain", 404)

        def do_POST(self):
            from urllib.parse import parse_qs as qs
            text = self.body()
            if text is None:
                return
            if self.path == "/api/analyze":
                rep = analyze(text)
                ai = ai_summary(rep["findings"], self.headers.get("X-Api-Key"))
                return self.send(json.dumps(report_json(rep, ai), indent=1),
                                 "application/json")
            if self.path.startswith("/live/"):
                if self.path.endswith("simulate"):
                    live_simulate(qs(text).get("s", ["brute"])[0])
                elif self.path.endswith("start"):
                    live_start()
                else:
                    live_stop()
                self.send_response(303)
                self.send_header("Location", "/live")
                self.end_headers()
                return
            fields = qs(text)
            log = fields.get("log", [""])[0]
            if not log.strip():                 # empty submit -> back to the hero
                return self.send(page())
            rep = analyze(log)
            # the key is used here and dropped; page() never receives it
            ai = ai_summary(rep["findings"], fields.get("key", [""])[0])
            self.send(page(log, render_results(rep, ai)))

        def log_message(self, *a):
            pass

    httpd = None
    for p in (port, port + 1, port + 2, 8080, 8123, 0):   # 0 = any free port
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", p), H)
            break
        except OSError as exc:
            print(f"port {p} unavailable ({exc.strerror or exc})")
    if live:
        paths = live_start()
        print(f"live monitoring: {', '.join(paths)}")
    url = f"http://localhost:{httpd.server_address[1]}{'/live' if live else ''}"
    print(f"LogMind dashboard -> {url}   (Ctrl+C to stop)")
    # Launching a browser can block for seconds; do it off the serving path or
    # the first request sits in the accept queue with nobody answering it.
    threading.Thread(target=webbrowser.open, args=(url,), daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


# ------------------------------------------------------------------- check --

def test():
    expect = {"brute_force.log": {"brute_force_success", "account_probing", "volume_spike"},
              "web_attack.log": {"web_attack"},
              "insider.log": {"sensitive_command", "off_hours", "log_tampering"}}
    for name, want in expect.items():
        rep = analyze(read_text(os.path.join(SAMPLES, name)))
        got = {f["cat"] for f in rep["findings"]}
        assert want <= got, f"{name}: missing {want - got} (got {got})"
        assert rep["risk"] == "High", f"{name}: risk {rep['risk']}"
        assert "detector_error" not in got, f"{name}: a detector crashed"
        assert markdown_report(rep) and text_report(rep) and svg_timeline(rep["events"])
        json.dumps(report_json(rep))            # must stay serialisable
        print(f"  {name:18} {len(rep['findings'])} findings, "
              f"risk {rep['risk']} ({rep['score']}/100)")
    quiet = "\n".join(f"Aug 10 {9+m//60:02d}:{m%60:02d}:00 host sshd[1]: Failed "
                      f"password for bob from 10.0.0.5 port 22 ssh2"
                      for m in range(0, 300, 37))
    assert not analyze(quiet)["findings"], analyze(quiet)["findings"]
    assert not analyze("")["findings"] and analyze("")["risk"] == "Low"
    assert parse("no timestamp here at all")[0].real_ts is False
    print("  quiet log          0 findings")

    # the API key must never survive a request: no network call without one,
    # and the field must never be re-rendered carrying what the user typed
    saved = os.environ.pop("ANTHROPIC_API_KEY", None)
    try:
        assert ai_summary([{"severity": "High", "title": "t", "what": "w"}], "  ") is None
    finally:
        if saved:
            os.environ["ANTHROPIC_API_KEY"] = saved
    ui = page("a log line", "")
    assert 'name="key"' in ui, "key field missing from the form"
    field = re.search(r"<input[^>]*id=\"apikey\"[^>]*>", ui).group(0)
    assert "value=" not in field, \
        "the key field must never be re-rendered carrying what the user typed"
    print("  key handling       ok")
    print("ok")


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    if arg == "--test":
        test()
    elif arg == "--json":
        print(json.dumps(report_json(analyze(read_text(sys.argv[2]))), indent=1))
    elif arg in ("-h", "--help"):
        print(__doc__)
    elif arg == "--live":
        serve(int(sys.argv[2]) if len(sys.argv) > 2 else 8000, live=True)
    elif arg and arg.isdigit():
        serve(int(arg), live="--live" in sys.argv)
    elif arg:
        print(text_report(analyze(read_text(arg))))
    else:
        serve()
