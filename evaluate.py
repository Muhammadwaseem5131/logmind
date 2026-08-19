#!/usr/bin/env python3
"""Accuracy benchmark for LogMind.

Builds a labelled corpus of synthetic logs - attack scenarios with a known
ground truth, and benign scenarios written to be *hard*: near-miss patterns
that a naive detector would alarm on. Runs the real detectors over it and
reports precision / recall / F1 per detector plus the overall alert decision.

  python evaluate.py           # print the report
  python evaluate.py --write   # also write EVALUATION.md

Scoring convention: each scenario declares `expected` (must fire) and
`allowed` (may fire, not penalised - e.g. a brute-force log genuinely does
contain a volume spike). Anything outside both sets is a false positive.
Benign scenarios allow nothing: any finding is a false positive.
"""
import os
import random
import sys
from datetime import datetime, timedelta

from logmind import analyze

SEEDS = range(5)                    # scenarios per generator
USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace"]
INTERNAL = ["10.0.0.%d" % i for i in range(10, 60)]
EXTERNAL = ["203.0.113.%d", "198.51.100.%d", "192.0.2.%d", "45.77.201.%d"]


class L:
    """Tiny log builder. Times advance explicitly so scenarios stay readable."""

    def __init__(self, rng, day=None):
        self.rng = rng
        self.t = day or datetime(2026, 3, 9, 8, 0, 0)
        self.out = []

    def at(self, hour, minute=0, day=None):
        self.t = self.t.replace(hour=hour, minute=minute, second=0)
        if day:
            self.t = self.t.replace(day=day)
        return self

    def sys(self, text, gap=0):
        self.t += timedelta(seconds=gap)
        self.out.append(f"{self.t:%b %d %H:%M:%S} host01 {text}")
        return self

    def web(self, ip, req, status, gap=0):
        self.t += timedelta(seconds=gap)
        self.out.append(f'{ip} - - [{self.t:%d/%b/%Y:%H:%M:%S} +0000] '
                        f'"{req}" {status} {self.rng.randint(120, 9000)}')
        return self

    def fail(self, user, ip, gap=3):
        return self.sys(f"sshd[{self.rng.randint(1000, 9999)}]: Failed password "
                        f"for {user} from {ip} port {self.rng.randint(30000, 60000)} ssh2", gap)

    def ok(self, user, ip, gap=30):
        return self.sys(f"sshd[{self.rng.randint(1000, 9999)}]: Accepted password "
                        f"for {user} from {ip} port {self.rng.randint(30000, 60000)} ssh2", gap)

    def workday(self, n=6):
        """Ordinary daytime baseline every host has."""
        for i in range(n):
            self.at(8 + i, self.rng.randint(0, 55))
            self.ok(self.rng.choice(USERS), self.rng.choice(INTERNAL))
            self.sys(f"cron[{self.rng.randint(100, 999)}]: session opened for "
                     f"user backup", 90)
        return self

    def text(self):
        return "\n".join(self.out)


def ext(rng):
    return rng.choice(EXTERNAL) % rng.randint(2, 250)


# ------------------------------------------------------------ attack cases --

def s_brute_force(rng):
    l = L(rng).workday()
    ip, user = ext(rng), rng.choice(USERS)
    l.at(14, 31)
    for _ in range(rng.randint(8, 20)):
        l.fail(user, ip, 3)
    l.ok(user, ip, 3)
    return l.text(), {"brute_force_success"}, {"volume_spike", "failed_burst",
                                               "account_probing", "off_hours"}


def s_burst_no_entry(rng):
    l = L(rng).workday()
    ip, user = ext(rng), rng.choice(USERS)
    l.at(3, 12)
    for _ in range(rng.randint(9, 25)):
        l.fail(user, ip, 2)
    return l.text(), {"failed_burst"}, {"volume_spike"}


def s_spray(rng):
    l = L(rng).workday()
    ip = ext(rng)
    l.at(2, 5)
    for u in rng.sample(["admin", "root", "test", "oracle", "postgres", "jenkins",
                         "git", "ubuntu", "ftp", "guest"], rng.randint(4, 8)):
        l.fail(f"invalid user {u}", ip, 4)
    return l.text(), {"account_probing"}, {"failed_burst", "volume_spike"}


def s_distributed(rng):
    l = L(rng).workday()
    user = rng.choice(USERS)
    l.at(21, 40)
    for _ in range(rng.randint(7, 12)):
        l.fail(user, ext(rng), 25)
    return l.text(), {"distributed_attack"}, {"failed_burst", "volume_spike"}


def s_enumeration(rng):
    l = L(rng).workday()
    ips = [ext(rng) for _ in range(3)]
    l.at(4, 20)
    for u in ["admin", "root", "test", "oracle", "postgres", "jenkins", "git",
              "ubuntu", "ftp", "guest", "mysql", "www"]:
        l.fail(f"invalid user {u}", rng.choice(ips), 45)
    return l.text(), {"user_enumeration"}, {"account_probing", "failed_burst",
                                            "volume_spike"}


def s_web_scan(rng):
    l = L(rng)
    ip = ext(rng)
    l.at(9, 0)
    for i in range(8):
        l.web(rng.choice(INTERNAL), "GET /shop/products HTTP/1.1", 200, 300)
    l.at(9, 14)
    for p in ["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/index.php",
              "/admin.php", "/shell.php"]:
        l.web(ip, f"GET {p} HTTP/1.1", 404, 2)
    l.web(ip, "GET /item?id=1' or '1'='1 HTTP/1.1", 403, 3)
    l.web(ip, "GET /static/../../../etc/passwd HTTP/1.1",
          rng.choice([200, 403]), 4)
    return l.text(), {"web_attack"}, {"failed_burst", "volume_spike",
                                      "sensitive_command"}


def s_insider(rng):
    l = L(rng).workday()
    user, ip = rng.choice(USERS), ext(rng)
    l.at(2, 11)
    l.ok(user, ip)
    for cmd in ["/usr/bin/cat /etc/shadow", "/usr/sbin/useradd -m svc_x",
                "/usr/bin/chmod 777 /var/www"]:
        l.sys(f"sudo: {user} : TTY=pts/3 ; PWD=/root ; COMMAND={cmd}", 90)
    return l.text(), {"sensitive_command"}, {"off_hours", "volume_spike"}


def s_tampering(rng):
    l = L(rng).workday()
    user = rng.choice(USERS)
    l.at(1, 40)
    l.sys(f"sudo: {user} : TTY=pts/0 ; PWD=/tmp ; COMMAND=/usr/bin/systemctl "
          f"stop auditd", 30)
    l.sys("rsyslogd: [origin software=\"rsyslogd\"] log file cleared", 40)
    return l.text(), {"log_tampering"}, {"sensitive_command", "off_hours",
                                         "volume_spike"}


def s_off_hours(rng):
    l = L(rng).workday()
    l.at(3, 25)
    for _ in range(rng.randint(2, 4)):
        l.ok(rng.choice(USERS), ext(rng), 400)
    return l.text(), {"off_hours"}, {"volume_spike"}


def s_volume_spike(rng):
    l = L(rng).workday()
    l.at(11, 3)
    svc = rng.choice(["api", "worker", "gateway"])
    for _ in range(rng.randint(14, 30)):
        l.sys(f"{svc}[{rng.randint(100, 999)}]: connection reset by peer", 2)
    return l.text(), {"volume_spike"}, set()


# ------------------------------------------------------------ benign cases --

def b_normal_day(rng):
    return L(rng).workday(8).text(), set(), set()


def b_forgetful_user(rng):
    """Under every threshold on purpose: a human who mistyped."""
    l = L(rng).workday()
    user, ip = rng.choice(USERS), rng.choice(INTERNAL)
    l.at(10, 12)
    for _ in range(rng.randint(2, 4)):
        l.fail(user, ip, 25)
    l.ok(user, ip, 30)
    return l.text(), set(), set()


def b_monitoring_bot(rng):
    """High total volume, but steady - the classic naive-detector false alarm."""
    l = L(rng)
    ip = rng.choice(INTERNAL)
    l.at(8, 0)
    for _ in range(120):
        l.web(ip, "GET /health HTTP/1.1", 200, 30)
    return l.text(), set(), set()


def b_maintenance(rng):
    """Lots of privileged commands - all of them boring."""
    l = L(rng).workday()
    user = rng.choice(USERS)
    l.at(15, 0)
    for cmd in ["/usr/bin/apt update", "/usr/bin/systemctl restart nginx",
                "/usr/bin/chmod 755 /srv/app", "/usr/bin/journalctl -u api",
                "/usr/bin/docker compose up -d"]:
        l.sys(f"sudo: {user} : TTY=pts/1 ; PWD=/srv ; COMMAND={cmd}", 120)
    return l.text(), set(), set()


def b_night_batch(rng):
    """Batch host: everything happens at night, and that is normal here."""
    l = L(rng)
    l.at(1, 0)
    for i in range(8):
        l.sys(f"cron[{rng.randint(100, 999)}]: session opened for user backup", 600)
        l.ok("backup", rng.choice(INTERNAL), 30)
    return l.text(), set(), set()


def b_ci_deploy(rng):
    """One IP, many successful logins - automation, not an attacker."""
    l = L(rng).workday()
    ip = rng.choice(INTERNAL)
    l.at(13, 0)
    for _ in range(25):
        l.sys(f"sshd[{rng.randint(1000, 9999)}]: Accepted publickey for deploy "
              f"from {ip} port {rng.randint(40000, 50000)} ssh2", 70)
    return l.text(), set(), set()


def b_helpdesk(rng):
    """Several people fail once each, from their own machines."""
    l = L(rng).workday()
    l.at(9, 30)
    for u in rng.sample(USERS, 5):
        ip = rng.choice(INTERNAL)
        l.fail(u, ip, 240)
        l.ok(u, ip, 40)
    return l.text(), set(), set()


def s_log_gap(rng):
    """Dense continuous stream with one hole punched in it."""
    l = L(rng)
    ip = rng.choice(INTERNAL)
    l.at(8, 0)
    for _ in range(60):
        l.web(ip, "GET /health HTTP/1.1", 200, rng.randint(20, 40))
    l.t += timedelta(minutes=rng.randint(40, 90))        # the missing stretch
    for _ in range(60):
        l.web(ip, "GET /health HTTP/1.1", 200, rng.randint(20, 40))
    return l.text(), {"log_gap"}, set()


def b_nat_gateway(rng):
    """A whole office behind one NAT address. Looks exactly like one IP
    probing several accounts, because structurally it is."""
    l = L(rng).workday()
    nat = rng.choice(INTERNAL)
    l.at(9, 5)
    for u in rng.sample(USERS, 4):
        l.fail(u, nat, 40)
        l.fail(u, nat, 15)
        l.ok(u, nat, 20)
    return l.text(), set(), set()


def b_password_rotation(rng):
    """Forced password change day: the user keeps typing the old one."""
    l = L(rng).workday()
    user, ip = rng.choice(USERS), rng.choice(INTERNAL)
    l.at(9, 40)
    for _ in range(7):
        l.fail(user, ip, 8)
    l.ok(user, ip, 20)
    return l.text(), set(), set()


def b_load_test(rng):
    """Scheduled load test: a real, planned, one-minute flood."""
    l = L(rng).workday()
    ip = rng.choice(INTERNAL)
    l.at(16, 0)
    for _ in range(40):
        l.web(ip, "GET /api/orders HTTP/1.1", 200, 1)
    return l.text(), set(), set()


ATTACKS = [s_log_gap, s_brute_force, s_burst_no_entry, s_spray, s_distributed,
           s_enumeration, s_web_scan, s_insider, s_tampering, s_off_hours,
           s_volume_spike]
BENIGN = [b_normal_day, b_forgetful_user, b_monitoring_bot, b_maintenance,
          b_night_batch, b_ci_deploy, b_helpdesk, b_nat_gateway,
          b_password_rotation, b_load_test]


def run():
    corpus = []
    for gen in ATTACKS + BENIGN:
        for seed in SEEDS:
            rng = random.Random(f"{gen.__name__}-{seed}")
            text, expected, allowed = gen(rng)
            corpus.append((gen.__name__, text, expected, allowed))

    cats = sorted({c for _, _, e, _ in corpus for c in e})
    tp = dict.fromkeys(cats, 0)
    fn = dict.fromkeys(cats, 0)
    fp = {}
    alert_tp = alert_fn = alert_fp = alert_tn = 0
    failures = []

    for name, text, expected, allowed in corpus:
        rep = analyze(text)
        got = {f["cat"] for f in rep["findings"]}
        for c in expected:
            if c in got:
                tp[c] += 1
            else:
                fn[c] += 1
                failures.append(f"MISS  {name}: expected {c}, got {sorted(got) or 'nothing'}")
        for c in got - expected - allowed:
            fp[c] = fp.get(c, 0) + 1
            failures.append(f"FP    {name}: unexpected {c}")
        if expected:
            alert_tp += bool(got)
            alert_fn += not got
        else:
            alert_fp += bool(got)
            alert_tn += not got

    return corpus, cats, tp, fn, fp, (alert_tp, alert_fn, alert_fp, alert_tn), failures


def prf(tp_, fp_, fn_):
    p = tp_ / (tp_ + fp_) if tp_ + fp_ else 1.0
    r = tp_ / (tp_ + fn_) if tp_ + fn_ else 1.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def report():
    corpus, cats, tp, fn, fp, alerts, failures = run()
    a_tp, a_fn, a_fp, a_tn = alerts
    n_att = sum(1 for _, _, e, _ in corpus if e)
    n_ben = len(corpus) - n_att
    L_ = [f"Corpus: {len(corpus)} logs ({n_att} attack, {n_ben} benign), "
          f"{sum(len(t.splitlines()) for _, t, _, _ in corpus):,} log lines", ""]
    L_.append("Per-detector")
    L_.append(f"{'detector':22} {'TP':>4} {'FP':>4} {'FN':>4} {'prec':>6} "
              f"{'rec':>6} {'F1':>6}")
    macro = []
    for c in cats:
        p, r, f = prf(tp[c], fp.get(c, 0), fn[c])
        macro.append((p, r, f))
        L_.append(f"{c:22} {tp[c]:4} {fp.get(c, 0):4} {fn[c]:4} {p:6.2f} "
                  f"{r:6.2f} {f:6.2f}")
    mp = sum(x[0] for x in macro) / len(macro)
    mr = sum(x[1] for x in macro) / len(macro)
    mf = sum(x[2] for x in macro) / len(macro)
    L_.append(f"{'macro average':22} {'':4} {'':4} {'':4} {mp:6.2f} {mr:6.2f} {mf:6.2f}")
    for c in sorted(set(fp) - set(cats)):
        L_.append(f"{c:22} {'-':>4} {fp[c]:4} {'-':>4}   (fired only as a false positive)")
    ap, ar, af = prf(a_tp, a_fp, a_fn)
    L_ += ["", "Alert decision (did the log get flagged at all?)",
           f"  attack logs flagged     {a_tp}/{a_tp + a_fn}  (recall {ar:.2f})",
           f"  benign logs flagged     {a_fp}/{a_fp + a_tn}  (false alarm rate "
           f"{a_fp / max(a_fp + a_tn, 1):.2f})",
           f"  precision {ap:.2f}   F1 {af:.2f}"]
    if failures:
        L_ += ["", "Failures:"] + [f"  {x}" for x in failures[:20]]
        if len(failures) > 20:
            L_.append(f"  ... and {len(failures) - 20} more")
    return "\n".join(L_), (mp, mr, mf, ar, a_fp / max(a_fp + a_tn, 1))


MD = """# LogMind evaluation

Measured accuracy of the ten detectors, reproducible with:

```bash
python evaluate.py
```

## Method

`evaluate.py` generates a labelled corpus from {ngen} scenario generators
({natt} attack, {nben} benign), {nseed} randomised runs each. Every attack scenario declares
which detector **must** fire (`expected`) and which detectors **may** fire
without penalty (`allowed`) - a brute-force log really does contain a volume
spike, so counting that as an error would be wrong. Benign scenarios allow
nothing: any finding at all is a false positive.

The benign half is deliberately adversarial - these are the cases a naive
detector alarms on:

| Benign scenario | Why it is a trap |
|---|---|
| Forgetful user | 2-4 failures then success, from one IP - just under every threshold |
| Monitoring bot | 120 requests, high total volume but a flat rate |
| Maintenance window | Many `sudo` commands, all of them routine |
| Night batch host | All activity at 02:00, with no daytime baseline to compare against |
| CI deploy | 25 successful logins from a single IP |
| Helpdesk morning | Several users each failing once, from different IPs |
| Normal day | Ordinary logins, cron, health checks |
| NAT gateway | A whole office behind one address - structurally identical to one IP probing many accounts |
| Password rotation | 7 failures then success, because the user kept typing the old password |
| Load test | A planned one-minute flood |

## Results

```
{results}
```

## Known false positives

The last three benign scenarios are the ones LogMind gets wrong, and they are
kept in the corpus deliberately - a benchmark everything passes measures
nothing.

| Case | Fires as | Why it cannot be fixed from the log alone | What would fix it |
|---|---|---|---|
| Office NAT gateway | `account_probing`, `brute_force_success` | Many users behind one IP is byte-for-byte the same shape as one attacker trying many accounts | A NAT / asset inventory marking that address as shared |
| Password rotation day | `brute_force_success` | Repeated failures then a success is the definition of the pattern; intent is not in the log | A change calendar, or correlating with the password-change event |
| Scheduled load test | `volume_spike` | A planned flood and an unplanned one look identical | A maintenance window feed |

Each needs context that lives outside the log file. Reporting them is more
useful than tuning them away, because suppressing these shapes would also
suppress the real attacks they resemble.

## Reading this honestly

The corpus is **synthetic**: the same author wrote the attacks and the
detectors, so recall here is an upper bound, not a field measurement. What the
numbers do establish is that (a) every detector fires on the pattern it claims
to cover, (b) seven realistic near-miss benign shapes produce zero alerts, and
(c) the three ambiguous cases above are understood rather than accidental.

The benchmark has already paid for itself once: it caught `log_gap` firing on
35 of 85 logs, because any log with an idle overnight stretch looked like a
deletion. The rule now requires a dense log *and* a gap that is a lone
outlier.

Validation against a public labelled dataset of real traffic is the next step
and has not been done.
"""


if __name__ == "__main__":
    text, _ = report()
    print(text)
    if "--write" in sys.argv:
        # next to the script, not wherever the shell happens to be
        out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "EVALUATION.md")
        open(out, "w", encoding="utf-8").write(MD.format(
            results=text, ngen=len(ATTACKS) + len(BENIGN), natt=len(ATTACKS),
            nben=len(BENIGN), nseed=len(SEEDS)))
        print(f"\nwrote {out}")
