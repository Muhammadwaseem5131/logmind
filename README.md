# LogMind — AI Security Log Anomaly Explainer

[![tests](https://github.com/Muhammadwaseem5131/logmind/actions/workflows/test.yml/badge.svg)](https://github.com/Muhammadwaseem5131/logmind/actions/workflows/test.yml)
[![live demo](https://img.shields.io/badge/live%20demo-open-1D4ED8)](https://muhammadwaseem5131.github.io/logmind/)
[![python](https://img.shields.io/badge/python-3.8%2B-3776AB)](https://python.org)
[![license](https://img.shields.io/badge/license-MIT-555)](LICENSE)

Detects unusual patterns in security logs and explains them in plain language,
with a risk level, MITRE ATT&CK mapping, and recommended actions.

No installs, no dependencies, no internet required — Python standard library only.

## Install

There is nothing to install. Python 3.8 or newer is the only requirement, and
every import is from the standard library.

```bash
git clone https://github.com/Muhammadwaseem5131/logmind.git
cd logmind
python logmind.py --test     # proves the build is good
python logmind.py            # opens the dashboard
```

**One click:** double-click **`start.bat`** on Windows, or run **`./start.sh`**
on macOS and Linux. That single step runs the self-check, refuses to continue if
it fails, starts monitoring this machine's readable logs, and opens the live
dashboard in your browser. Nothing else to type.

**Administrator rights are requested automatically.** The Windows Security
log — logons, RDP attempts, new accounts — is unreadable without them, so
`start.bat` asks Windows for elevation immediately and Windows shows its own
UAC prompt. Choose **No** and everything still runs on the logs you can read;
`start.bat limited` skips the request entirely. On Linux the equivalent is
membership of the `adm` group, which the script points out rather than
encouraging a root web server. The dashboard states which mode it is in.

If `python` is not recognised, install it from
[python.org/downloads](https://python.org/downloads) and tick *"Add python.exe
to PATH"* during setup. No `pip install` step exists, because there is nothing
to install.

The dashboard opens in your browser. Press **Load demo log** to see it work.

**[Open the live demo →](https://muhammadwaseem5131.github.io/logmind/)** —
three real attack logs, already analysed, no install needed. Republished on
every push from the samples in this repository, and only when the self-check
passes.

Every push also runs the full test suite on **Linux, macOS, and Windows**
across Python 3.8 and 3.12 — the badge above is that result, not a claim.

## How it works

```mermaid
flowchart LR
    A[Log text<br/>paste · file · API] --> B[Parser]
    B -->|timestamp, IP,<br/>user, event kind| C[Event stream]
    C --> D{10 detectors}
    D --> D1[Credential attacks<br/>brute force · burst<br/>spraying · distributed]
    D --> D2[Behaviour<br/>off-hours · volume<br/>sensitive commands]
    D --> D3[Exposure<br/>web attacks · enumeration<br/>log tampering · gaps]
    D1 & D2 & D3 --> E[Findings<br/>severity · evidence<br/>ATT&CK · actions]
    E --> F[Risk score<br/>0-100 + level]
    F --> G[Dashboard]
    F --> H[CLI / JSON API]
    E -.optional.-> I[LLM analyst<br/>summary]
    I -.-> G
```

The parser and the ten detectors are pure functions over an event list, which
is why the same engine serves the dashboard, the CLI, the JSON API, and the
accuracy benchmark without a second code path.

## Accuracy

Measured on a 105-log labelled benchmark (55 attack, 50 benign) — full method
and the false positives it does **not** hide in [EVALUATION.md](EVALUATION.md):

| Metric | Result |
|---|---|
| Attack logs detected | 55 / 55 (recall 1.00) |
| Per-detector macro F1 | 0.89 |
| False alarms on hard benign logs | 15 / 50 |
| False alarms on realistic benign logs | 0 / 35 |

The 15 false alarms are three known-ambiguous cases — an office NAT gateway, a
password-rotation day, and a scheduled load test — each documented with why the
log alone cannot separate them from the real thing.

```bash
python evaluate.py
```

## Live mode

One machine watches the logs it can reach and reports continuously. It never
blocks, never modifies a firewall, and never touches the system it watches —
it reads, analyses, and tells you.

Either click **Live monitor** in the dashboard header, or start it already
running:

```bash
python logmind.py --live          # dashboard, already watching
python watch.py /var/log/auth.log --port 8000   # terminal, explicit paths
```

The dashboard's Live page finds this machine's readable log files by itself,
shows what it is watching, and has **Start** and **Stop** buttons. It refreshes
on its own, so an alert appears without touching anything.

```
LogMind watching 1 source(s): /var/log/auth.log
window 15m | detectors every 10s | alert cooldown 10m | notify only, nothing is ever blocked
live dashboard -> http://localhost:8000

[10:18:46] HIGH   Successful login after repeated failures (203.0.113.45)
  203.0.113.45 failed 12 times, then logged in successfully as 'carol'...
  ATT&CK: T1110 Brute Force
  -> Force a password reset and end active sessions for the account
[10:33:00] normal: 1.5 events/min, 4 failed (7%), 6 source IPs, 3 accounts | nothing abnormal for 14m
```

Two kinds of line: **alerts** when something is abnormal, and a periodic
**normal** line so you can see the baseline it is judging against.

| | |
|---|---|
| Many logs at once | `python watch.py "/var/log/*.log" /var/log/nginx/access.log` |
| Anything on a pipe | `journalctl -f \| python watch.py -` |
| Windows events | `Get-WinEvent -LogName Security ... \| python watch.py -` |
| Live dashboard | `--port 8000` — the normal UI, refreshing itself |
| Chat alerts | `--webhook https://hooks.slack.com/...` |
| Tuning | `--window 15 --interval 10 --cooldown 10 --status 15` (minutes / seconds) |

It handles the things that break naive tailers: log rotation, truncation,
a writer caught mid-line, and repeat alerts — one alert per distinct finding
per cooldown, not one per scan. `python watch.py --test` proves each of those.

**It does not block, by design.** Log lines are attacker-controllable, and the
benchmark shows an office NAT gateway looks exactly like one IP probing many
accounts — auto-blocking that logs out a building. LogMind reports; a human
decides.

**What it can and cannot see:** it reads logs, not packets. Point it at
firewall, proxy, VPN, and web-server logs and it sees the network behaviour
those record. It cannot see traffic nothing logged.

## Faking an attack, to see it work

Run LogMind in one window and the simulator in another. It writes a real
attack pattern into the watched log, one line at a time, so the finding
appears while you watch. Nothing is attacked — these are log lines.

**From the dashboard:** open the Live monitor page, pick a scenario in the
**Demo** bar, click **Simulate attack**. The finding appears below it a few
seconds later. Nothing else to open.

**From a terminal**, if you prefer two windows:

```bash
python logmind.py --live      # window 1
python simulate.py            # window 2
```

**By double-click:** `attack.bat` on Windows (start LogMind first).

| Scenario | What it writes |
|---|---|
| `brute` | Failed logins, then one succeeds |
| `spray` | One IP trying many usernames |
| `burst` | A flood of failures that never gets in |
| `spread` | One account attacked from many IPs |
| `web` | Scanner, SQL injection, path traversal |
| `insider` | Off-hours login, then credential theft |
| `cleanup` | auditd stopped and the log cleared |
| `enumerate` | Hunting for usernames that exist |

`python simulate.py --list` shows them all; `--speed 0.1` runs faster.

These are the same generators the accuracy benchmark scores against, so what
you demo is exactly what was measured.

## Run modes

| Command | What it does |
|---|---|
| `python logmind.py` | Dashboard on http://localhost:8000 (`python logmind.py 8137` for another port) |
| `python logmind.py samples/insider.log` | Plain-text report to the terminal |
| `python logmind.py --json samples/insider.log` | Machine-readable JSON report |
| `python logmind.py --test` | Self-check across all sample logs |
| `POST /api/analyze` with raw log text | JSON report over HTTP |

## What it detects

| # | Detector | Fires when | MITRE |
|---|---|---|---|
| 1 | Successful brute force | ≥5 failures from an IP, then a success from the same IP | T1110 |
| 2 | Failed login burst | ≥5 failures from one IP inside 60s | T1110.001 |
| 3 | Account probing | One IP tries ≥3 usernames | T1110.003 |
| 4 | Distributed attack | One account attacked from ≥3 IPs | T1110.003 |
| 5 | Volume spike | A minute with ≥10 events and >3× the median | T1499 |
| 6 | Off-hours access | Successful logins 22:00–05:00 on a host with a daytime baseline | T1078 |
| 7 | Sensitive commands | shadow/id_rsa reads, useradd, chmod 777, curl‑pipe‑bash, `history -c`, auditd stopped, reverse shells | T1003 / T1136 / T1222 / T1059 / T1070 / T1562 |
| 8 | Web attack patterns | Traversal, SQLi, XSS, JNDI, sensitive-path scanning — flagged **High** if any returned 2xx | T1190 / T1595 |
| 9 | Username enumeration | ≥8 invalid usernames from ≥2 sources | T1087 |
| 10 | Log tampering / gaps | Log-clearing lines, or a ≥30 min gap 20× the normal interval | T1070.002 |

Each finding carries: severity, a plain-English explanation, the log lines that
triggered it, and 2–4 concrete next actions.

## Log formats

Syslog (`Aug 10 14:31:02 …`), ISO (`2026-08-10 14:31:02`), and web access logs
(`10/Aug/2026:14:31:02`). Lines without a parseable timestamp still get analysed
— they get a synthetic 1s ordering, and wall-clock checks skip them.

## Optional AI summary

Detection is rule-based and runs fully offline. With an API key, LogMind adds
one analyst-voice paragraph tying the findings together.

Open **"Optional — add an AI key for an analyst summary"** under the log box
and paste a key from either provider — the one it belongs to is detected from
the key itself:

| Provider | Key looks like | Get one |
|---|---|---|
| **Google Gemini** (free tier) | `AIza…` | [aistudio.google.com/apikey](https://aistudio.google.com/apikey) |
| **Anthropic** | `sk-ant-…` | [console.anthropic.com](https://console.anthropic.com/settings/keys) |

`GEMINI_API_KEY` / `ANTHROPIC_API_KEY` still work for scripted use, and
`POST /api/analyze` accepts an `X-Api-Key` header.

Press **Connect** after pasting a key: LogMind asks the provider for its model
list — an authenticated call that spends no tokens — and reports **Connected**
or exactly why not, before you rely on it in a demo.

**How the key is handled**

- only the **findings** are sent — never your raw log
- it goes to your own local LogMind process, then to that provider, and
  nowhere else
- sent as a request **header**, never in a URL, so it cannot reach browser
  history, a proxy log, or an error message
- never written to disk by LogMind, never printed to a log line, never echoed
  back into the page, never included in an exported report — all asserted by
  `python logmind.py --test`
- kept in your browser **only** if you tick *Remember in this browser*
- **Delete key** removes it from this browser immediately: storage entry,
  input field, and the remembered preference
- the connection check returns only *ok* and a message — never the key
- the call has a hard deadline; a wrong key or dead network shows a message
  and the report renders regardless

What deleting cannot reach: a copy you pasted elsewhere, your clipboard, or
your OS's memory. If a key was ever exposed, revoke it at the provider — that
is the only guaranteed removal, and it takes one click on either console.

## Interface

Dark-first data-dense dashboard, light theme remembered per browser.

- **First run** — hero, three-step explainer, and one-click demo attack cards
  instead of an empty box.
- **Results** — sticky status bar, stacked event timeline (with a "show the
  numbers" data table for screen readers), findings column plus a sticky
  sidebar holding the risk gauge, severity breakdown, top sources, and exports.
- **Evidence** — the IPs, usernames, and keywords that triggered each finding
  are highlighted inside the log lines, so you can see *why* it fired.
- **ATT&CK** — every technique badge links to attack.mitre.org.
- **Filters** — severity chips deep-link via the URL hash (`#sev=High`).
- **Export** — Markdown to clipboard, JSON download, or print/PDF.

Accessibility: keyboard operable with a skip link and visible focus rings,
44px touch targets, no horizontal scroll at 375px, `prefers-reduced-motion`
honoured, and every text pair measured at ≥4.5:1 in **both** themes.

Design tokens generated with `ui-ux-pro-max` — see
[design-system/logmind/MASTER.md](design-system/logmind/MASTER.md).

## Files

```
logmind.py                 engine, detectors, HTTP server, CLI, self-check
ui.html                    dashboard template (design system lives here)
watch.py                   live mode: tail, analyse, alert (never blocks)
evaluate.py                labelled benchmark -> EVALUATION.md
build_demo.py              renders demo.html, the static shareable snapshot
samples/brute_force.log    SSH brute force + spraying + botnet spread
samples/web_attack.log     scanner, SQLi, traversal that returned 200
samples/insider.log        off-hours access, privilege abuse, log clearing
design-system/             generated design tokens and rules
```

## Limits

Batch or live tail on one machine — no database, no multi-user, no agents on
other hosts, and no per-account baseline yet (it judges patterns, not "carol
never logs in from Brazil"). Uploads are capped at 5 MB and 50,000 lines. Detection is
heuristic: it finds these ten patterns, and finding nothing is not proof that
nothing happened.
