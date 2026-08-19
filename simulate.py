#!/usr/bin/env python3
"""Write a fake attack into a log file, one line at a time, so live mode has
something to find. Nothing is attacked - these are log lines, not traffic.

  python simulate.py                    # brute force into demo.log
  python simulate.py insider            # a different scenario
  python simulate.py --list             # what is available
  python simulate.py spray --file C:/logs/test.log --speed 0.2

Run LogMind first, then this in a second window:

  window 1:  python logmind.py --live
  window 2:  python simulate.py

The scenarios are the same generators the accuracy benchmark scores against,
so what you demo is exactly what was measured - see EVALUATION.md.
"""
import os
import random
import sys
import time
from datetime import datetime

from logmind import TS_RE
import evaluate

HERE = os.path.dirname(os.path.abspath(__file__))

SCENARIOS = {
    "brute":    (evaluate.s_brute_force,    "failed logins, then one succeeds"),
    "spray":    (evaluate.s_spray,          "one IP tries many usernames"),
    "burst":    (evaluate.s_burst_no_entry, "a flood of failures that never gets in"),
    "spread":   (evaluate.s_distributed,    "one account attacked from many IPs"),
    "web":      (evaluate.s_web_scan,       "scanner, SQL injection, path traversal"),
    "insider":  (evaluate.s_insider,        "off-hours login, then credential theft"),
    "cleanup":  (evaluate.s_tampering,      "auditd stopped and the log cleared"),
    "enumerate": (evaluate.s_enumeration,   "hunting for usernames that exist"),
}


def restamp(line, when):
    """Rewrite the line's timestamp to `when`, keeping whichever format it
    already uses - otherwise every line would look hours old to the window."""
    m = TS_RE.search(line)
    if not m:
        return line
    if m.group(1):
        new = when.strftime("%Y-%m-%d %H:%M:%S")
    elif m.group(2):
        new = when.strftime("%d/%b/%Y:%H:%M:%S")
    else:
        new = when.strftime("%b %d %H:%M:%S")
    return line[:m.start()] + new + line[m.end():]


def simulate(name="brute", path=None, speed=0.35):
    gen, blurb = SCENARIOS[name]
    path = path or os.path.join(HERE, "demo.log")
    text, expected, _ = gen(random.Random())
    lines = text.splitlines()

    print(f"Scenario : {name} - {blurb}")
    print(f"Writing  : {path}")
    print(f"Expect   : {', '.join(sorted(expected))}")
    print(f"{len(lines)} lines, about {len(lines) * speed:.0f}s. Ctrl+C to stop.\n")

    for i, line in enumerate(lines, 1):
        with open(path, "a", encoding="utf-8") as f:
            f.write(restamp(line, datetime.now()) + "\n")
        print(f"  [{i:3}/{len(lines)}] {line[:96]}")
        time.sleep(speed)
    print("\nDone. The finding should be on the live page within a few seconds.")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:]]
    if "--list" in args or "-h" in args or "--help" in args:
        print(__doc__)
        print("Scenarios:")
        for k, (_, blurb) in SCENARIOS.items():
            print(f"  {k:11} {blurb}")
        sys.exit()
    opts = {}
    name = "brute"
    i = 0
    while i < len(args):
        if args[i].startswith("--"):
            opts[args[i][2:]] = args[i + 1]
            i += 1
        else:
            name = args[i]
        i += 1
    if name not in SCENARIOS:
        sys.exit(f"unknown scenario '{name}'. Try: {', '.join(SCENARIOS)}")
    try:
        simulate(name, opts.get("file"), float(opts.get("speed", 0.35)))
    except KeyboardInterrupt:
        print("\nstopped")
