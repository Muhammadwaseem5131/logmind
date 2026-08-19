#!/usr/bin/env python3
"""Build demo.html - one self-contained page showing all three sample reports.

For sharing a link with someone who will not install Python. The real tool
needs the server; this is a frozen snapshot of its output.

  python build_demo.py
"""
import os
import re

from logmind import (DEMO_BLURBS, HERE, SAMPLES, analyze, demo_files, icon,
                     render_results)

NOTE = (
    '<p class="note">Static snapshot of three analysed logs &mdash; the live '
    'tool (paste your own log, filter, export) runs locally with '
    '<code>python logmind.py</code>. Source: '
    '<a href="https://github.com/">github repository</a>.</p>')


def build():
    tpl = open(os.path.join(HERE, "ui.html"), encoding="utf-8").read()
    tpl = re.sub(r"<!--FORM-->.*?<!--/FORM-->", NOTE, tpl, flags=re.S)
    assert "<form" not in tpl, "form survived the strip"

    hero = ('<section class="hero"><h1>Understand your security logs in '
            'seconds</h1><p class="lede">LogMind reads raw log files, finds the '
            'patterns that matter, and explains each one in plain language with '
            'a risk level, the evidence, the MITRE ATT&amp;CK technique, and the '
            'actions to take. Ten detectors, measured at 0.89 macro F1 on a '
            '105-log labelled benchmark. Python standard library only.</p>'
            '<ul class="facts"><li><strong>10</strong> detectors</li>'
            '<li><strong>0.89</strong> macro F1</li>'
            '<li><strong>0</strong> dependencies</li>'
            '<li><strong>3</strong> reports below</li></ul></section>')

    blocks = []
    for i, f in enumerate(demo_files(), 1):
        title, blurb = DEMO_BLURBS.get(f, (f, ""))
        rep = analyze(open(os.path.join(SAMPLES, f), encoding="utf-8").read())
        blocks.append(f'<h2 class="section-h">{icon("bolt")} Report {i} &mdash; '
                      f'{title}</h2><p class="lede" style="font-size:15px">'
                      f'{blurb}. Source file: <code>samples/{f}</code></p>'
                      + render_results(rep, static=True, idx=i))

    out = (tpl.replace("{{HERO}}", hero)
              .replace("{{RESULTS}}", "\n".join(blocks))
              .replace("{{LOG}}", "").replace("{{DEMOS}}", ""))
    assert "{{" not in out, "unfilled placeholder"
    assert out.count('id="reportJson"') == 0, "export payloads leaked in"
    path = os.path.join(HERE, "demo.html")
    open(path, "w", encoding="utf-8").write(out)
    print(f"wrote {path}  ({len(out):,} bytes, {len(blocks)} reports)")
    return path


if __name__ == "__main__":
    build()
