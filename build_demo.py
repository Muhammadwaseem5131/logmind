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
    '<a href="https://github.com/Muhammadwaseem5131/logmind">github.com/Muhammadwaseem5131/logmind</a>.</p>')


LIVE_LINK = (
    '<a class="btn ghost" href="https://github.com/Muhammadwaseem5131/logmind"'
    ' title="Live monitoring runs on your own machine">Get it on GitHub</a>')


NOT_FOUND = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LogMind - page not here</title>
<style>
:root{color-scheme:light dark;--bg:#F6F7F9;--card:#fff;--ink:#16202E;
 --muted:#576678;--rule:#D8DEE7;--link:#1D4ED8}
@media (prefers-color-scheme:dark){:root{--bg:#0A0F17;--card:#121A26;
 --ink:#E8EEF6;--muted:#93A3B8;--rule:#26313F;--link:#8AB4FF}}
body{margin:0;background:var(--bg);color:var(--ink);display:grid;
 place-items:center;min-height:100vh;padding:24px;
 font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:56ch;background:var(--card);border:1px solid var(--rule);
 border-radius:10px;padding:32px}
h1{margin:0 0 8px;font-size:24px}
p{margin:0 0 16px;color:var(--muted)}
code{font:14px ui-monospace,Consolas,monospace;background:var(--bg);
 padding:2px 6px;border-radius:4px;color:var(--ink)}
a{color:var(--link)}
.row{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px}
.btn{display:inline-block;padding:10px 16px;border-radius:6px;
 background:var(--link);color:#fff;text-decoration:none;font-weight:500}
.btn.ghost{background:transparent;color:var(--ink);border:1px solid var(--rule)}
</style></head><body><main>
<h1>That page lives on your own machine</h1>
<p>Live monitoring watches the logs of the computer LogMind is running on, so
it only exists while the tool is running locally. This site is a static
snapshot of three analysed reports.</p>
<p>To get live monitoring, clone the repository and run
<code>python logmind.py --live</code> — or double-click <code>start.bat</code>
on Windows.</p>
<div class="row">
  <a class="btn" href="/logmind/">See the analysed reports</a>
  <a class="btn ghost" href="https://github.com/Muhammadwaseem5131/logmind">Get it on GitHub</a>
</div>
</main></body></html>
"""


def build():
    tpl = open(os.path.join(HERE, "ui.html"), encoding="utf-8").read()
    tpl = re.sub(r"<!--FORM-->.*?<!--/FORM-->", NOTE, tpl, flags=re.S)
    # Live monitoring needs the local server; on static hosting the link 404s.
    tpl = re.sub(r"<!--LIVE-->.*?<!--/LIVE-->", LIVE_LINK, tpl, flags=re.S)
    assert "<form" not in tpl, "form survived the strip"
    assert 'href="/' not in tpl, "a server-only link survived into the static page"

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

    # GitHub Pages serves 404.html for any unknown path. Someone arriving with
    # a cached copy of an older page - or a bookmarked /live - lands here
    # instead of a dead end.
    open(os.path.join(HERE, "404.html"), "w", encoding="utf-8").write(NOT_FOUND)
    print(f"wrote {path}  ({len(out):,} bytes, {len(blocks)} reports)")
    return path


if __name__ == "__main__":
    build()
