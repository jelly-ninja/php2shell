#!/usr/bin/env python3
"""oom32: victim decode — for each k, classify exactly which ask dies at LIMIT.
Victim classes by tried-size: 4096=refill, 8192/20480=linebuf, 1310720/40960=resize.
Key death = last keycommit has NO keyok after it (post-commit window open).
RC 139 = SIGSEGV = corruption materialized.
usage: oom32.py [k_start] [k_end]
"""
import re
import subprocess
import sys

exec(open("/tmp/phplab/oom31.py").read().replace('if __name__ == "__main__":\n    main()', ''))

LIMIT = 20_800_000


def decode(k):
    body = build(k)
    rc, tr = run(body, LIMIT)
    commits = [(m.start(), m.group(1), m.group(2), m.group(3))
               for m in re.finditer(r"TRACE keycommit stage=(\d+) elem=(\d+) free=(\d+)", tr)]
    ok_positions = [m.start() for m in re.finditer(r"TRACE keyok", tr)]
    last = commits[-1] if commits else None
    key_death = last is not None and not any(p > last[0] for p in ok_positions)
    tried = re.findall(r"tried to allocate (\d+) bytes", tr)
    rcnum = rc.replace("RC=", "")
    cls = {"4096": "refill", "8192": "linebuf1", "20480": "linebuf2",
           "1310720": "resize-big", "40960": "resize512"}.get(tried[-1] if tried else "?", "other")
    tag = ("*** KEY DEATH elem=%s free=%s ***" % (last[2], last[3])) if key_death else (
        "fatal:%s(%s)" % (cls, tried[-1] if tried else "-") if "Allowed memory" in tr else "survive")
    print("k=%d rc=%s %s commits=%d oks=%d" %
          (k, rcnum, tag, len(commits), len(ok_positions)), flush=True)
    if key_death or rcnum == "139":
        i = tr.rfind("TRACE keycommit")
        print(tr[max(0, i - 1200):i + 400])
        print("---")
        return True
    return False


for k in range(int(sys.argv[1]) if len(sys.argv) > 1 else 0,
               int(sys.argv[2]) if len(sys.argv) > 2 else 7):
    if decode(k):
        break
