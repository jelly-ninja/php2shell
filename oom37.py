#!/usr/bin/env python3
"""oom37: page-granular limit sweep — geometry name=3576 (keys 3602B=1 page,
cycle net +1 page). Death = chunk-tail page countdown hitting <need at some
ask. Sweeping LIMIT in 4096B (1 page) steps shifts the countdown by exactly
one ask; hunting the limit where it hits zero AT THE KEY ASK.
Detector: keycommit without following keyok, or RC 139.
usage: oom37.py [lo] [hi] [step=4096]
"""
import re
import sys

exec(open("/tmp/phplab/oom33.py").read().replace('if __name__ == "__main__":', 'if False:'))

NAMELEN = 3576


def decode_lim(limit, build):
    rc, tr = run(build(), limit)
    commits = [(m.start(), m.group(2), m.group(3))
               for m in re.finditer(r"TRACE keycommit stage=(\d+) elem=(\d+) free=(\d+)", tr)]
    ok_positions = [m.start() for m in re.finditer(r"TRACE keyok", tr)]
    last = commits[-1] if commits else None
    key_death = last is not None and not any(p > last[0] for p in ok_positions)
    tried = re.findall(r"tried to allocate (\d+) bytes", tr)
    rcnum = rc.replace("RC=", "")
    if key_death or rcnum == "139":
        i = tr.rfind("TRACE keycommit")
        print("lim=%d rc=%s *** KEY DEATH elem=%s free=%s tried=%s ***" %
              (limit, rcnum, last[1], last[2], tried[-1] if tried else "-"), flush=True)
        ctx = [l for l in tr[max(0, i - 700):i + 300].splitlines()
               if ("TRACE" in l or "tried" in l or "Allowed" in l)][-14:]
        print("\n".join(ctx))
        print("---")
        return True
    tag = "fatal:" + (tried[-1] if tried else "?") if "Allowed memory" in tr else "survive"
    print("lim=%d rc=%s %s commits=%d oks=%d" %
          (limit, rcnum, tag, len(commits), len(ok_positions)), flush=True)
    return False


if __name__ == "__main__":
    lo = int(sys.argv[1]) if len(sys.argv) > 1 else 20_700_000
    hi = int(sys.argv[2]) if len(sys.argv) > 2 else 21_000_000
    step = int(sys.argv[3]) if len(sys.argv) > 3 else 4096
    build = make_builder(NAMELEN)
    for lim in range(lo, hi + 1, step):
        if decode_lim(lim, build):
            break
