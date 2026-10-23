#!/usr/bin/env python3
"""oom57: DISCRIMINATOR — instrumented module + lab ini + BENIGN-ONLY soak.
If instrument alone crashes (no attack poison delivered), the rdi=0x08 core
is an instrument artifact. If benign-only is clean and attack crashes (oom56),
the poison delivery is causal. 60 benign posts incl. large-ish bodies,
new-segv watch throughout."""
import re
import subprocess
import time
import urllib.request

LAB = "http://127.0.0.1:8081"
LIB = "/usr/lib/apache2/modules/libphp.so"


def sh(cmd, timeout=20, retries=2):
    for _ in range(retries + 1):
        try:
            r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                               capture_output=True, timeout=timeout)
            return (r.stdout.decode("latin1") + r.stderr.decode("latin1")[:150]).strip()
        except subprocess.TimeoutExpired:
            time.sleep(1)
    return "<<EXEC TIMEOUT>>"


def logs():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=90)
    return (r.stdout + r.stderr).decode("latin1", "replace")


def http(path, body=None, ctype=None, timeout=20):
    req = urllib.request.Request(LAB + path, data=body)
    if ctype:
        req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("latin1", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("latin1", "replace")[:120]
    except Exception as e:
        return type(e).__name__, str(e)[:120]


def main():
    print("[module md5]", sh("md5sum %s | cut -c1-8" % LIB), "(501 owner = instr)", flush=True)
    c, probe = http("/oom_sapi.php", timeout=8)
    print("[ini]", c, probe[:60], flush=True)
    base = len(re.findall(r"exit signal Segmentation", logs()))
    print("[baseline] segv=%d" % base, flush=True)
    failures = 0
    for i in range(60):
        # benign: small and medium multipart posts, no poison names
        if i % 3 == 0:
            body = (b"--BOUND\r\nContent-Disposition: form-data; name=\"f" +
                    str(i).encode() + b"\"\r\n\r\n" + b"v" * 300000 + b"\r\n--BOUND--\r\n")
        else:
            body = (b"--BOUND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--BOUND--\r\n")
        code, text = http("/oom_mod.php", body,
                          "multipart/form-data; boundary=BOUND", 20)
        if not (code == 200 and ("POSTCOUNT=1" in text or "Fatal error" in text)):
            failures += 1
            print("  benign%d: %s %r <<< ABNORMAL" % (i, code, text[:80]), flush=True)
        if i % 10 == 9:
            now = len(re.findall(r"exit signal Segmentation", logs()))
            print("  ..%d ok new_segv=%d" % (i + 1, now - base), flush=True)
            if now > base:
                print("[VERDICT] instrument crashed WITHOUT attack -> artifact", flush=True)
                return
    time.sleep(2)
    now = len(re.findall(r"exit signal Segmentation", logs()))
    print("[VERDICT] benign_soak=%d failures=%d new_segv=%d -> %s"
          % (60, failures, now - base,
             "ARTIFACT (instrument alone crashes)" if now > base else "INSTRUMENT CLEAN — poison delivery causal"), flush=True)


if __name__ == "__main__":
    main()
