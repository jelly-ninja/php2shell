# php2shell: from OpenAI's "Patch the Planet" announcement to a working RCE on stock php:8.2.34

*The announcement described the lock in detail. Nobody shipped the key.
This is the timeline of how our one-container Docker lab rebuilt the
withheld exploit chain in three days — and the seven gates it had to pass.*

**Target:** stock `php:8.2.34-apache` (x86_64), libphp md5
`ce1f3c48ba22f8f17834ac791aead613` — unmodified, verified after every boot.
**Result:** `system("whoami>/tmp/x")` during request cleanup; `/tmp/x`
contains `www-data`; the worker survives; the HTTP response is a clean 200.
**Scope:** our own local Docker lab, nothing else. All targets are on the
vulnerable side of the patched releases (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).

---

## October 21, 2026: the announcement

OpenAI's **"Patch the Planet"** initiative announced its flagship case: two
critical vulnerabilities in PHP's POST handling — CVE-2026-109618 and
CVE-2026-109619, CVSS 9.2, remote code execution, exploitable before any
application code runs.

**What they said happened:**

- **Calif** found the bug **using GPT-5.6 Sol** under Patch the Planet;
  **Wiz independently discovered and reported both CVEs**. Credits:
  109618 = Calif, Wiz, OpenAI, Quarkslab; 109619 = Wiz, Calif, OpenAI.
- A **two-month secret coalition**: PHP maintainers, Wiz, Cloudflare,
  Corelight (Zeek/Suricata detection rules pre-shipped), CrowdStrike, and
  government partners — the White House "Super Intelligence Force", ONCD,
  CISA.
- The framing: *"Frontier AI found these vulnerabilities before attackers
  did"* — coining the **"Defender's Window"** for the secret prep period
  between discovery and disclosure.
- Shipped alongside: an `openai/php2shell-checker` Codex skill for
  operators, $1B in subsidized "Daybreak for Frontline Defenders" access,
  and a proposed 5-stage disclosure framework offered for community
  feedback.

**The same day, PHP shipped the fixes:** 8.5.12, 8.4.27, 8.3.36, 8.2.35.

## The timeline

| Date | Event |
| --- | --- |
| PHP 5.4 era | The vulnerable pattern enters the codebase (per Sansec, the class dates back ~14 years) |
| Aug–Oct 2026 | The secret coalition works the bug for two months |
| **Oct 17** | AWS observes exploitation attempts in the wild — *four days before disclosure* |
| **Oct 20** | Details leak (Huntress: "leaked critical PHP vulnerabilities") — the Defender's Window partially blown |
| **Oct 21** | Patches shipped; OpenAI's Patch the Planet announcement; watchTowr honeypots report **in-the-wild exploitation the same day** |
| **Oct 22** | Datadog Security Labs publishes the walkthrough that made the shape public |
| **Oct 22–24** | Our lab ports the shape to stock `php:8.2.34-apache` |
| **Oct 24** | `/tmp/x` contains `www-data` — the withheld chain, rebuilt |

## What the announcement didn't ship

The chain itself. CrowdStrike's part of the disclosure *admits* a working
exploit exists — consistent across x86-64 **and** ARM, survives worker
restarts, **defeats ASLR using only HTTP requests** — with zero code.
Calif's writeup stops at mechanics ("we achieved RCE"). Every public PoC
stops at the memory-disclosure primitive. The working weapon lives inside
the coalition, and exits nowhere public.

And the "before attackers did" window lasted exactly as long as the secret:
details leaked Oct 20, honeypots caught exploitation within about a day of
the patches.

That's the gap this article sits in. Everything below is what it took to
rebuild the missing half — the *shape* was public as of Datadog's
walkthrough; the *constants* were not; and the difference between them is
the whole story.

## Where we were before Datadog: the sea

For weeks the lab ran on probabilistic grooming. The idea was simple: POST a
huge multipart body — a "sea" of allocations — hope the freed chunks land in
the right malloc bin, crash the request at a memory-exhaustion fatal, and
inspect the core dump of the dead worker. The outcome was always the same:
cores full of junk. Sometimes the crash pointer held ASCII from an old
request, sometimes unmapped garbage, never anything we controlled. We had
laws — tcache is LIFO, memory is retained between requests, the crash walk
reads buckets 32 bytes apart — but no control over *what* sat in the bucket
when the walk arrived. Every miss looked identical to every other miss.

That's the honest baseline. The bug class was understood; the *grooming* was
guesswork. The announcement had told the world the lock existed — and, two
days later, Datadog's post showed its shape.

## The Datadog moment

On **October 22, 2026**, Datadog Security Labs released their walkthrough:
[*PHP2Shell — Critical vulnerabilities in PHP (CVE-2026-109618, CVE-2026-109619)*](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/).
Context for why that date mattered: PHP shipped the fixes on October 21
(CVSS 9.2 on both CVEs), AWS had already seen exploitation attempts in the
wild **four days before disclosure**, watchTowr published the same day, and
the bug class itself dates back to PHP 5.4. This was a live fire, and the
public write-ups were forensic, not instructional.

Datadog's post changed our lab in one afternoon. Four things mattered:

**1. The deterministic body shape.** No multipart, no sea. A plain
`application/x-www-form-urlencoded` body with three fields, each with a job:

```
=<binary value>&a=1&<very long field name>[x]=1
```

- the **empty-name field** plants controlled bytes (PHP parses it, copies
  the value, then frees the copies because the name is empty);
- **`a=1`** forces PHP to allocate the hash-table storage right after —
  into the memory just freed;
- the **oversized name with `[x]`** drives the array-insertion path that
  increments the table's counters *before* allocating the key
  (`zend_hash.c`, `_zend_hash_str_add_or_update_i()`). When the key copy
  blows `memory_limit`, the fatal leaves a counted-but-never-initialized
  bucket behind — a slot full of whatever bytes were there before.
  Ours is the *same* counter-before-key sequence we had confirmed in the
  8.2.34 source at `zend_hash.c:1110`.

**2. The fatal signature is a ruler, not a mystery.** Their lab fatal:

```
PHP Fatal error: Allowed memory size of 16777216 bytes exhausted
(tried to allocate 3500032 bytes) in Unknown on line 0
```

`tried to allocate 3500032` = 3,500,000 + 32 — the key-alloc of a 3.5 MB
field name, plus a fixed 32-byte string header. That means the failure point
is *tunable*: the field-name length **is** the allocation size. `Unknown on
line 0` proves it died during request initialization, before any
application code — which is also why authentication can't stop this.

**3. The stage settings.** `memory_limit=16M` and POST parsing on. The 16M
limit makes the oversized name the *only* allocation that fails, at a
predictable point, with everything before it intact.

**4. The win-shape.** Their refined exploit returns **HTTP 200**, the
worker keeps running, and `system()` executes during cleanup. A successful
exploit doesn't crash anything — which also means "no 500" proves nothing.

One more thing their post made explicit: a small hash table (8 elements)
uses a **320-byte allocation** on their build, and their planted value was
sized (276 bytes + string header) to land in that same size class. That's
the whole grooming theory in one sentence: *free a chunk of size class X,
make the table allocate its array from size class X, and the stale bucket
reads your bytes.*

## Porting to stock php:8.2.34-apache

Their lab: PHP 8.5.11 built from source, Debian 12, ARM64. Ours: the
official Docker image, x86_64, nobody's debug build. Every constant they
quoted — bin sizes, offsets, struct layout — had to be re-measured for our
binary. Method was the same as theirs in spirit, stricter in one rule we
kept from the sea era: **every claim needs an artifact** — a core dump, an
md5, a log line. A plausible theory is a hypothesis until a core confirms it.

Lab rig: `php_vuln` on port 8083, booted with `--ulimit core=-1` and
`SYS_PTRACE` so crashed workers dump cores; `phpbuild` as the analysis
container with the matching unstripped `libphp.so` (md5-matched to the
target) for symbols and source at `/usr/src/php-8.2.34/`. A tiny
`oom_mod.php` fires the body; the driver sweeps parameters, checks
`test -f /tmp/x` after every attempt, and pulls cores for decoding.

## The killer bug: percent-encoding

First port of the body shape failed *silently* — the worst way. Every
attempt returned a clean 200 with the DV fatal, no crash, no SIG8 in any
core. Weeks of sea-era failures look exactly like this, and we nearly
concluded the groom concept didn't port.

The bug was ours, and it was encoding. My body builder percent-encoded the
planted value — the *correct* instinct for any normal form library. But the
urlencoded decoder allocates the **decoded** value by wire length first, and
every `%XX` triple collapses to one byte: our 295 payload bytes became
**885 wire bytes**. The freed chunk sat in the ~960-byte bin. The table's
array allocates from the ~320-byte bin. Different size classes = the tcache
never hands the table our chunk = the unfinished bucket reads random
leftovers, forever.

The fix is one law: **the wire length of the raw value IS the groom size.**
Send the value as raw bytes (avoiding `%`, `&`, `+` so nothing gets
re-encoded) and size it so wire length + header lands in the target bin.
After the fix, the very next run crashed.

## First crash: our own filler

All five tested value lengths crashed on the first try, and the crash
pointer register held `0xdededededededede` — not junk. `0xde` was **our
filler byte**, padding the planted value. The cleanup walk had dereferenced
a bucket containing *our* payload. Capture: confirmed. Offset: wrong — the
walk read filler where we had written our pointer, and our pointer sat in a
slot that the `a=1` bucket had already overwritten.

## Reading geometry out of a core dump

The core around the walk cursor (`rbx` in `zend_array_destroy`) settled it.
Our `0x0106` type marker and a 16-byte zero run survived at exact spacing —
but shifted 32 bytes from where we wrote them. Conclusion, measured not
guessed: with a 16-byte hash-slot prefix, **bucket 1 starts at value+72**:

| planted offset | meaning |
| --- | --- |
| v+72 | `zval.val` — the pointer the walk loads |
| v+80 | `zval.u1.type_info` |
| v+88 | `zval.h` |
| v+96 | bucket key — read **last**, after the crash instruction |

We re-ran with the pointer at v+72 and a canary value
(`0x51e2c0de51e2c0de`) in it. The **measure gate passed on the first try**:

```
measure rdi=0x51e2c0de51e2c0de want=0x51e2c0de51e2c0de
```

The crash pointer was *exactly* the value we planted. That's the moment the
campaign changed character: we didn't hope for a useful crash anymore — we
**command** what the cleanup walk dereferences. Parameters, for the record:
planted value 295 bytes, N = 3,500,000 `Z`s, first try.

## Arming: fake object → system()

From the measure core we read the planted chunk's live heap address, and
the fake-object base follows: **B = (SIG8 address − 72) + 96**, which
landed on `0x7f3be0868158` — and automatically satisfied the alignment
constraints the object path needs (byte 0 ≡ 8 mod 16, bit 8 set, bit 9
clear). At k=96 inside the value we packed the proven 184-byte fake
`zend_object`: refcount 1, type `IS_OBJECT`, handlers table pointer at
B+0x68, and `free_obj` — the destructor slot at table+8 — aimed at
`base + zif_system` (PHP's `system()` implementation, file offset
`0x39b8a0` in our libphp). The command travels as a proper string zval:
`whoami>/tmp/x`, length 13.

The first armed run crashed *inside* `zif_system` — at its **first
instruction**, with the full chain verified in the core: walk → refcount-0
→ `rc_dtor_func` → `store_del` → `call *0x8(%rdi)` with rdi = our B exactly,
and the command zval decoding clean in the register window. Everything was
right except one number: we had jumped to the raw **file** offset. The
driver imports the build module and calls its body builder directly — which
skips the code that resolves the **load base** — so the handler pointer was
built with `BASE = 0`.

Fix: read the real base at fire time from `/proc/1/maps` of the Apache
master (`0x7f3be24ae000`), cross-checked against the core-derived base
(crash RIP minus known function offset gave the same number). Forked
workers inherit the mapping — ASLR randomizes per *boot*, not per request
in this model, which is the same reason a leak like Wiz's PHPSESSID
technique is worth so much to real attackers.

## The win

```
  body[:180]: '<br />\n<b>Fatal error</b>:  Allowed memory size of
  16777216 bytes exhausted (tried to allocate 3500032 bytes) in <b>Unknown</b>
  on line <b>0</b><br />\n'
  alloc=3500032 delta_vs_N=+32 <-- KEY-ALLOC FATAL (DV point)
arm done, no x after 3 tries
final x: X_EXISTS:www-data
=== done ===
```

Verified independently, outside the driver:

```
-rw-r--r-- 1 www-data www-data 9 Oct 23 18:06 /tmp/x
www-data
md5: e617cca2dc3a09a36a846dab7467a64d
```

The exact Datadog win-shape: the response is the ordinary
memory-exhaustion fatal (a clean 200), the worker survives, and the command
ran during cleanup — `system("whoami>/tmp/x")` executing as `www-data` on a
stock, unmodified runtime that no application-level defense can reach,
because the whole chain runs before any PHP script.

## The seven gates

The chain only works if every stage hands the next one a proven invariant.
Ours, in order:

**Gate 1 — Predictable failure.** One oversized urlencoded field name; the
fatal reads `tried to allocate N+32 ... in Unknown on line 0`. The failure
point is the key allocation at hash-insert (`zend_hash.c:1110`), tunable by
N, and it fires before any application code. N = 3,500,000 → `3500032`,
byte-for-byte Datadog's signature.

**Gate 2 — Capture.** The freed field-value buffer must land in the same
malloc size class the hash table allocates from, so the stale bucket reads
*our* bytes. Evidence standard: the crash pointer holds our filler
(`0xdedede…`), not foreign ASCII. This gate stayed invisible until we
killed the percent-encoding bug — the wire length of the raw value IS the
groom size.

**Gate 3 — Geometry.** Know exactly where the walk reads. The core dump
answered: bucket 1 starts at value+72; val/type/h/key sit at
+72/+80/+88/+96, and the key is read last. Measured from surviving markers
in the core, not derived from hope.

**Gate 4 — Measure: command the crash.** Plant a canary pointer at v+72:
`measure rdi=0x51e2c0de51e2c0de want=0x51e2c0de51e2c0de`, first try. From
this gate on, the walk dereferences whatever we choose.

**Gate 5 — Dispatch.** Swap the canary for a fake `zend_object` (type
IS_OBJECT, refcount 1): the walk's refcount-0 path runs `rc_dtor_func` →
`store_del` → `call *0x8(%rdi)` — the destructor slot — with rdi = our
object base exactly. The first arm run proved the jump landed on
`zif_system`'s first instruction.

**Gate 6 — Relocation.** A function pointer is only as good as its base.
That first arm jumped to the raw file offset (the BASE=0 bug) and died
unmapped. Reading the live load base from `/proc/1/maps` — cross-checked
against the core-derived base — turned the jump into a real call.

**Gate 7 — Win.** The command string zval survives `system()`'s prologue:
`whoami>/tmp/x` runs as `www-data` during cleanup, the response is the
ordinary memory fatal (clean 200), the worker survives — and `/tmp/x`
exists with the right md5.

Gates 1–3 are the groom. Gate 4 is the pivot from hoping to commanding.
Gates 5–6 are the arm. Gate 7 is the only one that counts.

## Did they really patch it? Yes — verified

We didn't take the fix on faith. We diffed the sources and fired the exact
winning groom at a real `php:8.2.35-apache` container.

**What changed in the source** (8.2.34 → 8.2.35): the POST-parsing path
gained an out-of-memory check after *every* allocation — including the
`estrndup` of each field value and the exact key allocation whose failure
was our fatal point. On exhaustion, parsing now unwinds cleanly: free the
value, abort the request, leave nothing behind. The NEWS entry names it:
"Fixed ... Avoid state corruption via bailout." Around it: GPC arrays
switched to `array_init_singleton` (no more classic bucket tables at our
capture size), 21 hunks of rework in the very `zend_hash.c` walk we
hijacked, and a new regression suite — `oom_request_parsing.phpt`,
`oom_pending_at_shutdown.phpt` and ~150 siblings — that treats this attack
class as a permanent test target.

**What the live probe measured**: same body, same constants (SIG8 at v+72,
VLEN 295, N swept 3.2M–3.8M). On 8.2.34, five of five runs died at N+32 —
the key allocation of hash-insert — and the shutdown walk segfaulted.
On 8.2.35: zero of five. Every run fatals at a *different* allocation
(N+1072, N+528, N+2080, N+3632, N+1088) — wherever the memory budget
happens to run out — with no crash, no core, no `/tmp/x`. The vulnerable
signature is gone. The parse never reaches the corrupted state, so there
is nothing left at shutdown to exploit.

The Defender's Window held. When the disclosure landed, the patched
releases were already waiting.

## What Datadog got right — and what only measurement gives

The post is a model of responsible disclosure research: full mechanics, no
copy-paste weapon. It gave us the *shape* — the deterministic three-field
body, the tunable fatal, the stage settings, the win conditions. What it
cannot give anyone is the *constants*: bin sizes, bucket offsets, struct
field offsets, symbol addresses, the load base. Those are properties of
your exact binary, and we got every one of them the same way — crash the
lab target, pull the core, read the truth out of it. The percent-encoding
bug is the cautionary tale: the concept was right for weeks while one wire
format detail silently guaranteed failure. Artifacts, not theories, ended
every stuck phase in this campaign.

## For defenders

- **Patch.** 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or vendor backports).
- **Configuration works — measured.** We fired the exact winning groom
  (plus a 7.7 MB adversarial max-alloc body) at the same stock vulnerable
  `php:8.2.34-apache` binary with production-default ini
  (`memory_limit=128M`, `post_max_size=8M`, `max_input_vars=1000`):
  clean HTTP 200 every time, no fatal, no segfault, no core, no shell.
  The chain needs the memory_limit fatal to fire *during* POST parsing —
  keep `memory_limit` at least ~2× your `post_max_size` (parse roughly
  doubles wire allocations) and the trigger becomes unreachable. The win
  lab's `16M / 4096M` ratio is the exploit's home turf; don't live there.
  Note `max_input_vars` alone does nothing here: one field name is one
  variable, and 3 variables is under any sane limit.
- **Detect on the trio**, correlated: ~3.5 MB urlencoded form field names
  with raw control bytes in field *values*; `memory size ... exhausted
  (tried to allocate ...) ... in Unknown on line 0` in the PHP log; shells
  spawned by Apache/php-fpm workers. Datadog's post ships the WAF/IDS
  shapes; NCSC-NL maintains a defensive tracker with detection rules and
  affected-vendor inventory — both are built from real captured traffic,
  and our measured field sizes (295-byte value, 3.5 MB name) sit exactly
  in their detection envelope.
- **Don't trust HTTP status or worker health.** Our successful run looks
  like a routine 413-adjacent fatal in the access log.

## Artifacts

Everything in this story is in the repo: `oom141.py` (measure/arms driver,
groom body builder), `oom141h.py` (arm phase with live-base resolution),
`STATE.md` (full campaign record with every law and every dead end),
`instr/` (instrumented Zend sources used to settle the geometry), and the
per-round output logs `oom110` → `oom141h2` — including all the failures
reproduced above.

*Rebuilt from public shape + our own core dumps in three days. The
coalition had two months, five orgs, and the source. We had a Docker
container, Datadog's walkthrough, and a rule that every claim needs an
artifact.*
