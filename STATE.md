# STATE.md — php2shell lab (moved to ~/Projects/queue/php2shell-lab)

## HEADLINE (2026-10-23 night, oom84–98) — WALK LAW DECODED; SELF-SCAN AIMING LIVE; ONE AIMED SEQUENCE IN FLIGHT

Everything except "which slot does the walk read in AIM-armed boots" is
measured. Laws:

### oom84–98 laws (2026-10-23 night)
- **Walk-slot drift**: probe boots read slot 32 (oom85) vs 8 (oom88) —
  the walked slot VARIES per arm. Never reuse a slot across arms.
- **One armed crash per boot** (176B tiles): the first crash consumes
  the arm; probe-then-aim in one boot impossible. Converge across boots.
- **oom93-B core = dispatch-moment proof**: walk READ the planted pointer
  (rdi=OBJ, crash at zend_array_destroy+539 dec). Pointer arm works;
  the OBJ address was stale (cross-boot ASLR) — aim must be same-boot.
- **Object layout (source)**: handle@+8 (gc=8B!), handlers@+0x18,
  num_args frame+44, argz frame+80, gs rc/type/len <IIQI>, cmd@g+16.
  ti=0x108 correct (DESTRUCTOR_CALLED=1<<8; 0x208 sets IS_OBJ_FREE_CALLED
  =1<<9 which SKIPS free_obj). zif_system arg check: type byte == 6 at
  argz+8 (cmpb $0x6,0x58(%rdi)).
- **zval-type law (oom91b/c)**: walked zval type-info read from [S+8];
  0x5a (ref) or 1 (undef) SKIP dispatch; with 8-periodic pointer tile
  the ti is the next pointer copy -> low nibble 8 (IS_OBJECT) +
  bit8 refcounted — boot-independent because regions are 2MB-aligned
  (OBJ suffix 0x…17C8).
- **Region picker law**: content regions are 0x7f… mmap'd; Apache brk
  arena can be 0x55… AND >=2MB -> require va0 >= 0x7f0000000000.
  Pattern sits at R+0x1718 in EVERY content region (c93_B0 scan).
- **Port law**: a stray `bun` process bound host 8081 -> all requests
  hit a fake 404 server ("not found" body = known-fake signature).
  Container internally answered 200. Check `lsof -iTCP:8081`.
- **Container recreation**: php:8.2.34-apache docroot = /var/www/html;
  needs ini docker-cp + apache2ctl restart; SYS_PTRACE cap addable but
  NOT needed (self-scan below).
- **SELF-SCAN (oom98, the winning instrument)**: worker reads its OWN
  /proc/self/mem (no caps needed) via /tmp/phplab/oom_probe.php:
  GET /oom_probe.php?h=<hex> -> "R=<va0> d=<offsets> pid=N";
  ?read=<va>&n=<n> -> hex readback. Sent report found pattern at
  R=0x7f8039a00000 off=0x670f8. V measured per boot, zero crashes.
- Aim design (oom98): OBJ = V+off, off>=352 (BLOCK copies must not cover
  observed walk slots 8/32/158), 16-aligned+8, refcounted bit 1;
  8-periodic OBJ pointer tile except BLOCK window; BLOCK = obj_block()
  with free_obj = &zif_system = libphp_base+0x39b8a0.


- Same-envelope law: fat values (1537B tile) must shrink names by exactly
  1536 (multiple of 16) or the crash geometry dies (oom71A proven).
- Values carrier: NUL-safe; stride 3584B; copy0 at heap+0x1718 in every
  observed boot; copy0 VA readable from the crash core via PT_LOAD parse.
- ASLR: bases per-boot, SHARED by all prefork children; readable from
  /proc/pid/maps; heap = the only anon rw-p region >= 2MB.
- Dispatch chain verified in source: subl $1,(%rdi) at +539; zero ->
  rc_dtor_func -> store_del -> handlers->free_obj(obj); free_obj can be
  zif_system (cmd zval at frame+80, string type 6 check at +88).
- Correct object layout (P = copy0+8): rc@P+0=1, ti@P+4, handle@P+16=1,
  handlers@P+32, num_args@P+44=1, argz@P+80{P+104,6,0}, gs@P+104
  {rc=1,ti=0x106,len=13}, cmd@P+136, table@P+152{0,&zif_system}.
- F-artifact law (oom83 closure): CAL marker tile has identical markers
  at slots 0/32/88/160 -> core_phi always returned 0. TRUE walk slot in
  AIM-armed boots is 32 or 88 (everything else eliminated: 0/160 silent
  even with INVALID pointers, oom82/83; 32 decs table zeros = silent;
  88 decs gs.rc 1->0 = string-release silent).
- zif control check: disable_functions empty, no suhosin (oom81).
- Population law: CAL warm arms MULTIPLE workers; crashes sample them
  one per crash; AIM workers must be armed with AIM tiles (oom79-80).

NEXT (single step): distinguishable-marker CAL (0x2222@32, 0x8888@88)
-> crash rdi names the true slot -> put TARGET there -> whoami.

## HEADLINE (2026-10-23, oom68–69c) — RDI CONTROL ON STOCK PATH: PROVEN

Step 2 (payload shaping) milestone reached on UNMODIFIED php:8.2.34-apache:

- oom68 (sacrifice model): warm-up → one sacrificial fatal fire → then
  4/6 (boot A) and 3/3 (boot B) crashes; NO re-warmup after restart = 0/3.
  Recipe = warm → sacrifice → fires; arming does NOT survive restart.
- payload68.py: drop-in builder (defaults byte-identical to oom67, self-
  checked). Weaponized mode tiles KEY fillers with a periodic 16-byte
  cell C aimed by reclaim PHASE (stock phase = 7, measured).
- oom69b (all bodies patterned, target 0x414141414141):
  rdi = 0x417a7a7a7a7a7a7a ×3 — value bytes ARE our pattern (K crash gone).
- oom69c (phase-7 aim): rdi = 0x7a7a414141414141 ×3/3 EXACT as aimed.
  Stable within boot; survivor rate 1/4 (single sacrifice enough).
- Source verdicts (PAYLOAD68.md): destroy path = rc_dtor_func[type]
  dispatch; empirical crash = OOB slot 122 wild call, rdi = zval.value;
  free_obj(object) is the clean path (slot #1, rdi = object addr,
  ce deref skippable via default dtor_obj). NUL: names NO, values YES.
- Next (v2): value-carrier (NUL-safe) → real-shaped pointers
  (0x00007f…), type byte 0x08 → fake zend_object → free_obj → system;
  needs measured obj/table/system addresses (ASLR oracle program).

Previous milestone: stock-path crash proven + reproducible (oom65–67).
**Pure unmodified php:8.2.34-apache mod_php crashes via HTTP upload.**
Core #0: `zend_array_destroy+539` (stock binary), rdi=`0x4b4b4b4b4b4b4b4b`
= our 'K' filler bytes read AS A POINTER. Call chain php_handler →
php_request_shutdown → zend_array_destroy. md5-verified stock (`ce1f3c48`).

### The recipe is a SEQUENCE (reproduced on 2 independent boots):
1. Lab ini: `memory_limit=8M` (NOT 19.6M — that was instrument-tuned;
   stock dies at the same resize point at 8M), `max_input_vars=100000`,
   `post_max_size=4096M`.
2. Warm-up: ~11 OOM deaths, k1 ascending 1900→3200 (heap shaping).
3. Finisher: k1=3400 body (P=40-page stamped poison, KEYLEN=3064,
   prep=3) → crashes ~75% (broken-pipe mid-upload, core in /tmp).
   Fresh boot + finisher alone (no warm-up) = 0/18 (oom66).
4. Sensor note: OOM fatals return HTTP 200; warning is in the RESPONSE
   BODY (display_errors on) — read bodies, not just logs.

### Reread of oom58–60 (instrument era): evidence VALID as instrumented-
build behavior; the tuned recipe (lim=19.6M, k1=2044) does NOT transfer
to stock (oom61: 4/4 clean) — different alloc overhead → different
geometry. Address-stability result (same cell #30433, slot 3956+offset,
9/9) holds for the instrumented binary only.t, zero fails).**
- Stamped poison (per-16B-cell hex index): dying-table slot 3956/3957 receives
  **uploaded cell #30433 in bucket.val + #30434 in bucket.h** — byte-exact
  attacker→slot mapping, identical every fire and across restarts.
- Slot addr within run CONSTANT across 5 worker children:
  arData=0x…d49000, slot=arData+0x1EE80. After restart only the mmap base
  changes; **table-relative offset 0x1EE80 is fixed** (bss/brk-adjacency).
- type=122 (0x7a 'z'), refcounted flag set (0x7a&1=0... byte1=0x7a sets
  GC_INFO/high flags; v0 low qword = our bytes; key ptr = 0x7a7a7a7a7a7a7a7a
  (all-z)); **stock teardown derefs our bytes** (zend_string_release on key →
  GC_DELREF at attacker-chosen-ish addr) → SIGSEGV. Probe never derefs poison
  (write2-only) ⇒ crash is STOCK code on ATTACKER data. No confound left.
- Slot 3955 = healthy zval {v0=0x7f…310 → next arData block, type=7}.
- Crash mechanism: W2 dtor probe fires at slot 3956 print, NEXT iteration
  i_zval_ptr_dtor(&p->val) with type=122 → zval_ptr_dtor → GC_DELREF(faked
  pointer) → segfault in stock path.

## oom59/60 mechanics (reusable)
- Stamped cell = 6 hex digits + 10 'z' = 16B; poison name = 'q' + 10237 cells
  + %06d = ~163849B (DO NOT truncate — the 163840B name geometry is load-bearing).
- Attack = 2044 key parts + 3 poison + 2156 key parts = 13,590,263B total.
- W2 dtorH probe prints at=/arData=/h= (full bucket). stamp decode: regex
  [0-9a-f]{6} anywhere in first bytes of v0 (slot starts 14B into cell stream).
- **IN-CONTAINER ports: curl 127.0.0.1/ (port 80), NOT :8081 (host-side only).**
- Container /tmp/libphp.so.stock got clobbered once (7b095102) — ALWAYS verify
  md5 ce1f3c48ba22f8f17834ac791aead613 after restore; pristine copy kept at
  ~/Projects/queue/php2shell-lab/libphp.so.stock (pulled from php:8.2.34-apache).
- core_pattern in container is relative 'core' → cores land in child CWD, and
  CoreDumpDirectory only helps if conf-active; check BOTH next time.

## Next (step 2): FAKE OBJECT → CALL
1. Poison geometry is ours: craft the 3956-slot payload as a forged
   zend_object {gc.refcount=1, gc.type_info, handle, ce→valid, handlers→fake
   table in our other cells}. Teardown calls handlers->free_obj(obj) → our
   chosen address. Lab build has NO ASLR uncertainty for the demo (we know
   libphp base each run from /proc/<pid>/maps) — demo free_obj→system with
   printable command in header bytes ("cat /etc/hostname>#").
2. Then oom62: without-instrument repro attempt on STOCK (probe module off,
   same body) — check whether stock child dies the same way.
3. Then oom63: ASLR recon oracle (crash/no-crash byte-wise base recovery).

## Environment state
- php_vuln: STOCK ce1f3c48 restored + verified (lim=128M vars=1000), lab ini
  purged. libphp.so.w2 (write2-probe, arData/at/h instrumentation) kept in archive.
- w2 instrument: 9 W2 sites total (3 inline in array_destroy incl dtor/dtorH,
  6 w2() call-sites), zero stdio, zero poison derefs.


## oom58 mechanics (reusable)
- W2 probe = snprintf to stack buf + single raw write(2). NO stdio/FILE —
  instrument cannot crash via poison. 6 w2() sites + 3 inline W2 in
  zend_array_destroy/zend_hash_destroy/clean/symtable_clean/graceful x2.
- Triggers: last-2 slots OR type>IS_OBJECT OR v0==0x0808…fill. Dumps v0, key,
  full 16 value bytes.
- Trigger conditions fired on the W2 array_destroy line: nNumUsed=3957,
  static=1 (keys-only flag NOT set — key path alive), holes=1 (holes path).
- Slot 3956 = SECOND-to-last slot; slot 3955 v0=0x7fa7aabf0310 → points to the
  NEXT arData region (self-referential table chain / carved arData adjacency!).
- 399 W2 lines in one attack; poison-hit line unique, slot 3956/3957.
- Negative segv delta = earlier crashes outside measured window — always
  re-baseline from docker logs TAIL, not all-time grep.

## Environment state (post-oom58)
- php_vuln: STOCK restored + VERIFIED: libphp.so md5 ce1f3c48ba22f8f17834ac791aead613
  (pulled pristine from docker image php:8.2.34-apache). Lab ini/conf/envvars
  ACTIVE again (re-established by oom58 [0]; will re-verify before next run).
  Server healthy (lim=128M vars=1000 = stock ini).
- ~/Projects/queue/php2shell-lab = durable archive (moved from /tmp/phplab;
  /tmp/phplab kept ONLY as container docroot mount).
  libphp.so.stock saved = pristine reference copy (md5 ce1f3c48…).
  libphp.so.w2 = write(2)-probe instrument (25.6MB). libphp.so.instr = old fprintf probe.
- oom58.py = gate driver (env re-estab + swap + attack + W2 read + auto-restore).

## Next moves (in order)
1. oom59: address control — vary poison size/count to steer WHERE the dying
   table's arData gets carved; goal = poison lands at predictable/known address.
2. oom60: fake-object reclaim — put a forged object header (gc/handle/ce/
   handlers) into poison; craft free_obj→system; lab has no ASLR for the demo
   (same build); run whoami as www-data.
3. oom61: ASLR recon oracle — byte-wise fault/no-fault oracle to reconstruct
   libphp base remotely (prefork children inherit frozen parent layout).

## oom117–123 (2026-10-23 night, session 967+)
- CORE LAW (decisive): recreated containers lacked `--ulimit core=-1` (soft core limit 0) → every post-112 "silent" fresh-boot fire was read through a broken instrument; apache flushes the Fatal 200 BEFORE the teardown segfault kills the child → clean-looking 200 ≠ no crash. Honest crash signals: segv-count in `docker logs` (RemoteDisconnected/URLError/TimeoutError per post) + core file. recreate() recipe MUST carry `--ulimit core=-1` (fixed in oom117+).
- H-SHAPE CONFIRMED: 98-era crash reproduces 5×/boot when the full shaping sequence (warm K1S sweep → sacrifice → benign×2) runs first; fresh-boot single fires are inert. Shape matters, recipe restored verbatim in oom118.
- WALK MECHANISM (decisive, core.122 + gdb disasm): crash is at `zend_array_destroy+539` = `subl $0x1,(%rdi)`; caller loop: `cmpb $0x0,0x9(%rbx)` (+530) skip-if-zero-type → `mov (%rbx),%rdi` (+536) → rc decrement through value pointer → `call rc_dtor_func` (+544) when rc hits 0. rbx strides +=0x20 (bucket zvals). core.122: rdi=0x4b4b4b4b4b4b4b4b — WALK WINDOWS ARE RECYCLED STALE HEAP (prior warm posts' ~3KB 'K' name filler pages recycled into the fatal array's arData by glibc dynamic mmap threshold; freed small chunks stay mapped, content readable after free).
- NAMES-DEAD LAW: names can never carry canonical pointers (two high NUL bytes impossible) → names-produced rdi always non-canonical → write-fault at +539, never dispatch. 98-era `0x7a7a41414141…` rdi = stale-name lottery, not dispatch. zend_rc_dtor_func[122] = NULL (verified): type-'z' windows call address 0.
- CARRIER LAW: dispatch-capable carrier must (a) contain NULs (values, binary-safe), (b) land in recycled arData pages → ~3KB-class heap-resident values (large enough to empty pages / hit the recycled size class; 64B/256B values share small-bin pages and never recycle — oom119/120/121 marker posts all showed zero real hits).
- MEASUREMENT LAW: cross-request marker probes are structurally poisoned — probe's own 16B needle allocation reuses the marker's freed slot (self-copy at identical VA, ctx=malloc metadata); fatal's own teardown overwrites the region before any probe. Context-aware probe (ctx hexdump before each hit, scans [heap] too, no first-region break) installed in oom_probe.php; real hits = ctx==0202… SKIP16 tiles.
- VALUES-ARENA (revised): 1537B zend strings live in heap (mmap-threshold inference withdrawn); diag115 "PPPP re-use" consistent with freed-but-mapped heap. Arena address was stable across posts within boot (oom116b) but the WALK NEVER READS IT (windows = recycled names/K region).
- OPEN (next): arData window content ← which freed chunks is measurable per-crash via core (window VA − probe R= region base = rebasable offset). Design: boot N measures the recycled-pages ↔ arData mapping from its core; boot N+1 fires armed with tiles+block planted at rebased addresses (B need only point at freed-but-MAPPED bytes readable at walk time — not live allocations). Then: warm posts tile ~3KB values with cell_of(B); crash post same shape; walk window dispatch value=B ti=legal → rc→0 → rc_dtor_func → store_del → free_obj(B)=zif_system; block+GS bytes live at B in a freed chunk.
- Files: oom117.py (bisect, aborted—no-core instrument), oom118.py (shape proof, 5 segvs, no core), oom119.py/119c.py (small-value arm; NameError fix; "no legal B"), oom120diag.py (6-marker slot map: zero real hits), oom121.py (half-needle: zero hits), oom122.py (core-enabled replica: core.122 rdi=0x4b4b4b…), oom123.py (3KB phase A: slots unmeasurable). Cores: phpbuild /tmp/core.122 (+ .98g/.98f/c93_B0 preserved).

## oom124–126 (2026-10-23 late night, session 967+ cont.)
- FRESH-CORE LAW: /tmp/core in php_vuln may be STALE from a previous boot —
  always `rm -f /tmp/core /tmp/core.used` BEFORE firing (oom124 burned by
  stale core; "fire1 segv+0" + old core md5 = inherited).
- WIN-CHECK LAW: NEVER substring-match `/tmp/x` in output (oom125 false WIN:
  matched "cat: /tmp/x: No such file"). Use `test -f /tmp/x && echo X_EXISTS`.
- NO-SHAPE LAW (reinforced): fresh-boot armed post WITHOUT the warm K1S
  sequence = clean Fatal 200, NO crash, NO core (oom125 r1: 3 tries, segv+0,
  zero-filled tail walked quietly). H-SHAPE remains mandatory.
- TAIL-IDENTITY LAW (core.123d decode + oom124 correction): walked arData =
  REAL buckets then STALE TAIL starting at first counted-but-unwritten
  bucket; tail = freed RAW-BODY READ-BUFFER REALLOC COPIES (attacker-
  controlled bytes, NUL-capable). K-sea = body's own 'K'*3056 names.
  Therefore: seed = SEA of B||B in the crash post's OWN early body parts
  (first ~60KB); block = live part13 value; B from same-core tag map.
- oom126 = body-seed arm: warm shape -> r1 SIG8-sea measure (tags MAGIC+i
  at value starts; A13 = tags[13]) -> legal B -> r2 sea=B||B + block at OFF
  -> r3 re-aim from freshest core if drift. Win-check via test -f.

## WIN (2026-10-24, oom141h2) — stock-path RCE on php:8.2.34-apache
`/tmp/x` = "www-data" in php_vuln. Full chain: Datadog deterministic urlencoded groom
(body `=<RAW V295>&a=1&<N×"Z">[x]=1`, VLEN=295, N=3500000) → DV fatal (key-alloc,
tried 3500032 = N+32) → php_request_shutdown → zend_array_destroy walk → stale
bucket1 (our chunk) → rc-0 → rc_dtor_func → zend_objects_store_del → call *0x8(%rdi)
→ fake free_obj = zif_system → system("whoami>/tmp/x"). HTTP 200 + fatal, win check `test -f /tmp/x`.
LAWS (core-decoded, supersede all prior): bucket1.val=v+72, type=v+80 (0x0106 measure / 0x108 arm),
h=v+88, key=v+96; str_val = sig_vaddr − 72; B-laws mod16=8/bit8=1/bit9=0 fall out of sig≡0 mod16;
wire length IS the estrndup groom size (RAW bytes only — percent-encoding 3×'d the size, killed capture);
walk reads key LAST (`mov 0x18(%rbx),%rdi`) so arm block may clobber key slot; k=96 sole legal block @ VLEN 295;
BASE must be read per-run from /proc/1/maps of php_vuln (importing oom141 leaves BASE=0 → jump to raw file vaddr);
cores land in php_vuln /tmp/core on arm (driver only auto-pulls in measure branch); arm core: rip=zif_system+0,
rdi=rbx=B exact, rdx=B+0x68 handler table, GS zval @ B+0x90 (type 6, len 13). Measure gate: rdi == SIG8 exact (141g, try0).
NCSC-NL/php2shell = defensive tracker, no PoC; detection rules = fallback field-size source (unused — groom worked).

## WORKAROUND VERIFICATION (2026-10-24, oom143)
- php_vuln_sane: stock php:8.2.34-apache, SAME topology as php_vuln, sane ini (40-sane.ini: memory_limit=128M, post_max_size=8M, max_input_vars=1000, upload 2M/20) on 127.0.0.1:8085.
- A) exact winning groom (SIG8@v+72, VLEN=295, N=3500000) x3 → 200, no parse fatal, segv [], cores 0, NO_X.
- B) adversarial 900-var × 8.7KB ≈ 7.75M wire (< 8M post, < 1000 vars) ×2 → 200, POSTCOUNT path clean, segv [], cores 0, NO_X.
- VERDICT: config workaround MEASURED effective on unpatched 8.2.34. Mechanism: chain requires memory_limit fatal DURING POST parse; sane ratio (memory_limit ≥ 2× post_max_size) makes trigger unreachable. max_input_vars irrelevant (3 vars only).
- Confounders controlled: same binary, same volume mounts, same worker conf, only ini differs vs 8083 win container.
