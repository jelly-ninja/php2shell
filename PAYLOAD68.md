# PAYLOAD68 — plain-English byte map + source verdicts

Lab: local Docker only. What the payload does, byte by byte, in words.

## 0. RESULT (oom69b/oom69c, stock unmodified php:8.2.34)

**rdi control of the crashing wild call: PROVEN.**
All-patterned sequence, 3 crashes / 4 fires, every core identical:

```
fire0: rdi = 0x7a7a414141414141
fire1: rdi = 0x7a7a414141414141
fire2: rdi = 0x7a7a414141414141
fire3: survivor (OOM 200)
```

The 0x7a7a prefix = the two bytes we cannot write through NAMES
(NULs needed for real addresses). See §6 for the value-carrier fix.

## 1. What happens when the crashing table dies (source-verified)

```
zend_array_destroy (Zend/zend_hash.c)
  -> i_zval_ptr_dtor          (if type says refcounted)
  -> rc_dtor_func             (Zend/zend_variables.c)
       zend_rc_dtor_func[ type_byte ]( value )   <-- DISPATCH TABLE
  -> zend_objects_store_del   (only if type_byte == 8 = IS_OBJECT)
       -> object->handlers->free_obj( object )
```

**Handler-slot answer:** `free_obj`, slot #1 of `zend_object_handlers`
(#0 = offset, #1 = free_obj, #2 = dtor_obj, ...), called with
**rdi = the object address itself**.

**Is `ce` dereferenced before `free_obj`?** YES on the general path
(store_del's dtor gate reads `object->ce->destructor`) — but ONLY when
`handlers->dtor_obj != zend_objects_destroy_object`. With the default
dtor_obj, `ce` is never touched and `free_obj(object)` runs.

## 2. What the empirical crash actually is

In real crashes the type byte is `'z'` = 122 (our filler!). The
dispatch table has ~19 entries, so PHP calls entry #122 — **past the
end** — with rdi = the 8 zval.value bytes. That's the observed
`0x4b4b…` crash. We control rdi, not the call target.

## 3. Byte map — the periodic pattern (what WORKS)

The walked zval is an 8-byte **cyclic window** of a 16-byte repeated
cell C that tiles the freed region. Which window = the reclaim PHASE:

- instrument build: phase 14 (zval starts 14B before a cell boundary)
- **stock build: phase 7** (measured in oom69b, stable across fires)

Aim (payload68.py `cell_pattern`): `C[(phase+i) % 16] = pointer_byte_i`
for i in 0..5, window bytes 6–7 stay 0x7a. Result: rdi = exactly the
aimed 8 bytes. Phase-proof — no byte-level alignment guessing.

## 4. NUL survival — VERDICT: NO for names, YES for values

- Part NAME: `php_ap_getword`/`estrdup`, `getword_conf`/`substring_conf`
  all strlen-based → **NUL truncates**. Also forbidden: `"` `'` `\`
  `;` `=` CR LF.
- Part VALUE: `multipart_buffer_read_body` → plain `memcpy`
  (rfc1867.c:652) → **binary-safe, NULs survive**.

## 5. Partial overwrite — VERDICT: IMPOSSIBLE here

Cells tile whole 16-byte spans from a page-aligned allocation; there
is no primitive that writes only 1–3 attacker bytes at the slot. Every
poison byte is ours. (Also measured: cross-request slab reuse —
warm-up/sacrifice bodies' filler reappears in later fires' crashes;
69a fired "patterned" finishers over K-filled warm-up and cores still
showed K. ALL bodies in the sequence must carry the pattern.)

## 6. What the main thread must measure / build next (v2)

1. **Switch carrier NAME → VALUE** (binary-safe): then window bytes
   6–7 can be 0x00 0x00 → **real-shaped pointers** `0x00007fxxxxxxxxxx`.
2. **What is at `zend_rc_dtor_func[122]`?** The wild-call target —
   fixed, read-only. If useful (e.g. a call-through-register gadget),
   v1 might reach system with only rdi control. Otherwise:
3. **Object path (full control):** type byte = window byte 8 =
   `C[(phase+8)%16]` → set 0x08 via value-carrier; then fake object =
   repeated pattern: refcount=1 at +0, type_info=8 at +4, handlers ptr
   at +24 → fake table (free_obj at +8 = &system). Needs 3 measured
   addresses (obj, table, system) → the ASLR fault-oracle program.
   `nm -D` shows no `system` export; `zend_eval_string` is at static
   0x47a630 (no-PIE libphp?) — verify base at runtime.
4. **Command placement:** with the object path, the fake object's
   first bytes are the command string; NUL-safe value carrier makes
   arbitrary command bytes easy.

## 7. Files

- `payload68.py` — drop-in builder (`build_attack(k1, stamp_base, target_obj=…)`);
  defaults byte-identical to oom67 (self-checked True at k1=3400/2044).
- `oom69b.py` — all-patterned firing + per-crash rdi decode (two-hop
  docker cp via host: container→container docker cp silently no-ops!).
