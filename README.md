# php2shell

Working exploit chain for the PHP urlencoded POST CVE pair (2026-109618 / 2026-109619),
developed and verified against a stock, unmodified `php:8.2.34-apache` container
(libphp md5 `ce1f3c48ba22f8f17834ac791aead613`).

- `STATE.md` — full campaign record: chain walkthrough, measured constants, laws, win artifact.
- `oom141.py` — deterministic groom driver (measure + arm phases).
- `oom141h.py` — arm-only driver (reads libphp base from `/proc/1/maps`).
- `instr/`, `patchdiff/` — instrumented/patched Zend sources used to settle geometry questions.

Win condition: `system("whoami>/tmp/x")` in the request-shutdown array walk of a
memory-limit fatal; artifact `www-data` in `/tmp/x`.

Lab scope: 127.0.0.1 Docker containers only. Patched in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (2026-10-21).
