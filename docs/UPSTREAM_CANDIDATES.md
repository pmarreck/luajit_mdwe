# Upstream submission candidates

Fixes and improvements made in this fork that stand on their own, independent
of the MDWE allocator design, and could be offered to LuaJIT/LuaJIT. Each entry
records its evidence. Applied here when tests and benchmarks support it.

## 1. FFI callback page: check the RX protection change

- Commit: see `git log -- src/lj_ccallback.c` (2026-09-29).
- Problem: `callback_mcode_new` (`src/lj_ccallback.c`) ignored the result of
  `mprotect(PROT_READ|PROT_EXEC)` (and of `VirtualProtect` on Windows). Under
  W^X enforcement (Linux `PR_SET_MDWE`, systemd `MemoryDenyWriteExecute=yes`,
  PaX MPROTECT, SELinux without `execmem`) the call fails, the trampoline page
  stays non-executable, and the first callback invocation dies with `SIGSEGV`
  (`SEGV_ACCERR`), even with `-joff`.
- Fix: on failure, release the page, leave `cts->cb.mcode` NULL and raise a
  catchable `"runtime code generation failed, restricted kernel?"` error from
  the `ffi.cast` that created the callback (new `LJ_ERR_FFI_CBACKPROT`, because
  `LJ_ERR_JITPROT` does not exist in `LUAJIT_DISABLE_JIT` builds).
- Consistency with upstream policy: Mike Pall's 2013 rule for mcode was "no
  silent failure"; this turns a silent failure into a reported one.
- Evidence: `tests/mdwe/lua/ffi_callback_pcall.lua` under kernel, systemd and
  seccomp-replica MDWE: SIGSEGV before, `cb=error ...` after; unrestricted still
  `cb=ok sorted=12345`. JIT-disabled build checked by hand. Upstream
  LuaJIT-test-cleanup suite unchanged (505/508, same 3 baseline failures as
  pinned upstream). `./bm`: all 20 benchmarks within noise of upstream.
- Upstream form: drop the fork's test scaffolding; the C change is ~20 lines.

## 2. macOS hardened runtime: `return 0;` in void `mcode_setprot`

- Problem: `68354f44` (2025-11-06, "Allow mcode allocations outside of the
  jump range to the support code") changed `mcode_setprot` from `int` to
  `void` but left `return 0;` in the `LUAJIT_ENABLE_OSX_HRT` (MAP_JIT) branch.
  Clang rejects this (`error: void function 'mcode_setprot' should not return
  a value [-Wreturn-mismatch]`, clang 21.1.8 via zig 0.16.0), so an HRT build
  of upstream v2.1 fails to compile. Still present at upstream `c6ffc141`
  (fetched 2026-09-29). With the `return` removed, `mcode_protfail` becomes
  unused on that path (`-Wunused-function`).
- Fix: drop the `return 0;`; hoist the MCMAP_CREATE (hardened-runtime)
  detection above `mcode_protfail` and define it only when a caller exists
  (`LUAJIT_SECURITY_MCODE != 0 && !MCMAP_CREATE`).
- Evidence: `tests/compile/cross-targets` compiled `lj_mcode.c` for aarch64
  and x86_64 macOS 13 with `-DLUAJIT_ENABLE_OSX_HRT` and failed before the fix;
  after it, 10 compiles (macOS HRT/plain, Windows x86_64/aarch64) are clean
  with `-Wall -Werror`. On Linux x86_64 the fork's `lj_mcode.o` disassembly is
  byte-identical to upstream's. Not executed on macOS (no Mac runner here).
