# PLAN

Research-first fork of LuaJIT v2.1. Purpose and constraints: `INTENT.md`.

## Research and design

- [x] Reproduce JIT-on failure plus interpreted control under systemd MDWE, kernel PR_SET_MDWE and a systemd seccomp-filter replica (`tests/mdwe/run`). (2026-09-29 20:10 EDT)
- [x] Found: FFI callbacks SIGSEGV under MDWE even with -joff (unchecked mprotect in `lj_ccallback.c`); early note sent to Einstein. (2026-09-29 20:05 EDT)
- [x] Probe W^X strategies (mprotect, RWX, memfd dual alias, MAP_FIXED remap, /proc/self/mem, fork isolation, memfd flags) under each enforcement surface. (2026-09-29 20:20 EDT)
- [x] Research upstream LuaJIT discussion, maintained forks and other JIT designs using primary sources. (2026-09-29 20:15 EDT)
- [x] Inventory RW/RX address-translation sites per backend for the dual-alias option. (2026-09-29 20:10 EDT)
- [x] Write `docs/MDWE_RESEARCH.md` and `docs/MDWE_SPEC.md`. (2026-09-29 20:25 EDT)
- [x] Ask Einstein to start an independent Grok reviewer against the completed spec (request sent 2026-09-29 20:30 EDT).
- [x] Grok review received (accept with required changes); reproduced its measured claims; spec revision 2 resolves all five blockers and advisories (§10). (2026-09-29 22:10 EDT)
- [x] Peter accepted spec revision 2 (2026-09-30 14:00 EDT).
- [x] Implement design R (`LUAJIT_SECURITY_MCODE=2`) test-first; T1-T11 pass under none/kernel/seccomp/systemd; fork and P1/P2 audits mutation-checked. (2026-09-30 14:20 EDT)
- [x] Benchmark `=2` vs `=1`/upstream with layout control: compile-bound +35%, steady state unresolved except possible ~1% on mandelbrot; MAP_POPULATE and range-limited remap measured and rejected. (2026-09-30 14:45 EDT)
- [ ] Decide with Peter: `=2` default `sizemcode` (16 KB cuts compile overhead to +20%) and whether compile-heavy startup matters for Dune.
- [ ] Deliver to Dune/Einstein: how to build and use `=2` under MemoryDenyWriteExecute; FFI callbacks work in `=2`.
- [ ] arm64 hardware run of `=2` (qemu-user covers functional behavior only).
- [x] Pin upstream LuaJIT and LuaJIT-test-cleanup as flake inputs; add `./bm` (fork vs upstream, median/MAD noise gate, memory-capped). (2026-09-29 21:35 EDT)
- [ ] Track upstream-worthy fixes in `docs/UPSTREAM_CANDIDATES.md`; apply ones that test better (Peter, 2026-09-29; ongoing).
- [x] Fix unchecked mprotect in FFI callback allocation (catchable error instead of SIGSEGV), test-first. (2026-09-29 21:45 EDT)
- [x] Run the upstream LuaJIT-test-cleanup suite from `./test` with exact baseline-failure gate. (2026-09-29 21:35 EDT)
- [x] `bm`: ABBA ordering and fork/upstream ratio history gate; proven to trip with `BM_FORK_FLAGS=-joff`. (2026-09-29 21:45 EDT)
- [x] Fix upstream macOS HRT compile error (void `mcode_setprot` returning 0) with cross-target compile test. (2026-09-29 21:55 EDT)

- [x] Zig build architecture (Peter, 2026-09-29): `build.zig`/`build.zig.zon` mirroring the Makefile config; flake default builds via Zig; `./build`, `./build-all` (5 targets); differential test vs Makefile (46 identical, mutation-checked); emulated arm64 suite; bm parity with upstream. (2026-09-29 22:20 EDT)

## Reviewed implementation

- [x] Flake packages/checks (Zig default, Makefile controls, upstream-suite check); `./build`, `./build-all`, `./test`, `./bm`. (2026-09-29)
- [x] Implement design R behind `LUAJIT_SECURITY_MCODE=2` (`./build --mcode 2`), failing tests first. (2026-09-30)
- [x] Upstream suite, stress, fork, negative enforcement controls and upstream comparisons; gaps recorded in spec §9. (2026-09-30)
- [x] Document measured capabilities and limits (spec §7, research §5.1). (2026-09-30)
