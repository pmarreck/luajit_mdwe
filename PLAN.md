# PLAN

Research-first fork of LuaJIT v2.1. Purpose and constraints: `INTENT.md`.

## Code review

- [ ] Read AGENTS.md, audit the fork across all deep-code-review dimensions, verify findings and write CODE_REVIEW.md with separate upstream and fork attribution.

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
- [x] Deliver to Dune: flake input, `-Omcoderemap=1` usage, costs and open items (llmsend note to dune_awakening_server). (2026-09-30 16:40 EDT)
- [ ] arm64 hardware run of `=2` (qemu-user covers functional behavior only).
- [x] Documented `-Osizemcode=16` tuning knob in README and spec §7 (no default change). (2026-09-30 16:35 EDT)
- [x] `bin/sizemcode-tune` autotune script (trace_churn: 8 KB fastest, 64 KB +21%). (2026-09-30 16:35 EDT)
- [x] Fixed ./bm ratio gate pairing the previous fork row with another variant's upstream row (tests/bm/prev-pair). (2026-09-30 16:20 EDT)
- [x] Runtime switch: JIT param `mcoderemap` (`-Omcoderemap=1`, `jit.opt.start`) on every Linux build; default 1 only for =2; latched per empty area chain; callback page follows it. r_mode runtime 56/56, =2 56/56, arm64 qemu, no-JIT FFI build ok; bm: default build = upstream on 20/20, flag: steady-state same, trace_churn +45%. (2026-09-30 16:35 EDT)
- [x] README "About this fork" section and GitHub repo description set. (2026-09-30 16:40 EDT)
- [x] Pushed a1d1ff3f and notified dune_awakening_server for its flake. (2026-09-30 16:40 EDT)
- [ ] Hold M4 Max VM work until Peter says the Hyperspace dedup run is finished (disk at 97%) (Peter, 2026-09-30).
- [ ] Use the M4 Max MacBook Pro (tailscale, nix) as a remote dev/test machine: native macOS runs (incl. hardened-runtime JIT), and arm64 Linux via its builder VM if present (Peter, 2026-09-30).
- [x] macOS on the M4 Max: native suite 505/508; HRT build fails upstream (candidate 2) and callbacks SIGBUS (candidate 3, fixed, tests/macos). (2026-09-30 15:55 EDT)
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

## Lockdown escalation (Peter via dune_awakening_server, 2026-09-30 17:41 EDT)

Rescoped 2026-09-30 17:51 EDT (Peter, via Dune): not a Dune requirement; Dune stops at MDWE + systemd sandboxing + dedicated user. Lockdown is an optional fork feature, built only if it earns its place. Peter chose: research doc only, minimal code; he arranges the review.

Keep the JIT but close the memfd-to-executable route that MDWE leaves open. Same process: research + spec, independent Grok review, then implement.

- [x] Research record `docs/LOCKDOWN_RESEARCH.md`: routes MDWE leaves open, BEAMJIT/.NET 8 behavior, partial seccomp prototype, recommendation not to build (Peter: write the research doc; he arranges review). Probes kept out of the repo in .build-work/lockdown/. (2026-09-30 18:40 EDT)
- [ ] Open: vm.memfd_noexec measured in a root pid namespace or VM; /proc/self/mem force parameter verified; NoExecPaths vs this fork.
