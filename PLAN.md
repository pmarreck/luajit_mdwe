# PLAN

Research-first fork of LuaJIT v2.1. Purpose and constraints: `INTENT.md`.

## Research and design

- [x] Reproduce JIT-on failure plus interpreted control under systemd MDWE, kernel PR_SET_MDWE and a systemd seccomp-filter replica (`tests/mdwe/run`). (2026-09-29 20:10 EDT)
- [x] Found: FFI callbacks SIGSEGV under MDWE even with -joff (unchecked mprotect in `lj_ccallback.c`); early note sent to Einstein. (2026-09-29 20:05 EDT)
- [x] Probe W^X strategies (mprotect, RWX, memfd dual alias, MAP_FIXED remap, /proc/self/mem, fork isolation, memfd flags) under each enforcement surface. (2026-09-29 20:20 EDT)
- [x] Research upstream LuaJIT discussion, maintained forks and other JIT designs using primary sources. (2026-09-29 20:15 EDT)
- [x] Inventory RW/RX address-translation sites per backend for the dual-alias option. (2026-09-29 20:10 EDT)
- [x] Write `docs/MDWE_RESEARCH.md` and `docs/MDWE_SPEC.md`. (2026-09-29 20:25 EDT)
- [ ] Ask Einstein to start an independent Grok reviewer against the completed spec; stop implementation at that boundary.

## Reviewed implementation (blocked on Grok review)

- [ ] Add package/check outputs and build/test/benchmark adapters to the pinned flake (dev shell exists).
- [ ] Implement the reviewed Linux x86_64 design behind a selectable build option using failing regression tests first.
- [ ] Run upstream and JIT stress suites, negative enforcement controls and reproducible upstream comparisons; record remaining architecture and OS gaps.
- [ ] Document measured capabilities and security limits, then commit and push only a tested unit of work.
