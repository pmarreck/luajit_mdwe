# LuaJIT under MemoryDenyWriteExecute: technical spec

Status: **draft for independent (Grok) review. No implementation exists.**
Evidence and sources: [`MDWE_RESEARCH.md`](MDWE_RESEARCH.md). Purpose: [`../INTENT.md`](../INTENT.md).

Baseline: LuaJIT v2.1 @ `c6ffc141` (2026-09-08). Measurements: Linux 6.18.54
x86_64 (NixOS, 128 logical CPUs), systemd 261, GCC 15.3.0, nixpkgs `7a0f122f`.

## 1. Problem

With the default `LUAJIT_SECURITY_MCODE=1`, LuaJIT maps each machine-code
(mcode) area anonymous `PROT_READ|PROT_WRITE`, writes a trace, then calls
`mprotect(PROT_READ|PROT_EXEC)`; exit patching flips the area back to RW and
then to RX again (`src/lj_mcode.c`). Under Linux W^X enforcement that gain of
`PROT_EXEC` is refused and LuaJIT panics at the first trace:

```
PANIC: unprotected error in call to Lua API (runtime code generation failed, restricted kernel?)
```

Separately, and **even with `-joff`**, the FFI callback trampoline page
(`src/lj_ccallback.c:callback_mcode_new`) makes the same RW→RX `mprotect`,
ignores its failure and the first callback dies with `SIGSEGV`
(`SEGV_ACCERR`). Both are reproduced by `tests/mdwe/run`.

## 2. Enforcement surfaces in scope

| Surface | Mechanism | Refuses | errno |
|---|---|---|---|
| Kernel `PR_SET_MDWE` + `PR_MDWE_REFUSE_EXEC_GAIN` (Linux ≥ 6.3) | per-VMA check in mmap/mprotect | any W+X VMA; any `mprotect` that adds `PROT_EXEC` to a VMA without it | `EACCES` |
| systemd `MemoryDenyWriteExecute=yes`, systemd ≥ v254 on Linux ≥ 6.3 | calls the prctl above | same as above | `EACCES` |
| systemd `MemoryDenyWriteExecute=yes`, older systemd or kernel | stateless seccomp filter | `mmap` with W and X; **every** `mprotect`/`pkey_mprotect` carrying `PROT_EXEC`; `shmat(SHM_EXEC)` | `EPERM` |

Both refuse the upstream path. Both **permit a fresh `mmap(PROT_READ|PROT_EXEC)`
of a file**, including a memfd that the process also maps writable elsewhere.
That permission is the only reason any design below works, and systemd's own
manual names it as a known circumvention that a unit may close with
`SystemCallFilter=~memfd_create` or by making writable non-`noexec`
filesystems inaccessible. This design therefore **does not strengthen** the
protection MDWE offers; it runs LuaJIT inside the envelope MDWE actually
enforces while trying not to be weaker than upstream's RW^X discipline.

The seccomp surface is stricter than the kernel one: it also refuses
`mprotect(PROT_EXEC)` on memory that never was writable (probe `rx-noop`).
The design must therefore never call `mprotect` with `PROT_EXEC`.

## 3. Threat model

In scope: an attacker who has found a memory-corruption bug in the host
process (or in a C library LuaJIT loads) and holds an arbitrary or relative
**write** primitive, but does not yet control execution or syscalls. W^X aims
to stop that attacker from turning a write into injected code.

Out of scope: an attacker who can already issue syscalls with chosen
arguments (they can `mmap` a file RX themselves; MDWE never stopped them);
malicious Lua source (LuaJIT is not a sandbox for untrusted bytecode);
cross-process attackers with ptrace or `/proc/<pid>/mem` access.

Security properties the chosen design must keep, relative to upstream `=1`:

- P1. No mapping is ever writable and executable at once.
- P2. Outside a compile/patch window, no writable virtual alias of any mcode page exists.
- P3. The window during which an mcode area is writable is no longer than upstream's.
- P4. A `fork()` child's JIT activity cannot change the parent's executing code, and vice versa (upstream gets this from private anonymous copy-on-write).

## 4. Candidate designs

| | Design | Works under both surfaces | P1 | P2 | P4 without extra work | Backend changes | Flip cost (µs, §7) |
|---|---|---|---|---|---|---|---|
| U | upstream `mprotect` RW↔RX | **no** | yes | yes | yes | none | 8.2 |
| 0 | upstream `LUAJIT_SECURITY_MCODE=0` (RWX) | **no** | no | no | yes | none | 0 |
| **R** | **single address; toggle by `MAP_FIXED` re-`mmap` of a memfd, RW↔RX** | yes | yes | yes | no | **none** | 11.9 |
| D | persistent dual alias: memfd mapped RW at X+δ and RX at X | yes | yes | **no** | no | every emit/branch/patch/unwind/debug site | ≈0.1 |
| D′ | dual alias, RW alias mapped only during a window | yes | yes | yes | no | as D | ≥ R |
| P | anonymous RX, writes via `pwrite(/proc/self/mem)` | yes (FOLL_FORCE) | yes | yes | **yes** | as D (needs a shadow buffer) | not measured |
| O | out-of-process compiler writing a shared memfd | yes | yes | yes in-process | no | redesign | not measured |
| K | pkeys (x86 PKU / arm64 POE) gating a W+X mapping | **no** (W+X mapping refused) | — | — | — | — | — |
| J | `-joff` | yes (except FFI callbacks, §1) | n/a | n/a | n/a | none | n/a |

**Recommendation: R.** It is the only option that works under both surfaces
while keeping P1-P3 and changing only `src/lj_mcode.c` and the callback
allocator. The code keeps executing at the address it was assembled for, so
the assembler, every backend's PC-relative arithmetic, exit stubs, trace
linking, `lj_asm_patchexit`, the unwinder FDE registered by
`lj_err_register_mcode`, GDB JIT symbol files and `lj_mcode_sync` cache
maintenance all keep their current meaning. D is rejected as the default
because it violates P2 (a permanent writable alias turns one address leak
plus one arbitrary write into code injection) and because its address
translation touches every backend (see `MDWE_RESEARCH.md` §6 inventory). D
stays a measured fallback if R's overhead proves unacceptable (§7).

K fails on the premise: MDWE refuses the W+X mapping pkeys would guard.
P is fork-safe but needs the same translation layer as D, a syscall per
write batch, a mounted `/proc`, and breaks under
`proc_mem.force_override=never` (Linux ≥ 6.12). O is out of scope for a
library fork.

## 5. Design R in detail

### 5.1 Mode selection

- New value `LUAJIT_SECURITY_MCODE=2` ("RW^X by remapping"), recorded in the
  existing 2-bit `mcode` field of `LJ_SECURITY_MODE`, visible as `jit.security("mcode")` (`lib_jit.c`, added in `2e68e1fc`). Values 0 and 1 remain
  byte-for-byte upstream behavior; `=1` stays the default.
- `=2` is compiled only for `LJ_TARGET_LINUX`. Other targets reject it with
  `#error` rather than silently falling back.
- No runtime auto-switching from `=1` to `=2` in this phase: detecting the
  seccomp surface requires a failing `mprotect`, and silently changing
  allocator semantics at runtime is harder to reason about. Revisit after review.

### 5.2 Backing store

- One memfd per `jit_State`, created lazily at the first area allocation with
  `memfd_create("luajit-mcode", MFD_CLOEXEC|MFD_NOEXEC_SEAL)`, retrying with
  `MFD_CLOEXEC` on `EINVAL` (Linux < 6.3). `MFD_NOEXEC_SEAL` governs
  `execve` only; RX `mmap` of such a memfd works at every
  `vm.memfd_noexec` level (measured for the flag values; the sysctl value 2
  itself is untested here). `MFD_EXEC`, as asmjit uses, is refused under
  `vm.memfd_noexec=2`.
- Each new area appends `sz` bytes (`ftruncate`) and records its file offset
  in the `MCLink` header (new field `ofs`).
- The fd is a process-local write capability. It is never exposed through
  the Lua API. Anyone who can issue `pwrite` on it could equally `mmap` new
  code, so it adds no capability to an in-scope attacker (§3).

### 5.3 Protection transitions

- Allocation: `mmap(hint, sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, ofs)` using
  the existing jump-range hint loop (`mcode_alloc`, `mcode_alloc_at`).
  Hint misses unmap and retry exactly as today.
- `mcode_setprot(p, sz, prot)` becomes
  `mmap(p, sz, prot, MAP_SHARED|MAP_FIXED, fd, ofs(p))`. A result other than
  `p` is a fatal protection failure, handled as `mcode_protfail` is today.
- `MAP_FIXED` must never be used on a range that is not already a LuaJIT
  mcode area (guarded by an assertion against the `MCLink` chain).
- Freeing: `munmap` plus `fallocate(FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE)`
  on the area's file range. On `lj_mcode_free` of the whole state, close the fd.
- The `J->mcprot` protection cache, `lj_mcode_reserve/commit/abort/patch`
  call pattern and all their callers stay unchanged.

Invariant for P1: every mapping LuaJIT creates is either
`PROT_READ|PROT_WRITE` or `PROT_READ|PROT_EXEC`; no call passes both W and X,
and no `mprotect` passes `PROT_EXEC`.

Atomicity: code in another thread must never observe the area unmapped.
`MAP_FIXED` replaces the old VMA and installs the new one under the process
`mmap_lock`, so a concurrent fault sees one or the other. This is observed
kernel behavior, not a documented guarantee, and gets a stress test (§8, T7).
Only the owning `lua_State` thread executes an area's code, and upstream
already makes the area non-executable while writing, so R does not add a new
concurrent-execution window.

### 5.4 FFI callback page

`callback_mcode_new` uses the same memfd mechanism in `=2` mode (map RW,
initialize, sync, re-map RX) and **checks** the final mapping. The page is
never written again afterwards, so it needs no fork handling. Independently
of `=2`, the unchecked `mprotect` result is a latent upstream bug: on failure
the call should raise `LJ_ERR_FFI_CBACKOV`-style error instead of leaving a
non-executable trampoline. That fix is a candidate upstream patch.

### 5.5 fork()

Measured: memfd `MAP_SHARED` code pages stay shared after `fork()` even when
the RX view is `MAP_PRIVATE` (probes `fork-dual`, `fork-dual-private-rx`), so
without handling, a child that compiles or patches rewrites the parent's
running code. Upstream anonymous private areas stay isolated (`fork-anon`).

Proposed handling, "lazy re-home":

1. A process-global fork generation counter, incremented in `pthread_atfork`
   parent **and** child handlers (registered once via `pthread_once`).
2. Each `jit_State` records the generation at which it created its memfd.
3. Before any transition to RW (`lj_mcode_reserve`, `lj_mcode_patch`,
   allocation), if the recorded generation differs, the state creates a new
   memfd, copies each area's current bytes (`copy_file_range` from the old
   fd, falling back to reading through the mapping), re-maps every area from
   the new fd at its existing address with its existing protection, closes
   the old fd and records the new generation.
4. Both processes re-home before their first post-fork write, so neither ever
   writes the shared file again. Processes that never compile after
   `fork()` (typical `fork`+`exec`, or read-only workers) pay nothing, and
   share read-only code pages.

Precedent: PCRE2's sljit dual-mapped allocator (`--enable-jit-sealloc`) has no fork handling; its README says it "does not support fork() operation", and nixpkgs enabled it for MemoryDenyWriteExecute units in 2022, disabled it for PHP after fork crashes and removed it in 2026-08 (`MDWE_RESEARCH.md` §4.1). Fork handling is therefore a first-class requirement, not an edge case.

Limits to review: `fork()` issued by a raw `clone`/`syscall` bypasses
`pthread_atfork` (a pid comparison can add partial protection for the parent
only); a `jit_State` whose owning thread is mid-compile in another thread at
`fork()` is already unusable in the child, but its parent-side writes before
re-homing would reach the child's copy. `posix_spawn`/`vfork` do not run
atfork handlers and do not need them.

### 5.6 Failure behavior

- `memfd_create` failure (for example `SystemCallFilter=~memfd_create` with
  `SystemCallErrorNumber=EPERM`): treat as `LJ_TRERR_MCODEAL` on the first
  area, which already disables the JIT (`lj_trace.c`, "Disable JIT compiler
  if first mcode alloc fails") instead of panicking. With systemd's default
  action the process gets `SIGSYS` at the `memfd_create` call and nothing in
  LuaJIT can catch it; document this.
- Any other `mmap` failure during a transition is fatal, as upstream's
  `mcode_protfail` is today.
- Tension with upstream policy: Mike Pall rejected silent fallback for
  protection failures in 2013 ("Silent failure is not an option, nor are any
  checks upfront", `7e538b5f`). Disabling the JIT on a failed *first
  allocation* is already upstream behavior for `LJ_TRERR_MCODEAL`, so the
  memfd case reuses it rather than adding a new silent path. A later
  protection failure still panics. Reviewers should say whether `=2` should
  instead panic on `memfd_create` failure too.

### 5.7 Cache coherence and debuggers

- Code executes at the address it was written at, so `lj_mcode_sync` keeps
  its arguments. On arm64, `DC CVAU`/`IC IVAU` by VA run while the range is
  mapped RW (readable), as upstream does today. Instruction-cache validity
  across the RW→RX remap relies on the caches being physically indexed for
  the same page (the remap keeps the physical page). This needs execution on
  arm64 (§9).
- `lj_err_register_mcode` writes its EH frame into the area header at
  allocation and registers that address. It remains valid because the
  address does not change.
- `lj_gdbjit.c` publishes `T->mcode`; unchanged.
- Valgrind (`LUAJIT_USE_VALGRIND`) keys on addresses; unchanged but untested.
- `perf` JIT maps: unchanged addresses. Mappings now show as
  `/memfd:luajit-mcode (deleted)` in `/proc/<pid>/maps`.

## 6. Why not D (dual alias), concretely

Correctness cost: each assembler write pointer (`as->mcp`) would be an RW
address while every displacement to targets outside the area (interpreter,
`lj_vm_exit_*`, other traces' areas, `lj_gc_step_jit`) and every published
address (`T->mcode`, exit stub groups, trace link targets, `mcauth` pointer
signing on arm64e, unwind FDE, GDB symbols) must use the RX address. Cache
maintenance on arm64 must use RX addresses to be correct with VIPT
instruction caches, and the alias delta must be a multiple of `SHMLBA` (16 KiB on ARMv6-style VIPT caches, 256 KiB on MIPS) and of 4 KiB for arm64 ADRP. The cheapest shape keeps the assembler execution-address canonical and routes about 60 store sites (a dozen emitter primitives per backend plus stub generation, loop/tail fixups, patching, the FDE and MIPS spare jumps) through a per-backend write macro. The per-backend inventory is in `MDWE_RESEARCH.md` §6.
Security cost: P2 violated for the process lifetime. Benefit: no syscalls per
flip. If §7 shows R's overhead matters, D′ (transient RW alias) recovers P2
but not the syscall cost, so the tradeoff is R versus D only.

## 7. Performance model and targets

Microbenchmark (`tests/mdwe/flip_bench.c`, 20,000 rounds, 64 KiB area, one
page written and executed per round, hyperfine 15 runs, unrestricted
process): mprotect 163.2 ± 3.6 ms (8.2 µs/round); remap 238.5 ± 3.8 ms
(11.9 µs/round); dual 2.6 ± 0.4 ms (≈0.1 µs/round). Under `PR_SET_MDWE`, remap
237.2 ± 3.3 ms and dual 3.5 ± 1.0 ms. Remap costs about 3.7 µs more than
mprotect per round, mostly re-faulting pages of the replaced VMA [inference;
not profiled].

Workload model: `tests/mdwe/lua/trace_churn.lua` compiles ~764-790 traces and
performs ~1,576-1,610 `mprotect` calls (≈2 per trace) in ~19 ms. At 3.7 µs
extra per round trip that predicts ≈2.9 ms (≈15%) extra for this deliberately
compile-bound script and near zero for steady-state loops, which make no
protection changes. These are predictions to test, not results.

Acceptance: report R versus upstream `=1` (unrestricted) on the LuaJIT
benchmark suite and `trace_churn`, with hyperfine means, σ, and at least 20
runs; state the measured run-to-run σ of each benchmark before calling any
difference noise. Steady-state benchmarks must not regress beyond their own
measured σ; compile-bound overhead is reported, not gated, until reviewed.
Optimizations held in reserve: remapping only the touched page range;
`MAP_POPULATE` on the RX remap.

## 8. Acceptance tests (to write first, failing, before implementation)

- T1. `jit_smoke.lua` under kernel `PR_SET_MDWE`, systemd
  `MemoryDenyWriteExecute=yes` and the seccomp replica: exit 0, `jit=true`,
  ≥ 1 compiled trace, same checksum as `-joff`. Currently fails (panic).
- T2. `ffi_callback.lua` under the same three surfaces, with and without
  `-joff`: `sorted=12345`. Currently `SIGSEGV`.
- T3. `trace_churn.lua` under the three surfaces: identical checksum to the
  unrestricted upstream binary and to `-joff`; compiled-trace counts within
  the upstream run-to-run range.
- T4. Exit patching and trace linking: a workload whose side traces patch
  exits in a non-current mcode area (force small `sizemcode`, e.g.
  `-Omaxmcode=... -Osizemcode=...`), verified under MDWE.
- T5. Fork: parent compiles, forks, child compiles and patches, parent keeps
  producing its expected results, and the reverse. Include a
  `vm.memfd_noexec`-independent path and a raw-`clone` negative case that
  documents the residual risk.
- T6. Negative enforcement controls: under each surface, `LUAJIT_SECURITY_MCODE=1`
  still fails exactly as upstream; a `strace`/seccomp audit of an `=2` run
  shows no `mmap` with W|X and no `mprotect` with `PROT_EXEC`
  (mechanical check of P1).
- T7. Remap atomicity stress: many threads, each with its own `lua_State`,
  compiling and executing concurrently for a fixed iteration count, no
  crashes, checksums correct.
- T8. `SystemCallFilter=~memfd_create` + `SystemCallErrorNumber=EPERM`: the
  JIT disables itself and the script still completes interpreted.
- T9. Upstream test suite (LuaJIT-test-cleanup, pinned revision) passes for
  `=1` and `=2`, unrestricted and (for `=2`) under MDWE.
- T10. `jit.security("mcode")` returns 2 for the new mode (upstream returns 1 today, measured), so callers can tell which allocator is active.

## 9. Untested targets and open questions

- arm64 Linux: cache coherence across remap, `MAP_FIXED` behavior with 16K/64K
  pages, pointer authentication (`mcauth`). No arm64 Linux execution yet.
- 32-bit ARM, PPC, MIPS, x86: not executed; `=2` should build on them if
  Linux, but correctness is unclaimed. Where `SHMLBA` exceeds the page size
  (32-bit ARM, MIPS), shared mappings are placement-colored, which may move
  or refuse the jump-range hint.
- macOS/iOS (`MAP_JIT`), OpenBSD (`wxallowed`), Windows (ACG), PaX, SELinux
  policies (memfd `file { map execute }`, 6.19 `memfd_file` class): not
  applicable to `=2` or untested.
- `vm.memfd_noexec=2`: flag path reasoned from source; setting the sysctl
  requires root and was not done on this shared machine.
- Kernels < 6.3 with systemd's seccomp surface: covered only by the replica
  filter, not by an old kernel.
- Open for review: lazy re-home versus snapshot-at-fork; whether `=2` should
  become auto-selected when `PR_GET_MDWE` reports MDWE; whether the callback
  fix should go upstream independently.
