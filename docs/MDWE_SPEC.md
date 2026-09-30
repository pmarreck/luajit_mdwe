# LuaJIT under MemoryDenyWriteExecute: technical spec

Status: **revision 2, accepted by Peter on 2026-09-30 and implemented as
`LUAJIT_SECURITY_MCODE=2` (commit `8b7d18ee`); acceptance tests T1-T11 pass
(`tests/mdwe/r_mode`).** Revision 2 resolved the independent Grok review of
revision 1 (`cefa181e`, "accept with required changes"); see §10. Measured
costs of the implementation are in §7 and `MDWE_RESEARCH.md` §5.1.
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
- P2. Outside a compile/patch window, no writable virtual mapping of any mcode page exists.
- P3. The writable window has upstream's shape: it opens on reserve/patch
  start and closes on commit/abort/patch finish, with no other writes. Its
  duration is longer than upstream's by the remap cost (§7: about 3.5-3.7 µs
  per RW+RX pair, almost all system time). Revision 1 claimed "no longer than
  upstream"; that was false and is withdrawn.
- P4. A `fork()` child's JIT activity cannot change the parent's executing
  code, and vice versa (upstream gets this from private anonymous
  copy-on-write). Scope: `fork()` through libc, which runs `pthread_atfork`
  handlers. A raw `clone` without `CLONE_VM` bypasses them (§5.5, residual).

## 4. Candidate designs

| | Design | Works under both surfaces | P1 | P2 | P4 | Backend changes | Flip cost (µs, §7) |
|---|---|---|---|---|---|---|---|
| U | upstream `mprotect` RW↔RX | **no** | yes | yes | yes | none | 8.0-8.2 |
| 0 | upstream `LUAJIT_SECURITY_MCODE=0` (RWX) | **no** | no | no | yes | none | 0 |
| **R** | **single address; `MAP_FIXED` re-`mmap` of a memfd, RW↔RX; seal at fork** | yes | yes | yes | yes, with §5.5 | **none** | 11.5-11.9 |
| D | persistent dual alias: memfd mapped RW at X+δ and RX at X | yes | yes | **no** | needs §5.5 too | every emit/branch/patch/unwind/debug site | ≈0.1 |
| D′ | dual alias, RW alias mapped only during a window | yes | yes | yes | needs §5.5 too | as D | ≥ R |
| P | anonymous RX, writes via `pwrite(/proc/self/mem)` | yes (FOLL_FORCE) | yes | yes | yes | as D (needs a shadow buffer) | not measured |
| O | out-of-process compiler writing a shared memfd | yes | yes | yes in-process | no | redesign | not measured |
| K | pkeys (x86 PKU / arm64 POE) gating a W+X mapping | **no** (W+X mapping refused) | — | — | — | — | — |
| J | `-joff` | yes (FFI callbacks still fail, §1, §5.4) | n/a | n/a | n/a | none | n/a |

**Recommendation: R.** It is the only option that works under both surfaces
while keeping P1, P2 and the shape of P3, and it changes only `src/lj_mcode.c`
and the callback allocator. The code keeps executing at the address it was
assembled for, so the assembler, every backend's PC-relative arithmetic, exit
stubs, trace linking, `lj_asm_patchexit`, the unwinder FDE registered by
`lj_err_register_mcode`, GDB JIT symbol files and `lj_mcode_sync` cache
maintenance all keep their current meaning. P4 requires the fork protocol in
§5.5; without it R, D and D′ all share code pages across `fork()`. D is
rejected as the default because it violates P2 (a permanent writable alias
turns one address leak plus one arbitrary write into code injection) and
because its address translation touches every backend (see
`MDWE_RESEARCH.md` §6 inventory). The review advised against reviving D on
the strength of the §7 overhead prediction; that stands.

K fails on the premise: MDWE refuses the W+X mapping pkeys would guard.
P is fork-safe but needs the same translation layer as D, a syscall per
write batch, a mounted `/proc`, and breaks under
`proc_mem.force_override=never` (Linux ≥ 6.12). O is out of scope for a
library fork.

## 5. Design R in detail

### 5.1 Mode selection

- New value `LUAJIT_SECURITY_MCODE=2` ("RW^X by remapping"), recorded in the
  existing 2-bit `mcode` field of `LJ_SECURITY_MODE`, visible as
  `jit.security("mcode")` (`lib_jit.c`, added in `2e68e1fc`). Values 0 and 1
  remain byte-for-byte upstream behavior; `=1` stays the default.
- `=2` is compiled only for `LJ_TARGET_LINUX`. Other targets reject it with
  `#error` rather than silently falling back. Linux targets other than
  x86_64 build but are not claimed as supported until executed (§9).
- **No runtime auto-selection**, including when `PR_GET_MDWE` reports MDWE.
  A prctl check would miss the seccomp surface, would contradict T6 (`=1`
  must still fail as upstream does), and is the kind of upfront check Mike
  Pall rejected in 2013 (§5.6). Selection is a build decision.

### 5.2 Backing store and file-offset allocation

- One memfd per `jit_State`, created lazily at the first area allocation with
  `memfd_create("luajit-mcode", MFD_CLOEXEC|MFD_NOEXEC_SEAL)`, retrying with
  `MFD_CLOEXEC` only on `EINVAL` (Linux < 6.3). `MFD_NOEXEC_SEAL` governs
  `execve`, not `mmap`, and it leaves `F_SEAL_SEAL` clear, which §5.5 needs
  (a memfd created with `MFD_EXEC` or no flag carries `F_SEAL_SEAL` and can
  never be write-sealed). At `vm.memfd_noexec=2` only calls without
  `MFD_NOEXEC_SEAL` are refused (`mm/memfd.c` v6.18
  `check_sysctl_memfd_noexec`), so this flag works at every level; the
  sysctl itself was not set here.
- The fd is a process-local write capability, never exposed through the Lua
  API. Anyone who can issue `pwrite` on it could equally `mmap` new code, so
  it adds no capability to an in-scope attacker (§3).
- Placement first, file offset second (review blocker 5). The existing
  jump-range hint loop (`mcode_alloc`, up to 16 probes plus a fallback)
  probes with an **anonymous `PROT_NONE`** reservation, which is neither
  writable nor executable and costs no file space. Only when a reservation is
  accepted does the allocator pick a file offset and `MAP_FIXED` the memfd RW
  over the reservation. A hint miss therefore unmaps an anonymous
  reservation and never grows or punches the file.
- File offsets come from a free-extent list, else by appending with
  `ftruncate`. Freeing an area (`lj_mcode_free`, trace flush) unmaps it and,
  only if the memfd is **not sealed** and the state lock is held, punches the
  extent (`FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE`) and returns it to the
  free list. On a sealed memfd, free only unmaps; the next re-home (§5.5)
  compacts by copying live areas only. The file never shrinks in place.
- Each area's offset is kept in LuaJIT-owned memory outside the area (a side
  table in the per-state mcode context), not only in the `MCLink` header.

### 5.3 Protection transitions

- Views: the writable view is `MAP_SHARED`, `PROT_READ|PROT_WRITE`. The
  executable view is `MAP_PRIVATE`, `PROT_READ|PROT_EXEC`, from the same
  descriptor. A private view never written stays backed by the file's page
  cache, and it does not count as a writable mapping, so the file can be
  write-sealed while it exists (probe `seal-private`; the reviewer's
  `O_RDONLY` reopen through `/proc/self/fd` also works, probe `seal-ro`, but
  would make `/proc` a dependency).
- `mcode_setprot(p, sz, prot)` becomes one `mmap(p, sz, prot, view flags |
  MAP_FIXED, fd, ofs(p))`. Before that call, a **hard runtime check** (not
  `lj_assertJ`, which is compiled out unless `LUA_USE_ASSERT`) verifies that
  `p` and `sz` exactly match a registered area of this state; a mismatch is
  fatal. The callback page never goes through this path (§5.4).
- A result other than `p` is fatal through `mcode_protfail`. Unlike a failed
  `mprotect`, a failed `MAP_FIXED` can leave **no mapping** at `p` (the
  kernel may already have detached the old VMA). `mcode_protfail` must
  therefore not read or write the area, and nothing may run code in it
  afterwards; it panics and exits as today.
- `J->mcprot` caching, the `lj_mcode_reserve/commit/abort/patch` call
  pattern and all their callers stay unchanged.

Invariant for P1: every mapping LuaJIT creates is RW (shared) or RX
(private) or anonymous `PROT_NONE`; no call passes both W and X, and no
`mprotect` passes `PROT_EXEC`. T6 checks this mechanically.

Replacement atomicity is **supported by a falsifiable stress, not claimed as
a guarantee**: probe `remap-race` replaces an RX page RX→RX 20,000 times while
another thread executes it, with no fault (also 200,000 once by hand), and
its negative control `remap-race-gap` (explicit `munmap` first) crashes
(SIGSEGV 5/5 by hand, asserted by the suite). Within one `jit_State`, only
the owning thread executes an area's code, and during the RW phase the area
is non-executable exactly as upstream makes it, so R does not add a new
concurrent-execution window; the stress covers the kernel side.

### 5.4 FFI callback page

- In `=2` mode, `callback_mcode_new` creates its own small memfd
  (`MFD_NOEXEC_SEAL`), maps it RW shared, writes the trampolines, syncs,
  `MAP_FIXED`s it RX private at the same address, **write-seals the file
  (`F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW`) and closes the fd**. Nothing can
  write that page afterwards, so it needs no fork handling and no registry
  entry. Any failure raises the catchable callback error.
- Already committed independently (`f1ca4762`, upstream candidate):
  `callback_mcode_new` now checks its `mprotect`/`VirtualProtect` result and
  raises `"runtime code generation failed, restricted kernel?"` instead of
  handing out a trampoline that faults. This turns `SIGSEGV` into a Lua
  error. **It does not make callbacks work under MDWE**; only `=2` does.
  Dune's `-joff` mitigation still cannot use FFI callbacks.

### 5.5 fork(): seal at fork, re-home before the next mutation

Measured (all under none/kernel/seccomp, asserted by `tests/mdwe/run`):
memfd code pages stay shared across `fork()` even with a private RX view
(`fork-dual`, `fork-dual-private-rx`); a parent hole-punch after `fork()`
kills a child executing the code (`fork-punch`, SIGSEGV); `F_SEAL_WRITE`
succeeds when the only mappings are RX private (`seal-private`) or RX shared
from an `O_RDONLY` description (`seal-ro`), and fails with `EBUSY` while an RX
shared view from the writable description exists (`seal-rw-busy`). After the
seal, `pwrite` and punch return `EPERM` and the sealed code still executes.

Protocol (replaces revision 1's lazy re-home, which the review refuted):

1. **State lock.** Each `jit_State` using `=2` owns a mutex held for the whole
   time any of its areas has a writable view (`J->mcprot` RW, or an area
   between `lj_mcode_patch(...,0)` and `(...,1)`, nested counts), and around
   every other mutation of its memfd: allocation, `ftruncate`, punch, free,
   re-home. The mutex lives in LuaJIT-allocated memory (no malloc in fork
   handlers).
2. **Registry.** A process-global list of live `=2` states, guarded by a
   global mutex. States register when they create their memfd and deregister
   in `lj_mcode_free` of the whole state.
3. **`pthread_atfork`,** registered once (`pthread_once`) before the first
   memfd is created. Registration failure is fatal (panic), not a silent
   downgrade. The library must link the symbol in a default build.
4. **prepare:** take the registry mutex, then every registered state's mutex
   in registry order (this waits for any other thread's in-flight write,
   free or punch). Then for each state, `F_ADD_SEALS(F_SEAL_WRITE |
   F_SEAL_SHRINK | F_SEAL_GROW)`; a state already sealed stays sealed. Any
   seal failure panics before `fork()` proceeds. If the forking thread itself
   holds a state mutex (it is inside that state's write window, for example
   a vmevent handler that forks mid-compile), prepare panics with a specific
   message instead of deadlocking; this is detected with an owner-thread
   field, not by locking.
5. **parent and child handlers:** release all state mutexes and the registry
   mutex. No allocation, no copying and no syscalls beyond unlock in either
   handler.
6. **Re-home before any later mutation.** When a sealed state needs to
   reserve, patch, allocate, free or punch, it first creates a fresh memfd
   (same flags), sizes it, copies every **live** area (`copy_file_range`
   from the sealed fd, which stays readable), and `MAP_FIXED`s each area RX
   private from the new fd at its existing address. Then it closes the old fd
   without punching or truncating it. Any failure part-way is fatal (panic);
   there is no mixed-fd continuation. Both parent and child re-home
   independently; neither can write the sealed file, so neither can change
   the other's code.

Costs: a process that never forks never seals or re-homes. `fork`+`exec`
pays one `fcntl` per state in prepare and nothing afterwards. A forked child
that never compiles keeps executing the sealed pages it shares with the
parent. The first mutation after a fork costs one copy of live mcode (up to `maxmcode`,
default 2048 KiB per `lj_jit.h`) in whichever
process mutates.

Residuals, documented and tested:

- A raw `clone()` without `CLONE_VM` (not through libc `fork`) runs no
  atfork handlers, so the file is not sealed and later writes by either side
  reach the other. T5 includes a test that shows this sharing, so the
  residual is visible rather than assumed.
- `vfork`/`posix_spawn` run no atfork handlers and need none, provided the
  child execs without touching the JIT.
- Sealing is Linux-only (§5.1 already restricts `=2` to Linux).

### 5.6 Failure behavior

- `memfd_create` failure while `=2` is trying to compile (for example
  `SystemCallFilter=~memfd_create` with `SystemCallErrorNumber=EPERM`) is
  **fatal**: the same panic as upstream's protection failure,
  `"runtime code generation failed, restricted kernel?"`, followed by exit
  (`mcode_protfail`, `c50232eb`). It does not reuse `LJ_TRERR_MCODEAL`,
  whose first-allocation path silently disables the JIT (`lj_trace.c`).
  Revision 1 proposed that silent path; the review rejected it, citing
  INTENT ("without ... silently disabling JIT") and Mike Pall's 2013 mail
  ("Silent failure is not an option, nor are any checks upfront", luajit
  list, "Re: luajit crashes with grsec kernel", 2013-10-24; commit
  `7e538b5f`). Operators who want the interpreter pass `-joff`.
- With systemd's default `SystemCallFilter=` action the process dies with
  `SIGSYS` at `memfd_create`; nothing in LuaJIT can catch that.
- Seal failure in fork prepare, `pthread_atfork` registration failure,
  re-home failure, any failed `MAP_FIXED` transition and the hard area check
  in §5.3 are all fatal through the same panic.

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

- Debuggers that set software breakpoints through `ptrace`/`FOLL_FORCE`
  write into the private RX view, which copy-on-writes that page. The file
  is unaffected, but the next RW→RX remap of that area discards the
  breakpoint. Untested; upstream's anonymous areas keep breakpoints across
  `mprotect`.

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
6-byte write to one of 16 pages plus one call per round, hyperfine 15 runs,
warmup 3, unrestricted process):

| Strategy | Revision 1 run | Reviewer rerun | Per round |
|---|---|---|---|
| mprotect | 163.2 ± 3.6 ms | 159.8 ± 2.7 ms | 8.0-8.2 µs |
| remap | 238.5 ± 3.8 ms | 229.9 ± 8.9 ms | 11.5-11.9 µs |
| dual | 2.6 ± 0.4 ms | 2.7 ± 0.6 ms | ≈0.1 µs |
| remap under `PR_SET_MDWE` | 237.2 ± 3.3 ms | 228.2 ± 6.0 ms | |

Remap costs about 3.5-3.7 µs more than mprotect per RW+RX pair, almost all
system time. The cause (re-faulting pages of the replaced VMA) is inference:
`mincore` still reports residency after `MAP_FIXED` because it reflects the
page cache, so it neither confirms nor refutes it. The bench only executes one
page per round and uses `MFD_EXEC`; R uses `MFD_NOEXEC_SEAL` (no timing
difference expected, not measured).

Workload model: `trace_churn.lua` makes about two `mprotect` calls per compiled
trace (1,542-1,610 calls, 764-790 traces, 22-46 aborts across six recorded
runs; checksum `105769494.398` every time). At 3.5-3.7 µs per pair that
**predicts** about 2.8-2.9 ms extra on a 19.0 ± 2.6 ms script. That is about
one σ of the measured script time, so a single hyperfine comparison cannot
resolve it; it is a prediction to test with enough runs, not a result, and it
is not an argument for D.

Acceptance (uses `./bm`, which runs fork vs pinned upstream with ABBA ordering
and median/MAD statistics; `MDWE_RESEARCH.md` §5):

- Steady-state benchmarks: no change beyond 3× the combined robust spread
  and 3%, in either direction, versus upstream `=1` in the same run.
- Compile-bound (`trace_churn`): overhead reported with its measured spread,
  not gated, until reviewed with data.
- Report runs, medians, spreads and machine load for every comparison.

Optimizations held in reserve, each needing its own measurement: remapping
only the touched page range; `MAP_POPULATE` on the RX remap.

**Measured after implementation** (`MDWE_RESEARCH.md` §5.1): the compile-bound
cost is about +31-38% on `trace_churn` (all extra system time), consistent
across five code layouts (geomean 1.35); steady-state benchmarks show no
resolved mode effect across layouts (`mandelbrot` +0.6-1.9% in 5/5 layouts is
a possible small effect). Both reserved optimizations were measured and are
slower (`MAP_POPULATE` +10 ms; range-limited remapping +15 ms on a 68 ms
baseline) and were not adopted. The cost scales with `sizemcode`: +20% at
16 KB, +31% at 64 KB (default), +48% at 256 KB; lowering the default for `=2`
is a tuning decision left open (larger traces could exceed smaller areas).

## 8. Acceptance tests (written first and failing, before implementation)

- T1. `jit_smoke.lua` under kernel `PR_SET_MDWE`, systemd
  `MemoryDenyWriteExecute=yes` and the seccomp replica: exit 0, `jit=true`,
  ≥ 1 compiled trace, same checksum as `-joff`. Currently fails (panic).
- T2. `ffi_callback.lua` and `ffi_callback_pcall.lua` under the same three
  surfaces, with and without `-joff`: `sorted=12345`. Currently a catchable
  error (`f1ca4762`).
- T3. `trace_churn.lua` under the three surfaces: checksum identical to the
  unrestricted upstream binary and to `-joff`. Trace counts are reported, not
  compared against an envelope (the review found runs outside revision 1's
  three-run range).
- T4. Cross-area patching: a workload run with a small `-Osizemcode` so side
  traces land in a different area from their parent. Observable: checksum
  correct, and `jit.util.traceinfo`/`tracemc` addresses show at least one
  side trace whose parent's `mcode` lies in a different area (addresses at
  least one area apart), under each surface.
- T5. fork, each under the three surfaces:
  (a) parent compiles, forks; child compiles and patches; both keep correct
  checksums and neither changes the other's code bytes (compare
  `jit.util.tracemc` bytes of a pre-fork trace before and after the other
  side's activity);
  (b) parent flushes (frees and would punch) while the child executes
  pre-fork traces: child survives with correct results (revision 1 failed
  this, probe `fork-punch`);
  (c) a C harness with a second thread compiling in its own `lua_State`
  across `fork()`: the child's copy of that state's code is unchanged
  afterwards;
  (d) raw `clone` residual: a test that demonstrates the unsealed sharing,
  so the residual stays visible;
  (e) FFI callback created before fork works in both processes.
- T6. Enforcement and mechanism controls: under each surface `=1` still fails
  exactly as upstream; an `=2` run under `strace` shows no `mmap` with W|X
  and no `mprotect` with `PROT_EXEC` (P1); `/proc/self/maps`, sampled from a
  `jit.attach` hook outside compile/patch and at exit, shows no writable
  mapping of `memfd:luajit-mcode` (P2).
- T7. Remap atomicity: the `remap-race` probe and its `remap-race-gap`
  negative control (already in `tests/mdwe/run`), plus a bounded
  multi-`lua_State` threaded compile stress (at most 8 threads, fixed
  iteration count, memory-capped) with correct checksums.
- T8. `SystemCallFilter=~memfd_create` with `SystemCallErrorNumber=EPERM`: a
  JIT-on run exits non-zero with the `runtime code generation failed,
  restricted kernel?` panic; the same script with `-joff` completes.
- T9. Upstream LuaJIT-test-cleanup (pinned) matches the upstream baseline for
  `=1` and `=2` unrestricted, and for `=2` under MDWE.
- T10. `jit.security("mcode")` returns 2 for the new mode (upstream returns 1
  today, measured).
- T11. Seal protocol regressions (already in `tests/mdwe/run`): `seal-private`
  and `seal-ro` succeed and block `pwrite`/punch; `seal-rw-busy` fails with
  `EBUSY`. In LuaJIT: after a fork, `/proc/<pid>/fdinfo` of the mcode memfd
  shows the write seals in both processes, and a post-fork compile in either
  process uses a new memfd.

## 9. Untested targets and open items

- arm64 Linux: cache coherence across remap, `MAP_FIXED` behavior with 16K/64K
  pages, pointer authentication (`mcauth`). No arm64 Linux execution yet.
- 32-bit ARM, PPC, MIPS, x86: not executed; `=2` should build on them if
  Linux, but correctness is unclaimed and they are not supported until
  executed. Where `SHMLBA` exceeds the page size (32-bit ARM, MIPS), shared
  mappings are placement-colored, which may move or refuse the jump-range hint.
- macOS/iOS (`MAP_JIT`), OpenBSD (`wxallowed`), Windows (ACG), PaX, SELinux
  policies (memfd `file { map execute }`, 6.19 `memfd_file` class): not
  applicable to `=2` or untested.
- `vm.memfd_noexec=2`: behavior read from `mm/memfd.c` v6.18; the sysctl was not
  set (needs root; not done on this shared machine).
- Kernels < 6.3 with systemd's seccomp surface: covered only by the replica
  filter, not by an old kernel.
- A failed `MAP_FIXED` leaving a hole was not reproduced; §5.3 treats it as
  possible.
- Valgrind, GDB breakpoints (§5.7), perf's view of
  `/memfd:luajit-mcode (deleted)`, and throwing through JIT frames after a
  remap are untested.
- Multi-thread TLB-shootdown cost of remapping was not measured.

## 10. Review resolution (Grok review of revision 1)

| Finding | Resolution in revision 2 | Evidence |
|---|---|---|
| Blocker 1: lazy re-home does not give P4 (punch after fork kills child; in-flight writer ignores counter; `F_SEAL_WRITE` `EBUSY` on revision 1's mapping) | §5.5 replaced: per-state mutation lock, prepare-time write seal with RX **private** views (reviewer proposed an `O_RDONLY` reopen; both measured to work, private avoids `/proc`), re-home before any later mutation, fatal on failure; raw `clone` residual tested | probes `fork-punch`, `seal-private`, `seal-ro`, `seal-rw-busy` reproduced here under none/kernel/seccomp and asserted in `tests/mdwe/run` |
| Blocker 2: P3 false; `MAP_FIXED` atomicity unobserved; failed `MAP_FIXED` can leave a hole; assert-only area guard | P3 reworded (§3); atomicity now backed by `remap-race` plus a negative control; hole acknowledged, `mcode_protfail` must not touch the area; hard runtime area check (§5.3) | `remap-race` 3×20k + 1×200k clean; `remap-race-gap` SIGSEGV 5/5 |
| Blocker 3: panic on `memfd_create` failure; no auto-select | §5.1, §5.6, T8 rewritten | Pall 2013 mail; INTENT |
| Blocker 4: T5/T7 could not falsify their claims | T5 (a)-(e), T7 and T11 rewritten with observables | — |
| Blocker 5: hint misses leak file space; shrink is a cross-process mutation | §5.2: `PROT_NONE` anonymous placement first, offset second; free list; punch only unsealed and locked; never shrink | — |
| Advisory: T3 envelope, T4 observable, T6 P2 check | T3 checksum-only; T4 names addresses; T6 adds `/proc/self/maps` | — |
| Advisory: callback check is not a fix | §5.4 says so explicitly; `docs/UPSTREAM_CANDIDATES.md` too | — |
| Advisory: `vm.memfd_noexec` wording | Checked `mm/memfd.c` v6.18: flagless calls are upgraded to `NOEXEC_SEAL` at scope ≥ 1, and a call without `MFD_NOEXEC_SEAL` (that is, explicit `MFD_EXEC`) is refused at 2. Revision 1's research wording was accurate; now cited to source | `check_sysctl_memfd_noexec`, `MEMFD_NOEXEC_SCOPE_*` in `include/linux/pid_namespace.h` v6.18 |
| Advisory: unopened nixpkgs commits | Marked as reported by a research pass, not opened, in research §4.1 | — |
| Advisory: `pthread_atfork` failure/linking; debugger/perf untested | §5.5 step 3; §9 | — |
