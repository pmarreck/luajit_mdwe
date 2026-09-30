# LuaJIT under MemoryDenyWriteExecute: research record

Companion to [`MDWE_SPEC.md`](MDWE_SPEC.md). Labels: **[MEAS]** measured on the
environment below by `tests/mdwe/run` or the commands shown; **[SRC]** stated
by a primary source (link, file, commit or tag given); **[INF]** my inference;
**[UNV]** not verified. Observations relayed in the Dune brief are cited as
Dune's and re-measured before use.

## 1. Environment

| Item | Value |
|---|---|
| Machine | thelio-nixos, x86_64, 128 logical CPUs |
| Kernel | Linux 6.18.54 (NixOS, `#1-NixOS SMP PREEMPT_DYNAMIC Fri Sep 25 2026`) |
| systemd | 261 (261.2), `+SECCOMP -SELINUX +APPARMOR` |
| `vm.memfd_noexec` | 0 |
| LuaJIT | v2.1 @ `c6ffc141a876` (2026-09-08), built `make -C src BUILDMODE=static` (x64, GC64, external unwinding detected by the Makefile) |
| Toolchain | Nix flake, nixpkgs `7a0f122f5090` (2026-09-28): GCC 15.3.0, hyperfine 1.20.0 |

Reproduce everything below with:

```sh
nix develop -c ./test        # builds LuaJIT, then runs tests/mdwe/run
MDWE_SYSTEMD=0 nix develop -c tests/mdwe/run   # without the systemd-run --user column
```

`tests/mdwe/run` asserts 65 cells (all passing at commit time). Helpers:

- `tests/mdwe/mdwe_exec.c`: `prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN)` then `execvp`.
- `tests/mdwe/sdmdwe_seccomp_exec.c`: raw-BPF replica of systemd's seccomp fallback (§2.2), native ABI only.
- `tests/mdwe/wx_probe.c`: one W^X strategy per invocation (§3).
- `tests/mdwe/flip_bench.c`: cost of one protection round trip (§5).
- `tests/mdwe/lua/{jit_smoke,ffi_callback,trace_churn}.lua`: LuaJIT workloads.

The systemd column uses `systemd-run --user --wait --pipe --collect -p
MemoryDenyWriteExecute=yes` against the user manager only. No system unit,
production sandbox or sysctl was changed.

## 2. Enforcement surfaces

### 2.1 Kernel `PR_SET_MDWE`

- Added in Linux 6.3 by Joey Gouly, `b507808ebce2` ("mm: implement
  memory-deny-write-execute as a prctl") **[SRC]**. `PR_SET_MDWE`=65,
  `PR_GET_MDWE`=66, `PR_MDWE_REFUSE_EXEC_GAIN`=1. The commit message explains
  the motivation: systemd's BPF filter cannot know whether a mapping was ever
  writable, so it refuses every `mprotect(PROT_EXEC)`, which broke arm64 BTI.
- `PR_MDWE_NO_INHERIT` (`1UL<<1`) arrived in Linux **6.7** (Florent Revest,
  `24e41bf8a6b4`, committed 2023-10-06) **[SRC]**. Verified by fetching
  `include/uapi/linux/prctl.h`: absent at `v6.5` and `v6.6`, present at `v6.7`.
  (One research pass said 6.6; the uapi header disproves it.)
- Linux 6.9 (`d5aad4c2ca05`, `166ce846dc59`) made support per-architecture;
  unsupported architectures (parisc, pre-ARMv6) return `EINVAL`, which is what
  systemd's fallback keys on **[SRC]**.
- Logic of `map_deny_write_exec()` **[SRC]**: refuse if the new flags have
  `VM_EXEC` and `VM_WRITE`; refuse if the new flags have `VM_EXEC` and the old
  ones did not. In Linux 6.18 (the kernel measured here) it is `static inline`
  in `include/linux/mman.h`; the mmap path calls it as
  `map_deny_write_exec(vm_flags, vm_flags)` (`mm/vma.c:2724` at `v6.18`), so a
  fresh `mmap(PROT_READ|PROT_EXEC)` of anything is allowed; `mm/mprotect.c`
  calls it with the old and new flags and returns `EACCES`. Current mainline
  moved it to `mm/vma.h` with unchanged logic.
  The check is per VMA; it never inspects pages, files or other mappings.
- The flag is sticky and inherited across `fork` and `execve` (unless
  `NO_INHERIT`) **[SRC]**. Refusals return `EACCES` **[MEAS]**.

### 2.2 systemd `MemoryDenyWriteExecute=`

- Added in systemd v231 **[SRC, NEWS]**.
- systemd ≥ **v254** calls `prctl(PR_SET_MDWE)` first and uses seccomp only if
  that returns `EINVAL` (commit `7a114ed4b39e`, "execute: use prctl(PR_SET_MDWE)
  for MemoryDenyWriteExecute=yes", PR #25276). Verified with the GitHub compare
  API: the commit is not in `v253` and is contained in `v254` **[SRC]**. Current
  code: `src/core/exec-invoke.c:apply_memory_deny_write_execute` at systemd main
  `889bc48f` (2026-09-29) **[SRC]**.
- On this machine a `MemoryDenyWriteExecute=yes` transient unit reports
  `PR_GET_MDWE=1`, `Seccomp: 0`, `Seccomp_filters: 0`, `NoNewPrivs: 1`, and
  refusals return `EACCES` **[MEAS]**. **The Dune brief's description of a
  seccomp filter is accurate only for systemd < v254 or kernels < 6.3.** On
  current systems systemd installs only the kernel mechanism. The seccomp filter
  still behaves differently (§2.3), which is why the suite keeps the replica.
- The seccomp fallback, `src/shared/seccomp-util.c:seccomp_memory_deny_write_execute`
  **[SRC]**, answers `EPERM` to: `mmap`/`mmap2` with `PROT_WRITE|PROT_EXEC`
  both set; `mprotect`/`pkey_mprotect` with `PROT_EXEC` set; `shmat` with
  `SHM_EXEC`. It is stateless, so it also refuses re-asserting `PROT_EXEC` on
  memory that was never writable. Architecture coverage varies (`shmat` is not
  filtered where it is multiplexed through `ipc()`: i386, s390, ppc*).
- `man/systemd.exec.xml` **[SRC]** states the protection "can be circumvented,
  if the service can write to a filesystem, which is not mounted with noexec
  (such as /dev/shm), or it can use memfd_create()", and recommends
  `SystemCallFilter=~memfd_create` to close that path.

To compare the surfaces anyway, `sdmdwe_seccomp_exec.c` replicates the
fallback filter. Its refusals return `EPERM` **[MEAS]**, distinguishing it
from the kernel path. It filters only the native ABI; systemd also filters
secondary ABIs.

### 2.3 Observed differences between the surfaces **[MEAS]**

| Probe | kernel `PR_SET_MDWE` | seccomp replica |
|---|---|---|
| anon RW → `mprotect` RX | EACCES | EPERM |
| anon `mmap` RWX | EACCES | EPERM |
| memfd RW → `mprotect` RX | EACCES | EPERM |
| anon RX → `mprotect` RWX | EACCES | EPERM |
| anon RX → `mprotect` RX again (no gain) | **allowed** | **EPERM** |
| memfd RW alias + separate RX alias | allowed | allowed |
| memfd `MAP_FIXED` re-map RW ↔ RX at one address | allowed | allowed |
| anon RX written via `/proc/self/mem` | allowed | allowed |

A passing run under either surface does not show the protection is
equivalent to upstream W^X or stronger than it; §4 compares the designs'
security properties separately.

## 3. Upstream LuaJIT reproduction **[MEAS]**

| Workload | none | kernel | systemd 261 | seccomp replica |
|---|---|---|---|---|
| `jit_smoke.lua` (JIT on) | `jit=true traces=1 sum=2999998` | PANIC `runtime code generation failed, restricted kernel?` rc=1 | same PANIC | same PANIC |
| `jit_smoke.lua -joff` | `jit=false … sum=2999998` | same | same | same |
| `ffi_callback.lua` | `sorted=12345` | SIGSEGV (139) | `status=11/SEGV` | SIGSEGV |
| `ffi_callback.lua -joff` | `sorted=12345` | **SIGSEGV** | **`status=11/SEGV`** | **SIGSEGV** |

This confirms Dune's observation (JIT-on panics at the first trace, `-joff`
works) for trace compilation. The failing call, from `strace` under
`PR_SET_MDWE`: `mprotect(0x55e1fa810000, 65536, PROT_READ|PROT_EXEC) = -1 EACCES`.

New finding: `-joff` does not make FFI callbacks work.
`src/lj_ccallback.c:callback_mcode_new` maps its page RW, then
`mprotect(p, sz, PROT_READ|PROT_EXEC)` without checking the result:

```
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x742aec9d0000
mprotect(0x742aec9d0000, 4096, PROT_READ|PROT_EXEC) = -1 EACCES (Permission denied)
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_ACCERR, si_addr=0x742aec9d0008} ---
```

Einstein was notified of this early (inbox note, 2026-09-29) because it
affects Dune's `-joff` mitigation.

## 4. Candidate strategies, probed **[MEAS]**

`wx_probe` writes `mov eax, imm; ret` (x86_64) or `movz w0, #imm; ret`
(aarch64, compiled but not executed) and calls it.

| Strategy | none | kernel | seccomp | systemd 261 |
|---|---|---|---|---|
| `mprotect` (upstream `=1`) | OK | refused | refused | refused |
| `rwx` (upstream `=0`) | OK | refused | refused | refused |
| `dual`: memfd RW alias + RX alias, write, run, patch, run | OK | OK | OK | OK |
| `remap`: memfd at one address, `MAP_FIXED` re-map RW→RX, patch via RW re-map | OK | OK | OK | OK |
| `procmem`: anon RX, `pwrite` to `/proc/self/mem` | OK | OK | OK | OK |

memfd flags: `dual` and `remap` succeed with `MFD_EXEC`, `MFD_NOEXEC_SEAL` and
no flag under kernel and seccomp surfaces. `MFD_NOEXEC_SEAL` clears the exec
mode bits and seals them, which gates `execve`, not `mmap` (`do_mmap` checks
only `path_noexec()` of the mount) **[SRC: mm/memfd.c,
Documentation/userspace-api/mfd_noexec.rst; MEAS for the flags]**. Under
`vm.memfd_noexec=2`, Linux ≥ 6.6 upgrades flagless calls to `NOEXEC_SEAL` and
refuses `MFD_EXEC` with `EACCES` **[SRC: `202e14222fad`, `9876cfe8ec1c`; checked
in `mm/memfd.c` v6.18 `check_sysctl_memfd_noexec`: flagless calls get
`MFD_NOEXEC_SEAL` at scope ≥ 1 (`MEMFD_NOEXEC_SCOPE_NOEXEC_SEAL`), and any call
still lacking it is refused at scope 2]**. I
could not set the sysctl in an unprivileged user+pid namespace (`Permission
denied`) and did not set it globally, so the level-2 behavior is untested.

Closing the memfd path: under `-p SystemCallFilter=~memfd_create` the probe is
killed (`status=31/SYS`); adding `-p SystemCallErrorNumber=EPERM` turns it into
a catchable `memfd_create: Operation not permitted` **[MEAS]**.

### 4.1 fork() isolation

| Probe | Result |
|---|---|
| `fork-anon`: upstream-style private anonymous code; child flips RW and overwrites | parent unaffected (`ISOLATED`) |
| `fork-dual`: memfd RW + RX `MAP_SHARED`; child writes via inherited RW alias | parent now runs the child's code (`SHARED … (666)`) |
| `fork-dual-private-rx`: same, RX alias `MAP_PRIVATE` | parent also runs the child's code |

A `MAP_PRIVATE` view only copies pages that are written through that view;
the RX view is never written, so it keeps reflecting the file. Any memfd design
needs explicit fork handling **[MEAS; INF for the mechanism]**.

Precedent: PCRE2's sljit `--enable-jit-sealloc` uses exactly this kind of
dual-mapped memfd allocator. Its README warns it "does not support fork()
operation" **[SRC]**. nixpkgs enabled it in `365831bb44` (2022-06-28)
because a NixOS gitea unit set `MemoryDenyWriteExecute=true`, disabled it
for PHP in `6dc3ef5e1a` after fork crashes, saw nginx workers crash in
`sljit_free_exec` (nixpkgs #384302), and removed it in `1e9bd5d98f`
(2026-08-02) **[SRC, as reported by the ecosystem research pass; commits not
re-read by me]**.

### 4.2 Review follow-up probes (2026-09-29) **[MEAS]**

Added after the Grok review of spec revision 1; each is asserted by
`tests/mdwe/run` under none, kernel `PR_SET_MDWE` and the seccomp replica
(and systemd, except the crash-expected control).

| Probe | Result |
|---|---|
| `seal-private`: memfd (`MFD_NOEXEC_SEAL`) written through a shared RW view, then `MAP_FIXED` RX **private** from the same fd; `F_ADD_SEALS(WRITE\|SHRINK\|GROW)` | seals `0x2e`; `pwrite` and punch `EPERM`; code still runs |
| `seal-ro`: same, RX **shared** from an `O_RDONLY` reopen via `/proc/self/fd` (reviewer's configuration) | seals `0x2e`; same |
| `seal-rw-busy`: RX shared view from the writable description | `F_ADD_SEALS`: `EBUSY` |
| `fork-punch`: parent punches the memfd after `fork()` while the child executes | child killed by SIGSEGV |
| `remap-race`: 20,000 `MAP_FIXED` RX→RX replacements while a second thread executes the page | no fault (also 200,000 once by hand) |
| `remap-race-gap`: same with an explicit `munmap` before each replacement (negative control) | SIGSEGV (5/5 by hand; asserted) |

## 5. Performance measurements **[MEAS]**

`flip_bench`, 20,000 rounds, 64 KiB area, one 4 KiB page written and executed
per round; `hyperfine -N --warmup 3 --runs 15`; single-threaded:

| Strategy | Unrestricted | Under `PR_SET_MDWE` | Per round |
|---|---|---|---|
| `mprotect` | 163.2 ± 3.6 ms (user 3.8, sys 155.7) | refused | 8.2 µs |
| `remap` | 238.5 ± 3.8 ms (user 6.9, sys 229.6) | 237.2 ± 3.3 ms | 11.9 µs |
| `dual` | 2.6 ± 0.4 ms | 3.5 ± 1.0 ms | ≈0.1 µs |

Times include process start (≈1-2 ms, from the `dual` row). Multi-threaded
TLB-shootdown costs were not measured.

LuaJIT flip frequency (`trace_churn.lua`, unrestricted upstream): 764-790
traces compiled and 25-46 aborted per run; 1,576-1,610 `mprotect` calls per
run (`strace -c`, three runs); 19.0 ± 2.6 ms JIT-on versus 17.1 ± 0.9 ms
`-joff` (hyperfine, 20 runs). The spread across runs comes from LuaJIT's
randomized hot-counter penalties and mcode placement (`LUAJIT_SECURITY_PRNG`)
**[INF]**; the checksum is identical in every run. Benchmarks must therefore
report counts and variance, not a single run.

## 6. Address translation inventory for the dual-alias option

Source reading of `src/` at `c6ffc141` **[SRC; counts are approximate, per
distinct function or emitter family]**. "W" is the assembler's write pointer
(`as->mcp`, `mctop`, `mcbot`, patch pointer `p`); "X" is the execution address.
Classes: A writes instruction or data bytes into an area; B computes a
PC-relative displacement or range test from a pointer; C stores or publishes an
absolute code address; D reads code; E cache maintenance.

| Backend | A | B | C | D | E |
|---|---|---|---|---|---|
| x86/x64 (`lj_emit_x86.h`, `lj_asm_x86.h`) | ~14 | ~12 | 3 | 3 | 1 |
| arm64 | ~11 | ~10 | 0 | 3 | 1 |
| arm | ~10 | ~8 | 3 | 2 | 2 |
| ppc | ~8 | ~7 | 1 | 3 | 2 |
| mips | ~9 | ~8 | 4 | 3 | 2 |
| shared (`lj_asm.c`, `lj_mcode.c`, `lj_trace.c`, `lj_err.c`, `lj_gdbjit.c`, `lib_jit.c`, `lj_ccallback.c`, `vm_*.dasc`) | 5 | 2 | ~20 | ~9 | 2 |

Emission runs backwards: `lj_asm.c:2505` takes `mctop`/`mcbot` from
`lj_mcode_reserve`; code grows down through `*--as->mcp`, while exit-stub
groups and interned 64-bit constants grow up from `mcbot`. `T->mcode = as->mcp`
is set at `lj_asm.c:2627`, before `asm_tail_fixup`, so a trace can link to itself.

References that cross areas or leave the JIT, and so need X on both ends:

- x86 and 32-bit ARM use global exit-stub groups (`J->exitstubgroup[]`,
  `lj_target.h:152-161`) generated in whichever area was current; guards in
  later areas branch into older areas, and x64 also jumps RIP-indirectly
  through slots at `exitstubgroup[0]-8/-16`.
- Tail links to `traceref(lnk)->mcode`; `lj_asm_patchexit` writing a parent
  trace in an older area with a target in the new trace.
- Calls and branches to `lj_vm_exit_handler`, `lj_vm_exit_interp`, `lj_vm_*`
  helpers and C functions; RIP-relative / ADR / ADRP / LDR-literal references
  to constants.
- arm64 ADRP page arithmetic (`emit_kadrp`, `lj_emit_arm64.h:221-237`)
  additionally needs the alias delta to be a multiple of 4 KiB.
- MIPS `loop_fixup` (`lj_asm_mips.h:2637`) builds an absolute `J` target from
  `as->mcp`, and `J`/`JAL` 256 MB region tests (`(target ^ p) >> 28`) must use X.
- ARM64, PPC and MIPS `exitstub_trace_addr` read instructions after
  `T->mcode + szmcode` (`lj_target_arm64.h:110-118` and siblings); trace-exit
  handlers read instructions at the return address (X, readable, fine).
- `lj_err_register_mcode` (`lj_err.c:604-628`): the FDE uses PC-relative
  `pc_begin`, so it must be registered at its X address, and on pointer-auth
  builds the handler is signed with the X storage address as discriminator.
- `lj_gdbjit.c` (477, 620-621, 668, 780), perf map (`lj_trace.c:118`), `mcauth`
  signing (`lj_trace.c:157`), `jit.util.tracemc`/`traceexitstub` (`lib_jit.c:376-401`),
  and the `BC_JLOOP` jumps in every `vm_*.dasc` publish or consume X.

Cache maintenance with distinct aliases must be done on X, and the delta must
be a multiple of `SHMLBA` so lines dirtied through W are the lines cleaned
through X: 16 KiB on ARMv6-style VIPT data caches, 256 KiB on MIPS where
`synci`/`cacheflush` are VA-indexed **[INF from SRC]**. `lj_asm.c:2638` and ARM
`exitstub_gen` (`lj_asm_arm.h:119`) currently pass W-derived pointers.

The cheapest dual-alias shape keeps the assembler **X-canonical**: all
`mcp/mctop/mcbot/mclim/mctail/mcexit`, `J->mcarea/mctop/mcbot` and
`exitstubgroup[]` hold X addresses so every B and C site stays unchanged, and
every store goes through one per-backend macro adding `J->mcdelta`. That is
about 60 store sites (a dozen emitter primitives per backend plus hand-written
stores in stub generation, loop/tail fixups, guard inversions, peepholes,
`asm_mcode_fixup`, MIPS spare jumps, the PPC `clearso` workaround,
`lj_asm.c:900` and the FDE memcpy), plus `lj_mcode_patch` returning a delta
and a separate treatment for `lj_ccallback.c`. A W-canonical assembler would
instead need translation at about 45 scattered B/C sites **[INF]**.

Under design R (single address, re-mapped) none of the above changes; only
`lj_mcode.c` and `lj_ccallback.c` do. On architectures where `SHMLBA` exceeds
the page size (32-bit ARM, MIPS), shared mappings have placement coloring, so
R's jump-range hint may be moved or refused; R re-maps at the same address and
file offset, which keeps the color, but this is untested.

## 7. Precedents in other JITs

| Project | Mechanism | Under Linux MDWE |
|---|---|---|
| .NET (`src/coreclr/minipal/Unix/doublemapping.cpp`) | memfd double mapping, but reserves `PROT_NONE` and commits with `mprotect(PROT_READ|PROT_EXEC)` | refused **[INF from SRC]**; a third-party report (innovayse/maran#40) says .NET JIT cannot run under it **[SRC, not reproduced]** |
| BEAM (asmjit `virtmem.cpp`) | memfd RW + RX both mapped directly; `MFD_EXEC` on ≥ 6.3; `+JMsingle` forces RWX | allowed **[INF]**; likely fails under `vm.memfd_noexec=2` because `MFD_EXEC` is refused and the fallback is RWX **[INF]** |
| PCRE2 / sljit (`sljitProtExecAllocatorPosix.c`) | memfd or temp file, direct RW + RX | allowed; fork unsafe (§4.1) |
| libffi (`closures.c`, `tramp.c`) | static trampolines (3.4+) re-map a prebuilt code table; else temp-file dual map when SELinux/PaX detected | static trampolines allowed **[INF]** |
| V8 | pkeys for code space; `--jitless` disables executable allocation; `--write-protect-code-memory` removed (`dce30c643f28`, 2023) | only `--jitless` **[INF]** |
| SpiderMonkey | `mprotect` flipping; disabled in content processes (Mozilla bug 1835876, Firefox 116) except arm64 macOS | refused **[INF]** |
| HotSpot | `pthread_jit_write_protect_np` on macOS/AArch64 (JEP 391); RWX code cache on Linux | refused **[INF]** |
| Wasmtime (`code_memory.rs`) | `mprotect` to publish; embedder `CustomCodeMemory` hook | default refused **[INF]** |
| LLVM ORC (`ExecutorSharedMemoryMapperService.cpp`) | `shm_open`, `PROT_NONE` reserve, then `mprotect(EXEC)` | refused **[INF]** |

Only directly-mapped file RX views survive MDWE. No project I found claims
MDWE compatibility in its own documentation.

Other platforms **[SRC unless noted]**:

- SELinux: `execmem` applies to anonymous or private-file executable mappings;
  a `MAP_SHARED` RX view of a memfd (a non-`S_PRIVATE` shmem file) instead needs
  `file { map execute }` on the memfd's label (`security/selinux/hooks.c`,
  **[INF]** for the conclusion). Linux 6.19 adds a `memfd_file` class
  (`094e94d13b60`). Fedora/RHEL policy for memfds: **[UNV]**.
- PaX MPROTECT forbids executable anonymous mappings and exec gain on
  existing mappings, but a file mapped `PROT_EXEC` is the documented way in;
  libffi falls back to a file dual map under PaX. Current grsecurity: **[UNV]**.
- OpenBSD: W|X mappings need a `wxallowed` mount and `wxneeded` binary
  (`mmap(2)`). LuaJIT allocates RX first and flips to RW there (`b876d6da`).
- Apple: `MAP_JIT` + per-thread `pthread_jit_write_protect_np`, one
  `MAP_JIT` region under the hardened runtime ("Porting just-in-time
  compilers to Apple silicon"). LuaJIT supports it only behind
  `-DLUAJIT_ENABLE_OSX_HRT` (`02547705`, `e3c70a7d`, `4f2bb199`, 2025-03).
- pkeys: PKRU is per-thread and writable from user space (`WRPKRU`); arm64 POE
  since Linux 6.12. Keyhan Vakil replaced LuaJIT's `mprotect` with pkeys in
  2022 (up to 17% on fasta, 1.1% geomean) **[SRC: kvakil.me post]**. Pkeys do
  not help here: MDWE refuses the W+X mapping they would guard **[INF]**.

## 8. LuaJIT history and ecosystem

- Mike Pall, 2013-10-24, on the luajit list after a grsecurity crash: "Silent
  failure is not an option, nor are any checks upfront (a moody kernel might
  change its mind midway)." His commit `7e538b5f` introduced the
  `LJ_ERR_JITPROT` panic. `c50232eb` (2022, #802) made it always exit.
  **[SRC]** No Pall statement on dual mapping, memfd, MDWE or `PR_SET_MDWE`
  was found (GitHub issues and web search; freelists has no reliable search,
  so absence is **[UNV]**).
- `LUAJIT_SECURITY_MCODE` replaced `LUAJIT_UNPROTECT_MCODE` in `a44f53ac`
  (2020-06-15); `jit.security()` exposes the mode (`2e68e1fc`) **[SRC]**.
- OpenResty `luajit2` `src/lj_mcode.c` is byte-identical to upstream at
  `c6ffc141`; RaptorJIT and moonjit (archived 2021) carry only upstream changes
  there. Debian, Fedora and Alpine patches do not touch W^X; Gentoo used
  `pax-mark m` until 2024. **[SRC]**
- Known MDWE conflicts: NixOS nginx/openresty (#140655, fixed by disabling
  MDWE for openresty; in 2026-08 nixpkgs turned MDWE off for nginx
  generally, `ea6542782d`); Bottlerocket 1.26.0 set MDWE=yes for containerd,
  ingress-nginx pods panicked with the LuaJIT message, and the release was
  rolled back (bottlerocket #4262) **[SRC]**.

## 9. Open items

- arm64 execution of the probes and of any implementation.
- `vm.memfd_noexec=2` behavior (needs root or a disposable VM).
- An old-kernel (< 6.3) run to exercise real systemd seccomp rather than the replica.
