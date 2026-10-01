# Code review: LuaJIT MDWE fork

Date: 2026-10-01. Reviewer: Codex, using the deep-code-review skill and independent review agents for its 13 dimensions.

Upstream baseline: `c6ffc141a8762b41703f9287d63d93622a13dd8f` (the flake's pinned LuaJIT input). Reviewed fork: `c9155c216f7a`, including the changes since the initial review snapshot `abc6cf8ab353e73661825ddeec6aedbf616d423a`. The intervening commits changed build/test tooling and documentation; the allocator and callback findings below apply to both snapshots.

The review covers the complete fork delta and the surrounding upstream allocation, tracing, callback, parameter, build and error-handling paths. It also checks the current tree across all 13 review dimensions. This is not an exhaustive proof of the unchanged LuaJIT compiler's correctness. Upstream attribution refers to the pinned baseline, not a claim about the latest upstream HEAD.

## Assessment

The normal Linux acceptance suite passes, but two failure paths need attention before broadening use of the remap allocator: a recoverable allocation failure terminates the embedding process, and fork ownership detection contains a sanitizer-confirmed data race. The installed Zig/Nix product also fails to locate its own Lua modules without an environment override. Several tests accept incomplete evidence or cannot detect the incorrect result they claim to check.

| Outstanding findings | Count |
| --- | ---: |
| CRITICAL | 0 |
| WARNING | 13 |
| ADVISORY | 6 |

All outstanding findings are fork additions or incomplete fork functionality. Three defects present in original LuaJIT are already fixed in this fork and appear separately below. They do not count as outstanding findings. No additional unresolved defect in unchanged upstream code was established.

WARNING indicates a concrete correctness, resource, product or acceptance-control defect. R1 and R2 have the highest fix priority. ADVISORY indicates a narrower configuration issue, a documented unsupported-platform edge case, or a verification improvement. Severity does not imply that an exploit or resulting corruption was demonstrated.

## Outstanding issues in our fork

### Memory safety and resource lifetime

#### R1. WARNING: Allocation failure publishes an incomplete code area and exits the host

Locations: `src/lj_mcode.c:693`, `src/lj_mcode.c:326`, `src/lj_mcode.c:415`, `src/lj_mcode.c:417`; abort cleanup at `src/lj_trace.c:593`.

With remapping enabled, `mcode_allocarea` assigns the new OS reservation to `J->mcarea` before `mc_area_commit` allocates its context and metadata vectors. Those Lua heap allocations can raise `LUA_ERRMEM`. The area has not yet acquired a size, protection state, registration or chain link. Trace error cleanup calls `lj_mcode_abort`, which tries to protect that incomplete area; `mc_find` cannot find it and calls the fatal protection-error path. The embedding host exits instead of recovering from allocation failure. Allocation of a later area can also overwrite the old chain before the new link is initialized.

The two vector reallocations have a related ownership problem: if `c->area` grows but `c->ext` fails, `c->cap` still describes the old allocation size. A subsequent realloc/free passes incorrect size information to the embedding allocator and LuaJIT's accounting.

Evidence: a custom allocator rejected the context allocation during a normal Lua loop's first trace compilation. The program printed the following and exited 1 without returning from `lua_pcall`:

```text
INJECT allocation failure n=112 old=0
PANIC: runtime code generation failed, restricted kernel?
```

Separate protected reserve probes rejected the context, area vector and extent vector allocations independently; all left an incomplete active area. The first context is 112 bytes on the reviewed x86_64 build. Appendix A supplies the natural-trace reproduction.

Fix: prepare fallible metadata before publishing the reservation, or provide complete rollback of the reservation and old `J` fields on every unwind. Track the two vector allocations transactionally or give them separate capacities. Add allocator-failure cases for every allocation site, both with an empty cache and with existing live traces, and require that the host survives and closes the state safely.

Attribution: introduced by the fork. Upstream had no Lua heap allocation between successful OS reservation and code-area initialization.

Resolution (2026-10-01): fixed. `mc_reserve` makes the context and both array allocations before `mcode_alloc` publishes the area, and the arrays have separate capacities (`acap`, `ecap`). Test: `tests/mdwe/embed_oom.c` fails each Lua allocation in turn (k = 1, 2, ...) in a forked child, cold and with live traces and small areas that grow past the initial capacity; every child must survive, recover and close. Wired into `tests/mdwe/r_mode` (none and kernel MDWE). Unfixed code panics at k=30; fixed code survives all 531 cold and 536 warm points.

#### R5. WARNING: Failed hole punching silently retains freed code storage

Location: `src/lj_mcode.c:450`, with extent recycling immediately afterwards.

`mc_area_free` ignores the result of `fallocate(PUNCH_HOLE)` and records the extent as reusable even if reclamation failed. A sandbox that denies `fallocate` leaves memfd page-cache storage allocated after `jit.flush()`. Changing area sizes across flushes prevents immediate reuse of all retained extents. The live-area `maxmcode` accounting excludes this backing storage.

Evidence: an embedding probe enabled runtime remapping, configured `maxmcode=64`, and compiled/flushed with `sizemcode=4` through `64`. A seccomp rule returned `EPERM` specifically for `fallocate`. Independent `fstat().st_blocks * 512` measurements after the final flush were:

| Policy | Live traces after flush | Allocated memfd storage |
| --- | ---: | ---: |
| Unrestricted control | 0 | 0 bytes |
| Deny `fallocate` | 0 | 126,976 bytes |

Both processes exited successfully. The denied case retained more backing than the configured 65,536-byte live-code limit. This is resource retention; trace results remained correct.

Fix: check reclamation errors and account for unreclaimed backing. When the last live area is gone, closing the empty context's memfd is a simple way to release storage even when punching is unavailable; recreate it lazily. Preserve the sealing rules for forked peers. Test reclamation with `fallocate` denied and varying sizes.

Attribution: introduced by the fork. Upstream releases anonymous code storage with `munmap`.

### Concurrent embedding and FFI boundary correctness

#### R2. WARNING: Fork ownership detection reads shared state without synchronization

Locations: `src/lj_mcode.c:294`, `src/lj_mcode.c:383`, `src/lj_mcode.c:391`; ownership fields at `src/lj_mcode.c:262`.

`mc_prepare` reads `c->owned` and potentially `c->owner` before acquiring `c->lock`. The compiler writes those fields under the context lock, while the fork handler holds a different registry lock. These accesses have no synchronization relationship. Declaring `owned` volatile does not make the ownership protocol thread safe.

The trigger uses supported independent states: one thread compiles in its own `lua_State`, while another calls ordinary `fork()`. It does not require two threads to use the same Lua state.

Evidence: only the actual `lj_mcode.c` object was instrumented with GCC ThreadSanitizer in a private copy of the built archive. The existing embedding fork test was copied and extended with 1,000 ordinary forks during compilation. Two review runs exited 66 and reported:

```text
Read of size 4 by main thread:
  mc_prepare src/lj_mcode.c:294
Previous write of size 4 by thread T1:
  mc_end src/lj_mcode.c:391
SUMMARY: ThreadSanitizer: data race ... in mc_prepare
```

The unextended single-fork test passed with the same instrumentation. The race is established; no consequent corruption or isolation failure was observed. ThreadSanitizer is specifically designed to detect such races. [ThreadSanitizer documentation](https://clang.llvm.org/docs/ThreadSanitizer.html).

Fix: use thread-local ownership information to detect a fork initiated by the compiling thread, then lock each context before reading its shared state. An alternative needs a complete atomic owner-publication protocol; making only `owned` atomic leaves the concurrently reassigned `owner` unprotected. Retain repeated-fork sanitizer coverage alongside the functional isolation test.

Attribution: introduced by the fork's process-wide remap registry.

Resolution (2026-10-01): fixed. A thread-local `mc_held` count of contexts this thread has locked replaces the shared `owner`/`owned` fields; the prepare handler reads only its own thread's count, then locks each context before touching it. Test: `tests/mdwe/tsan-fork` rebuilds `lj_mcode.o` with ThreadSanitizer and runs the new `embed-fork forkloop` mode (1,000 forks while another thread compiles, memfd allocator on); in `./test`. Before the fix it reported the race at `mc_prepare` (exit 66); after, clean.

### Inconsistent or incomplete functionality

#### R4. WARNING: Mode 2 loses callback remapping when the JIT is compiled out

Locations: `src/lj_arch.h:773`, `src/lj_ccallback.c:354`; broad availability wording in `README:17`.

Linux builds with both `LUAJIT_DISABLE_JIT` and `LUAJIT_SECURITY_MCODE=2` succeed and report `jit.security("mcode") == 2`, but `LJ_MCODE_REMAP` requires `LJ_HASJIT`. The callback remap implementation disappears, even though FFI callbacks need generated executable code independently of the trace compiler. Under MDWE, callback creation therefore still attempts the rejected anonymous-page protection change and raises a protection error. A compiled-out JIT has no `jit.opt` runtime workaround.

Evidence: an isolated no-JIT/mode-2 Makefile build created and invoked an `int (*)(int)` callback returning 42 unrestricted. The identical script failed at callback creation under kernel MDWE. A JIT-capable mode-2 binary with `-joff` passed both controls.

Fix: separate callback-backend availability from trace-compiler availability and select the memfd callback backend for Linux no-JIT/mode-2 builds. Alternatively reject that unsupported configuration explicitly and narrow the documentation. Add an executable callback test for this configuration, rather than only a compile check.

Attribution: incomplete fork configuration support. Upstream's callback inability under MDWE is inherited; the new mode reports remapping without providing it in this configuration.

Resolution (2026-10-01): rejected rather than implemented, to keep the change minimal. `src/lj_arch.h` now fails the build with `#error "LUAJIT_SECURITY_MCODE=2 requires the JIT"` when combined with `LUAJIT_DISABLE_JIT`; the README says so and limits the runtime switch to JIT-enabled builds. Test: `tests/compile/cross-targets` requires that refusal and, as a control, that `=2` with the JIT compiles.

### Build and installation configuration

#### R3. WARNING: Installed Zig/Nix binaries cannot find their own Lua modules

Locations: `build.zig:313`, `build.zig:363`; upstream prefix handling at `src/Makefile:288` and defaults at `src/luaconf.h:40`.

The Zig graph installs modules under `<prefix>/share/luajit-2.1`, but never defines `LUA_ROOT` or `LUA_LJDIR` for that prefix. POSIX binaries continue searching `/usr/local/share/luajit-2.1`. Commands such as `-jv`, `-jdump`, `-b` and `require("jit.vmdef")` fail even though their modules were installed. The Windows layout also installs under `share`, while its defaults search executable-relative `lua` directories. Tests supply `LUA_PATH`, concealing the installed-product problem.

Evidence: both the normal Zig installation and a built Nix default package failed this command with `unknown luaJIT command or jit.* modules not installed`:

```sh
env -u LUA_PATH -u LUA_CPATH \
  zig-out/x86_64-linux-gnu/ReleaseFast/bin/luajit -jv -e 'print(1)'
```

`package.path` contained `/usr/local` paths and omitted the actual installation prefix. `require("jit.vmdef")` also failed.

Fix: derive the POSIX search paths from the actual prefix, as the upstream Makefile does, and align the Windows installation with its executable-relative search paths. Test installed commands from an unrelated directory with path environment overrides unset.

Attribution: introduced by the fork's Zig build. The upstream Makefile supplies custom-prefix definitions.

#### R11. WARNING: `build-all` fails before building anything in a fresh checkout

Location: `build-all:11`.

The script redirects target logs into `.build-work` without creating that directory. If it does not already exist, shell redirection fails for every target before invoking `build`. Ordinary `./build` does not create the log directory either.

Evidence: an unchanged copy of `build-all` in a fresh temporary directory, with a recording build stub, exited 5, emitted five missing-directory errors, and never called the stub.

Fix: create `.build-work` before the loop. Check the driver from an empty work directory.

Attribution: introduced by the fork.

#### R13. WARNING: The full test entrypoint unconditionally selects Linux paths on macOS

Locations: `test:17`, `test:20`, `test:25`, `test:31`.

The flake declares a Darwin development shell and the build supports native macOS, but `./test` unconditionally compiles Linux MDWE probes, looks for `zig-out/arm64-linux-gnu/...` on a Mac, requests Linux-only mode 2, and runs qemu/Linux checks. `./build` actually installs the native Mac product under `zig-out/aarch64-macos/...`. The dedicated hardened-runtime test exists but is not selected by this entrypoint.

Evidence: source-confirmed host/path mismatch. This review did not execute `./test` on a Mac. Recorded successful native macOS runs used the separate macOS driver and do not establish that the full runner works there.

Fix: derive the host target with the same normalization as `build`, route MDWE/remap checks to Linux, and route native hardened-runtime checks to Darwin.

Attribution: introduced by the fork's full-suite driver.

### Inadequate and futile test coverage

#### R6. WARNING: The upstream-suite wrapper accepts a crashed or truncated run

Locations: `tests/upstream-suite:20`, `tests/upstream-suite:22`, `tests/upstream-suite:26`.

The wrapper discards the target's exit status and accepts any parsed summary with the expected failing-test IDs. It does not require the expected total number of tests. A run that emits the baseline text and then crashes, or runs only a subset, can satisfy the gate.

Evidence: a target fixture printed `0 passed, 3 failed` and `pass command line arguments: 363 365 366`, then exited 139. The wrapper returned 0 and described the run as matching the upstream baseline.

Fix: retain and validate the suite exit status as well as the complete expected test count and failure IDs. The pinned suite intentionally reports baseline test failures, so establish its normal exit convention rather than assuming that a green wrapper requires every test to pass. Add crash-after-summary and truncated-summary controls.

Attribution: introduced by the fork's wrapper, not a failure of LuaJIT or the pinned test suite.

#### R7. WARNING: Early child failure can hang the fork isolation test indefinitely

Locations: `tests/mdwe/lua/fork_isolation.lua:29`, `tests/mdwe/lua/fork_isolation.lua:52`; pipe helpers at `tests/mdwe/lua/mdwe_ffi.lua:61`.

Both processes retain both ends of both pipes. If the child exits before sending its readiness byte, the parent still owns a write end and its blocking read never sees EOF. A failed `fork()` also reaches the parent wait without a live child. The acceptance runner gives these commands no enclosing deadline.

Evidence: an isolated copy injected child `_exit(1)` before its first handshake. Instead of reporting failure, the parent blocked until an external three-second deadline returned 124.

Fix: check the `fork` result, close unused pipe ends in each process, and propagate EOF/child status as a failure. Use a bounded failure-reporting deadline as a fallback, not a sleep-based handshake. Test early child exit and failed-fork behavior. The C embedding fork harness already closes unused ends and offers a useful pattern.

Attribution: introduced by the fork's Lua test.

#### R8. WARNING: Post-fork arithmetic is checked against itself

Locations: `tests/mdwe/lua/fork_isolation.lua:41`, `tests/mdwe/lua/fork_isolation.lua:57`.

Both sides check `work2(k) == work2(k)`. A repeatable wrong result passes, so these assertions do not establish correct execution of newly generated code after re-homing. The separate seal, inode and pre-fork byte checks remain useful. The printed trace count describes the pre-fork snapshot and does not establish which post-fork functions compiled.

Evidence: changing the copied `work2` function to return `s + 1` still produced `fork_isolation: ok remap=1 traces=4` and exit 0.

Fix: compare the child inputs 3..8 and parent inputs 13..18 with independently computed expected scalars, using separate interpreter-only reference functions or fixed verified results. Require compilation evidence for the intended post-fork functions. Keep the isolation checks and make the result mutation fail.

Attribution: introduced by the fork's test oracle.

#### R9. WARNING: The syscall audit accepts partially failed evidence collection

Locations: `tests/mdwe/r_mode:94`, `tests/mdwe/r_mode:95`, `tests/mdwe/r_mode:99`.

Five `strace` calls are concatenated without checking their individual statuses. Missing traces make the absence-of-forbidden-syscalls checks pass, while a single successful workload can supply the positive remap event for the entire group. A green P1 audit can therefore omit callback, churn, cross-area or fork evidence.

Evidence: an isolated execution of the exact collector/gates supplied one valid RX/private `MAP_FIXED` event, then returned 99 with collection errors for the other four workloads. All three audit gates passed.

Fix: require every collector invocation and workload to succeed before evaluating its syscall set, and record failures in the parent shell. Require relevant per-workload positive evidence. Test first/middle/last collector failures alongside allowed/forbidden syscall sets.

Attribution: introduced by the fork's acceptance runner. This finding does not claim the actual full-suite run suffered a collection failure.

#### R12. WARNING: The macOS remote driver masks the plain suite's failure

Location: `tests/macos/remote:18`.

The inner `nix develop -c bash -c` shell pipes the plain upstream suite through `sed` without enabling `pipefail`. If the suite fails while `sed` succeeds, the failure count stays zero. A successful hardened-runtime branch then permits a successful overall remote result. The outer shell's pipefail setting does not automatically configure the new inner shell.

Evidence: in the pinned development shell, the same clean nested-shell pipeline shape, with a failing producer and successful `sed`, returned 0. This is a shell-status reproduction; no remote Mac was contacted for this review.

Fix: enable pipefail inside the remote Bash or inspect the producer status explicitly. Test a failing plain suite with a passing hardened-runtime branch.

Attribution: introduced by the fork's remote driver. The Nix flake's `runCommand` pipelines are different: the pinned stdenv already enables pipefail, and an isolated failing-producer probe correctly failed its derivation.

### Duplicated run metadata and benchmark controls

#### R10. WARNING: Separate timestamps silently disable benchmark history pairing

Locations: `bm:156`, `tests/bm/prev-pair:10`; existing evidence at `bench/12623490c26b.ndjson:239`.

`bm` computes `date -Iseconds` independently for the fork and upstream rows. `prev-pair` requires identical timestamps to associate them with the same run. If row generation crosses a second, it returns no pair and the historical fork/upstream ratio check is skipped silently.

Evidence is already committed: the latest `trace_churn` fork/upstream rows at lines 239 and 240 have timestamps `16:08:55` and `16:08:56`. This command returns no pair:

```sh
tests/bm/prev-pair bench/12623490c26b.ndjson trace_churn fork
```

The ledger also contains adjacent-second `recursive-fib` and `coroutine-ring` pairs. The within-run comparison still operates; the missing control is the historical ratio comparison.

Fix: compute one shared run timestamp or unique run ID before emitting both variant rows. Pair by that identifier. Test producer/helper integration across a clock boundary and define how to recover existing unmatched adjacent rows without pairing unrelated runs.

Attribution: introduced by the fork's benchmark producer/helper contract.

## Fork advisories

### A1. Small remap areas need actual OS page-size alignment

Locations: `src/lj_mcode.c:428`, `src/lj_mcode.c:432`, `src/lj_arch.h:304`.

On a 64 KiB arm64 kernel, `sizemcode=16` produces a first file offset of zero and a second offset of 16,384 bytes. The latter cannot satisfy `mmap`'s actual page-size alignment requirement, so allocation fails fatally. The backing allocator increments offsets by logical area size without OS alignment. Upstream anonymous allocation has no corresponding file-offset requirement. The requirement is specified by the [Linux mmap manual](https://man7.org/linux/man-pages/man2/mmap.2.html).

This is source-confirmed, not reproduced on 64 KiB hardware. Current default areas are 64 KiB, and the recorded arm64 hardware run used 4 KiB pages. The current spec explicitly leaves 16/64 KiB kernels unverified. Before extending those support claims, round backing extents to the actual OS page size or clamp accepted sizes, then test multiple areas and extent reuse on those kernels.

### A2. Nix checks do not exercise MDWE enforcement

Location: `flake.nix:73`.

The remap check runs mode reporting, a trace smoke test and the upstream suite unrestricted. It does not run the kernel/seccomp enforcement paths, fork isolation or P1/P2 audits. The full `./test` covers these on Linux, but passing only the exposed Nix checks does not establish the fork's principal MDWE behavior. Add sandbox-compatible kernel/seccomp acceptance checks to the Nix check surface, with explicit unsupported-kernel handling and the upstream negative control.

### A3. A negative test relies on clocks and RNG variation

Location: `tests/bm/sizemcode-tune-test:20`.

The varying-output fixture prints `os.clock()` and RNG values seeded from clocks. It needs separate processes to produce different clock samples. Freezing the clocks in an isolated wrapper made the correct tuner accept identical output and caused exactly its two negative-control assertions to fail; the other seven checks passed. No spontaneous ordinary-suite failure was observed. Replace this fixture with output that deterministically depends on the explicit requested size argument.

### A4. Failure diagnostics rerun the entire upstream suite

Location: `tests/mdwe/r_mode:119`; per-run deadline at `tests/upstream-suite:20`.

On T9 failure, the original output is discarded and the complete suite is invoked again solely to obtain a diagnostic line. An isolated failing producer was called twice and the reported message came from invocation 2. A timed-out run can cost another 900 seconds, and a nondeterministic failure's first evidence is lost. Capture the first invocation's output and status once.

### A5. Benchmark coverage does not constrain growth in live-area count

Locations: `src/lj_mcode.c:397`, `src/lj_mcode.c:442`, `bm:75`.

`mc_find` adds linear area lookup to protection transitions; a full flush makes quadratic aggregate lookup comparisons. Default settings usually bound live areas to 32. A review sweep retaining 17/34/67/133 areas showed near-linear total compile CPU growth, with remap doubling ratios 2.10, 1.86 and 2.05 and matching results; no material complexity regression was established. These finite measurements do not prove an asymptotic bound.

The retained benchmark controls use fixed workload sizes or vary code layout. They do not gate growing live-area count or post-fork copy size. Add labeled scaling cases while preserving fixed-workload history; deterministic lookup counts would constrain the mechanism more directly than tight timing limits. Re-homing's O(live bytes + areas) copy is an explicit design cost, not an additional defect.

### A6. Passthrough options can invalidate the published executable path

Locations: `build:41`, `build:53`.

The wrapper computes its prefix, then passes arbitrary later Zig arguments. A later `--prefix` wins in Zig while publication still targets the original directory. An unchanged wrapper with a minimal real Zig graph returned success, installed at the alternate prefix, and published a dangling host symlink. An existing artifact at the original prefix would instead leave a stale executable selected. Reject overrides of wrapper-owned output settings, or derive publication from the effective settings and verify the installed executable before replacing the link. Normal builds are unaffected.

## Issues in original LuaJIT, already fixed by our fork

### U1. Callback executable-protection failures were ignored

Original location: `callback_mcode_new` in upstream `src/lj_ccallback.c`. Current fixes: `src/lj_ccallback.c:380`, `src/lj_ccallback.c:389`.

Original LuaJIT ignored `mprotect` and `VirtualProtect` failure and returned a callback trampoline that could remain non-executable. Under Linux MDWE, invoking it faults even with `-joff`. The fork releases the failed page, clears the callback pointer and raises a catchable callback-creation error. Remapping additionally permits the callback to work under MDWE in supported configurations.

Status: fixed here. Linux behavior and the protection-failure path have executable coverage. The Windows error check was reviewed and cross-compiled; a Windows denial-policy runtime was not exercised. See [upstream candidate 1](docs/UPSTREAM_CANDIDATES.md#1-ffi-callback-page-check-the-rx-protection-change).

### U2. The macOS hardened-runtime branch returned a value from a void function

Original location: upstream `src/lj_mcode.c`, `mcode_setprot`. Current fix: `src/lj_mcode.c:195`.

The upstream hardened-runtime branch contains `return 0` in a void function. Clang rejects it. The fork removes that return and restricts `mcode_protfail` to configurations that actually call it, avoiding an unused-function warning.

Status: fixed here. This review independently compiled the original baseline file for aarch64 macOS with HRT and `-Wall -Werror` and reproduced the return-type error; the current cross-target checks pass. See [upstream candidate 2](docs/UPSTREAM_CANDIDATES.md#2-macos-hardened-runtime-return-0-in-void-mcode_setprot).

### U3. macOS MAP_JIT callback pages lacked execute permission at creation

Original location: upstream `src/lj_ccallback.c`, `CCPROT_CREATE`. Current fix: `src/lj_ccallback.c:303`.

The original callback mapping omits initial `PROT_EXEC` on the hardened-runtime path. Toggling thread write protection does not add that mapping permission. The fork now creates that MAP_JIT page executable, matching the existing trace allocator's approach.

Status: fixed here. The source difference was reviewed; the project's recorded M4 Max test shows pre-fix SIGBUS and post-fix success with hardened-runtime signing and the allow-jit entitlement. This review did not repeat the native Mac execution. See [upstream candidate 3](docs/UPSTREAM_CANDIDATES.md#3-macos-hardened-runtime-ffi-callback-page-not-executable-sigbus).

### Inherited behavior and compatibility observations

The ordinary upstream JIT allocator deliberately fails loudly when the kernel refuses executable protection. Keeping that selectable behavior is an explicit fork requirement; it is not a fork regression. The raw-clone sharing residual and debugger breakpoint loss across remaps are already documented design limits, not newly discovered defects.

The pinned 2016 upstream test suite reports three known library-content mismatches (IDs 363, 365 and 366) against both implementations. The static arm64 build has four additional FFI symbol-resolution failures, already accounted for by `--static`. These comparisons do not establish new runtime bugs. R6 concerns whether the fork's wrapper proves the expected complete run occurred.

## Verification and coverage

On x86_64 Linux 6.18.54, `nix develop -c ./test` completed with exit 0 against the final reviewed code. The original run and the final run both passed. Final results:

| Check | Result |
| --- | --- |
| Makefile MDWE characterization | 90 passed, 0 failed, 0 skipped; systemd available |
| Zig MDWE characterization | 90 passed, 0 failed, 0 skipped |
| Upstream suite, Makefile and Zig | 505 passed, 3 known failures each |
| Runtime `mcoderemap=1` acceptance | 56 passed, 0 failed, 0 skipped |
| Build-time mode 2 acceptance | 56 passed, 0 failed, 0 skipped |
| Host ELF interpreter | Passed with an existing Nix store loader |
| Generated-source differential | 46 identical, 0 failed |
| Cross-target compilation | 12 checks clean |
| Benchmark helper tests | 9 tuner checks and 4 previous-pair checks passed |
| arm64 qemu upstream suite | 501 passed, 7 known static-build failures |
| arm64 qemu runtime/mode-2 workloads | Smoke, churn, cross-area and maps checks passed |

Also built the Nix default package, tested installed module loading without path overrides, built a private glibc-2.31 Zig target successfully, and ran isolated allocation, syscall-denial, sanitizer, early-child-exit, oracle-mutation and driver-status probes. Zig supplies pthread linkage for the tested older-glibc target; a Makefile/GCC build against an older glibc sysroot remains unverified. The suspected Nix `tee` status-masking issue was falsified by an actual derivation and is excluded.

The current spec records a separate native arm64 Linux run on M4 Max hardware in a Linux-builder VM using 4 KiB pages. That run was performed outside this review and is credited as recorded project evidence. Qemu runs here verify functional behavior, not native instruction-cache behavior or guest MDWE enforcement. This review did not execute native macOS, Windows, 16/64 KiB Linux kernels, or the other 32-bit/back-end targets. No fresh full performance comparison was run; the complexity sweep and committed measurements have the limits described above.

| Deep-review dimension | Coverage and disposition |
| --- | --- |
| 1. Inconsistent/incomplete functionality | Runtime latching, callbacks, build configurations; R4, A1. Enable/disable transitions across flush passed. |
| 2. Inadequate coverage | Complete-run gate, fork failure paths, enforcement coverage; R6, R7, A2. |
| 3. Futile coverage | Independent arithmetic and collection controls; R8, R9. Existing maps/cross-area/stress oracles remain useful. |
| 4. Fast coverage | Clock-dependent fixture and duplicate failure runs; A3, A4. No added sleep-based tests identified. |
| 5. Superfluous/duplicated functionality | Producer/helper metadata contract; R10. Reference Makefile and Zig graphs are intentional differential controls. |
| 6. Organization | Build wrapper output ownership; A6. Native ELF loader correction passed. |
| 7. Algorithmic complexity | Area/extent lookup, fork copying, tooling loops and finite scaling experiment; A5. No measured material complexity defect. |
| 8. File purpose | Fork research, probes, benchmarks, build and generated-source boundaries have identifiable roles; no actionable finding. |
| 9. Language/build configuration | Zig/Nix flag and installation behavior; R3, R11, R13. No generic C/Zig style findings. |
| 10. Memory/resource safety | Reservation transactions, context/area teardown, callback cleanup and backing storage; R1, R5. |
| 11. FFI/embedding correctness | Callback allocation and supported independent-state fork behavior; R2, R4. Public C signatures remain unchanged. |
| 12. Error handling | OOM, denied syscalls, callback errors and test-driver status propagation; R1, R5, R12. Fatal remap failure follows the accepted spec. |
| 13. Database access | Not applicable to the product. Codescan's SQLite index is development infrastructure. |

Review experiments were kept outside the source tree. The review changed this document and progress metadata; it did not fix runtime code or modify the production sandbox. Passing ordinary tests and failing isolated probes are reported separately so neither is mistaken for the other.

## Appendix A: Natural-trace allocator-failure reproduction

Save this as a temporary `oom_trace.c`. It uses internal headers only to inject a failure during the incomplete reservation window, and otherwise drives an ordinary Lua loop through the public embedding API.

```c
#include <stdio.h>
#include <stdlib.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "lj_obj.h"
#include "lj_jit.h"
#include "lj_dispatch.h"

static lua_State *active;
static int armed;
static void *alloc(void *ud, void *p, size_t old, size_t n)
{
  (void)ud;
  if (!n) { free(p); return NULL; }
  if (armed && active && L2J(active)->mcarea && !L2J(active)->szmcarea) {
    fprintf(stderr, "INJECT allocation failure n=%zu old=%zu\n", n, old);
    armed = 0;
    return NULL;
  }
  return realloc(p, n);
}
static int panic(lua_State *L)
{
  fprintf(stderr, "PANIC: %s\n", lua_tostring(L, -1));
  return 0;
}
int main(void)
{
  lua_State *L = lua_newstate(alloc, NULL);
  if (!L) return 2;
  active = L;
  lua_atpanic(L, panic);
  luaL_openlibs(L);
  if (luaL_loadstring(L, "local s=0 for i=1,10000 do s=s+i end return s"))
    return 3;
  armed = 1;
  int rc = lua_pcall(L, 0, 1, 0);
  fprintf(stderr, "PCALL RETURNED %d\n", rc);
  lua_close(L);
  return rc;
}
```

After `./build --mcode 2`, compile using the matching mode and headers:

```sh
nix develop -c cc -O2 -g -DLUAJIT_SECURITY_MCODE=2 -Isrc \
  /tmp/oom_trace.c \
  zig-out/x86_64-linux-gnu/ReleaseFast-mcode2/lib/libluajit-5.1.a \
  -lm -ldl -pthread -o /tmp/oom_trace
/tmp/oom_trace
```

On the reviewed code, the panic exits the process before `PCALL RETURNED`. A regression fix must allow normal error recovery and safe state teardown; merely changing the fatal diagnostic would leave the transaction defect.
