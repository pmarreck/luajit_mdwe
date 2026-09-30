# Beyond MDWE: research on a post-init "mcode lockdown"

Status: **research record only; no spec and no implementation.** Requested by
Peter via dune_awakening_server (2026-09-30 17:41 EDT) as the next hardening
step after MemoryDenyWriteExecute (MDWE), keeping the JIT. Rescoped at 17:51
EDT: Dune stops at MDWE with this fork, systemd sandboxing and a dedicated
service user, so a lockdown is an optional fork feature, to be built only if it
is worth it for LuaJIT users generally. The recommendation (§6) is not to build
it, and to rely on host-level controls instead.

Labels as in [`MDWE_RESEARCH.md`](MDWE_RESEARCH.md): **[MEAS]** measured here,
**[SRC]** primary source, **[INF]** inference, **[UNV]** not verified.

## 1. Question

MDWE (kernel `PR_SET_MDWE`, systemd `MemoryDenyWriteExecute=yes`) forbids
mappings that are writable and executable at once, and forbids adding
`PROT_EXEC` to an existing mapping. It does not forbid a fresh
`mmap(PROT_READ|PROT_EXEC)` of a file: that is how the dynamic loader works,
and it is the route this fork's memfd allocator uses. The question: can a
process keep its JIT while losing the ability to create *other* executable
memory after startup, and at what cost?

## 2. Environment

Same machine as `MDWE_RESEARCH.md` §1: Linux 6.18.54 (NixOS), systemd 261,
AMD Ryzen Threadripper 3990X (Zen 2), nixpkgs `7a0f122f`. Kernel config
[MEAS, `/proc/config.gz`]: `CONFIG_SECCOMP_FILTER=y`,
`CONFIG_SECURITY_LANDLOCK=y` (active LSMs: capability, landlock, yama, bpf,
ima), `CONFIG_PROC_MEM_ALWAYS_FORCE=y`, `CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS=y`.
The CPU has no `pku` flag, so memory protection keys cannot be exercised here.
Host `vm.memfd_noexec` = 0.

Enforcement surfaces, as in `tests/mdwe/run`: none, kernel `PR_SET_MDWE`
(`tests/mdwe/mdwe_exec.c`), the systemd seccomp-filter replica
(`tests/mdwe/sdmdwe_seccomp_exec.c`) and `systemd-run --user -p
MemoryDenyWriteExecute=yes`.

Measurement code: small probes written for this research were deliberately
not committed, to keep the fork's code changes minimal. They are kept, git
ignored, in `.build-work/lockdown/` (`wx_probe-routes.patch` against
`tests/mdwe/wx_probe.c`, and `lockdown_probe.c`). Results below come from
those probes and from `strace`.

## 3. Routes to executable memory that MDWE leaves open

| # | Route | none | kernel | seccomp replica | systemd | What closes it |
|---|---|---|---|---|---|---|
| R1 | Any writable file (tmpfs `/tmp`, `/dev/shm`, `O_TMPFILE`, ZFS home) written, then mapped RX | allowed | allowed | allowed | allowed | `noexec` mounts / systemd `NoExecPaths=` + `ExecPaths=` for every writable location; or a filter restricting `PROT_EXEC` mappings (§5) |
| R2 | Program executed from a memfd (`execveat` with `AT_EMPTY_PATH`), memfd created with `MFD_EXEC` or no flag | allowed | allowed | allowed | allowed | `MFD_NOEXEC_SEAL` on the memfd (refused with `EACCES`, measured); host-wide: `vm.memfd_noexec` (§4.3) |
| R3 | Writes to existing RX pages through `/proc/self/mem` | allowed | allowed | allowed | not run | kernel `proc_mem.force_override` boot parameter or a `PROC_MEM_*` kernel config (§4.4); not expressible in seccomp |

All [MEAS] except the "What closes it" column. The R1 and R2 rows were run in
all four columns; R3 matches the existing `procmem` cell of `tests/mdwe/run`.

Consequences:

- Denying `memfd_create` alone does not close R1: any writable file serves.
- This fork's own memfd uses `MFD_NOEXEC_SEAL`, so the fork does not add an
  R2 route [MEAS for the flag's effect; the fork's flag is in
  `src/lj_mcode.c:lj_mcode_memfd`].
- R3 needs no new mapping at all, so no mmap/mprotect filter addresses it.

## 4. Neighbors a lockdown would affect

### 4.1 Erlang/OTP 27 BEAMJIT (RabbitMQ's runtime)

nixpkgs `erlang_27` = OTP 27.3.4.18, `emu_flavor` = `jit`; `rabbitmq-server`
4.3.1 depends on exactly this Erlang [MEAS, `nix-store -q --references`].

- Startup calls `memfd_create("vmem", MFD_CLOEXEC|MFD_EXEC)` twice, tries a
  4 KiB anonymous RWX mapping, and maps a 64 MiB RX shared view of the memfd
  (its dual mapping) [MEAS, strace].
- Runs (`jit ok`) under kernel MDWE, the seccomp replica and systemd MDWE
  [MEAS].
- With systemd MDWE plus `SystemCallFilter=~memfd_create`
  (`SystemCallErrorNumber=EPERM`), it aborts: `beam/jit/beam_jit_main.cpp:233:
  pick_allocator(): Internal error: jit: Cannot allocate executable memory.
  Use the interpreter instead.` [MEAS]. Without MDWE the same denial is
  survived (it falls back to RWX) [MEAS].
- The nixpkgs build ships only `beam.smp`; `-emu_flavor emu` is not
  available, so there is no interpreter fallback [MEAS].
- Under `vm.memfd_noexec=2` its `MFD_EXEC` request would be refused
  [INF from `mm/memfd.c` v6.18, as cited in `MDWE_RESEARCH.md`; UNV].

So any control that denies `memfd_create` to a process tree containing
`rabbitmqctl` breaks it.

### 4.2 .NET 8

nixpkgs `dotnet-sdk_8` = 8.0.425. `dotnet --info` calls
`memfd_create("doublemapper", MFD_CLOEXEC)`, maps its ReadyToRun images RX
from their files, and makes 123 `mprotect(..., PROT_READ|PROT_EXEC)` calls
[MEAS, strace]. It dies with SIGSEGV under all three MDWE surfaces (systemd:
`code=dumped, status=11/SEGV`), including with
`DOTNET_EnableWriteXorExecute=0` under the kernel prctl [MEAS]. With only
`memfd_create` denied and no MDWE, it runs [MEAS]. .NET 8 is therefore
already incompatible with MDWE, independent of any lockdown.

### 4.3 `vm.memfd_noexec`

The sysctl is per pid namespace. Writing it from an unprivileged user plus pid
namespace (`unshare -Urpf --mount-proc`) fails with `Permission denied`
[MEAS]. Measuring its real effect needs root in a throwaway pid namespace or
a VM; not done. From source [SRC, `mm/memfd.c` v6.18]: level 1 makes flagless
memfds `NOEXEC_SEAL`; level 2 also refuses `MFD_EXEC`. It would close R2
host-wide and should not affect this fork (which already asks for
`NOEXEC_SEAL` and maps with `mmap`, not `execve`) [INF, UNV], but it would
break BEAMJIT (§4.1) [INF].

### 4.4 `/proc/self/mem`

The kernel is built with `CONFIG_PROC_MEM_ALWAYS_FORCE=y` [MEAS]. The same
kernel option group offers "force only for ptrace" and "never force"
variants, and a `proc_mem.force_override=` boot parameter selects among them
[UNV: option names seen in this kernel's config; the parameter name is from
memory of the upstream change, not checked against source or tested].

## 5. The in-process lockdown design and its limits

The idea in Dune's note: pre-create the mcode memfd, then self-install a
seccomp filter that denies `memfd_create`, allows `PROT_EXEC` in `mmap` only
for the mcode fd, denies `PROT_EXEC` in `mprotect`/`pkey_mprotect`, and
guards that fd number against being replaced.

Partial prototype results [MEAS, `lockdown_probe.c`, none and kernel MDWE]:

- The fork's remap cycle (RW shared view, RX private view, patch, RX again) on
  the pre-created fd works with the filter installed.
- New-file RX mappings (R1), `memfd_create`, and `dup2` onto the mcode fd are
  refused with `EPERM`.
- The mcode fd itself can still be mapped writable and then executable. This
  is the ceiling of any in-process design: the process that legitimately
  writes code can be made to write other code. Only a compiler outside the
  attacker's process closes it, and only if the attacker's process cannot
  choose the bytes that compiler emits [INF].
- `close` / `close_range` of the mcode fd were not refused: the filter had a
  jump-offset bug that was not fixed before the work stopped.
- The child-process test (fork, then exec a dynamically linked `true`) exited
  0 under the filter. This does **not** show that children work. The mcode
  memfd was probably fd 3 and close-on-exec, so the child's first library
  load plausibly reused fd 3 and matched the filter [INF, UNV]. An earlier
  note to Dune stated that such a filter stops the loader in children; that
  was a prediction, not a measurement.
- The R3 check under the filter was refused during its own setup, before the
  route was attempted, so it says nothing either way.
- Filter cost per syscall was not measured.

Structural limits, independent of the bugs above [INF]:

- Seccomp filters survive `fork` and `execve`. A filter keyed to one fd number
  applies to every descendant, where that number means something else, so
  children either break or accidentally pass. A process that spawns helpers
  (Dune's bridge runs `bash`, then `rabbitmqctl`, then BEAMJIT) must spawn
  them before lockdown or through a helper started before it.
- After lockdown, `dlopen` (so `ffi.load`) cannot map new libraries.
- After `fork`, this fork's allocator moves each process to a new memfd
  before its next code write (`MDWE_SPEC.md` §5.5). Under a `memfd_create`
  ban that needs a pre-created pool, and the child's JIT would have to stop
  when the pool runs out.
- R3 is out of reach of seccomp (paths are not visible to it); it needs
  Landlock or the host-level `/proc` controls above.
- Memory protection keys limit writes from user space without a syscall, so
  they do not stop an attacker who can make syscalls. They could not be
  exercised on this CPU.

## 6. Recommendation

Do not add a lockdown mode to the fork for now.

- It would add a seccomp filter, an fd pool and fork/dlopen special cases to
  LuaJIT for a gain that stops at the in-process ceiling (§5), against the
  fork's goal of minimal changes to upstream.
- The routes MDWE leaves open are better closed at the host or service level,
  without touching LuaJIT: `noexec` mounts or systemd `NoExecPaths=` +
  `ExecPaths=` for R1; `MFD_NOEXEC_SEAL` (already used by the fork) and
  optionally `vm.memfd_noexec` for R2 (mind BEAMJIT, §4.1); the
  `/proc/self/mem` force setting for R3.
- The main consumer (Dune) has declined it (§ Status).

Revisit if a user needs a JIT in a process that spawns no children and loads
no libraries after startup; the prototype results in §5 are the starting
point, and its open bugs must be fixed and the child and cost questions
measured first.

## 7. Open items

- Measure `vm.memfd_noexec=1/2` in a root-owned throwaway pid namespace or a
  VM: effect on this fork, on BEAMJIT and on R2.
- Verify the `/proc/self/mem` force parameter against kernel source and test it.
- Systemd `NoExecPaths=`/`ExecPaths=` against R1 with this fork running:
  expected to leave the memfd route working, since memfds live on an internal
  mount [INF, UNV].
