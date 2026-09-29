# LuaJIT under MemoryDenyWriteExecute

This fork investigates whether LuaJIT can compile and execute JIT traces under systemd `MemoryDenyWriteExecute=yes` without hiding the resulting security tradeoffs. Its upstream is [LuaJIT/LuaJIT](https://github.com/LuaJIT/LuaJIT); retain the upstream `v2.1` branch convention and license.

Intended users maintain sandboxed services that benefit from LuaJIT compilation. The immediate consumer can use `-joff` while this investigation proceeds, so there is no production deadline.

## Outcomes and scope

Research precedents and actual enforcement behavior, write a technical spec, obtain an independent Grok review, then implement the reviewed design. Linux x86_64 is the first execution target. Account for other LuaJIT architectures and operating systems without claiming unexecuted coverage; preserve selectable upstream behavior.

A proposed dual-mapping strategy is a hypothesis. Separate writable and executable virtual addresses do not prove executable contents are protected from writes. The spec must state the threat model, residual writable aliases, address translation, code patching, cache coherence and debugger-interface effects.

Systemd's seccomp implementation and kernel `PR_SET_MDWE` are distinct enforcement surfaces to reproduce and compare. Passing either launch does not establish identical semantics or a stronger security boundary.

## Verification

Create an isolated failing regression that forces real trace compilation and detects the current MDWE failure, then test the fix without weakening MDWE or silently disabling JIT. Compare actual JIT execution with upstream and interpreted controls. Run relevant upstream suites plus stress, trace-link/patch and callback tests. Use deterministic workloads and retain benchmark measurements against upstream; "within noise" requires measured noise, not an arbitrary unexplained threshold.

Do not alter production service sandboxes or deploy this fork during research. Keep implementation behind the spec-review checkpoint. See `PLAN.md` for the sequence.
