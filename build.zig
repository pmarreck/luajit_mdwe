//! Zig build for LuaJIT, alongside upstream's Makefile (which stays the
//! reference). It mirrors src/Makefile's configuration logic: the target C
//! preprocessor is run over lj_arch.h and DynASM/buildvm flags are derived
//! from the same macros the Makefile greps for, so cross targets get the same
//! flags a native Makefile build would. Tested against the Makefile by
//! comparing generated headers and lj_vm.S (tests/zig/compare-generated).
//!
//!   zig build [-Dtarget=...] [-Doptimize=...] [-Dxcflags=-DFOO ...]
//!   zig build flags   # print the derived configuration and exit
const std = @import("std");

const Arch = enum { x64, arm64 };

/// Configuration derived from `cc -E -dM lj_arch.h`, following src/Makefile.
const Config = struct {
    arch: Arch,
    dasm_arch: []const u8,
    dasm_flags: []const []const u8,
    /// Makefile TARGET_ARCH: defines for the host tools (buildvm/minilua).
    host_arch_flags: []const []const u8,
    unwind_external: bool,
};

/// Makefile-style `findstring`: substring test over the macro dump.
fn has(macros: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, macros, needle) != null;
}

/// Value of a `#define NAME VALUE` line in a `-dM` dump, if present.
fn defineValue(macros: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, macros, '\n');
    while (lines.next()) |line| {
        const prefix = "#define ";
        if (!std.mem.startsWith(u8, line, prefix)) continue;
        const rest = line[prefix.len..];
        if (std.mem.startsWith(u8, rest, name) and rest.len > name.len and rest[name.len] == ' ')
            return std.mem.trim(u8, rest[name.len + 1 ..], " \r");
    }
    return null;
}

/// Mirror src/Makefile's TARGET_TESTARCH -> TARGET_LJARCH/DASM_AFLAGS/TARGET_ARCH
/// logic for the architectures this build supports (x64, arm64).
fn deriveConfig(b: *std.Build, target: std.Build.ResolvedTarget, macros: []const u8) Config {
    const os = target.result.os.tag;
    var dasm: std.ArrayList([]const u8) = .empty;
    var host: std.ArrayList([]const u8) = .empty;
    const a = b.allocator;

    const arch: Arch = if (has(macros, "LJ_TARGET_X64 ")) .x64 else if (has(macros, "LJ_TARGET_ARM64 ")) blk: {
        if (has(macros, "__AARCH64EB__ ")) host.append(a, "-D__AARCH64EB__=1") catch @panic("OOM");
        break :blk .arm64;
    } else std.debug.panic("build.zig supports x64 and arm64 targets only; use src/Makefile for {s}", .{@tagName(target.result.cpu.arch)});

    host.append(a, b.fmt("-DLUAJIT_TARGET=LUAJIT_ARCH_{s}", .{@tagName(arch)})) catch @panic("OOM");

    dasm.append(a, if (has(macros, "LJ_LE 1")) "ENDIAN_LE" else "ENDIAN_BE") catch @panic("OOM");
    if (has(macros, "LJ_ARCH_BITS 64")) dasm.append(a, "P64") catch @panic("OOM");
    if (has(macros, "LJ_HASJIT 1")) dasm.append(a, "JIT") catch @panic("OOM");
    if (has(macros, "LJ_HASFFI 1")) dasm.append(a, "FFI") catch @panic("OOM");
    if (has(macros, "LJ_DUALNUM 1")) dasm.append(a, "DUALNUM") catch @panic("OOM");
    if (has(macros, "LJ_ARCH_HASFPU 1")) {
        dasm.append(a, "FPU") catch @panic("OOM");
        host.append(a, "-DLJ_ARCH_HASFPU=1") catch @panic("OOM");
    } else host.append(a, "-DLJ_ARCH_HASFPU=0") catch @panic("OOM");
    if (!has(macros, "LJ_ABI_SOFTFP 1")) {
        dasm.append(a, "HFABI") catch @panic("OOM");
        host.append(a, "-DLJ_ABI_SOFTFP=0") catch @panic("OOM");
    } else host.append(a, "-DLJ_ABI_SOFTFP=1") catch @panic("OOM");
    const no_unwind = has(macros, "LJ_NO_UNWIND 1");
    if (no_unwind) {
        dasm.append(a, "NO_UNWIND") catch @panic("OOM");
        host.append(a, "-DLUAJIT_NO_UNWIND") catch @panic("OOM");
    }
    if (has(macros, "LJ_ABI_PAUTH 1")) {
        dasm.append(a, "PAUTH") catch @panic("OOM");
        host.append(a, "-DLJ_ABI_PAUTH=1") catch @panic("OOM");
    }
    if (has(macros, "LJ_ABI_BRANCH_TRACK 1")) {
        dasm.append(a, "BRANCH_TRACK") catch @panic("OOM");
        host.append(a, "-DLJ_ABI_BRANCH_TRACK=1") catch @panic("OOM");
    }
    if (has(macros, "LJ_ABI_SHADOW_STACK 1")) {
        dasm.append(a, "SHADOW_STACK") catch @panic("OOM");
        host.append(a, "-DLJ_ABI_SHADOW_STACK=1") catch @panic("OOM");
    }
    // Empty when undefined (x64), exactly as the Makefile's "-D VER=".
    const ver = defineValue(macros, "LJ_ARCH_VERSION") orelse "";
    dasm.append(a, b.fmt("VER={s}", .{ver})) catch @panic("OOM");
    if (os == .windows) dasm.append(a, "WIN") catch @panic("OOM");

    const dasm_arch: []const u8 = switch (arch) {
        .x64 => if (has(macros, "LJ_FR2 1")) "x64" else "x86",
        .arm64 => "arm64",
    };

    // Makefile: -DLUAJIT_OS=... for the host tools when host and target OS differ.
    if (os != b.graph.host.result.os.tag) {
        host.append(a, switch (os) {
            .windows => "-DLUAJIT_OS=LUAJIT_OS_WINDOWS",
            .linux => "-DLUAJIT_OS=LUAJIT_OS_LINUX",
            .macos => "-DLUAJIT_OS=LUAJIT_OS_OSX",
            else => "-DLUAJIT_OS=LUAJIT_OS_OTHER",
        }) catch @panic("OOM");
    }

    // Makefile: always on Darwin; elsewhere (not Windows) when the toolchain
    // emits unwind tables, which this build requests explicitly (see lib).
    const unwind_external = !no_unwind and os != .windows;

    // DynASM takes "-D FLAG" pairs.
    var dflags: std.ArrayList([]const u8) = .empty;
    for (dasm.items) |f| dflags.appendSlice(a, &.{ "-D", f }) catch @panic("OOM");

    return .{
        .arch = arch,
        .dasm_arch = dasm_arch,
        .dasm_flags = dflags.items,
        .host_arch_flags = host.items,
        .unwind_external = unwind_external,
    };
}

/// Generated files that a Makefile build leaves in src/. They must never be
/// compiled into a Zig build: quote-includes search the including file's own
/// directory first, so a stale copy would shadow the Zig-generated one.
const makefile_generated = [_][]const u8{
    "luajit.h",         "lj_bcdef.h",      "lj_ffdef.h",    "lj_libdef.h",
    "lj_recdef.h",      "lj_folddef.h",    "lj_vm.S",       "luajit_relver.txt",
    "buildvm_arch.h",   "vmdef.lua",
};

fn isGenerated(name: []const u8) bool {
    for (makefile_generated) |g| if (std.mem.eql(u8, name, g)) return true;
    return false;
}

fn wantedSource(name: []const u8) bool {
    const exts = [_][]const u8{ ".c", ".h", ".hpp", ".dasc", ".lua" };
    for (exts) |e| if (std.mem.endsWith(u8, name, e)) return !isGenerated(name);
    return false;
}

/// Copy src/{.,host,jit} and dynasm/ sources (never Makefile outputs) into a
/// build-owned directory, so the Zig build is independent of `make` state.
fn stageSources(b: *std.Build) *std.Build.Step.WriteFile {
    const wf = b.addWriteFiles();
    const io = b.graph.io;
    const dirs = [_][]const u8{ "src", "src/host", "src/jit", "dynasm" };
    for (dirs) |d| {
        var dir = b.build_root.handle.openDir(io, d, .{ .iterate = true }) catch |e|
            std.debug.panic("cannot open {s}: {t}", .{ d, e });
        defer dir.close(io);
        var it = dir.iterate();
        while (it.next(io) catch |e| std.debug.panic("reading {s}: {t}", .{ d, e })) |entry| {
            if (entry.kind != .file or !wantedSource(entry.name)) continue;
            const rel = b.fmt("{s}/{s}", .{ d, entry.name });
            _ = wf.addCopyFile(b.path(rel), rel);
        }
    }
    return wf;
}

/// Rolling release version the way the Makefile computes luajit_relver.txt:
/// committer timestamp of HEAD, else the contents of .relver.
fn relver(b: *std.Build) []const u8 {
    if (b.option([]const u8, "relver", "Rolling release version (default: git HEAD commit time, else .relver)")) |v| return v;
    var code: u8 = undefined;
    const out = b.runAllowFail(&.{ "git", "-C", b.build_root.path orelse ".", "show", "-s", "--format=%ct" }, &code, .ignore) catch null;
    if (out) |o| if (std.mem.trim(u8, o, " \r\n").len > 0) return o;
    return b.build_root.handle.readFileAlloc(b.graph.io, ".relver", b.allocator, .limited(256)) catch "";
}

const lib_sources = [_][]const u8{
    "lib_base.c", "lib_math.c", "lib_bit.c",   "lib_string.c", "lib_table.c", "lib_io.c",
    "lib_os.c",   "lib_package.c", "lib_debug.c", "lib_jit.c",    "lib_ffi.c",   "lib_buffer.c",
};

/// src/Makefile LJCORE_O order (tests/zig/compare-generated checks the set).
const core_sources = [_][]const u8{
    "lj_assert.c",  "lj_gc.c",       "lj_err.c",        "lj_char.c",      "lj_bc.c",        "lj_obj.c",
    "lj_buf.c",     "lj_str.c",      "lj_tab.c",        "lj_func.c",      "lj_udata.c",     "lj_meta.c",
    "lj_debug.c",   "lj_prng.c",     "lj_state.c",      "lj_dispatch.c",  "lj_vmevent.c",   "lj_vmmath.c",
    "lj_strscan.c", "lj_strfmt.c",   "lj_strfmt_num.c", "lj_serialize.c", "lj_api.c",       "lj_profile.c",
    "lj_lex.c",     "lj_parse.c",    "lj_bcread.c",     "lj_bcwrite.c",   "lj_load.c",      "lj_ir.c",
    "lj_opt_mem.c", "lj_opt_fold.c", "lj_opt_narrow.c", "lj_opt_dce.c",   "lj_opt_loop.c",  "lj_opt_split.c",
    "lj_opt_sink.c", "lj_mcode.c",   "lj_snap.c",       "lj_record.c",    "lj_crecord.c",   "lj_ffrecord.c",
    "lj_asm.c",     "lj_trace.c",    "lj_gdbjit.c",     "lj_ctype.c",     "lj_cdata.c",     "lj_cconv.c",
    "lj_ccall.c",   "lj_ccallback.c", "lj_carith.c",    "lj_clib.c",      "lj_cparse.c",    "lj_lib.c",
    "lj_alloc.c",   "lib_aux.c",
} ++ lib_sources ++ [_][]const u8{"lib_init.c"};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Peter's convention: ReleaseFast unless asked otherwise.
    const optimize = b.option(std.builtin.OptimizeMode, "optimize", "Optimization mode (default: ReleaseFast)") orelse .ReleaseFast;
    const user_xcflags = b.option([]const []const u8, "xcflags", "Extra C flags, as Makefile XCFLAGS (repeatable)") orelse &.{};
    // 0 = RWX, 1 = upstream RW^X via mprotect (default), 2 = RW^X by memfd
    // remapping, usable under MemoryDenyWriteExecute (docs/MDWE_SPEC.md).
    const security_mcode = b.option(u2, "security-mcode", "LUAJIT_SECURITY_MCODE (default: upstream's 1)");
    // Benchmark methodology only: -falign-functions=N moves every C function,
    // changing code layout (and so icache/iTLB behavior) without changing code.
    // Comparing configurations across several alignments separates their effect
    // from layout luck (Mytkowicz et al., ASPLOS 2009). (Permuting the source
    // list was tried first and did not move any symbol.)
    const layout_align = b.option(u32, "layout-align", "-falign-functions=N for the library (benchmarking)");
    const xcflags = if (security_mcode) |m|
        std.mem.concat(b.allocator, []const u8, &.{ user_xcflags, &.{b.fmt("-DLUAJIT_SECURITY_MCODE={d}", .{m})} }) catch @panic("OOM")
    else
        user_xcflags;

    const t = target.result;
    const os = t.os.tag;
    if (os != .linux and os != .macos and os != .windows)
        std.debug.panic("build.zig supports linux, macos and windows targets; use src/Makefile for {s}", .{@tagName(os)});

    // --- Configure: target preprocessor over lj_arch.h (Makefile TARGET_TESTARCH).
    const probe_argv = blk: {
        var argv: std.ArrayList([]const u8) = .empty;
        argv.appendSlice(b.allocator, &.{ b.graph.zig_exe, "cc" }) catch @panic("OOM");
        if (!target.query.isNative())
            argv.appendSlice(b.allocator, &.{ "-target", t.zigTriple(b.allocator) catch @panic("OOM") }) catch @panic("OOM");
        argv.appendSlice(b.allocator, xcflags) catch @panic("OOM");
        argv.appendSlice(b.allocator, &.{ "-E", "-dM", b.pathFromRoot("src/lj_arch.h") }) catch @panic("OOM");
        break :blk argv.items;
    };
    const macros = b.run(probe_argv);
    const cfg = deriveConfig(b, target, macros);

    const flags_step = b.step("flags", "Print derived DynASM/host flags");
    const print = b.addSystemCommand(&.{"echo"});
    print.addArgs(&.{ "dasm_arch:", cfg.dasm_arch, "dasm:" });
    print.addArgs(cfg.dasm_flags);
    print.addArg("host:");
    print.addArgs(cfg.host_arch_flags);
    print.addArgs(&.{ "unwind_external:", if (cfg.unwind_external) "yes" else "no" });
    flags_step.dependOn(&print.step);

    const staged = stageSources(b);
    const src = staged.getDirectory().path(b, "src");

    // --- Host tools.
    const host_mod = struct {
        fn make(bb: *std.Build) *std.Build.Module {
            return bb.createModule(.{
                .target = bb.graph.host,
                .optimize = .ReleaseFast,
                .link_libc = true,
                .sanitize_c = .off,
            });
        }
    };
    const minilua = b.addExecutable(.{ .name = "minilua", .root_module = host_mod.make(b) });
    minilua.root_module.addCSourceFile(.{ .file = src.path(b, "host/minilua.c") });
    minilua.root_module.linkSystemLibrary("m", .{});

    const dynasm = b.addRunArtifact(minilua);
    dynasm.addFileArg(staged.getDirectory().path(b, "dynasm/dynasm.lua"));
    dynasm.addArgs(cfg.dasm_flags);
    dynasm.addArg("-o");
    const buildvm_arch_h = dynasm.addOutputFileArg("buildvm_arch.h");
    dynasm.addFileArg(src.path(b, b.fmt("vm_{s}.dasc", .{cfg.dasm_arch})));

    const relver_txt = b.addWriteFiles().add("luajit_relver.txt", relver(b));
    const genversion = b.addRunArtifact(minilua);
    genversion.addFileArg(src.path(b, "host/genversion.lua"));
    genversion.addFileArg(src.path(b, "luajit_rolling.h"));
    genversion.addFileArg(relver_txt);
    const luajit_h = genversion.addOutputFileArg("luajit.h");

    const buildvm = b.addExecutable(.{ .name = "buildvm", .root_module = host_mod.make(b) });
    var host_cflags: std.ArrayList([]const u8) = .empty;
    host_cflags.appendSlice(b.allocator, cfg.host_arch_flags) catch @panic("OOM");
    host_cflags.appendSlice(b.allocator, xcflags) catch @panic("OOM");
    buildvm.root_module.addCSourceFiles(.{
        .root = src,
        .files = &.{ "host/buildvm.c", "host/buildvm_asm.c", "host/buildvm_peobj.c", "host/buildvm_lib.c", "host/buildvm_fold.c" },
        .flags = host_cflags.items,
    });
    buildvm.root_module.addIncludePath(src);
    buildvm.root_module.addIncludePath(buildvm_arch_h.dirname());
    buildvm.root_module.addIncludePath(luajit_h.dirname());

    const gen = b.addWriteFiles(); // collects generated headers in one include dir
    const lib_files = blk: {
        var l: [lib_sources.len]std.Build.LazyPath = undefined;
        for (lib_sources, 0..) |f, i| l[i] = src.path(b, f);
        break :blk l;
    };
    for ([_][]const u8{ "bcdef", "ffdef", "libdef", "recdef" }) |mode| {
        const r = b.addRunArtifact(buildvm);
        r.addArgs(&.{ "-m", mode, "-o" });
        const out = r.addOutputFileArg(b.fmt("lj_{s}.h", .{mode}));
        for (lib_files) |f| r.addFileArg(f);
        _ = gen.addCopyFile(out, b.fmt("lj_{s}.h", .{mode}));
    }
    const folddef = b.addRunArtifact(buildvm);
    folddef.addArgs(&.{ "-m", "folddef", "-o" });
    _ = gen.addCopyFile(folddef.addOutputFileArg("lj_folddef.h"), "lj_folddef.h");
    folddef.addFileArg(src.path(b, "lj_opt_fold.c"));
    _ = gen.addCopyFile(luajit_h, "luajit.h");

    const vmdef = b.addRunArtifact(buildvm);
    vmdef.addArgs(&.{ "-m", "vmdef", "-o" });
    const vmdef_lua = vmdef.addOutputFileArg("vmdef.lua");
    for (lib_files) |f| vmdef.addFileArg(f);

    const ljvm = b.addRunArtifact(buildvm);
    ljvm.addArgs(&.{ "-m", if (os == .windows) "peobj" else if (os == .macos) "machasm" else "elfasm", "-o" });
    const ljvm_out = ljvm.addOutputFileArg(if (os == .windows) "lj_vm.o" else "lj_vm.S");

    // --- Library (Makefile TARGET_ACFLAGS equivalents).
    var cflags: std.ArrayList([]const u8) = .empty;
    cflags.appendSlice(b.allocator, &.{ "-Wall", "-D_FILE_OFFSET_BITS=64", "-D_LARGEFILE_SOURCE", "-U_FORTIFY_SOURCE" }) catch @panic("OOM");
    if (cfg.unwind_external) cflags.append(b.allocator, "-DLUAJIT_UNWIND_EXTERNAL") catch @panic("OOM");
    cflags.appendSlice(b.allocator, xcflags) catch @panic("OOM");

    const lib_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .sanitize_c = .off, // LuaJIT relies on behavior UBSan would trap.
        .stack_protector = if (os == .windows) null else false,
        .omit_frame_pointer = true,
        .unwind_tables = if (cfg.unwind_external) .async else null,
    });
    lib_mod.addIncludePath(gen.getDirectory());
    lib_mod.addIncludePath(src);
    var lib_cflags: std.ArrayList([]const u8) = .empty;
    lib_cflags.appendSlice(b.allocator, cflags.items) catch @panic("OOM");
    if (layout_align) |n| lib_cflags.append(b.allocator, b.fmt("-falign-functions={d}", .{n})) catch @panic("OOM");
    lib_mod.addCSourceFiles(.{ .root = src, .files = &core_sources, .flags = lib_cflags.items });
    if (os == .windows) lib_mod.addObjectFile(ljvm_out) else lib_mod.addAssemblyFile(ljvm_out);
    const lib = b.addLibrary(.{ .name = "luajit-5.1", .linkage = .static, .root_module = lib_mod });
    for ([_][]const u8{ "lua.h", "lualib.h", "lauxlib.h", "luaconf.h", "lua.hpp" }) |h|
        lib.installHeader(src.path(b, h), b.fmt("luajit-2.1/{s}", .{h}));
    lib.installHeader(luajit_h, "luajit-2.1/luajit.h");
    b.installArtifact(lib);

    // --- CLI (Makefile luajit: luajit.o + libluajit, -lm -ldl, -Wl,-E).
    const exe_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .sanitize_c = .off,
        .stack_protector = if (os == .windows) null else false,
        .omit_frame_pointer = true,
    });
    exe_mod.addIncludePath(gen.getDirectory());
    exe_mod.addIncludePath(src);
    exe_mod.addCSourceFile(.{ .file = src.path(b, "luajit.c"), .flags = cflags.items });
    exe_mod.linkLibrary(lib);
    if (os != .windows) exe_mod.linkSystemLibrary("m", .{});
    if (os == .linux) exe_mod.linkSystemLibrary("dl", .{});
    // gcc links libgcc's unwinder implicitly; with Zig, -lunwind selects its
    // bundled LLVM libunwind (needed for LUAJIT_UNWIND_EXTERNAL on ELF targets).
    if (cfg.unwind_external and os != .macos) exe_mod.linkSystemLibrary("unwind", .{});
    const exe = b.addExecutable(.{ .name = "luajit", .root_module = exe_mod });
    if (os == .linux) exe.rdynamic = true;
    b.installArtifact(exe);

    // jit.* Lua modules (for -jv, -jdump, -p) plus the generated vmdef.lua.
    const jitlib = "share/luajit-2.1/jit";
    b.installDirectory(.{ .source_dir = src.path(b, "jit"), .install_dir = .prefix, .install_subdir = jitlib, .include_extensions = &.{".lua"} });
    b.getInstallStep().dependOn(&b.addInstallFileWithDir(vmdef_lua, .prefix, jitlib ++ "/vmdef.lua").step);

    // Generated sources, for comparison against a Makefile build.
    const gen_step = b.step("generated", "Install generated headers and lj_vm into <prefix>/generated");
    for ([_]struct { std.Build.LazyPath, []const u8 }{
        .{ buildvm_arch_h, "buildvm_arch.h" }, .{ luajit_h, "luajit.h" }, .{ vmdef_lua, "vmdef.lua" },
        .{ ljvm_out, if (os == .windows) "lj_vm.o" else "lj_vm.S" },
    }) |g| gen_step.dependOn(&b.addInstallFileWithDir(g[0], .prefix, b.fmt("generated/{s}", .{g[1]})).step);
    gen_step.dependOn(&b.addInstallDirectory(.{ .source_dir = gen.getDirectory(), .install_dir = .prefix, .install_subdir = "generated" }).step);
}
