{
	description = "LuaJIT v2.1 fork investigating JIT execution under Linux MemoryDenyWriteExecute";

	inputs = {
		nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
		# Comparison control: the upstream commit this fork branched from.
		luajit-upstream = {
			url = "github:LuaJIT/LuaJIT/c6ffc141a8762b41703f9287d63d93622a13dd8f";
			flake = false;
		};
		# Upstream test suite and benchmarks (bench/, test/).
		luajit-test-cleanup = {
			url = "github:LuaJIT/LuaJIT-test-cleanup/014708bceb70550a3ab8d539cff14d9085ca9cb8";
			flake = false;
		};
	};

	outputs = { self, nixpkgs, luajit-upstream, luajit-test-cleanup }:
		let
			systems = [ "x86_64-linux" "aarch64-linux" ];
			forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
			# Upstream's Makefile build (reference and comparison control).
			mkLuajit = pkgs: pname: src: pkgs.stdenv.mkDerivation {
				inherit pname src;
				version = "2.1";
				enableParallelBuilding = true;
				makeFlags = [ "PREFIX=$(out)" "BUILDMODE=static" ];
				dontStrip = true;
			};
			# The fork's primary build graph: build.zig (no Zig package dependencies,
			# so no fixed-output fetch step is needed).
			mkZigLuajit = pkgs: pkgs.stdenv.mkDerivation {
				pname = "luajit-mdwe";
				version = "2.1";
				src = self;
				nativeBuildInputs = [ pkgs.zig ];
				dontConfigure = true;
				dontStrip = true;
				buildPhase = ''
					export HOME=$TMPDIR ZIG_GLOBAL_CACHE_DIR=$TMPDIR/zig-cache ZIG_LOCAL_CACHE_DIR=$TMPDIR/zig-local
					zig build --prefix $out -Doptimize=ReleaseFast -Dcpu=baseline -Drelver=${toString (self.lastModified or 0)}
				'';
				dontInstall = true;
			};
		in {
			packages = forAll (pkgs: {
				default = mkZigLuajit pkgs;
				luajit-mdwe-make = mkLuajit pkgs "luajit-mdwe-make" self;
				luajit-upstream = mkLuajit pkgs "luajit-upstream" luajit-upstream;
				luajit-test-cleanup = pkgs.runCommandLocal "luajit-test-cleanup" { } ''
					cp -r ${luajit-test-cleanup} $out
				'';
			});

			checks = forAll (pkgs: let pkg = self.packages.${pkgs.stdenv.hostPlatform.system}; in {
				build = pkg.default;
				# Upstream LuaJIT-test-cleanup against the Zig-built binary, requiring
				# the exact upstream baseline failure set (tests/upstream-suite).
				upstream-suite = pkgs.runCommand "luajit-mdwe-upstream-suite" {
					LUAJIT_TEST_CLEANUP = "${luajit-test-cleanup}";
				} ''
					bash ${self}/tests/upstream-suite ${pkg.default}/bin/luajit | tee $out
				'';
			});

			devShells = forAll (pkgs: {
				default = pkgs.mkShell {
					packages = with pkgs; [
						gcc
						gnumake
						hyperfine
						strace
						gdb
						linuxHeaders
						coreutils
						util-linux
						jq
						zig
						qemu
					];
					LUAJIT_TEST_CLEANUP = "${luajit-test-cleanup}";
				};
			});
		};
}
