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
			# Upstream's Makefile is the build graph; Nix only pins inputs.
			mkLuajit = pkgs: pname: src: pkgs.stdenv.mkDerivation {
				inherit pname src;
				version = "2.1";
				enableParallelBuilding = true;
				makeFlags = [ "PREFIX=$(out)" "BUILDMODE=static" ];
				dontStrip = true;
			};
		in {
			packages = forAll (pkgs: {
				default = mkLuajit pkgs "luajit-mdwe" self;
				luajit-upstream = mkLuajit pkgs "luajit-upstream" luajit-upstream;
				luajit-test-cleanup = pkgs.runCommandLocal "luajit-test-cleanup" { } ''
					cp -r ${luajit-test-cleanup} $out
				'';
			});

			checks = forAll (pkgs: {
				build = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
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
					];
					LUAJIT_TEST_CLEANUP = "${luajit-test-cleanup}";
				};
			});
		};
}
