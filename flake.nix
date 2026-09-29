{
	description = "LuaJIT v2.1 fork investigating JIT execution under Linux MemoryDenyWriteExecute";

	inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

	outputs = { self, nixpkgs }:
		let
			systems = [ "x86_64-linux" "aarch64-linux" ];
			forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
		in {
			# Research/dev shell. Upstream's Makefile remains the build graph.
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
					];
				};
			});
		};
}
