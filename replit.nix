{ pkgs }: {
	deps = [
        pkgs.rlwrap
        pkgs.wget
        pkgs.valgrind
        pkgs.less
        pkgs.lua5_4
		pkgs.luajit
        pkgs.clang_12
		pkgs.ccls
		pkgs.gdb
		pkgs.gnumake
	];
}