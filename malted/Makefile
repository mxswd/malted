default:
	clang -I../include -undefined dynamic_lookup main.c
	DYLD_INSERT_LIBRARIES=/usr/lib/libcrypto.44.dylib ./a.out
