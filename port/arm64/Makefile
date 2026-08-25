# Makefile for native AArch64 ports of the x86-64 assembly modules.
# Usage: make <target-all>  e.g.  make sha256-test  ;  add more below as ported.
#
# Each port lives in this dir as <name>.S (AArch64 GNU as) and must expose the
# SAME public symbols as the upstream asm/<name>.asm so existing C harnesses
# link unchanged. Build with the native (host) aarch64 gcc.

CC     := gcc
CFLAGS := -no-pie -O2

.PHONY: all sha256-test clean

all: sha256-test

# ---- sha256.S : upstream interface = sha256_init/sha256_block/sha256_full ----
sha256.o: sha256.S
	$(CC) -c -o $@ sha256.S

test_sha256: sha256.o ../asm/tests/test_sha256.c
	$(CC) $(CFLAGS) -o $@ ../asm/tests/test_sha256.c sha256.o -I../asm

sha256.so: sha256.S
	$(CC) -shared -fPIC -o $@ sha256.S

sha256-test: test_sha256 sha256.so
	./test_sha256
	@python3 fuzz_sha256.py

clean:
	rm -f *.o *.so test_sha256
