# Makefile for native AArch64 ports of the x86-64 assembly modules.
# Each port is <name>.S exposing the SAME symbols as upstream asm/<name>.asm so
# the shared C harnesses link unchanged. Build with the native (host) aarch64 gcc.
# Run from this directory (port/arm64); repo asm is two levels up (../../asm).

CC     := gcc
CFLAGS := -no-pie -O2
ASMDIR := ../../asm

MODULES := sha256 sha1 sha512 ripemd160 bitcoin_hash

.PHONY: all test-all harness so fuzz clean

all: test-all

# one object + one shared lib per module
%.o: %.S
	$(CC) -c -o $@ $<

so: $(patsubst %,%.so,$(MODULES))

%.so: %.S
	$(CC) -shared -fPIC -o $@ $<
bitcoin_hash.so: bitcoin_hash.S sha256.S
	$(CC) -shared -fPIC -o $@ bitcoin_hash.S sha256.S

# repo C harness -> native test binary
test_sha256: sha256.o $(ASMDIR)/tests/test_sha256.c
	$(CC) $(CFLAGS) -o $@ $(ASMDIR)/tests/test_sha256.c sha256.o -I$(ASMDIR)
test_sha512: sha512.o $(ASMDIR)/tests/test_sha512.c
	$(CC) $(CFLAGS) -o $@ $(ASMDIR)/tests/test_sha512.c sha512.o -I$(ASMDIR)
test_ripemd160: ripemd160.o $(ASMDIR)/tests/test_ripemd160.c
	$(CC) $(CFLAGS) -o $@ $(ASMDIR)/tests/test_ripemd160.c ripemd160.o -I$(ASMDIR)

harness: test_sha256 test_sha512 test_ripemd160
	./test_sha256 && ./test_sha512 && ./test_ripemd160

fuzz: so
	python3 fuzz_all.py

test-all: harness fuzz
	@echo "ALL PORTED HASHING MODULES VERIFIED NATIVELY"

clean:
	rm -f *.o *.so test_sha256 test_sha512 test_ripemd160 t_ripemd
