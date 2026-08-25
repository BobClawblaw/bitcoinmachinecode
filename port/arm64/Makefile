# Makefile for native AArch64 ports of the x86-64 assembly modules.
# Each port is <name>.S exposing the SAME symbols as upstream asm/<name>.asm so
# the shared C harnesses link unchanged. Build with the native (host) aarch64 gcc.
# Run from this directory (port/arm64); repo asm is two levels up (../../asm).

CC     := gcc
CFLAGS := -no-pie -O2
ASMDIR := ../../asm

MODULES := sha256 sha1 sha512 ripemd160 bitcoin_hash bitcoin_net bitcoin_p2p bitcoin_headers bitcoin_tx bitcoin_store bitcoin_pubkey bitcoin_cons bitcoin_sighash bech32 secp256k1_fe secp256k1_scalar secp256k1_point secp256k1_ecdsa secp256k1_schnorr

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

harness: test_sha256 test_sha512 test_ripemd160 test_net test_p2p test_p2p_inv test_headers test_tx test_txtxid test_store t_roll test_fe test_scalar test_point
	./test_sha256 && ./test_sha512 && ./test_ripemd160 && \
	./test_net && ./test_p2p && ./test_p2p_inv && ./test_headers && \
	./test_tx >/dev/null && ./test_txtxid >/dev/null && ./test_store >/dev/null && ./t_roll >/dev/null && \
	./test_fe >/dev/null && ./test_scalar >/dev/null && ./test_point >/dev/null

# net layer harnesses (also link bitcoin_hash + sha256 for the frame checksum)
test_net: bitcoin_net.o bitcoin_hash.o sha256.o $(ASMDIR)/tests/test_net.c
	$(CC) $(CFLAGS) -o $@ $(ASMDIR)/tests/test_net.c bitcoin_net.o bitcoin_hash.o sha256.o -I$(ASMDIR)
test_p2p: bitcoin_p2p.o $(ASMDIR)/tests/test_p2p.c
	$(CC) $(CFLAGS) -o $@ $(ASMDIR)/tests/test_p2p.c bitcoin_p2p.o -I$(ASMDIR)
test_p2p_inv: bitcoin_p2p.o $(ASMDIR)/tests/test_p2p_inv.c
	$(CC) $(CFLAGS) -o $@ $(ASMDIR)/tests/test_p2p_inv.c bitcoin_p2p.o -I$(ASMDIR)
test_headers: bitcoin_headers.o bitcoin_hash.o sha256.o $(ASMDIR)/tests/test_headers.c
	$(CC) $(CFLAGS) -o $@ $(ASMDIR)/tests/test_headers.c bitcoin_headers.o bitcoin_hash.o sha256.o -I$(ASMDIR)

test_tx: bitcoin_tx.o bitcoin_hash.o sha256.o $(ASMDIR)/tests/test_tx.c
	$(CC) $(CFLAGS) -o $@ $(ASMDIR)/tests/test_tx.c bitcoin_tx.o bitcoin_hash.o sha256.o -I$(ASMDIR)
test_txtxid: bitcoin_tx.o bitcoin_hash.o sha256.o $(ASMDIR)/tests/test_txtxid.c
	$(CC) $(CFLAGS) -o $@ $(ASMDIR)/tests/test_txtxid.c bitcoin_tx.o bitcoin_hash.o sha256.o -I$(ASMDIR)

test_store: bitcoin_store.o $(ASMDIR)/tests/test_store.c
	$(CC) $(CFLAGS) -o $@ $(ASMDIR)/tests/test_store.c bitcoin_store.o -I$(ASMDIR)
t_roll: bitcoin_store.o t_roll.c
	$(CC) $(CFLAGS) -o $@ t_roll.c bitcoin_store.o -I$(ASMDIR) -include sys/stat.h

test_fe: secp256k1_fe.o $(ASMDIR)/tests/test_fe.c
	$(CC) $(CFLAGS) -o $@ $(ASMDIR)/tests/test_fe.c secp256k1_fe.o -I$(ASMDIR)
test_scalar: secp256k1_scalar.o $(ASMDIR)/tests/test_scalar.c
	$(CC) $(CFLAGS) -o $@ $(ASMDIR)/tests/test_scalar.c secp256k1_scalar.o -I$(ASMDIR)
test_point: secp256k1_point.o secp256k1_fe.o $(ASMDIR)/tests/test_point.c
	$(CC) $(CFLAGS) -o $@ $(ASMDIR)/tests/test_point.c secp256k1_point.o secp256k1_fe.o -I$(ASMDIR)
test_bech32: bech32.o $(ASMDIR)/tests/test_bech32.c
	$(CC) $(CFLAGS) -o $@ $(ASMDIR)/tests/test_bech32.c bech32.o -I$(ASMDIR)
fuzz_bech32: fz_bech32.c bech32.o
	$(CC) $(CFLAGS) -o fz_bech32 fz_bech32.c bech32.o
fuzz_point: fz_point.c secp256k1_point.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o fz_point fz_point.c secp256k1_point.o secp256k1_fe.o
fuzz_sc: fz_sc.c secp256k1_scalar.o
	$(CC) $(CFLAGS) -o fz_sc fz_sc.c secp256k1_scalar.o
fuzz_ecdsa: fz_ecdsa.c secp256k1_ecdsa.o secp256k1_point.o secp256k1_fe.o secp256k1_scalar.o
	$(CC) $(CFLAGS) -o fz_ecdsa fz_ecdsa.c secp256k1_ecdsa.o secp256k1_point.o secp256k1_fe.o secp256k1_scalar.o
fuzz_schnorr: fz_schnorr.c secp256k1_schnorr.o bitcoin_pubkey.o secp256k1_point.o secp256k1_fe.o secp256k1_scalar.o sha256.o
	$(CC) $(CFLAGS) -o fz_schnorr fz_schnorr.c secp256k1_schnorr.o bitcoin_pubkey.o secp256k1_point.o secp256k1_fe.o secp256k1_scalar.o sha256.o
t_sighash: t_sighash.c bitcoin_sighash.o bitcoin_hash.o sha256.o
	$(CC) $(CFLAGS) -o t_sighash t_sighash.c bitcoin_sighash.o bitcoin_hash.o sha256.o
fuzz_sighash:
	python3 fuzz_sighash.py 1 3000
t_bip143: t_bip143.c bitcoin_bip143.o bitcoin_hash.o sha256.o
	$(CC) $(CFLAGS) -o t_bip143 t_bip143.c bitcoin_bip143.o bitcoin_hash.o sha256.o
t_codec: t_codec.c bitcoin_scriptcodec.o
	$(CC) $(CFLAGS) -o t_codec t_codec.c bitcoin_scriptcodec.o
fuzz_codec:
	python3 fuzz_codec.py 1 3000
t_stack: t_stack.c bitcoin_scriptcodec.o
	$(CC) $(CFLAGS) -o t_stack t_stack.c bitcoin_scriptcodec.o
fuzz_stack:
	python3 fuzz_stack.py 1 500
t_interp: t_interp.c bitcoin_interp.o bitcoin_scriptcodec.o
	$(CC) $(CFLAGS) -o t_interp t_interp.c bitcoin_interp.o bitcoin_scriptcodec.o
t_eval: t_eval.c bitcoin_interp.o bitcoin_scriptcodec.o bitcoin_sighash.o bitcoin_hash.o sha256.o sha1.o ripemd160.o
	$(CC) $(CFLAGS) -o t_eval t_eval.c bitcoin_interp.o bitcoin_scriptcodec.o bitcoin_sighash.o bitcoin_hash.o sha256.o sha1.o ripemd160.o
fuzz_eval:
	python3 eval_oracle.py 1 400
CKSOBJS=bitcoin_checksig.o bitcoin_sighash.o bitcoin_bip143.o bitcoin_script.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_fe.o secp256k1_scalar.o bitcoin_pubkey.o bitcoin_hash.o sha256.o
t_checksig: t_checksig.c $(CKSOBJS)
	$(CC) $(CFLAGS) -o t_checksig t_checksig.c $(CKSOBJS)
fuzz_checksig:
	python3 fuzz_checksig.py 1 1000
fuzz_bip143:
	python3 fuzz_bip143.py 1 2000
t_der: t_der.c bitcoin_script.o
	$(CC) $(CFLAGS) -o t_der t_der.c bitcoin_script.o
fuzz_der:
	python3 fuzz_der.py 1 3000
fuzz: so fuzz_sc fuzz_point fuzz_ecdsa fuzz_schnorr t_sighash
	python3 fuzz_all.py && python3 fuzz_sc.py 1 400 && python3 fuzz_fe.py 1 400 && python3 fuzz_point.py ./fz_point 500 2024 && python3 fuzz_ecdsa.py ./fz_ecdsa 300 2024 && python3 fuzz_schnorr.py ./fz_schnorr 80 2024 && python3 fuzz_sighash.py 1 3000

test-all: harness fuzz
	@echo "ALL PORTED HASHING + NETWORK MODULES VERIFIED NATIVELY"

clean:
	rm -f *.o *.so test_sha256 test_sha512 test_ripemd160 t_ripemd \
	       test_net test_p2p test_p2p_inv test_headers live_handshake live_download headers.dat
