# Makefile for native AArch64 ports of the x86-64 assembly modules.
# Each port is <name>.S exposing the SAME symbols as upstream asm/<name>.asm so
# the shared C harnesses link unchanged. Build with the native (host) aarch64 gcc.
# Run from this directory (port/arm64); repo asm is two levels up (../../asm).

CC     := gcc
CFLAGS := -no-pie -O2
ASMDIR := ../../asm

MODULES := sha256 sha1 sha512 ripemd160 bitcoin_hash bitcoin_net bitcoin_p2p bitcoin_headers bitcoin_tx bitcoin_store bitcoin_store_fast bitcoin_bip341 bitcoin_taproot_verify bitcoin_tapagg bitcoin_txv_dispatch bitcoin_cli bitcoin_pubkey bitcoin_cons bitcoin_sighash bech32 secp256k1_fe secp256k1_scalar secp256k1_point secp256k1_point_ct secp256k1_ecdsa secp256k1_schnorr bitcoin_utxo bitcoin_utxo_store bitcoin_utxo_lsm bitcoin_undo bitcoin_sigops bitcoin_strip_witness bitcoind bitcoin_serve bitcoin_scriptverify_drv bitcoin_witness_v0_drv bitcoin_store_ext bitcoin_sighash_all_ext

.PHONY: all test-all harness so fuzz clean

all: test-all

# one object + one shared lib per module
# -march=armv8.2-a+sha2: sha256.S's crypto-extension block (SHA256H/SU0/SU1)
# needs the SHA2 ISA; harmless for the other modules.
CARCH := -march=armv8.2-a+sha2
%.o: %.S
	$(CC) $(CARCH) -c -o $@ $<

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
t_prune: bitcoin_store.o t_prune.c
	$(CC) $(CFLAGS) -o $@ t_prune.c bitcoin_store.o

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
# constant-time point layer (pointh_add/pointh_double/point_scalar_mul_ct):
# differential fuzz vs the variable-time point_scalar_mul + pure-Python secp256k1
t_pct: t_pct.c secp256k1_point_ct.o secp256k1_point.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o t_pct t_pct.c secp256k1_point_ct.o secp256k1_point.o secp256k1_fe.o
fuzz_pct: t_pct
	python3 fuzz_pct.py 8 150 ./t_pct
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
	@$(CC) $(CFLAGS) -o $@ $+
t_utxo: t_utxo.c bitcoin_utxo.o
	@$(CC) $(CFLAGS) -o $@ $+
t_ustore: t_ustore.c bitcoin_utxo_store.o bitcoin_utxo.o
	@$(CC) $(CFLAGS) -o $@ $+
t_lsm: t_lsm.c bitcoin_utxo_lsm.o bitcoin_utxo_store.o bitcoin_utxo.o ../../asm/utxo_lsm_mm.c sha256.o
	@$(CC) $(CFLAGS) -o $@ t_lsm.c bitcoin_utxo_lsm.o bitcoin_utxo_store.o bitcoin_utxo.o ../../asm/utxo_lsm_mm.c sha256.o
fuzz_lsm: t_lsm
	python3 fuzz_lsm.py 1 800
# independent pure-Python BIP39 differential fuzz (self-contained gcc-from-.S)
fuzz_bip39:
	python3 fuzz_bip39.py 8 1200
# independent pure-Python BIP341/342 taproot differential (self-contained
# gcc-from-.S driver; asm vs C twin vs Python oracle, byte-exact)
fuzz_taproot:
	python3 fuzz_taproot.py 8 1200
t_undo_asm: t_undo.c bitcoin_undo.o
	@$(CC) $(CFLAGS) -o $@ $+
# LSM-backed UTXO-set builder (daemon/build_utxo.c -> our ported utxo_lsm store).
# Needs utxo_stats(->muhash) in addition to the x86 BUILDUTXOOBJS set, which
# omitted them; bitcoin_cons for tx-level gates. AArch64-native build.
build_utxo: ../../asm/daemon/build_utxo.c bitcoin_utxo_lsm.o utxo_lsm_mm.o bitcoin_utxo_store.o bitcoin_utxo.o bitcoin_idxscan.o bitcoin_store.o bitcoin_store_fast.o bitcoin_tx.o bitcoin_hash.o sha256.o bitcoin_utxo_stats.o bitcoin_muhash.o ripemd160.o
	@$(CC) $(CFLAGS) -I../.. -I../../asm/daemon -o $@ ../../asm/daemon/build_utxo.c $(filter %.o,$^) -lpthread
# AArch64-native full-block download + persist (live_blocks.c): getdata BLOCK,
# verify header-hash/prev-link/coinbase, store_append -> blk%05u.dat + index.dat.
live_blocks: live_blocks.c bitcoin_net.o bitcoin_p2p.o bitcoin_store.o bitcoin_tx.o bitcoin_hash.o sha256.o
	@$(CC) $(CFLAGS) -o $@ $+
fuzz_undo:
	python3 fuzz_undo.py 1 800
fuzz_strip:
	python3 fuzz_strip.py 1 1500
# strip_witness differential vs the C twin (bitcoin_segwit.c): synthetic + real block corpus
SWOBJS = bitcoin_strip_witness.o sha256.o ripemd160.o bitcoin_script.o secp256k1_ecdsa.o \
         secp256k1_point.o secp256k1_fe.o secp256k1_scalar.o bitcoin_pubkey.o
test_strip: ../../asm/tests/test_strip_witness_diff.c ../../asm/bitcoin_segwit.c $(SWOBJS)
	@$(CC) -no-pie -O2 -I../.. -o $@ ../../asm/tests/test_strip_witness_diff.c \
		../../asm/bitcoin_segwit.c $(SWOBJS)
fz_sw: fz_sw.c bitcoin_strip_witness.o sha256.o ripemd160.o
	@$(CC) $(CFLAGS) -o $@ $+
cmp_sw: cmp_sw.c ../../asm/bitcoin_segwit.c $(SWOBJS)
	@$(CC) -no-pie -O2 -I../.. -o $@ cmp_sw.c ../../asm/bitcoin_segwit.c $(SWOBJS)
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
fuzz_sigops: fz_sigops
	python3 fuzz_sigops.py 12345 4000 4
fz_sigops: fz_sigops.c bitcoin_sigops.o bitcoin_scriptcodec.o
	$(CC) $(CFLAGS) -o fz_sigops fz_sigops.c bitcoin_sigops.o bitcoin_scriptcodec.o

# integrated IBD driver: downloads + cons_verify + per-tx sv_verify_script + UTXO apply
IBDOBJS = bitcoin_net.o bitcoin_p2p.o bitcoin_hash.o sha256.o bitcoin_headers.o \
          bitcoin_tx.o bitcoin_store.o bitcoin_cons.o bitcoin_utxo.o \
          bitcoin_utxo_store.o bitcoin_undo.o bitcoin_sigops.o vobj/btc_scriptverify.o \
          bitcoin_checksig.o bitcoin_sighash.o bitcoin_bip143.o bitcoin_script.o \
          bitcoin_scriptcodec.o bitcoin_interp.o secp256k1_ecdsa.o secp256k1_point.o \
          secp256k1_fe.o secp256k1_scalar.o bitcoin_pubkey.o secp256k1_schnorr.o \
          sha1.o ripemd160.o node_log.o bitcoin_script_flags.o
ibd: ibd.c $(IBDOBJS)
	$(CC) $(CFLAGS) -o ibd ibd.c $(IBDOBJS)
# resumable LSM-backed downloader: ibd.c networking/cons + build_utxo.c LSM path
# (bitcoin_utxo_lsm.o + utxo_lsm_mm.o). Resumes at archive tip+1 via
# utxo_lsm_reload. Handles utxo_lsm_put's .full (2) with flush+retry.
IBDLSMOBJS = $(IBDOBJS) bitcoin_utxo_lsm.o utxo_lsm_mm.o
ibd_lsm: ibd_lsm.c $(IBDLSMOBJS)
	@$(CC) $(CFLAGS) -o ibd_lsm ibd_lsm.c $(IBDLSMOBJS)
# multi-client (<=16 parallel peers) resumable downloader: poll() mux over the
# client pool + x86 startup banner + [catchup]/[dl] logging (log parity with x86).
ibd_par: ibd_par.c $(IBDLSMOBJS)
	@$(CC) $(CFLAGS) -o ibd_par ibd_par.c $(IBDLSMOBJS)
ibd_dlc: ibd_dlc.c $(IBDOBJS)
	@$(CC) $(CFLAGS) -o ibd_dlc ibd_dlc.c $(IBDOBJS)
fuzz: so fuzz_sc fuzz_point fuzz_ecdsa fuzz_schnorr t_sighash
	python3 fuzz_all.py && python3 fuzz_sc.py 1 400 && python3 fuzz_fe.py 1 400 && python3 fuzz_point.py ./fz_point 500 2024 && python3 fuzz_ecdsa.py ./fz_ecdsa 300 2024 && python3 fuzz_schnorr.py ./fz_schnorr 80 2024 && python3 fuzz_sighash.py 1 3000

test-all: harness fuzz
	@echo "ALL PORTED HASHING + NETWORK MODULES VERIFIED NATIVELY"

clean:
	rm -f *.o *.so test_sha256 test_sha512 test_ripemd160 t_ripemd \
	       test_net test_p2p test_p2p_inv test_headers live_handshake live_download headers.dat
