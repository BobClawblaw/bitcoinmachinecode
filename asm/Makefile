# ============================================================================
# Makefile - 100% AI-generated build driver for the assembly crypto core.
#
#   make asm  : assemble all .asm sources into .o objects
#   make test : build every C harness against the objects and run them
#   make clean: remove generated objects and binaries
#
# Point arithmetic (secp256k1_point.asm) depends on the field primitives
# (secp256k1_fe.asm), so point test binaries link both objects.
# ============================================================================

NASM       := nasm
# -I. so .asm sources can %include "version.inc" (the single source of truth).
NASMFLAGS  := -f elf64 -I.
CC         := gcc
CFLAGS     := -no-pie -O2 -Wall

# Single source of truth for the node's wire identity (app version, user-agent,
# protocol version). version.inc is the ONLY human-authored definition; the
# derived values reach C via the generated version_gen.h below.
VERSION_INC      := version.inc
VERSION_GEN_H    := version_gen.h
VERSION_GEN_PY   := gen_version_header.py

# Regenerate the C header from the single source of truth every time the
# canonical .inc changes. C code #includes version_gen.h; it never hardcodes.
$(VERSION_GEN_H): $(VERSION_INC) $(VERSION_GEN_PY)
	python3 $(VERSION_GEN_PY) --out $@ --version-inc $(VERSION_INC)

OBJS := sha256.o sha1.o sha512.o bitcoin_hmac.o bitcoin_keys.o ripemd160.o bitcoin_addr.o bech32.o secp256k1_fe.o secp256k1_point.o secp256k1_point_ct.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_ecdsa.o bitcoin_hash.o bitcoin_tx.o bitcoin_net.o bitcoin_p2p.o bitcoin_store.o bitcoin_store_fast.o bitcoin_cons.o node_log.o bitcoin_cli.o bitcoind.o bitcoin_headers.o bitcoin_addrmgr.o bitcoin_idx.o bitcoin_serve.o bitcoin_mempool.o bitcoin_pubkey.o bitcoin_sighash.o bitcoin_script.o bitcoin_utxo.o bitcoin_utxo_store.o bitcoin_multisig.o bitcoin_bip39.o bitcoin_interp.o bitcoin_scriptcodec.o bitcoin_script_flags.o
# BIP152 compact blocks (bitcoin_cmpct.asm) needs sha256_full (single SHA256)
# and tx_parse (block tx enumeration for getblocktxn/blocktxn serving).
CMPCTOBJS := bitcoin_cmpct.o sha256.o bitcoin_hash.o bitcoin_tx.o
# bitcoin_hash.asm (sha256d/block-hash/merkle/pow) depends on sha256.o
HASHOBJS := sha256.o bitcoin_hash.o
# Full script interpreter (bitcoin_interp.asm over bitcoin_scriptcodec.asm) plus
# its hashing deps (OP_SHA256/OP_SHA1/HASH160/HASH256/RIPEMD160).
INTERPOBJS := bitcoin_interp.o bitcoin_scriptcodec.o sha256.o sha1.o ripemd160.o \
    bitcoin_hash.o
# bitcoin_tx.asm parser harness also exercises sha256d/merkle_root.
TXOBJS := sha256.o bitcoin_hash.o bitcoin_tx.o
# bitcoin_net.asm framing needs sha256d (checksum).
NETOBJS := sha256.o bitcoin_hash.o bitcoin_net.o
# P2P codec harness needs the net framing (framer uses sha256d).
P2POBJS := sha256.o bitcoin_hash.o bitcoin_net.o bitcoin_p2p.o
# store harness is standalone (no deps).
# cons_verify (block consensus) uses pow_check/merkle_root/sha256d + tx_parse.
CONSOBJS := sha256.o bitcoin_hash.o bitcoin_tx.o bitcoin_cons.o

.PHONY: all asm test clean

all: test

asm: $(OBJS)

%.o: %.asm
	$(NASM) $(NASMFLAGS) -o $@ $<

# bitcoind.asm and bitcoin_p2p.asm %include version.inc (the single source of
# truth), so they MUST rebuild when it changes -- otherwise a version bump
# would silently leave the assembled node advertising stale identity.
bitcoind.o bitcoin_p2p.o: $(VERSION_INC)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

tests/test_sha256: tests/test_sha256.c sha256.o
	$(CC) $(CFLAGS) -o $@ tests/test_sha256.c sha256.o

tests/test_fe: tests/test_fe.c secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_fe.c secp256k1_fe.o

tests/test_point: tests/test_point.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_point.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o

tests/test_addm: tests/test_addm.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_addm.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o

tests/test_scalarmul: tests/test_scalarmul.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_scalarmul.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o

tests/stress_pointmul: tests/stress_pointmul.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/stress_pointmul.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o

tests/test_scalarmul_ct: tests/test_scalarmul_ct.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_scalarmul_ct.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o

tests/stress_pointmul_ct: tests/stress_pointmul_ct.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/stress_pointmul_ct.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o

tests/diff_add_ct_homog: tests/diff_add_ct_homog.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/diff_add_ct_homog.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o

tests/test_add: tests/test_add.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_add.c secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o

tests/test_scalar: tests/test_scalar.c secp256k1_scalar.o secp256k1_scalar_c.o
	$(CC) $(CFLAGS) -o $@ tests/test_scalar.c secp256k1_scalar.o secp256k1_scalar_c.o

tests/test_ecdsa: tests/test_ecdsa.c secp256k1_ecdsa.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_ecdsa.c secp256k1_ecdsa.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o

tests/test_block: tests/test_block.c $(HASHOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_block.c $(HASHOBJS)

tests/test_tx: tests/test_tx.c $(TXOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_tx.c $(TXOBJS)

tests/test_net: tests/test_net.c $(NETOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_net.c $(NETOBJS)

tests/test_p2p: tests/test_p2p.c $(P2POBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_p2p.c $(P2POBJS)

tests/fakepeer_headers: tests/fakepeer_headers.c $(P2POBJS)
	$(CC) $(CFLAGS) -o $@ tests/fakepeer_headers.c $(P2POBJS)

# BIP152 compact-blocks primitives (SipHash short-ids + wire codecs).
tests/test_bip152: tests/test_bip152.c $(CMPCTOBJS) tests/bip152_vectors.h
	$(CC) $(CFLAGS) -o $@ tests/test_bip152.c $(CMPCTOBJS)

tests/bench_store_read: tests/bench_store_read.c bitcoin_store.o bitcoin_store_fast.o
	$(CC) $(CFLAGS) -o $@ tests/bench_store_read.c bitcoin_store.o bitcoin_store_fast.o

# bench_ecdsa -- signature verifications/sec on one core. Scoping input for
# block script verification: the chain needs ~1e9 of these, so this rate
# decides whether assumevalid is a prerequisite or just an optimisation.
tests/bench_ecdsa: tests/bench_ecdsa.c secp256k1_ecdsa.o secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o
	$(CC) -no-pie -O2 -o $@ tests/bench_ecdsa.c secp256k1_ecdsa.o secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o

tests/bench_idxscan: tests/bench_idxscan.c bitcoin_idxscan.o bitcoin_store.o
	$(CC) $(CFLAGS) -o $@ tests/bench_idxscan.c bitcoin_idxscan.o bitcoin_store.o

# -O0: -O2 miscompiles this harness (fread called with a NULL buffer per
# gdb; idx_build_from_file itself is independently verified correct via
# tests/debug_hashidx_min.c and this same harness built at -O0/-g -- see the
# LOG.md entry for this investigation).
tests/bench_hashidx: tests/bench_hashidx.c bitcoin_idx.o
	$(CC) -no-pie -O0 -Wall -o $@ tests/bench_hashidx.c bitcoin_idx.o

tests/test_store: tests/test_store.c bitcoin_store.o
	$(CC) $(CFLAGS) -o $@ tests/test_store.c bitcoin_store.o

# PRUNING (store_prune/store_set_prune in bitcoin_store.asm): configurable prune
# height, whole-file deletion, boundary compaction, -3-unavailable gate,
# prune.dat persistence. Standalone (links bitcoin_store.o only).
tests/test_prune: tests/test_prune.c bitcoin_store.o
	$(CC) $(CFLAGS) -o $@ tests/test_prune.c bitcoin_store.o

# ---- Stage A reorg/fork-choice primitives (standalone, additive -- see each
# new file's own header comment; nothing in the live daemon calls these yet) ----

# Primitive #1: chainwork tracking (bitcoin_chainwork.asm). Standalone.
tests/test_chainwork: tests/test_chainwork.c bitcoin_chainwork.o
	$(CC) $(CFLAGS) -o $@ tests/test_chainwork.c bitcoin_chainwork.o

# Primitive #2: real multi-hash block locator (p2p_getheaders count>1
# extension in bitcoin_p2p.asm + daemon/locator_build.c).
tests/test_locator: tests/test_locator.c $(P2POBJS) bitcoin_store.o daemon/locator_build.o
	$(CC) $(CFLAGS) -o $@ tests/test_locator.c $(P2POBJS) bitcoin_store.o daemon/locator_build.o

# Primitive #3: prevhash validation gate (store_get_tip_hash /
# store_validates_prevhash in bitcoin_store.asm). Standalone.
tests/test_prevhash: tests/test_prevhash.c bitcoin_store.o
	$(CC) $(CFLAGS) -o $@ tests/test_prevhash.c bitcoin_store.o

# Primitive #4: store truncate/rollback (store_truncate_to in
# bitcoin_store.asm). Also exercises the EXISTING, unmodified
# idx_build_from_file (bitcoin_idx.asm) against the truncated store.
tests/test_truncate: tests/test_truncate.c bitcoin_store.o $(IDXOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_truncate.c bitcoin_store.o $(IDXOBJS)

# Primitive #5: per-block undo-data structure (daemon/undo_log.c) against
# the real LSM UTXO store.
tests/test_undo_log: tests/test_undo_log.c daemon/undo_log.o $(UTXOLSMOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_undo_log.c daemon/undo_log.o $(UTXOLSMOBJS)

# ---- Stage B: the wired-together reorg engine ----------------------------
# tests/test_reorg.c drives the REAL production modules (daemon/reorg.c,
# daemon/utxo_live.c, daemon/undo_log.c, daemon/locator_build.c and the real
# mempool policy layer) against the real block store, the real LSM UTXO store
# and a real loopback fake peer. Built at -O0 for the same reason
# daemon/bitcoind is: the deep asm call chain (cons_verify -> tx_parse /
# sha256d) is documented in this Makefile as misbehaving under aggressive C
# optimisation, and this harness sits directly on top of it.
REORGSRCS := tests/test_reorg.c daemon/reorg.c daemon/utxo_live.c daemon/undo_log.c \
    daemon/locator_build.c daemon/node_config.c bitcoin_mempool_policy.c \
    daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c
REORGOBJS := bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_idxscan.o \
    bitcoin_chainwork.o bitcoin_hash.o sha256.o bitcoin_tx.o \
    bitcoin_cons.o bitcoin_p2p.o bitcoin_net.o bitcoin_mempool.o \
    bitcoin_utxo_lsm.o bitcoin_utxo_store.o bitcoin_utxo.o bitcoind.o \
    bitcoin_headers.o bitcoin_interp.o bitcoin_scriptcodec.o bitcoin_script_flags.o \
    bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o \
    secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o \
    secp256k1_scalar_c.o secp256k1_schnorr.o secp256k1_taproot.o ripemd160.o \
    bitcoin_addr.o sha1.o
tests/test_reorg: $(REORGSRCS) daemon/reorg.h daemon/utxo_walk.h $(REORGOBJS)
	$(CC) -no-pie -O0 -Wall -o $@ $(REORGSRCS) $(REORGOBJS) -lpthread

# test_tx_verify_parallel -- differential test for txv_verify_all's forked
# parallel path (>= TXV_PARALLEL_MIN non-taproot inputs) against a genuinely
# multi-signed P2WPKH tx (see tests/multi_p2wpkh_vec.h / gen_multi_p2wpkh.py).
TXVPARSRCS := tests/test_tx_verify_parallel.c daemon/tx_verify.c bitcoin_scriptverify.c \
    bitcoin_txval_modern.c bitcoin_segwit.c bitcoin_taproot_sighash.c
tests/test_tx_verify_parallel: $(TXVPARSRCS) tests/multi_p2wpkh_vec.h $(REORGOBJS)
	$(CC) -no-pie -O0 -Wall -o $@ $(TXVPARSRCS) $(REORGOBJS) -lpthread

# test_utxo_checkpoint -- utxo_live_catchup must persist a resumable
# checkpoint periodically during a long catch-up, not just on a (rare, during
# bulk mode) compaction or at the very end of the call.
CKPTSRCS := tests/test_utxo_checkpoint.c daemon/utxo_live.c daemon/undo_log.c \
    daemon/locator_build.c daemon/node_config.c bitcoin_mempool_policy.c \
    daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c
tests/test_utxo_checkpoint: $(CKPTSRCS) daemon/utxo_walk.h $(REORGOBJS)
	$(CC) -no-pie -O0 -Wall -o $@ $(CKPTSRCS) $(REORGOBJS) -lpthread

# test_apply_block_rollback -- a block that fails partway through must roll
# back everything it already committed (coinbase + any earlier-in-block tx),
# not just the failing tx -- see rollback_partial_apply in daemon/utxo_live.c.
ROLLBACKSRCS := tests/test_apply_block_rollback.c daemon/utxo_live.c daemon/undo_log.c \
    daemon/locator_build.c daemon/node_config.c bitcoin_mempool_policy.c \
    daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c
tests/test_apply_block_rollback: $(ROLLBACKSRCS) daemon/utxo_walk.h $(REORGOBJS)
	$(CC) -no-pie -O0 -Wall -o $@ $(ROLLBACKSRCS) $(REORGOBJS) -lpthread

# test_cross_tx_verify -- correctness properties specific to the cross-
# transaction (block-wide) parallel verification redesign in daemon/
# tx_verify.c's tx_verify_block_connect_all: a valid same-block chained
# spend must accept, an in-block double-spend must reject the whole block
# (not half-apply), and a many-tx block with a poisoned tx buried mid-list
# must both genuinely exercise the block-wide worker pool and still report
# the correct failing tx.
CROSSTXSRCS := tests/test_cross_tx_verify.c daemon/utxo_live.c daemon/undo_log.c \
    daemon/locator_build.c daemon/node_config.c bitcoin_mempool_policy.c \
    daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c
tests/test_cross_tx_verify: $(CROSSTXSRCS) daemon/utxo_walk.h $(REORGOBJS)
	$(CC) -no-pie -O0 -Wall -o $@ $(CROSSTXSRCS) $(REORGOBJS) -lpthread

# test_tx_verify_bytepool_realloc -- regression test for the g_spk_pool
# dangling-pointer bug (2026-08-20, real production incident at mainnet
# height 184390): a block whose Phase 1 resolve loop makes bytepool_alloc's
# realloc() relocate mid-loop must still verify every earlier-resolved
# input's script correctly, not read corrupted/dangling memory. See the
# test file's own header comment for full root-cause detail.
BYTEPOOLSRCS := tests/test_tx_verify_bytepool_realloc.c daemon/utxo_live.c daemon/undo_log.c \
    daemon/locator_build.c daemon/node_config.c bitcoin_mempool_policy.c \
    daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c
tests/test_tx_verify_bytepool_realloc: $(BYTEPOOLSRCS) daemon/utxo_walk.h $(REORGOBJS)
	$(CC) -no-pie -O0 -Wall -o $@ $(BYTEPOOLSRCS) $(REORGOBJS) -lpthread

# daemon/build_utxo -- batch UTXO-set construction from the archive. This is
# the RIGHT tool for a from-scratch (or long-gap) UTXO rebuild: its memtable is
# CLI-sized (slots_log2/blob_gb) for batch work, so it flushes -- and therefore
# full-compacts -- orders of magnitude less often than the live daemon's
# steady-state-sized memtable. Previously built by hand, which is how it went
# stale and briefly vanished; a real target keeps it buildable and honest.
BUILDUTXOOBJS := sha256.o bitcoin_hash.o bitcoin_tx.o bitcoin_store.o \
    bitcoin_store_fast.o bitcoin_utxo_lsm.o bitcoin_utxo_store.o bitcoin_utxo.o \
    bitcoin_idxscan.o
daemon/build_utxo: daemon/build_utxo.c $(BUILDUTXOOBJS)
	$(CC) -no-pie -O2 -o $@ daemon/build_utxo.c $(BUILDUTXOOBJS)

# test_truncate_guard_prim -- store_truncate_to must REFUSE an out-of-order
# archive and leave the block data intact. Asserts on the BLOCK FILES, not
# just index.dat: the test that missed the original ~600GB loss checked only
# index counts and never opened a block, so it passed while data was deleted.
tests/test_truncate_guard_prim: tests/test_truncate_guard_prim.c bitcoin_store.o bitcoin_store_fast.o bitcoin_hash.o sha256.o bitcoin_idxscan.o
	$(CC) -no-pie -O0 -o $@ tests/test_truncate_guard_prim.c bitcoin_store.o bitcoin_store_fast.o bitcoin_hash.o sha256.o bitcoin_idxscan.o

# test_archive_check -- boot verification (-checkblocks/-checklevel), hole
# detection, and the prune budget->height conversion. Builds its own archive
# in its own scratch dir and deletes it afterwards; it must never be pointed
# at a real datadir.
tests/test_archive_check: tests/test_archive_check.c daemon/archive_verify.c bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_idxscan.o bitcoin_cons.o bitcoin_hash.o bitcoin_tx.o sha256.o
	$(CC) -no-pie -O0 -I daemon -o $@ tests/test_archive_check.c daemon/archive_verify.c bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_idxscan.o bitcoin_cons.o bitcoin_hash.o bitcoin_tx.o sha256.o

# test_archive_repair -- boot-time duplicate-hash self-repair
# (archive_scan_duplicates / archive_repair_duplicates): marks corrupted
# heights as holes (never truncates) so the existing catch-up hole-filler
# re-downloads them. Synthetic index.dat only; never touches a real datadir.
tests/test_archive_repair: tests/test_archive_repair.c daemon/archive_verify.c bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_idxscan.o bitcoin_cons.o bitcoin_hash.o bitcoin_tx.o sha256.o
	$(CC) -no-pie -O0 -I daemon -o $@ tests/test_archive_repair.c daemon/archive_verify.c bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_idxscan.o bitcoin_cons.o bitcoin_hash.o bitcoin_tx.o sha256.o

# test_node_config -- bitcoin.conf parsing, Core-key compatibility, clamping,
# and the peer-sourcing lists. Hermetic (writes its own fixtures), so it runs
# in `make test`. It existed unbuilt for a day: written 2026-08-18 with no
# Makefile rule and never added to the test target, so it had never once been
# compiled while the suite reported green.
tests/test_node_config: tests/test_node_config.c daemon/node_config.c
	$(CC) -no-pie -O0 -I daemon -o $@ tests/test_node_config.c daemon/node_config.c

# test_addr_ingest -- live getaddr harvest against a REAL node. Needs a peer
# IP argument and the network, so like test_net_policy's live half it is built
# but DELIBERATELY NOT in `make test`:
#   ./tests/test_addr_ingest <peer-ip> [more...]
tests/test_addr_ingest: tests/test_addr_ingest.c daemon/addr_ingest.c daemon/net_policy.c daemon/node_config.c bitcoin_addrmgr.o bitcoin_net.o bitcoin_p2p.o bitcoin_hash.o sha256.o
	$(CC) -no-pie -O0 -I daemon -o $@ tests/test_addr_ingest.c daemon/addr_ingest.c daemon/net_policy.c daemon/node_config.c bitcoin_addrmgr.o bitcoin_net.o bitcoin_p2p.o bitcoin_hash.o sha256.o

# test_net_policy -- netgroup grouping, plus (with a peer argument) a live
# relay=0 block-relay-only handshake and feeler liveness check. The live half
# is opt-in; the netgroup half always runs.
tests/test_net_policy: tests/test_net_policy.c daemon/net_policy.c bitcoin_net.o bitcoin_p2p.o bitcoin_hash.o sha256.o
	$(CC) -no-pie -O0 -o $@ tests/test_net_policy.c daemon/net_policy.c bitcoin_net.o bitcoin_p2p.o bitcoin_hash.o sha256.o

# test_utxo_recover -- integration test for utxo_live_recover(), the in-place
# recovery that makes a failed catch-up survivable instead of terminal.
# DELIBERATELY NOT IN `make test`: it replays a real 250k-height archive
# (~3 min) and therefore needs a populated datadir, which a clean checkout
# does not have. Run it by hand against a real store:
#   make tests/test_utxo_recover && ./tests/test_utxo_recover <datadir>
# It still gets a rule so it is built/compiled-checked on demand rather than
# rotting the way daemon/build_utxo did with no target at all.
RECOVERSRCS := tests/test_utxo_recover.c daemon/utxo_live.c daemon/undo_log.c daemon/tx_accept.c \
    daemon/mempool_cfg.c daemon/reorg.c daemon/locator_build.c daemon/archive_verify.c \
    daemon/node_config.c bitcoin_mempool_policy.c bitcoin_txval_modern.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c daemon/tx_verify.c bitcoin_scriptverify.c
tests/test_utxo_recover: $(RECOVERSRCS) daemon/utxo_walk.h $(DAEMONOBJS)
	$(CC) -no-pie -O0 -o $@ $(RECOVERSRCS) $(DAEMONOBJS) -lpthread

# test_dial_budget -- regression test for the outbound_connect dial-budget hang
# (download worker wedged in a peer read() for 60+ min, 2026-08-18). It forks
# its own trickling fake peer, so it needs no external helper or network.
# outbound_connect is static in daemon/main.c, so the test #includes that TU
# directly (renaming its main) and therefore links the same objects the daemon
# does, minus daemon/main.c itself (it comes in via the #include).
DIALSRCS := tests/test_dial_budget.c daemon/utxo_live.c daemon/tx_accept.c daemon/mempool_cfg.c \
    daemon/upload_cap.c daemon/reorg.c daemon/undo_log.c daemon/locator_build.c \
    daemon/archive_verify.c daemon/addr_ingest.c daemon/net_policy.c daemon/node_config.c \
    bitcoin_mempool_policy.c bitcoin_txval_modern.c bitcoin_segwit.c bitcoin_taproot_sighash.c \
    daemon/tx_verify.c bitcoin_scriptverify.c
tests/test_dial_budget: $(DIALSRCS) daemon/main.c daemon/reorg.h daemon/utxo_walk.h $(DAEMONOBJS) $(VERSION_GEN_H)
	$(CC) -no-pie -O0 -o $@ $(DIALSRCS) $(DAEMONOBJS) -lpthread

tests/test_cons: tests/test_cons.c $(CONSOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_cons.c $(CONSOBJS)

# cons_verify on the REAL mainnet genesis block (offline, deterministic).
tests/test_block_genesis: tests/test_block_genesis.c $(CONSOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_block_genesis.c $(CONSOBJS)

# bitcoind: handshake + version builder (networked). node_sync also calls
# cons_verify + store_append, so DAEMONOBJS must include those objects.
# node_ibd_headers references hst_append (bitcoin_headers.asm), so include it.
# NOTE: this must be the FULL object list (matching the daemon/bitcoind link
# below) -- prerequisite lists are expanded at parse time, not build time, so
# an earlier/short DAEMONOBJS here would silently drop objects the later
# reassignment adds, even though the recipe line (expanded at build time)
# would look correct. A prior duplicate short definition caused exactly that:
# tests/test_bitcoind linked fine only because stale .o files happened to
# already exist on disk from earlier incremental builds; a clean rebuild
# failed with "cannot find X.o" at the final link step.
DAEMONOBJS := sha256.o bitcoin_hash.o bitcoin_net.o bitcoin_p2p.o \
    bitcoin_tx.o bitcoin_cons.o bitcoin_store.o bitcoind.o \
    node_log.o bitcoin_headers.o bitcoin_addrmgr.o bitcoin_idx.o \
    bitcoin_serve.o bitcoin_mempool.o bitcoin_cmpct.o bitcoin_idxscan.o \
    bitcoin_utxo_lsm.o bitcoin_utxo_store.o bitcoin_utxo.o bitcoin_store_fast.o \
    secp256k1_schnorr.o secp256k1_taproot.o bitcoin_script.o bitcoin_sighash.o \
    bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_point_ct.o \
    secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o ripemd160.o \
    bitcoin_addr.o bitcoin_chainwork.o bitcoin_interp.o bitcoin_scriptcodec.o \
    bitcoin_script_flags.o sha1.o

tests/test_bitcoind: tests/test_bitcoind.c $(SERVETXVALSRCS) $(DAEMONOBJS) $(VERSION_GEN_H)
	$(CC) $(CFLAGS) -o $@ tests/test_bitcoind.c $(SERVETXVALSRCS) $(DAEMONOBJS)

# Full IBD client (node_sync): handshake + headers + getdata + validate + store.
# Built at -O0: the deep asm hash call chain (node_sync -> cons_verify ->
# pow_check -> block_hash -> sha256d -> sha256_full) provably works at -O0, but
# gcc -O2's main register/stack layout triggers a latent sha256_full deep-frame-
# overlap crash in this specific networked harness. The asm is identical.
tests/test_bitcoind_sync: tests/test_bitcoind_sync.c $(SERVETXVALSRCS) $(DAEMONOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_bitcoind_sync.c $(SERVETXVALSRCS) $(DAEMONOBJS)

# all-asm leveled logger (uses fd_write_all from bitcoin_net.asm)
# Built at -O0: same gcc -O2 vs deep-asm-call-chain interaction as the sync
# harness; the asm logger is identical and correct at -O0.
LOGOBJS := node_log.o bitcoin_net.o bitcoin_hash.o sha256.o
tests/test_log: tests/test_log.c $(LOGOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_log.c $(LOGOBJS)

# S6 CLI (bitcoin_cli.asm): queries the store + hashing/tx primitives.
CLIOBJS := sha256.o bitcoin_hash.o bitcoin_tx.o bitcoin_store.o \
    bitcoin_cli.o
tests/test_cli: tests/test_cli.c $(CLIOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_cli.c $(CLIOBJS)

# Persistent header-chain store (bitcoin_headers.asm): appends a (header, block_hash)
# pair per entry; the harness checks continuity by computing block_hash of chain
# predecessors via the proven block_hash asm.
HEADOBJS := sha256.o bitcoin_hash.o bitcoin_headers.o
tests/test_headers: tests/test_headers.c $(HEADOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_headers.c $(HEADOBJS)

# Paged persistent headers-first IBD (bitcoind.asm node_ibd_headers) over the
# asm header store. Built at -O0: same gcc -O2 vs deep-asm-call-chain interaction
# as the bitcoind sync harness; the asm is identical and correct at -O0.
# bitcoind.o bundles node_sync/node_serve_block/node_drain which reference the
# cons/store/tx symbols, so link the full DAEMONOBJS superset.
IBDOBJS := sha256.o bitcoin_hash.o bitcoin_net.o bitcoin_p2p.o \
    bitcoin_tx.o bitcoin_cons.o bitcoin_store.o bitcoind.o \
    bitcoin_headers.o bitcoin_idxscan.o
tests/test_ibd_headers: tests/test_ibd_headers.c $(IBDOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_ibd_headers.c $(IBDOBJS)

# Block-body download off the persisted header chain (bitcoind.asm node_ibd_blocks).
# node_ibd_blocks calls cons_verify/block_hash/store_append/hst_*; bitcoind.o pulls
# the transitive cons/tx symbols too. Built at -O0 (deep-asm-call-chain convention).
tests/test_ibd_blocks: tests/test_ibd_blocks.c $(IBDOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_ibd_blocks.c $(IBDOBJS)

# FULL initial-block-download as one asm pass (bitcoind.asm node_ibd =
# node_ibd_headers + node_ibd_blocks) over a whole NB-block loopback chain.
tests/test_ibd_full: tests/test_ibd_full.c $(IBDOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_ibd_full.c $(IBDOBJS)

# LARGE-SCALE full-IBD demo (default NB=20000; slow, heavy manual test, NOT in
# the `test` target). Same IBDOBJS link set as test_ibd_full. Brought under the
# Makefile so `make tests/test_ibd_scale` always relinks against CURRENT objects
# (previously it was built by hand and rotted stale, failing spuriously).
tests/test_ibd_scale: tests/test_ibd_scale.c $(IBDOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_ibd_scale.c $(IBDOBJS)

# bitcoin_addrmgr.asm: peer address book + addr v1 codec (standalone deps).
ADMRGOBJS := bitcoin_addrmgr.o
tests/test_addrmgr: tests/test_addrmgr.c $(ADMRGOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_addrmgr.c $(ADMRGOBJS)

# bitcoin_keys.asm (secp256k1 pubkey derivation for wallet/BIP32).
KEYSOBJS := secp256k1_fe.o secp256k1_point.o secp256k1_point_ct.o secp256k1_scalar.o \
    secp256k1_scalar_c.o bitcoin_keys.o
tests/test_keys: tests/test_keys.c $(KEYSOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_keys.c $(KEYSOBJS)

# bitcoin_idx.asm: O(1) hash->height index for serving (standalone deps).
IDXOBJS := bitcoin_idx.o
tests/test_idx: tests/test_idx.c $(IDXOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_idx.c $(IDXOBJS)

# bitcoin_serve.asm: inbound (server) message loop over p2p + idx + serve_block.
# .do_tx now calls into daemon/tx_accept.c (mempool policy + whole-tx
# validation, LSM-backed UTXO snapshot), pulling in the same object set as
# tests/test_mempool_accept_modern's MEMPACCOBJS plus the LSM/memtable objects.
# SERVETXVALSRCS are raw .c sources (not pre-built .o) needed by every target
# that links bitcoin_serve.o, since .do_tx's new call sites live there.
SERVEOBJS := bitcoin_serve.o bitcoin_idx.o bitcoin_net.o bitcoin_p2p.o \
    bitcoin_store.o bitcoind.o bitcoin_headers.o bitcoin_hash.o \
    bitcoin_addrmgr.o node_log.o bitcoin_tx.o bitcoin_cons.o \
    sha256.o bitcoin_mempool.o bitcoin_cmpct.o bitcoin_idxscan.o \
    bitcoin_utxo_lsm.o bitcoin_utxo_store.o bitcoin_utxo.o secp256k1_schnorr.o \
    secp256k1_taproot.o bitcoin_script.o bitcoin_sighash.o bitcoin_pubkey.o \
    secp256k1_ecdsa.o secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o \
    secp256k1_scalar.o secp256k1_scalar_c.o ripemd160.o bitcoin_addr.o
SERVETXVALSRCS := daemon/tx_accept.c daemon/mempool_cfg.c daemon/node_config.c bitcoin_mempool_policy.c \
    bitcoin_txval_modern.c bitcoin_segwit.c bitcoin_taproot_sighash.c
tests/test_serve: tests/test_serve.c $(SERVETXVALSRCS) $(SERVEOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_serve.c $(SERVETXVALSRCS) $(SERVEOBJS)

# test_keepup: proves the inbound `block` keep-up path (.do_block) -- a peer
# pushes a block the server lacks; the server validates, stores, and indexes
# it so it becomes serveable, and survives duplicate pushes. Uses SERVEOBJS
# (needs cons_verify/store_append/idx_put from the listed objects).
tests/test_keepup: tests/test_keepup.c $(SERVETXVALSRCS) $(SERVEOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_keepup.c $(SERVETXVALSRCS) $(SERVEOBJS)

# BIP152 compact-block serving loopback e2e (sendcmpct/getblocktxn/cmpctblock).
tests/test_bip152_loop: tests/test_bip152_loop.c $(SERVETXVALSRCS) $(SERVEOBJS) tests/block_vec.h tests/cmpct_expected.h
	$(CC) -no-pie -O0 -o $@ tests/test_bip152_loop.c $(SERVETXVALSRCS) $(SERVEOBJS)

# sendheaders (BIP130) + feefilter: announce_tip inv-vs-headers wire bytes +
# forked serve-loop outbound feefilter & negotiation parsing (loopback e2e).
tests/test_sendheaders_fee: tests/test_sendheaders_fee.c $(SERVETXVALSRCS) $(SERVEOBJS) tests/block_vec.h
	$(CC) -no-pie -O0 -o $@ tests/test_sendheaders_fee.c $(SERVETXVALSRCS) $(SERVEOBJS)

# OUTBOUND P2P MULTIPLEXER loopback e2e: exec's the REAL daemon in serve-test
# mode (poll-multiplexed outbound node_sync + inbound serving), a mining-peer
# child that grows its chain, and an inbound client that fetches the freshly
# mined block -- proving the running node pulls+stores+serves new blocks with
# no restart. Links the server object set for the client/peer roles.
tests/test_outbound_mux: tests/test_outbound_mux.c daemon/bitcoind $(SERVETXVALSRCS) $(SERVEOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_outbound_mux.c $(SERVETXVALSRCS) $(SERVEOBJS)

# OUTBOUND MUX RE-DIAL e2e: regression for soak-defect D2 -- proves the mux
# re-dials a leg the peer rips down (POLLHUP) and recovers keep-up via a fresh
# connection to a rotated peer, instead of syncing on a dead socket forever.
tests/test_redial: tests/test_redial.c daemon/bitcoind $(SERVETXVALSRCS) $(SERVEOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_redial.c $(SERVETXVALSRCS) $(SERVEOBJS)

# OUTBOUND MUX SOAK HARNESS controlled mining peer: real process that serves the
# node_sync protocol from a GROWING chain (mines a block every N seconds) for
# unattended 24h+ soak runs; also periodically re-connects inbound to prove the
# node serves while downloading. Link set = SERVEOBJS (same as test_outbound_mux).
tests/soak_mux_peer: tests/soak_mux_peer.c $(SERVETXVALSRCS) $(SERVEOBJS)
	$(CC) -no-pie -O2 -o $@ tests/soak_mux_peer.c $(SERVETXVALSRCS) $(SERVEOBJS)

# SHA-512 (FIPS 180-4, wallet/BIP32+bech32 foundation).
tests/test_sha512: tests/test_sha512.c sha512.o
	$(CC) -no-pie -O0 -o $@ tests/test_sha512.c sha512.o

# HMAC-SHA512 (RFC 4231 / RFC 2104, BIP32+BIP39 primitive, on asm SHA-512).
HMACOBJS := sha512.o bitcoin_hmac.o
tests/test_hmac: tests/test_hmac.c $(HMACOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_hmac.c $(HMACOBJS)

# bitcoin_bip32.asm (BIP32 master + CKDpriv + full-path + extkey/fingerprint;
# secp256k1 + HMAC + SHA-512 + base58/hash160). bitcoin_bip32.o's fingerprint
# references hash160/base58check from bitcoin_addr.o, so those deps are here.
BIP32OBJS := bitcoin_bip32.o bitcoin_hmac.o sha512.o bitcoin_keys.o \
    secp256k1_fe.o secp256k1_point.o secp256k1_point_ct.o secp256k1_scalar.o \
    secp256k1_scalar_c.o bitcoin_addr.o sha256.o bitcoin_hash.o \
    ripemd160.o
tests/test_bip32_master: tests/test_bip32_master.c $(BIP32OBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_bip32_master.c $(BIP32OBJS)
tests/test_bip32_chain: tests/test_bip32_chain.c $(BIP32OBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_bip32_chain.c $(BIP32OBJS)

# BIP32 full-path derivation + extended key (xprv/xpub): derive_path +
# fingerprint + 78-byte serialize (all bitcoin_bip32.asm) + base58check/hash160
# (bitcoin_addr.asm). Same object set as the other bip32 tests.
EXTKEYOBJS := $(BIP32OBJS)
tests/test_bip32_extkey: tests/test_bip32_extkey.c tests/bip32_extkey_vec.h $(EXTKEYOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_bip32_extkey.c $(EXTKEYOBJS)

# regenerate the BIP32 extended-key vectors from the independent Python oracle
tests/bip32_extkey_vec.h: validation/gen_bip32_vectors.py
	cd tests && python3 ../validation/gen_bip32_vectors.py > bip32_extkey_vec.h

# bitcoin_bip39.asm -- BIP39 mnemonic <-> seed. Deps: sha256 (checksum),
# sha512 + bitcoin_hmac (PBKDF2-HMAC-SHA512). Vectors from the independent
# Python oracle (validation/gen_bip39_vectors.py -> tests/bip39_vec.h), which
# is itself cross-checked against the official bip-0039 vectors and the
# third-party `mnemonic` pip package.
BIP39OBJS := bitcoin_bip39.o sha256.o sha512.o bitcoin_hmac.o
tests/test_bip39: tests/test_bip39.c tests/bip39_vec.h $(BIP39OBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_bip39.c $(BIP39OBJS)

# regenerate the BIP39 vectors from the independent Python oracle
tests/bip39_vec.h: validation/gen_bip39_vectors.py
	python3 validation/gen_bip39_vectors.py > tests/bip39_vec.h

# ripemd160.asm (HASH160 half; needed for P2PKH address generation).
tests/test_ripemd160: tests/test_ripemd160.c ripemd160.o
	$(CC) -no-pie -O0 -o $@ tests/test_ripemd160.c ripemd160.o

# bitcoin_addr.asm (hash160 = RIPEMD160(SHA256), base58check P2PKH addresses).
ADDROBJS := bitcoin_addr.o sha256.o bitcoin_hash.o ripemd160.o
tests/test_addr: tests/test_addr.c $(ADDROBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_addr.c $(ADDROBJS)

# bech32.asm (BIP173) / bech32m (BIP350) address codec: polymod checksum,
# convert_bits + encode/decode, verified against the authoritative BIP173
# and BIP350 vectors plus real mainnet segwit (P2WPKH/P2WSH/P2TR) addresses.
BECH32OBJS := bech32.o
tests/test_bech32: tests/test_bech32.c $(BECH32OBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_bech32.c $(BECH32OBJS)

MEMPOOLOBJS := bitcoin_mempool.o
tests/test_mempool: tests/test_mempool.c $(MEMPOOLOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_mempool.c $(MEMPOOLOBJS)

# Mempool POLICY layer (bitcoin_mempool_policy.c -- pure C glue over the asm
# mempool + asm UTXO): fee/relay floor, double-spend, BIP125 RBF, ancestor/
# descendant limits, fee estimator. Vectors generated by an independent Python
# oracle (tests/gen_mempool_policy_vectors.py -> tests/mempool_policy_vec.h).
POLICYOBJS := bitcoin_mempool.o bitcoin_utxo.o
tests/test_mempool_policy: tests/test_mempool_policy.c tests/mempool_policy_vec.h bitcoin_mempool_policy.c $(POLICYOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_mempool_policy.c bitcoin_mempool_policy.c $(POLICYOBJS)

# regenerate the policy vectors from the independent Python oracle
tests/mempool_policy_vec.h: tests/gen_mempool_policy_vectors.py
	cd tests && python3 gen_mempool_policy_vectors.py

TXIDOBJS := sha256.o bitcoin_hash.o bitcoin_tx.o
tests/test_txtxid: tests/test_txtxid.c $(TXIDOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_txtxid.c $(TXIDOBJS)

# secp256k1 public-key parsing/decompression (affine-limb recovery for ecdsa_verify).
PUBKEYOBJS := bitcoin_pubkey.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o
tests/test_pubkey: tests/test_pubkey.c $(PUBKEYOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_pubkey.c $(PUBKEYOBJS)

# legacy SIGHASH_ALL preimage builder (tx signature digest).
SIGHASHOBJS := bitcoin_sighash.o sha256.o bitcoin_hash.o
tests/test_sighash: tests/test_sighash.c $(SIGHASHOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_sighash.c $(SIGHASHOBJS)

# legacy sighash source-bounds regression: a tx whose scriptSig length varint
# overruns the buffer must be REJECTED (not an OOB source read / SIGSEGV).
tests/test_sighash_oob: tests/test_sighash_oob.c $(SIGHASHOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_sighash_oob.c $(SIGHASHOBJS)

# legacy_sighash (Stage B: full ALL/NONE/SINGLE x ANYONECANPAY + CODESEPARATOR
# strip) against Bitcoin Core's own 500 official sighash.json vectors.
tests/test_legacy_sighash: tests/test_legacy_sighash.c tests/sighash_vec.h $(SIGHASHOBJS)
	$(CC) -no-pie -O0 -I tests -o $@ tests/test_legacy_sighash.c $(SIGHASHOBJS)

# script_flags_for_block (Stage C: activation-height flag schedule), against
# vectors re-derived independently from Core's chainparams.cpp.
tests/test_script_flags: tests/test_script_flags.c tests/flags_vec.h bitcoin_script_flags.o
	$(CC) -no-pie -O0 -I. -I tests -o $@ tests/test_script_flags.c bitcoin_script_flags.o

# script_find_and_delete / script_op_len / script_push_encode against Core's
# own FindAndDelete unit-test cases (transcribed from script_tests.cpp).
tests/test_find_and_delete: tests/test_find_and_delete.c $(SIGHASHOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_find_and_delete.c $(SIGHASHOBJS)

# script layer: DER sig parsing + full P2PKH verification.
SCRIPTOBJS := bitcoin_script.o bitcoin_sighash.o bitcoin_pubkey.o secp256k1_fe.o \
    secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_ecdsa.o secp256k1_point.o \
    secp256k1_point_ct.o bitcoin_hash.o sha256.o
tests/test_script: tests/test_script.c $(SCRIPTOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_script.c $(SCRIPTOBJS)

# end-to-end P2PKH spend validation (same object set).
tests/test_p2pkh: tests/test_p2pkh.c $(SCRIPTOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_p2pkh.c $(SCRIPTOBJS)

# UTXO set (unspent txout store for spend validation).
UTXOOBJS := bitcoin_utxo.o
tests/test_utxo: tests/test_utxo.c $(UTXOOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_utxo.c $(UTXOOBJS)

# PERSISTENT UTXO store (append-only WAL utxo.dat + checkpoint index utxo.idx +
# restart-resume reload), mirroring bitcoin_store.asm's store/index pattern.
# bitcoin_utxo_store.asm wraps bitcoin_utxo.asm's in-memory table.
UTXOSTOREOBJS := bitcoin_utxo_store.o bitcoin_utxo.o
tests/test_utxo_store: tests/test_utxo_store.c $(UTXOSTOREOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_utxo_store.c $(UTXOSTOREOBJS)

# LSM-tree UTXO store (bounded memtable + per-generation WAL + sorted
# immutable run files), Phase 1: replaces the giant-pre-sized-table
# approach above for full-archive replay to fix write amplification.
# NOT wired into DAEMONOBJS -- Phase 2 (compaction) is a hard gate before
# any live-daemon use; today's only real caller is daemon/build_utxo.c.
UTXOLSMOBJS := bitcoin_utxo_lsm.o bitcoin_utxo_store.o bitcoin_utxo.o
tests/test_utxo_lsm: tests/test_utxo_lsm.c $(UTXOLSMOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_utxo_lsm.c $(UTXOLSMOBJS)

# Regression test for the 2026-08-20 compaction manifest-ordering bug (see
# tests/test_compact_manifest_order.c's own header) -- needs manifest_n to
# exceed COMPACT_MAX_RUNS(64) before compacting, which no other test does.
tests/test_compact_manifest_order: tests/test_compact_manifest_order.c $(UTXOLSMOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_compact_manifest_order.c $(UTXOLSMOBJS)

# Whole-transaction validator (test_txval.c): tx_parse + UTXO store +
# P2PKH spend verification (verify_p2pkh + its sighash/pubkey/ecdsa chain).
TXVALOBJS := bitcoin_utxo.o bitcoin_tx.o bitcoin_script.o bitcoin_sighash.o \
    bitcoin_pubkey.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o \
    secp256k1_ecdsa.o secp256k1_point.o secp256k1_point_ct.o bitcoin_hash.o \
    sha256.o
tests/test_txval: tests/test_txval.c tests/txval_vec.h $(TXVALOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_txval.c $(TXVALOBJS)

# LIVE-WIRE end-to-end sighash test: builds a real P2PKH tx, signs it by
# invoking the ACTUAL daemon/wallet_cli binary (legacy SIGHASH_ALL), then
# validates the CLI-signed tx with the whole-transaction validator
# (tx_parse + UTXO + verify_p2pkh + fee). Ties the wallet signer and the
# validator together across a real process boundary instead of isolated
# pre-generated vectors. Requires bitcoin_keys/bitcoin_addr (for the prevout
# P2PKH script) on top of the validator set.
E2EOBJS := $(TXVALOBJS) bitcoin_keys.o bitcoin_addr.o ripemd160.o
tests/test_e2e_sighash: tests/test_e2e_sighash.c daemon/wallet_cli $(E2EOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_e2e_sighash.c $(E2EOBJS)

# "send" (createrawtx + sign-all-inputs) end-to-end: wallet_core.c builds the
# tx with the verified asm crypto (sighash/ecdsa/scalar/point/field from
# WALLETPRIMS), and the harness validates the signed tx with the
# whole-transaction validator (tx_parse + UTXO + verify_p2pkh from TXVALOBJS).
SENDOBJS = $(WALLETPRIMS) bitcoin_tx.o bitcoin_script.o
tests/test_send: tests/test_send.c wallet_core.c $(SENDOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_send.c wallet_core.c $(SENDOBJS)

# Wallet-core/RPC address surface (getnewaddress/getrawchangeaddress +
# getaddressinfo/validateaddress). wallet_core.c + WALLETPRIMS + bech32.o
# (bech32 codec for P2WPKH encode and decode).
WRPCADDR = $(WALLETPRIMS)
tests/test_wrpc_addr: tests/test_wrpc_addr.c wallet_core.c $(WRPCADDR)
	$(CC) -no-pie -O0 -o $@ tests/test_wrpc_addr.c wallet_core.c $(WRPCADDR)

# Wallet-core/RPC UTXO-query surface (gettxout + listunspent). wallet core
# (which includes bitcoin_utxo via WALLETPRIMS).
tests/test_wrpc_utxo: tests/test_wrpc_utxo.c wallet_core.c $(WALLETPRIMS)
	$(CC) -no-pie -O0 -o $@ tests/test_wrpc_utxo.c wallet_core.c $(WALLETPRIMS)

# Wallet-core/RPC decoderawtransaction. Builds a signed tx via wallet_send_tx
# then decodes it.
tests/test_wrpc_decoderaw: tests/test_wrpc_decoderaw.c wallet_core.c $(WALLETPRIMS)
	$(CC) -no-pie -O0 -o $@ tests/test_wrpc_decoderaw.c wallet_core.c $(WALLETPRIMS)

# Wallet-core/RPC signrawtransactionwithkey. wallet core + tx/script for the
# whole-tx validator.
tests/test_wrpc_sign: tests/test_wrpc_sign.c wallet_core.c $(WALLETPRIMS) bitcoin_tx.o bitcoin_script.o
	$(CC) -no-pie -O0 -o $@ tests/test_wrpc_sign.c wallet_core.c $(WALLETPRIMS) bitcoin_tx.o bitcoin_script.o

# Wallet-core/RPC sendtoaddress + getbalance (card 5 capstone). wallet core +
# tx/script for the validator.
tests/test_wrpc_send: tests/test_wrpc_send.c wallet_core.c $(WALLETPRIMS) bitcoin_tx.o bitcoin_script.o
	$(CC) -no-pie -O0 -o $@ tests/test_wrpc_send.c wallet_core.c $(WALLETPRIMS) bitcoin_tx.o bitcoin_script.o

# P2SH / multisig: p2sh_hash (RIPEMD160 of SHA256 of redeem script) +
# OP_CHECKMULTISIG verification over the existing sighash/pubkey/ecdsa chain.
MULTISIGOBJS := bitcoin_multisig.o bitcoin_script.o bitcoin_sighash.o bitcoin_pubkey.o \
    secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_ecdsa.o \
    secp256k1_point.o secp256k1_point_ct.o bitcoin_hash.o sha256.o \
    ripemd160.o
tests/test_multisig: tests/test_multisig.c $(MULTISIGOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_multisig.c $(MULTISIGOBJS)

# Script-level P2SH / BIP16 VerifyScript (bitcoin_verify.c): reuses the same
# sighash/pubkey/ecdsa/ripemd160 object set as test_multisig, plus the full
# C VerifyScript (two-pass + P2SH sub-script execution + CheckMultisig).
VERIFYOBJS := bitcoin_verify.c bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o \
    secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_ecdsa.o \
    secp256k1_point.o secp256k1_point_ct.o bitcoin_hash.o sha256.o \
    ripemd160.o
tests/verify_p2sh_shim: tests/verify_p2sh_shim.c $(VERIFYOBJS)
	$(CC) -no-pie -O0 -o $@ tests/verify_p2sh_shim.c $(VERIFYOBJS)
tests/test_verify_p2sh: tests/test_verify_p2sh.c $(VERIFYOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_verify_p2sh.c $(VERIFYOBJS)

# Full script interpreter harnesses (bitcoin_interp.asm + codec + hashing).
tests/smoke_interp: tests/smoke_interp.c $(INTERPOBJS)
	$(CC) -no-pie -O0 -o $@ tests/smoke_interp.c $(INTERPOBJS)
tests/test_interp: tests/test_interp.c $(INTERPOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_interp.c $(INTERPOBJS)
# test_scriptverify_parity -- the asm-driven VerifyScript must agree with the
# C reference, verdict AND ScriptError code, on the genuine P2SH vectors.
# Those vectors are already differentially validated against Core, so
# agreement here is agreement with Core transitively.
tests/test_scriptverify_parity: tests/test_scriptverify_parity.c bitcoin_scriptverify.c bitcoin_verify.c script_error_codes.h $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o
	$(CC) -no-pie -O0 -I. -I tests -o $@ tests/test_scriptverify_parity.c bitcoin_scriptverify.c bitcoin_verify.c $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o

# test_scriptverify_thread_stress -- many pthreads hammering sv_verify_script
# concurrently, proving the 2026-08-19 TLS conversion (bitcoin_scriptverify.c
# static->__thread + bitcoin_interp.asm/bitcoin_sighash.asm .bss->.tbss) is
# actually thread-safe, not just single-thread-correct.
tests/test_scriptverify_thread_stress: tests/test_scriptverify_thread_stress.c bitcoin_scriptverify.c script_error_codes.h $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o
	$(CC) -no-pie -O0 -I. -I tests -o $@ tests/test_scriptverify_thread_stress.c bitcoin_scriptverify.c $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o -lpthread

# real-mainnet OP_NOP1/NOP4..NOP10-treated-as-bad-opcode regression (the
# exact height-212613 spend that stopped the live daemon's UTXO catch-up).
tests/test_nop1_regression: tests/test_nop1_regression.c bitcoin_scriptverify.c script_error_codes.h $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o bitcoin_script_flags.o
	$(CC) -no-pie -O0 -I. -I tests -o $@ tests/test_nop1_regression.c bitcoin_scriptverify.c $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o bitcoin_script_flags.o

# Stage B end-to-end: genuine SIGHASH_NONE/SINGLE/ANYONECANPAY spends through
# the real interpreter (sv_verify_script), each with a tamper of a field the
# hashtype ignores (must still accept) and one it binds (must reject).
tests/test_hashtype_e2e: tests/test_hashtype_e2e.c tests/hashtype_vec.h bitcoin_scriptverify.c script_error_codes.h $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o
	$(CC) -no-pie -O0 -I. -I tests -o $@ tests/test_hashtype_e2e.c bitcoin_scriptverify.c $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o

# -I. so the test picks up the GENERATED script_error_codes.h instead of
# carrying its own copy of the interpreter's error numbering.
tests/test_tapscript_interp: tests/test_tapscript_interp.c script_error_codes.h $(INTERPOBJS)
	$(CC) -no-pie -O0 -I. -o $@ tests/test_tapscript_interp.c $(INTERPOBJS)
tests/test_interp_legacy_spend: tests/test_interp_legacy_spend.c wallet_core.c bitcoin_interp.o bitcoin_scriptcodec.o bitcoin_script.o sha1.o $(WALLETPRIMS)
	$(CC) -no-pie -O0 -o $@ tests/test_interp_legacy_spend.c wallet_core.c bitcoin_interp.o bitcoin_scriptcodec.o bitcoin_script.o sha1.o $(WALLETPRIMS)
tests/run_batch: tests/run_batch.c $(INTERPOBJS)
	$(CC) -no-pie -O0 -o $@ tests/run_batch.c $(INTERPOBJS)

# Consensus differential shim (consensus_diff.py): exposes cons_verify /
# block_hash / pow_check / diff_target / tx_parse / tx_txid over stdin so a
# Python oracle can feed the same REAL mainnet block/tx bytes to both this
# asm node and Bitcoin Core and compare verdicts byte-for-byte.
tests/consensus_shim: tests/consensus_shim.c $(CONSOBJS) bitcoin_sigops.o bitcoin_scriptcodec.o
	$(CC) -no-pie -O0 -o $@ tests/consensus_shim.c $(CONSOBJS) bitcoin_sigops.o bitcoin_scriptcodec.o

# Full-chain batch differential shim (fullchain_diff.py): same asm objects as
# consensus_shim, non-interactive batch protocol (len-prefixed frames in, one
# compact verdict line per block out) for chewing tens of thousands of blocks
# per process without per-block launch overhead.
tests/fullchain_shim: tests/fullchain_shim.c $(CONSOBJS)
	$(CC) -no-pie -O0 -o $@ tests/fullchain_shim.c $(CONSOBJS)

# Chain-context BIP30 differential shim (bip30_diff.py): maintains a persistent
# UTXO view (bitcoin_utxo.asm) across CONNECT calls and runs Core's ConnectBlock
# BIP30 duplicate-txid gate (validation.cpp, fEnforceBIP30 / IsBIP30Repeat).
tests/bip30_shim: tests/bip30_shim.c $(CONSOBJS) bitcoin_utxo.o
	$(CC) -no-pie -O0 -o $@ tests/bip30_shim.c $(CONSOBJS) bitcoin_utxo.o

# Smoke test for the chain-context BIP30 gate (drives tests/bip30_shim over
# stdin; full differential vs real Core is validation/bip30_diff.py).
tests/test_bip30: tests/test_bip30.c bitcoin_hash.o sha256.o
	$(CC) -no-pie -O0 -o $@ tests/test_bip30.c bitcoin_hash.o sha256.o

bitcoin_sigops.o: bitcoin_sigops.asm bitcoin_scriptcodec.asm
	$(NASM) -f elf64 -o $@ bitcoin_sigops.asm

tests/test_sigops: tests/test_sigops.c bitcoin_sigops.o bitcoin_scriptcodec.o
	$(CC) -O1 -o $@ tests/test_sigops.c bitcoin_sigops.o bitcoin_scriptcodec.o

# BIP340 Schnorr verify + BIP341 Taproot helpers (secp256k1_schnorr.asm,
# secp256k1_taproot.asm) over the verified point/field/scalar + sha256/pubkey.
TAPRIMSOBJS := secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o \
    secp256k1_scalar_c.o sha256.o bitcoin_pubkey.o
tests/test_schnorr: tests/test_schnorr.c secp256k1_schnorr.o $(TAPRIMSOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_schnorr.c secp256k1_schnorr.o $(TAPRIMSOBJS)
tests/test_taproot: tests/test_taproot.c secp256k1_taproot.o $(TAPRIMSOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_taproot.c secp256k1_taproot.o $(TAPRIMSOBJS)

# BIP341/BIP342 taproot sighash + spend validation: C glue (bitcoin_taproot_sighash.c)
# over the verified asm crypto core (sha256_full, tagged_hash256, schnorr_verify,
# point/fe/scalar/pubkey). Vectors are Core-validated (bip-0341 wallet-test-vectors).
TAPSIGHASHOBJS := bitcoin_taproot_sighash.c secp256k1_schnorr.o secp256k1_taproot.o bech32.o \
    bitcoin_interp.o bitcoin_scriptcodec.o ripemd160.o bitcoin_hash.o sha1.o \
    $(TAPRIMSOBJS)
tests/test_taproot_sighash: tests/test_taproot_sighash.c tests/taproot_spend.h tests/taproot_vec.h $(TAPSIGHASHOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_taproot_sighash.c $(filter %.c,$(TAPSIGHASHOBJS)) $(filter %.o,$(TAPSIGHASHOBJS))

# BIP143 segwit-v0 sighash + P2WPKH/P2WSH spend verification (bitcoin_segwit.c)
# over the verified asm primitives (sha256_full, ecdsa_verify, pubkey_parse,
# der_parse_sig, hash160). Vectors are oracle-generated genuine P2WPKH/P2WSH
# spends, oracle validated against the official BIP-0143 vector. Also covers the
# P2TR key-path spend through the same whole-tx materials.
SEGWITOBJS := bitcoin_segwit.c bitcoin_taproot_sighash.c secp256k1_schnorr.o secp256k1_taproot.o \
    bitcoin_script.o bitcoin_sighash.o bitcoin_pubkey.o secp256k1_ecdsa.o \
    secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o \
    secp256k1_scalar_c.o sha256.o bitcoin_hash.o ripemd160.o \
    bitcoin_addr.o
tests/test_segwit_sighash: tests/test_segwit_sighash.c tests/modern_vec.h tests/modern_spend.h $(SEGWITOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_segwit_sighash.c $(filter %.c,$(SEGWITOBJS)) $(filter %.o,$(SEGWITOBJS))

# FULL mempool acceptance pipeline for modern outputs: mempool policy +
# whole-tx validation + ECDSA/Schnorr verify (bitcoin_txval_modern.c +
# bitcoin_segwit.c + bitcoin_taproot_sighash.c + asm utxo/mempool/tx/taproot).
MEMPACCOBJS := bitcoin_txval_modern.c bitcoin_segwit.c bitcoin_taproot_sighash.c bitcoin_mempool_policy.c \
    bitcoin_utxo.o bitcoin_mempool.o bitcoin_tx.o secp256k1_schnorr.o \
    secp256k1_taproot.o bitcoin_script.o bitcoin_sighash.o bitcoin_pubkey.o \
    secp256k1_ecdsa.o secp256k1_point.o secp256k1_point_ct.o secp256k1_fe.o \
    secp256k1_scalar.o secp256k1_scalar_c.o sha256.o bitcoin_hash.o \
    ripemd160.o bitcoin_addr.o
tests/test_mempool_accept_modern: tests/test_mempool_accept_modern.c tests/modern_vec.h tests/modern_spend.h $(MEMPACCOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_mempool_accept_modern.c $(filter %.c,$(MEMPACCOBJS)) $(filter %.o,$(MEMPACCOBJS))

# End-to-end test of daemon/tx_accept.c's REAL pipeline (utxo_lsm_reload
# snapshot -> mempool_resolve_confirmed_utxo -> mpool_policy_add ->
# txval_modern -> tx_accept_validate's accept/reject + mempool storage) --
# NOT covered by test_mempool_accept_modern, which only exercises the old
# bitcoin_utxo.asm-backed passthrough shim, never tx_accept.c itself.
TXACCEPTOBJS := daemon/tx_accept.c daemon/mempool_cfg.c daemon/node_config.c bitcoin_mempool_policy.c \
    bitcoin_txval_modern.c bitcoin_segwit.c bitcoin_taproot_sighash.c bitcoin_utxo_lsm.o \
    bitcoin_utxo_store.o bitcoin_utxo.o bitcoin_mempool.o bitcoin_tx.o \
    secp256k1_schnorr.o secp256k1_taproot.o bitcoin_script.o bitcoin_sighash.o \
    bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_point_ct.o \
    secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o sha256.o \
    bitcoin_hash.o ripemd160.o bitcoin_addr.o
tests/test_tx_accept_e2e: tests/test_tx_accept_e2e.c tests/modern_spend.h $(TXACCEPTOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_tx_accept_e2e.c $(filter %.c,$(TXACCEPTOBJS)) $(filter %.o,$(TXACCEPTOBJS))

# Wallet CLI: generate key, show address, sign a P2PKH tx, and -- via BIP39 +
# BIP32 -- produce/restore recoverable seeds.
# asm/wallet_core.c glues the VERIFIED asm primitives (scalar_to_pubkey,
# hash160, base58check_encode, sighash_all, ecdsa_verify, BIP39 mnemonic<->seed,
# BIP32 master/path/extkey) plus the verified scalar/point/field ops (sc_*,
# point_scalar_mul, fe_*) used to construct ECDSA signatures.
WALLETPRIMS := secp256k1_fe.o secp256k1_point.o secp256k1_point_ct.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_ecdsa.o \
               bitcoin_keys.o bitcoin_addr.o bitcoin_pubkey.o bitcoin_sighash.o \
               bitcoin_hash.o sha256.o ripemd160.o \
               bitcoin_bip39.o sha512.o bitcoin_hmac.o bitcoin_bip32.o bech32.o \
               bitcoin_utxo.o
daemon/wallet_cli: daemon/wallet_cli.c wallet_core.c wallet_store.c wallet_book.c wallet_txlog.c wallet_msgsign.c $(WALLETPRIMS) bitcoin_script.o
	$(CC) -no-pie -O0 -o $@ daemon/wallet_cli.c wallet_core.c wallet_store.c wallet_book.c wallet_txlog.c wallet_msgsign.c $(WALLETPRIMS) bitcoin_script.o

tests/test_wallet_txlog: tests/test_wallet_txlog.c wallet_txlog.c
	$(CC) -no-pie -O0 -o $@ tests/test_wallet_txlog.c wallet_txlog.c

tests/test_msg_sign: tests/test_msg_sign.c wallet_msgsign.c wallet_core.c $(WALLETPRIMS) bitcoin_script.o
	$(CC) -no-pie -O0 -o $@ tests/test_msg_sign.c wallet_msgsign.c wallet_core.c $(WALLETPRIMS) bitcoin_script.o

tests/test_wallet: tests/test_wallet.c wallet_core.c $(WALLETPRIMS)
	$(CC) -no-pie -O0 -o $@ tests/test_wallet.c wallet_core.c $(WALLETPRIMS)

# ============================================================================
# bitcoin-cli RPC network layer (card t_8e5be37f): JSON-RPC 2.0 framing +
# HTTP POST transport (rpc_net.c), Core-bit-exact JSON rendering + command
# dispatch (rpc_json.c + rpc_commands.c), wired to the wallet-core command
# layer (wallet_core.c). Shared by the client binary and the loopback test;
# the production HTTP server endpoint (child card t_0ca5d72e) dispatches
# through the same rpc_dispatch().
# ============================================================================
RPCOBJS := rpc_json.o rpc_net.o rpc_commands.o
# bitcoin_utxo_lsm.o/bitcoin_utxo_store.o: rpc_commands.o's cmd_gettxout_w
# calls utxo_lsm_get unconditionally, so every rpc_commands.o-linking target
# needs them, not just daemon/bitcoin_rpcd (which additionally builds/reloads
# the store itself).
RPCLIBS := wallet_core.c $(WALLETPRIMS) bitcoin_utxo_lsm.o bitcoin_utxo_store.o

rpc_json.o: rpc_json.c rpc_json.h
	$(CC) -no-pie -O0 -c -o $@ rpc_json.c
rpc_net.o: rpc_net.c rpc_net.h rpc_json.h
	$(CC) -no-pie -O0 -c -o $@ rpc_net.c
rpc_commands.o: rpc_commands.c rpc_commands.h rpc_json.h
	$(CC) -no-pie -O0 -c -o $@ rpc_commands.c

daemon/bitcoin_cli: daemon/bitcoin_cli.c rpc_net.o rpc_commands.o rpc_json.o $(RPCLIBS)
	$(CC) -no-pie -O0 -o $@ daemon/bitcoin_cli.c rpc_net.o rpc_commands.o rpc_json.o $(RPCLIBS)

tests/test_rpc_json: tests/test_rpc_json.c rpc_json.o rpc_commands.o $(RPCLIBS)
	$(CC) -no-pie -O0 -o $@ tests/test_rpc_json.c rpc_json.o rpc_commands.o $(RPCLIBS)

tests/test_rpc_transport: tests/test_rpc_transport.c rpc_net.o rpc_commands.o rpc_json.o daemon/bitcoin_cli $(RPCLIBS)
	$(CC) -no-pie -O0 -o $@ tests/test_rpc_transport.c rpc_net.o rpc_commands.o rpc_json.o $(RPCLIBS) -lpthread

# ============================================================================
# HTTP JSON-RPC SERVER endpoint (card t_0ca5d72e): rpc_server.c owns the
# sockets/threads + Core-faithful HTTP/JSON-RPC behavior; daemon/bitcoin_rpcd
# is the production server binary (loads config/bitcoin.conf);
# tests/test_rpc_server forks+execs the REAL bitcoin_rpcd and drives it with
# the REAL bitcoin_cli + raw sockets. Shared render path = rpc_dispatch().
# ============================================================================
rpc_server.o: rpc_server.c rpc_server.h rpc_commands.h rpc_net.h rpc_json.h
	$(CC) -no-pie -O0 -c -o $@ rpc_server.c

daemon/bitcoin_rpcd: daemon/bitcoin_rpcd.c rpc_server.o rpc_net.o rpc_commands.o rpc_json.o $(RPCLIBS)
	$(CC) -no-pie -O0 -o $@ daemon/bitcoin_rpcd.c rpc_server.o rpc_net.o rpc_commands.o rpc_json.o $(RPCLIBS) -lpthread

tests/test_rpc_server: tests/test_rpc_server.c rpc_net.o rpc_commands.o rpc_json.o rpc_server.o daemon/bitcoin_cli daemon/bitcoin_rpcd $(RPCLIBS)
	$(CC) -no-pie -O0 -o $@ tests/test_rpc_server.c rpc_net.o rpc_commands.o rpc_json.o rpc_server.o $(RPCLIBS) -lpthread


# bitcoin_p2p.asm inv parsers (incoming protocol codecs).
P2PINVOBS := bitcoin_p2p.o bitcoin_net.o bitcoin_hash.o sha256.o
tests/test_p2p_inv: tests/test_p2p_inv.c $(P2PINVOBS)
	$(CC) -no-pie -O0 -o $@ tests/test_p2p_inv.c $(P2PINVOBS)

# daemon/bitcoind -- the runnable core node driver (sync/ibd/follow/serve/
# server-test). This is a REAL target so the daemon never goes stale or suffers
# a missing-object link, unlike the old ad-hoc manual gcc command. -O0 required
# (an -O2 rebuild regressed lsock's bind to EFAULT). DAEMONOBJS is defined
# once, above, near its first use (tests/test_bitcoind) -- see the note there.
# STAGE B adds daemon/reorg.c (fork choice / reorg engine), daemon/undo_log.c
# (per-block undo data, now wired into the live apply path) and
# daemon/locator_build.c (the real multi-hash block locator), plus
# bitcoin_chainwork.o for the cumulative-work primitives they run on.
DAEMONSRCS := daemon/main.c daemon/utxo_live.c daemon/tx_accept.c daemon/reorg.c \
    daemon/undo_log.c daemon/locator_build.c daemon/archive_verify.c daemon/addr_ingest.c \
    daemon/net_policy.c daemon/node_config.c daemon/mempool_cfg.c daemon/upload_cap.c \
    bitcoin_mempool_policy.c bitcoin_txval_modern.c bitcoin_segwit.c bitcoin_taproot_sighash.c \
    daemon/tx_verify.c bitcoin_scriptverify.c
daemon/bitcoind: $(DAEMONSRCS) daemon/utxo_walk.h daemon/reorg.h $(DAEMONOBJS) $(VERSION_GEN_H)
	$(CC) -no-pie -O0 -o $@ $(DAEMONSRCS) $(DAEMONOBJS) -lpthread

# pverify -- parallel block-chain verifier, machine-adaptive worker count.
# Built at -O1 (not -O2/-O3): the deep asm call chain (cons_verify -> tx_parse
# / sha256d) misparses a block when the C driver is compiled at aggressive -O2+,
# a documented codegen interaction. -O1 is safe; the speed comes from the
# parallel workers, not C-codegen.
daemon/pverify: daemon/pverify.c $(CONSOBJS)
	$(CC) -O1 -o $@ daemon/pverify.c $(CONSOBJS) -lpthread

# bitcoin_store.asm shared-append: concurrent-safe single-store write (standalone).
tests/test_shared: tests/test_shared.c bitcoin_store.o
	$(CC) -no-pie -O0 -o $@ tests/test_shared.c bitcoin_store.o
tests/test_shared2: tests/test_shared2.c bitcoin_store.o
	$(CC) -no-pie -O0 -o $@ tests/test_shared2.c bitcoin_store.o

test: tests/test_node_config tests/test_archive_check tests/test_scriptverify_parity tests/test_sha256 tests/test_sha512 tests/test_hmac tests/test_fe tests/test_point tests/test_addm tests/test_scalarmul tests/test_scalarmul_ct tests/test_add tests/test_scalar tests/test_ecdsa tests/test_keys tests/test_bip32_master tests/test_bip32_chain tests/test_bip32_extkey tests/test_bip39 tests/test_ripemd160 tests/test_addr tests/test_bech32 tests/test_mempool tests/test_mempool_policy tests/test_txtxid tests/test_block tests/test_tx tests/test_net tests/test_p2p tests/fakepeer_headers tests/test_store tests/test_prune tests/test_cons tests/test_block_genesis tests/test_bitcoind tests/test_bitcoind_sync tests/test_log tests/test_cli tests/test_headers tests/test_ibd_headers tests/test_ibd_blocks tests/test_ibd_full tests/test_addrmgr tests/test_shared tests/test_shared2 tests/test_idx tests/test_serve tests/test_keepup tests/test_p2p_inv tests/test_bip152 tests/test_bip152_loop tests/test_sendheaders_fee tests/test_outbound_mux tests/test_redial tests/test_pubkey tests/test_sighash tests/test_sighash_oob tests/test_script tests/test_p2pkh tests/test_utxo tests/test_utxo_store tests/test_utxo_lsm tests/test_txval tests/test_multisig tests/test_wallet tests/test_e2e_sighash tests/test_send tests/test_wrpc_addr tests/test_wrpc_utxo tests/test_wrpc_decoderaw tests/test_wrpc_sign tests/test_wrpc_send tests/smoke_interp tests/test_interp tests/test_tapscript_interp tests/run_batch tests/consensus_shim tests/test_sigops tests/test_schnorr tests/test_taproot tests/test_taproot_sighash tests/test_segwit_sighash tests/test_mempool_accept_modern tests/test_tx_accept_e2e tests/test_rpc_json tests/test_rpc_transport tests/test_rpc_server tests/verify_p2sh_shim tests/test_verify_p2sh tests/bip30_shim tests/test_bip30 \
tests/test_chainwork tests/test_locator tests/test_prevhash tests/test_truncate tests/test_undo_log tests/test_reorg tests/test_dial_budget tests/test_dial_budget tests/test_legacy_sighash tests/test_find_and_delete tests/test_hashtype_e2e tests/test_script_flags tests/test_archive_repair tests/test_tx_verify_parallel tests/test_utxo_checkpoint tests/diff_add_ct_homog tests/test_nop1_regression tests/test_apply_block_rollback tests/test_scriptverify_thread_stress tests/test_cross_tx_verify tests/test_compact_manifest_order tests/test_tx_verify_bytepool_realloc \
	./tests/test_node_config
	./tests/test_archive_check
	./tests/test_archive_repair
	./tests/test_scriptverify_parity
	./tests/test_scriptverify_thread_stress
	./tests/test_nop1_regression
	./tests/test_sha256
	./tests/test_sha512
	./tests/test_hmac
	./tests/test_fe
	./tests/test_point
	./tests/test_addm
	./tests/test_scalarmul
	./tests/test_scalarmul_ct
	./tests/diff_add_ct_homog
	./tests/test_add
	./tests/test_scalar
	./tests/test_ecdsa
	./tests/test_keys
	./tests/test_bip32_master
	./tests/test_bip32_chain
	./tests/test_bip32_extkey
	./tests/test_bip39
	./tests/test_ripemd160
	./tests/test_addr
	./tests/test_bech32
	./tests/test_mempool
	./tests/test_mempool_policy
	./tests/test_txtxid
	./tests/test_pubkey
	./tests/test_sighash
	./tests/test_sighash_oob
	./tests/test_script
	./tests/test_p2pkh
	./tests/test_utxo
	./tests/test_utxo_store
	./tests/test_utxo_lsm
	./tests/test_wallet
	./tests/test_e2e_sighash
	./tests/test_send
	./tests/test_wrpc_addr
	./tests/test_wrpc_utxo
	./tests/test_wrpc_decoderaw
	./tests/test_wrpc_sign
	./tests/test_wrpc_send
	./tests/test_txval
	./tests/test_multisig
	./tests/smoke_interp
	./tests/test_interp
	./tests/test_tapscript_interp
	./tests/test_schnorr tests/bip340_test_vectors.csv
	./tests/test_taproot
	./tests/test_taproot_sighash
	./tests/test_segwit_sighash
	./tests/test_mempool_accept_modern
	./tests/test_tx_accept_e2e
	./tests/test_rpc_json
	./tests/test_rpc_transport
	./tests/test_rpc_server
	./tests/test_block
	./tests/test_tx
	./tests/test_net
	./tests/test_p2p
	./tests/fakepeer_headers
	./tests/test_store
	./tests/test_prune
	./tests/test_cons
	./tests/test_block_genesis
	./tests/test_bitcoind
	./tests/test_bitcoind_sync
	./tests/test_log
	./tests/test_cli
	./tests/test_headers
	./tests/test_ibd_headers
	./tests/test_ibd_blocks
	./tests/test_ibd_full
	./tests/test_addrmgr
	./tests/test_shared
	./tests/test_shared2
	./tests/test_idx
	./tests/test_serve
	./tests/test_keepup
	./tests/test_p2p_inv
	./tests/test_bip152
	./tests/test_bip152_loop
	./tests/test_sendheaders_fee
	./tests/test_outbound_mux ./daemon/bitcoind
	./tests/test_redial ./daemon/bitcoind
	./tests/verify_p2sh_shim < /dev/null
	./tests/test_verify_p2sh
	./tests/test_bip30
	./tests/test_chainwork
	./tests/test_locator
	./tests/test_prevhash
	./tests/test_truncate
	./tests/test_undo_log
	./tests/test_reorg
	./tests/test_dial_budget
	./tests/test_legacy_sighash
	./tests/test_find_and_delete
	./tests/test_hashtype_e2e
	./tests/test_script_flags
	./tests/test_tx_verify_parallel
	./tests/test_utxo_checkpoint
	./tests/test_apply_block_rollback
	./tests/test_cross_tx_verify
	./tests/test_compact_manifest_order
	./tests/test_tx_verify_bytepool_realloc

clean:
	rm -f $(OBJS) secp256k1_taproot.o secp256k1_schnorr.o bitcoind.o sha512.o bitcoin_hmac.o bitcoin_keys.o bitcoin_bip39.o ripemd160.o bitcoin_addr.o tests/test_pubkey tests/test_sighash tests/test_script tests/test_p2pkh tests/test_utxo tests/test_sha256 tests/test_sha512 tests/test_hmac tests/test_fe tests/test_point tests/test_addm tests/test_scalarmul tests/test_add tests/test_scalar tests/test_ecdsa tests/test_keys tests/test_bip32_master tests/test_bip32_chain tests/test_bip32_extkey tests/test_bip39 tests/test_ripemd160 tests/test_addr tests/test_bech32 tests/test_mempool tests/test_txtxid tests/test_block tests/test_tx tests/test_net tests/test_p2p tests/fakepeer_headers tests/test_store tests/test_cons tests/test_block_genesis tests/test_bitcoind tests/test_bitcoind_sync tests/test_log tests/test_cli tests/test_headers tests/test_ibd_headers tests/test_ibd_blocks tests/test_ibd_full tests/test_addrmgr tests/test_shared tests/test_shared2 tests/test_idx tests/test_serve tests/test_keepup tests/test_p2p_inv tests/test_bip152 tests/test_bip152_loop tests/test_sendheaders_fee tests/test_pubkey tests/test_sighash tests/test_sighash_oob tests/test_script tests/test_p2pkh tests/test_utxo tests/test_utxo_store tests/test_utxo_lsm tests/test_txval tests/test_multisig tests/test_wallet tests/test_e2e_sighash tests/test_send tests/test_wrpc_addr tests/test_wrpc_utxo tests/test_wrpc_decoderaw tests/test_wrpc_sign tests/test_wrpc_send tests/test_schnorr tests/test_taproot tests/test_taproot_sighash tests/test_segwit_sighash tests/test_mempool_accept_modern tests/test_tx_accept_e2e tests/test_rpc_json tests/test_rpc_transport tests/test_rpc_server rpc_json.o rpc_net.o rpc_commands.o rpc_server.o daemon/bitcoin_cli daemon/bitcoin_rpcd daemon/wallet_cli tests/bip30_shim tests/test_bip30 bitcoin_chainwork.o daemon/locator_build.o daemon/undo_log.o tests/test_chainwork tests/test_locator tests/test_prevhash tests/test_truncate tests/test_undo_log tests/test_reorg