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

utxo_lsm_mm.o: utxo_lsm_mm.c
	$(CC) $(CFLAGS) -c -o $@ utxo_lsm_mm.c

OBJS := sha256.o sha1.o sha512.o bitcoin_hmac.o bitcoin_keys.o ripemd160.o bitcoin_addr.o bech32.o secp256k1_fe.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_ecdsa.o bitcoin_hash.o bitcoin_tx.o bitcoin_net.o bitcoin_p2p.o bitcoin_store.o bitcoin_store_fast.o bitcoin_cons.o node_log.o bitcoin_cli.o bitcoind.o bitcoin_headers.o bitcoin_addrmgr.o bitcoin_idx.o bitcoin_serve.o bitcoin_mempool.o bitcoin_pubkey.o bitcoin_sighash.o bitcoin_script.o bitcoin_utxo.o bitcoin_utxo_store.o bitcoin_multisig.o bitcoin_bip39.o bitcoin_interp.o bitcoin_scriptcodec.o bitcoin_script_flags.o
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

# ---------------------------------------------------------------------------
# Object/source groups used by rules FURTHER DOWN THIS FILE.
#
# A prerequisite list is expanded WHEN MAKE READS THE LINE; a recipe is
# expanded when the recipe RUNS.  So a group named in a prerequisite list
# before its own assignment expands to NOTHING there, while the recipe on the
# next line still gets the full list.  The rule then links objects make was
# never told about: fine on a warm tree, "cannot find X.o" on a fresh clone or
# under -j.  Every one of these five was in exactly that state (found by
# `make prereq-check`, 2026-08-23) -- so they all live up here now, above
# every rule that names them.
# ---------------------------------------------------------------------------
# bitcoin_idx.asm: O(1) hash->height index for serving (standalone deps).
IDXOBJS := bitcoin_idx.o
# LSM-tree UTXO store: bounded memtable + per-generation WAL + sorted runs.
UTXOLSMOBJS := bitcoin_utxo_lsm.o utxo_lsm_mm.o bitcoin_utxo_store.o bitcoin_utxo.o
# The FULL daemon object list, matching the daemon/bitcoind link below.
DAEMONOBJS := sha256.o bitcoin_hash.o bitcoin_net.o bitcoin_p2p.o \
    bitcoin_tx.o bitcoin_cons.o bitcoin_store.o bitcoind.o \
    node_log.o bitcoin_headers.o bitcoin_addrmgr.o bitcoin_idx.o \
    bitcoin_serve.o bitcoin_mempool.o bitcoin_cmpct.o bitcoin_idxscan.o \
    bitcoin_utxo_lsm.o utxo_lsm_mm.o bitcoin_utxo_store.o bitcoin_utxo.o bitcoin_store_fast.o \
    secp256k1_schnorr.o secp256k1_taproot.o bitcoin_script.o bitcoin_sighash.o \
    bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o \
    secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o ripemd160.o \
    bitcoin_addr.o bitcoin_chainwork.o bitcoin_interp.o bitcoin_scriptcodec.o \
    bitcoin_script_flags.o sha1.o \
    bitcoin_utxo_stats.o bitcoin_muhash.o
# C sources of the tx-accept / script-verify path linked into the serve and
# daemon harnesses.
SERVETXVALSRCS := daemon/tx_accept.c daemon/mempool_cfg.c daemon/node_config.c bitcoin_mempool_policy.c bitcoin_scriptverify.c \
    bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c
# asm/wallet_core.c's verified asm primitives (keys, addresses, sighash, ECDSA,
# BIP39/BIP32, field/scalar/point ops).
WALLETPRIMS := secp256k1_fe.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_ecdsa.o \
               bitcoin_keys.o bitcoin_addr.o bitcoin_pubkey.o bitcoin_sighash.o \
               bitcoin_hash.o sha256.o ripemd160.o \
               bitcoin_bip39.o sha512.o bitcoin_hmac.o bitcoin_bip32.o bech32.o \
               bitcoin_utxo.o

# Embedded RPC server objects (docs/RPC_LIVE_NODE.md): net-new objects not
# already in DAEMONOBJS, linked into daemon/bitcoind (+ any test that pulls in
# daemon/main.c). Defined HERE, before the first rule that references it in its
# prerequisites (tests/test_dial_budget), so make expands it in the prereq list
# at parse time -- otherwise the prereq-check audit flags the objects as
# linked-but-not-a-prerequisite.
DAEMON_RPCOBJS := rpc_server.o rpc_commands.o rpc_chain.o rpc_json.o rpc_net.o rpc_node.o \
    bitcoin_keys.o bitcoin_bip39.o sha512.o bitcoin_hmac.o bitcoin_bip32.o bech32.o

.PHONY: all asm test clean abi-check callee-saved-check prereq-check

# Per-test private working directory helper. Every test that includes it must
# list it as a prerequisite, or a change to the isolation mechanism silently
# fails to reach the binaries that depend on it.
TEST_TMPDIR_H = tests/test_tmpdir.h

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

tests/test_point: tests/test_point.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_point.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o

tests/test_point_inf: tests/test_point_inf.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_point_inf.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o

tests/test_addm: tests/test_addm.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_addm.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o

tests/test_scalarmul: tests/test_scalarmul.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_scalarmul.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o

tests/stress_pointmul: tests/stress_pointmul.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/stress_pointmul.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o

tests/test_scalarmul_ct: tests/test_scalarmul_ct.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_scalarmul_ct.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o

tests/stress_pointmul_ct: tests/stress_pointmul_ct.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/stress_pointmul_ct.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o

tests/diff_add_ct_homog: tests/diff_add_ct_homog.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/diff_add_ct_homog.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o

tests/test_add: tests/test_add.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_add.c secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_point_ct.o secp256k1_fe.o

tests/test_scalar: tests/test_scalar.c secp256k1_scalar.o secp256k1_scalar_c.o
	$(CC) $(CFLAGS) -o $@ tests/test_scalar.c secp256k1_scalar.o secp256k1_scalar_c.o

# PERF_SCOPE.md 4.3 (b): GLV split. glv_split_vec.h is generated (and
# committed) by validation/glv_split_oracle.py, which also re-derives the
# lattice constants from Core's stated basis and asserts they match the asm.
tests/glv_split_vec.h: validation/glv_split_oracle.py
	python3 validation/glv_split_oracle.py gen 2000 20260822 > $@
tests/test_glv_split: tests/test_glv_split.c tests/glv_split_vec.h secp256k1_scalar.o secp256k1_scalar_c.o
	$(CC) $(CFLAGS) -o $@ tests/test_glv_split.c secp256k1_scalar.o secp256k1_scalar_c.o

# PERF_SCOPE.md 4.3 (c): width-5 NAF encoder for the two GLV halves (C, like
# secp256k1_scalar_c.c), plus the BMC_ECDSA_GLV kill switch.
tests/test_glv_wnaf: tests/test_glv_wnaf.c secp256k1_glv_c.o
	$(CC) $(CFLAGS) -o $@ tests/test_glv_wnaf.c secp256k1_glv_c.o

# PERF_SCOPE.md 4.3 (d): the GLV multiply vs the oracle-validated
# point_scalar_mul it replaces, compared projectively.
GLVOBJS := secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_point_ct.o secp256k1_fe.o
tests/test_glv_pointmul: tests/test_glv_pointmul.c $(GLVOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_glv_pointmul.c $(GLVOBJS)

# Lost-carry regression (2026-08-21): exact vectors for the sc_mul MULACC and
# fe_mul fold-2 carry bugs, plus a structured-input inverse sweep.
tests/test_mul_carry_regression: tests/test_mul_carry_regression.c secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_mul_carry_regression.c secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_fe.o

# PERF_SCOPE.md section 5 (field rewrite, 2026-08-22). fe_vec.h is generated
# (and committed) by validation/fe_oracle.py: explicit Python ground-truth
# vectors plus a digest over the full 1547x1547 structured cross-product.
# tests/fe_ref.asm is a FROZEN copy of the pre-rewrite 4x64 field, symbols
# suffixed _ref, so the rewrite can be proved limb-identical to the code that
# replayed the chain to height ~575,000.
tests/fe_vec.h: validation/fe_oracle.py
	python3 validation/fe_oracle.py gen 1600 20260822 > $@
tests/test_fe_repr: tests/test_fe_repr.c tests/fe_vec.h secp256k1_fe.o tests/fe_ref.o
	$(CC) $(CFLAGS) -o $@ tests/test_fe_repr.c secp256k1_fe.o tests/fe_ref.o

# Field-primitive microbenchmark (not in the test target: it measures, it
# does not assert). CPU-time, min-of-N -- see the header comment.
tests/bench_fe: tests/bench_fe.c secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/bench_fe.c secp256k1_fe.o

# PERF_SCOPE.md 10 (EC-layer change, 2026-08-22): the 20 fe_mul(a,a) call sites
# now go through fe_sqr, and a dead fe_mul + fe_sub are gone from
# point_double. Neither touches the field, so the field campaign says nothing
# about them; what has to be proved is that the CALLERS still compute the same
# thing. tests/point_ref.asm and tests/point_ct_ref.asm are FROZEN copies of
# main's EC layer with every exported symbol suffixed _ref -- the point-layer
# analogue of tests/fe_ref.asm -- and they link against the LIVE (unchanged)
# field, so any difference they report is a difference in the point layer.
# tests/point_ref.asm needs -Itests/ for its renamed comb table.
tests/point_ref.o: tests/point_ref.asm tests/g_comb_table_ref.inc
	$(NASM) -f elf64 -Itests/ -o $@ tests/point_ref.asm
tests/point_ct_ref.o: tests/point_ct_ref.asm
	$(NASM) $(NASMFLAGS) -o $@ tests/point_ct_ref.asm
PTREPROBJS := secp256k1_point.o secp256k1_point_ct.o tests/point_ref.o \
    tests/point_ct_ref.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o \
    secp256k1_glv_c.o
tests/test_point_repr: tests/test_point_repr.c $(PTREPROBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_point_repr.c $(PTREPROBJS)

# PERF_SCOPE.md 4.2 A+B differential: the new ecdsa_verify (projective
# x-compare, variable-time s^-1) vs tests/ecdsa_verify_ref.asm, a frozen copy
# of the pre-change verifier, plus sc_inv_var vs Fermat sc_inv and the
# function-level r+n branch of ecdsa_x_eq_mod_n. Fixtures are signed by
# libsecp256k1 (validation/gen_ecdsa_inverse_vectors.py).
EIVOBJS := secp256k1_ecdsa.o tests/ecdsa_verify_ref.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o
tests/test_ecdsa_inverse: tests/test_ecdsa_inverse.c tests/ecdsa_inverse_vec.h $(EIVOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_ecdsa_inverse.c $(EIVOBJS)

# PERF_SCOPE.md 4.3 (e): ecdsa_verify with GLV on vs off vs the frozen
# reference, all three verdicts compared per case.
tests/test_ecdsa_glv_switch: tests/test_ecdsa_glv_switch.c tests/ecdsa_inverse_vec.h $(EIVOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_ecdsa_glv_switch.c $(EIVOBJS)

tests/test_ecdsa: tests/test_ecdsa.c secp256k1_ecdsa.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_ecdsa.c secp256k1_ecdsa.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o

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
tests/bench_ecdsa: tests/bench_ecdsa.c secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o
	$(CC) -no-pie -O2 -o $@ tests/bench_ecdsa.c secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o

# test_fe_inline -- the inline field macros (secp256k1_fe_inline.inc) driven
# directly, against fe_add/fe_sub AND a C big-integer oracle, with the carry
# boundaries constructed explicitly. tests/fe_inline_probe.asm is a test-only
# wrapper; nothing in the node links it.
tests/fe_inline_probe.o: tests/fe_inline_probe.asm secp256k1_fe_inline.inc
	$(NASM) $(NASMFLAGS) -o $@ $<
tests/test_fe_inline: tests/test_fe_inline.c tests/fe_inline_probe.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_fe_inline.c tests/fe_inline_probe.o secp256k1_fe.o

# bench_point -- EC-layer microbenchmark (point_double / point_add /
# point_add_mixed). The level at which "inline the field ops into the EC
# formulas" (PERF_SCOPE.md 12) has to be measured: bench_fe cannot see a call
# boundary that no longer exists.
tests/bench_point: tests/bench_point.c secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o tests/fe_inline_probe.o
	$(CC) $(CFLAGS) -o $@ tests/bench_point.c secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o tests/fe_inline_probe.o

tests/bench_idxscan: tests/bench_idxscan.c bitcoin_idxscan.o bitcoin_store.o
	$(CC) $(CFLAGS) -o $@ tests/bench_idxscan.c bitcoin_idxscan.o bitcoin_store.o

# This rule was pinned to -O0 with the note "-O2 miscompiles this harness
# (fread called with a NULL buffer per gdb)". Re-tested 2026-08-23 against a
# real 130,001-record index.dat: at -O2 it builds both tables, reports
# C == asm == 130001 and passes its 33 sampled idx_get cross-checks. Whatever
# the original miscompile was, it does not reproduce; the pin is removed with
# the rest.
tests/bench_hashidx: tests/bench_hashidx.c bitcoin_idx.o
	$(CC) -no-pie -O2 -Wall -o $@ tests/bench_hashidx.c bitcoin_idx.o

tests/test_store: tests/test_store.c bitcoin_store.o $(TEST_TMPDIR_H)
	$(CC) $(CFLAGS) -o $@ tests/test_store.c bitcoin_store.o

# PRUNING (store_prune/store_set_prune in bitcoin_store.asm): configurable prune
# height, whole-file deletion, boundary compaction, -3-unavailable gate,
# prune.dat persistence. Standalone (links bitcoin_store.o only).
tests/test_prune: tests/test_prune.c bitcoin_store.o $(TEST_TMPDIR_H)
	$(CC) $(CFLAGS) -o $@ tests/test_prune.c bitcoin_store.o

# ---- Stage A reorg/fork-choice primitives (standalone, additive -- see each
# new file's own header comment; nothing in the live daemon calls these yet) ----

# Primitive #1: chainwork tracking (bitcoin_chainwork.asm). Standalone.
tests/test_chainwork: tests/test_chainwork.c bitcoin_chainwork.o $(TEST_TMPDIR_H)
	$(CC) $(CFLAGS) -o $@ tests/test_chainwork.c bitcoin_chainwork.o

# Primitive #2: real multi-hash block locator (p2p_getheaders count>1
# extension in bitcoin_p2p.asm + daemon/locator_build.c).
tests/test_locator: tests/test_locator.c $(P2POBJS) bitcoin_store.o daemon/locator_build.o $(TEST_TMPDIR_H)
	$(CC) $(CFLAGS) -o $@ tests/test_locator.c $(P2POBJS) bitcoin_store.o daemon/locator_build.o

# Primitive #3: prevhash validation gate (store_get_tip_hash /
# store_validates_prevhash in bitcoin_store.asm). Standalone.
tests/test_prevhash: tests/test_prevhash.c bitcoin_store.o $(TEST_TMPDIR_H)
	$(CC) $(CFLAGS) -o $@ tests/test_prevhash.c bitcoin_store.o

# Primitive #4: store truncate/rollback (store_truncate_to in
# bitcoin_store.asm). Also exercises the EXISTING, unmodified
# idx_build_from_file (bitcoin_idx.asm) against the truncated store.
tests/test_truncate: tests/test_truncate.c bitcoin_store.o $(IDXOBJS) $(TEST_TMPDIR_H)
	$(CC) $(CFLAGS) -o $@ tests/test_truncate.c bitcoin_store.o $(IDXOBJS)

# Primitive #5: per-block undo-data structure (daemon/undo_log.c) against
# the real LSM UTXO store.
tests/test_undo_log: tests/test_undo_log.c daemon/undo_log.o $(UTXOLSMOBJS) $(TEST_TMPDIR_H)
	$(CC) $(CFLAGS) -o $@ tests/test_undo_log.c daemon/undo_log.o $(UTXOLSMOBJS)

# The asm twin vs the C oracle, on identical op streams. The C oracle is
# compiled with objcopy-prefixed symbols (ref_*) so both link into one
# binary; the prefixed object has its own rule so prereq-check sees it as a
# declared prerequisite rather than a file the recipe conjures.
tests/undo_log_ref.o: daemon/undo_log.c
	$(CC) $(CFLAGS) -c daemon/undo_log.c -o $@
	objcopy --redefine-sym undo_append_record=ref_undo_append_record \
	        --redefine-sym undo_capture_and_del=ref_undo_capture_and_del \
	        --redefine-sym undo_load=ref_undo_load \
	        --redefine-sym undo_replay=ref_undo_replay \
	        --redefine-sym undo_replay_tolerant=ref_undo_replay_tolerant \
	        --redefine-sym undo_discard=ref_undo_discard \
	        --redefine-sym undo_prune_from=ref_undo_prune_from \
	        --redefine-sym undo_prune=ref_undo_prune \
	        $@

tests/test_undo_asm_diff: tests/test_undo_asm_diff.c tests/undo_log_ref.o bitcoin_undo.o $(UTXOLSMOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_undo_asm_diff.c tests/undo_log_ref.o bitcoin_undo.o $(UTXOLSMOBJS)

# ---- Stage B: the wired-together reorg engine ----------------------------
# tests/test_reorg.c drives the REAL production modules (daemon/reorg.c,
# daemon/utxo_live.c daemon/block_witness.c, daemon/undo_log.c, daemon/locator_build.c and the real bitcoin_cmpct.o
# mempool policy layer) against the real block store, the real LSM UTXO store
# and a real loopback fake peer. Built at -O0 for the same reason
# daemon/bitcoind is: the deep asm call chain (cons_verify -> tx_parse /
# sha256d) is documented in this Makefile as misbehaving under aggressive C
# optimisation, and this harness sits directly on top of it.
REORGSRCS := tests/test_reorg.c daemon/reorg.c daemon/archive_verify.c daemon/utxo_live.c daemon/block_witness.c daemon/undo_log.c \
    daemon/locator_build.c daemon/node_config.c bitcoin_mempool_policy.c \
    daemon/tx_verify.c bitcoin_witness_v0.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c
REORGOBJS := bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_idxscan.o \
    bitcoin_chainwork.o bitcoin_hash.o sha256.o bitcoin_tx.o \
    bitcoin_cons.o bitcoin_p2p.o bitcoin_net.o bitcoin_mempool.o \
    bitcoin_utxo_lsm.o utxo_lsm_mm.o bitcoin_utxo_store.o bitcoin_utxo.o bitcoind.o \
    bitcoin_headers.o bitcoin_interp.o bitcoin_scriptcodec.o bitcoin_script_flags.o \
    bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o \
    secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o \
    secp256k1_scalar_c.o secp256k1_schnorr.o secp256k1_taproot.o ripemd160.o \
    bitcoin_addr.o sha1.o bitcoin_utxo_stats.o bitcoin_muhash.o
tests/test_reorg: $(REORGSRCS) daemon/reorg.h daemon/utxo_walk.h $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -o $@ $(REORGSRCS) $(REORGOBJS) -lpthread

# test_tx_verify_parallel -- differential test for txv_verify_all's forked
# parallel path (>= TXV_PARALLEL_MIN non-taproot inputs) against a genuinely
# multi-signed P2WPKH tx (see tests/multi_p2wpkh_vec.h / gen_multi_p2wpkh.py).
TXVPARSRCS := tests/test_tx_verify_parallel.c daemon/tx_verify.c bitcoin_scriptverify.c \
    bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c
tests/test_block_481827_pool_stack: tests/test_block_481827_pool_stack.c daemon/utxo_live.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c daemon/block_witness.c daemon/undo_log.c daemon/node_config.c $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -o $@ tests/test_block_481827_pool_stack.c daemon/utxo_live.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c daemon/block_witness.c daemon/undo_log.c daemon/node_config.c $(REORGOBJS) -lpthread
# NB: filter out the real LSM objects -- this test supplies its own adversarial
# utxo_lsm_get (single reused return buffer) to pin the transient-spk contract.
TXVBWPSOBJS := $(filter-out bitcoin_utxo_lsm.o utxo_lsm_mm.o bitcoin_utxo_store.o bitcoin_utxo.o bitcoind.o,$(REORGOBJS))
tests/test_txvb_wprog_stable: tests/test_txvb_wprog_stable.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(TXVBWPSOBJS)
	$(CC) -no-pie -O2 -Wall -o $@ tests/test_txvb_wprog_stable.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(TXVBWPSOBJS) -lpthread
# test_taproot_exception_block -- LOG.md incident #22 regression: the ONE
# mainnet block Core exempts from the taproot rules BY HASH (692261). Drives
# the real witnessless taproot spend through BOTH block-connection entry
# points -- at the exception hash (must ACCEPT) and at other hashes at the
# same height (must REJECT) -- so a dispatch site that ignores the flags
# script_flags_for_block already computed fails here. Uses the same filtered
# object set as test_txvb_wprog_stable: it supplies its own utxo_lsm_get and
# never stands up an LSM, so it touches no files at all.
tests/test_taproot_exception_block: tests/test_taproot_exception_block.c tests/taproot_exception_vec.h daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(TXVBWPSOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_taproot_exception_block.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(TXVBWPSOBJS) -lpthread
# bench_taproot_block -- wall time, CPU time and EFFECTIVE PARALLELISM for one
# whole block's script verification at the entry point the daemon uses. This is
# the offline, re-runnable form of the measurement PERF_SCOPE.md section 14 took
# from a live profile (32 workers asleep, ~1 core of 32 in use). Needs the same
# gitignored fixtures as test_taproot_block_diff; not in `test:` -- it is a
# benchmark, and a benchmark that runs on a loaded box reports noise.
# Run: python3 validation/fetch_taproot_blocks.py 825000 &&
#      make tests/bench_taproot_block && tests/bench_taproot_block 825000 --runs 5
tests/bench_taproot_block: tests/bench_taproot_block.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(TXVBWPSOBJS)
	$(CC) -no-pie -O2 -Wall -o $@ tests/bench_taproot_block.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(TXVBWPSOBJS) -lpthread
# test_taproot_block_diff -- whole-block differential against the scratch Core
# oracle for the PARALLEL taproot path (PERF_SCOPE.md section 14.7). Both entry
# points, accept AND reject direction, over real taproot-dense blocks at height
# >= 800,000. Fixtures are large and gitignored (validation/
# fetch_taproot_blocks.py); the test SKIPs cleanly without them, which is what
# `make test` gets -- it is a pre-deployment gate run by hand against the
# oracle, not a self-contained unit test. Same filtered object set as
# test_txvb_wprog_stable: supplies its own utxo_lsm_get, stands up no LSM.
tests/test_taproot_block_diff: tests/test_taproot_block_diff.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(TXVBWPSOBJS)
	$(CC) -no-pie -O2 -Wall -o $@ tests/test_taproot_block_diff.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(TXVBWPSOBJS) -lpthread
# test_taproot_parallel_arena -- the fixture PERF_SCOPE.md section 14.7 asks for
# by name: transactions with DIFFERENT input counts verifying concurrently,
# which is the shape a wrong shared arena breaks first. Baked into a committed
# header (validation/fetch_taproot_arena.py), so unlike test_taproot_block_diff
# it runs unconditionally in `make test`.
tests/test_taproot_parallel_arena: tests/test_taproot_parallel_arena.c tests/taproot_arena_vec.h daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(TXVBWPSOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_taproot_parallel_arena.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(TXVBWPSOBJS) -lpthread
# test_scriptnum_bool -- LOG.md incident #28 regression: SETcc writes only the
# low 8 bits, so every numeric opcode's boolean result carried the OPERAND's
# upper bits. Drives real mainnet block 792,980's CHECKSIG+OP_ADD threshold
# P2WSH through BOTH block-connection entry points, plus a Core-verdicted sweep
# of pure-arithmetic scripts across the 255/256 and 0/-1 boundaries -- loaded
# in BOTH directions, because the bug false-ACCEPTED as well as false-rejected.
# Same filtered object set as test_taproot_exception_block: supplies its own
# utxo_lsm_get, stands up no LSM, touches no files.
tests/test_scriptnum_bool: tests/test_scriptnum_bool.c tests/scriptnum_bool_vec.h daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(TXVBWPSOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_scriptnum_bool.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(TXVBWPSOBJS) -lpthread
tests/test_dersig_encoding: tests/test_dersig_encoding.c tests/dersig_vec.h daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(TXVBWPSOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_dersig_encoding.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(TXVBWPSOBJS) -lpthread
tests/test_segwit_real: tests/test_segwit_real.c tests/segwit_real_vec.h daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -o $@ tests/test_segwit_real.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(REORGOBJS) -lpthread
tests/test_segwit_coverage: tests/test_segwit_coverage.c tests/segwit_coverage_vec.h daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -o $@ tests/test_segwit_coverage.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(REORGOBJS) -lpthread
# test_tapscript_scale -- inscription-SCALE tapscript coverage: the last two
# open rows of CHAIN_AHEAD_CENSUS.md. The inline fixtures (42,594 B leaf,
# 21-node control block, 12-item script-path witness) always run; the 371,967 B
# and 3,938,182 B leaf fixtures live in the gitignored
# tests/fixtures/tapscript_big.txt (regenerate with
# `python3 validation/fetch_tapscript_scale.py --big tests/fixtures`) and SKIP
# loudly when absent, so this never fails merely because the oracle is offline.
tests/test_tapscript_scale: tests/test_tapscript_scale.c tests/tapscript_scale_vec.h tests/tapscript_stack_vec.h daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -o $@ tests/test_tapscript_scale.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(REORGOBJS) -lpthread
tests/test_tx_verify_parallel: $(TXVPARSRCS) tests/multi_p2wpkh_vec.h $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -o $@ $(TXVPARSRCS) $(REORGOBJS) -lpthread

# test_utxo_checkpoint -- utxo_live_catchup must persist a resumable
# checkpoint periodically during a long catch-up, not just on a (rare, during
# bulk mode) compaction or at the very end of the call.
CKPTSRCS := tests/test_utxo_checkpoint.c daemon/utxo_live.c daemon/block_witness.c daemon/undo_log.c \
    daemon/locator_build.c daemon/node_config.c bitcoin_mempool_policy.c \
    daemon/tx_verify.c bitcoin_witness_v0.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c
tests/test_utxo_checkpoint: $(CKPTSRCS) daemon/utxo_walk.h $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -o $@ $(CKPTSRCS) $(REORGOBJS) -lpthread

# test_apply_block_rollback -- a block that fails partway through must roll
# back everything it already committed (coinbase + any earlier-in-block tx),
# not just the failing tx -- see rollback_partial_apply in daemon/utxo_live.c daemon/block_witness.c. bitcoin_cmpct.o
ROLLBACKSRCS := tests/test_apply_block_rollback.c daemon/utxo_live.c daemon/block_witness.c daemon/undo_log.c \
    daemon/locator_build.c daemon/node_config.c bitcoin_mempool_policy.c \
    daemon/tx_verify.c bitcoin_witness_v0.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c
tests/test_apply_block_rollback: $(ROLLBACKSRCS) daemon/utxo_walk.h $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -o $@ $(ROLLBACKSRCS) $(REORGOBJS) -lpthread

# test_utxo_catchup_crash_resume -- a process death mid-catch-up must not
# corrupt the resumed catch-up on the next boot: utxo_live_catchup must
# persist its checkpoint after every block, not just at a compaction or the
# end of the call, or a stale checkpoint makes an already-durably-applied
# block get re-verified against UTXO state it already spent -- see the
# per-block persist_applied_height() call in daemon/utxo_live.c daemon/block_witness.c. bitcoin_cmpct.o
CRASHRESUMESRCS := tests/test_utxo_catchup_crash_resume.c daemon/utxo_live.c daemon/block_witness.c daemon/undo_log.c \
    daemon/locator_build.c daemon/node_config.c bitcoin_mempool_policy.c \
    daemon/tx_verify.c bitcoin_witness_v0.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c
tests/test_utxo_catchup_crash_resume: $(CRASHRESUMESRCS) daemon/utxo_walk.h $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -o $@ $(CRASHRESUMESRCS) $(REORGOBJS) -lpthread

# test_utxo_catchup_shutdown -- SIGTERM during a (multi-hour) bulk catch-up
# must stop utxo_live_catchup at the next block boundary, checkpoint
# persisted, instead of being ignored until systemd's TimeoutStopSec SIGKILLs
# the worker mid-block (every stop/restart did exactly that until 2026-08-22).
SHUTDOWNSRCS := tests/test_utxo_catchup_shutdown.c daemon/utxo_live.c daemon/block_witness.c daemon/undo_log.c \
    daemon/locator_build.c daemon/node_config.c bitcoin_mempool_policy.c \
    daemon/tx_verify.c bitcoin_witness_v0.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c
tests/test_utxo_catchup_shutdown: $(SHUTDOWNSRCS) daemon/utxo_walk.h $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -o $@ $(SHUTDOWNSRCS) $(REORGOBJS) -lpthread

# test_utxo_crash_recovery -- a kill between "block N's ops hit the WAL" and
# "checkpoint N persisted" (SIGKILL/OOM/power loss; production height 318148,
# 2026-08-22) must be rolled back on the next boot from N's undo records and
# re-applied, never rejected as "already-spent". Three kill points incl. a
# forced mac_flush inside the block; key-by-key diff vs a never-crashed run.
CRASHRECSRCS := tests/test_utxo_crash_recovery.c daemon/utxo_live.c daemon/block_witness.c daemon/undo_log.c \
    daemon/locator_build.c daemon/node_config.c bitcoin_mempool_policy.c \
    daemon/tx_verify.c bitcoin_witness_v0.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c
tests/test_utxo_crash_recovery: $(CRASHRECSRCS) daemon/utxo_walk.h $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -o $@ $(CRASHRECSRCS) $(REORGOBJS) -lpthread

# test_cross_tx_verify -- correctness properties specific to the cross-
# transaction (block-wide) parallel verification redesign in daemon/
# tx_verify.c's tx_verify_block_connect_all: a valid same-block chained
# spend must accept, an in-block double-spend must reject the whole block
# (not half-apply), and a many-tx block with a poisoned tx buried mid-list
# must both genuinely exercise the block-wide worker pool and still report
# the correct failing tx.
CROSSTXSRCS := tests/test_cross_tx_verify.c daemon/utxo_live.c daemon/block_witness.c daemon/undo_log.c \
    daemon/locator_build.c daemon/node_config.c bitcoin_mempool_policy.c \
    daemon/tx_verify.c bitcoin_witness_v0.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c
tests/test_cross_tx_verify: $(CROSSTXSRCS) daemon/utxo_walk.h $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -o $@ $(CROSSTXSRCS) $(REORGOBJS) -lpthread

# test_tx_verify_bytepool_realloc -- regression test for the g_spk_pool
# dangling-pointer bug (2026-08-20, real production incident at mainnet
# height 184390): a block whose Phase 1 resolve loop makes bytepool_alloc's
# realloc() relocate mid-loop must still verify every earlier-resolved
# input's script correctly, not read corrupted/dangling memory. See the
# test file's own header comment for full root-cause detail.
BYTEPOOLSRCS := tests/test_tx_verify_bytepool_realloc.c daemon/utxo_live.c daemon/block_witness.c daemon/undo_log.c \
    daemon/locator_build.c daemon/node_config.c bitcoin_mempool_policy.c \
    daemon/tx_verify.c bitcoin_witness_v0.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c
tests/test_tx_verify_bytepool_realloc: $(BYTEPOOLSRCS) daemon/utxo_walk.h $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -o $@ $(BYTEPOOLSRCS) $(REORGOBJS) -lpthread

# daemon/build_utxo -- batch UTXO-set construction from the archive. This is
# the RIGHT tool for a from-scratch (or long-gap) UTXO rebuild: its memtable is
# CLI-sized (slots_log2/blob_gb) for batch work, so it flushes -- and therefore
# full-compacts -- orders of magnitude less often than the live daemon's
# steady-state-sized memtable. Previously built by hand, which is how it went
# stale and briefly vanished; a real target keeps it buildable and honest.
BUILDUTXOOBJS := sha256.o bitcoin_hash.o bitcoin_tx.o bitcoin_store.o \
    bitcoin_store_fast.o bitcoin_utxo_lsm.o utxo_lsm_mm.o bitcoin_utxo_store.o bitcoin_utxo.o \
    bitcoin_idxscan.o
daemon/build_utxo: daemon/build_utxo.c $(BUILDUTXOOBJS)
	$(CC) -no-pie -O2 -o $@ daemon/build_utxo.c $(BUILDUTXOOBJS)

# test_truncate_guard_prim -- store_truncate_to must REFUSE an out-of-order
# archive and leave the block data intact. Asserts on the BLOCK FILES, not
# just index.dat: the test that missed the original ~600GB loss checked only
# index counts and never opened a block, so it passed while data was deleted.
tests/test_truncate_guard_prim: tests/test_truncate_guard_prim.c bitcoin_store.o bitcoin_store_fast.o bitcoin_hash.o sha256.o bitcoin_idxscan.o
	$(CC) -no-pie -O2 -o $@ tests/test_truncate_guard_prim.c bitcoin_store.o bitcoin_store_fast.o bitcoin_hash.o sha256.o bitcoin_idxscan.o

# test_archive_check -- boot verification (-checkblocks/-checklevel), hole
# detection, and the prune budget->height conversion. Builds its own archive
# in its own scratch dir and deletes it afterwards; it must never be pointed
# at a real datadir.
tests/test_archive_check: tests/test_archive_check.c daemon/archive_verify.c bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_idxscan.o bitcoin_cons.o bitcoin_hash.o bitcoin_tx.o sha256.o $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -I daemon -o $@ tests/test_archive_check.c daemon/archive_verify.c bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_idxscan.o bitcoin_cons.o bitcoin_hash.o bitcoin_tx.o sha256.o

# test_archive_repair -- boot-time duplicate-hash self-repair
# (archive_scan_duplicates / archive_repair_duplicates): marks corrupted
# heights as holes (never truncates) so the existing catch-up hole-filler
# re-downloads them. Synthetic index.dat only; never touches a real datadir.
tests/test_archive_repair: tests/test_archive_repair.c daemon/archive_verify.c bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_idxscan.o bitcoin_cons.o bitcoin_hash.o bitcoin_tx.o sha256.o $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -I daemon -o $@ tests/test_archive_repair.c daemon/archive_verify.c bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_idxscan.o bitcoin_cons.o bitcoin_hash.o bitcoin_tx.o sha256.o

# test_archive_truncate_nonmonotonic -- store_truncate_index_only
# (bitcoin_store.asm) and archive_truncate_safe (daemon/archive_verify.c):
# truncation-from-the-tip (reorg disconnect, corruption repair) must still
# be able to make progress on a non-monotonically-laid-out archive, instead
# of refusing outright the way a bare store_truncate_to safely does.
# Synthetic archive only; never touches a real datadir.
tests/test_archive_truncate_nonmonotonic: tests/test_archive_truncate_nonmonotonic.c daemon/archive_verify.c bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_idxscan.o bitcoin_cons.o bitcoin_hash.o bitcoin_tx.o sha256.o $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -I daemon -o $@ tests/test_archive_truncate_nonmonotonic.c daemon/archive_verify.c bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_idxscan.o bitcoin_cons.o bitcoin_hash.o bitcoin_tx.o sha256.o

# test_prune_nonmonotonic -- archive_prune_file_granular (daemon/archive_verify.c)
# and the store_get_at sentinel it depends on (bitcoin_store.asm): pruning
# (reclaiming disk space from OLD block data) must still be able to make
# progress, at whole-file granularity, on a non-monotonically-laid-out
# archive, instead of refusing outright the way store_prune's in-place
# compaction safely does. Synthetic archive only; never touches a real datadir.
tests/test_prune_nonmonotonic: tests/test_prune_nonmonotonic.c daemon/archive_verify.c bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_idxscan.o bitcoin_cons.o bitcoin_hash.o bitcoin_tx.o sha256.o $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -I daemon -o $@ tests/test_prune_nonmonotonic.c daemon/archive_verify.c bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_idxscan.o bitcoin_cons.o bitcoin_hash.o bitcoin_tx.o sha256.o

# test_node_config -- bitcoin.conf parsing, Core-key compatibility, clamping,
# and the peer-sourcing lists. Hermetic (writes its own fixtures), so it runs
# in `make test`. It existed unbuilt for a day: written 2026-08-18 with no
# Makefile rule and never added to the test target, so it had never once been
# compiled while the suite reported green.
tests/test_node_config: tests/test_node_config.c daemon/node_config.c
	$(CC) -no-pie -O2 -I daemon -o $@ tests/test_node_config.c daemon/node_config.c

# test_addr_ingest -- live getaddr harvest against a REAL node. Needs a peer
# IP argument and the network, so like test_net_policy's live half it is built
# but DELIBERATELY NOT in `make test`:
#   ./tests/test_addr_ingest <peer-ip> [more...]
tests/test_addr_ingest: tests/test_addr_ingest.c daemon/addr_ingest.c daemon/net_policy.c daemon/node_config.c bitcoin_addrmgr.o bitcoin_net.o bitcoin_p2p.o bitcoin_hash.o sha256.o
	$(CC) -no-pie -O2 -I daemon -o $@ tests/test_addr_ingest.c daemon/addr_ingest.c daemon/net_policy.c daemon/node_config.c bitcoin_addrmgr.o bitcoin_net.o bitcoin_p2p.o bitcoin_hash.o sha256.o

# test_net_policy -- netgroup grouping, plus (with a peer argument) a live
# relay=0 block-relay-only handshake and feeler liveness check. The live half
# is opt-in; the netgroup half always runs.
tests/test_net_policy: tests/test_net_policy.c daemon/net_policy.c bitcoin_net.o bitcoin_p2p.o bitcoin_hash.o sha256.o
	$(CC) -no-pie -O2 -o $@ tests/test_net_policy.c daemon/net_policy.c bitcoin_net.o bitcoin_p2p.o bitcoin_hash.o sha256.o

# test_utxo_recover -- integration test for utxo_live_recover(), the in-place
# recovery that makes a failed catch-up survivable instead of terminal.
# DELIBERATELY NOT IN `make test`: it replays a real 250k-height archive
# (~3 min) and therefore needs a populated datadir, which a clean checkout
# does not have. Run it by hand against a real store:
#   make tests/test_utxo_recover && ./tests/test_utxo_recover <datadir>
# It still gets a rule so it is built/compiled-checked on demand rather than
# rotting the way daemon/build_utxo did with no target at all.
RECOVERSRCS := tests/test_utxo_recover.c daemon/utxo_live.c daemon/block_witness.c daemon/undo_log.c daemon/tx_accept.c \
    daemon/mempool_cfg.c daemon/reorg.c daemon/locator_build.c daemon/archive_verify.c \
    daemon/node_config.c bitcoin_mempool_policy.c bitcoin_txval_modern.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c daemon/tx_verify.c bitcoin_witness_v0.c bitcoin_scriptverify.c
tests/test_utxo_recover: $(RECOVERSRCS) daemon/utxo_walk.h $(DAEMONOBJS)
	$(CC) -no-pie -O2 -o $@ $(RECOVERSRCS) $(DAEMONOBJS) -lpthread

# test_dial_budget -- regression test for the outbound_connect dial-budget hang
# (download worker wedged in a peer read() for 60+ min, 2026-08-18). It forks
# its own trickling fake peer, so it needs no external helper or network.
# outbound_connect is static in daemon/main.c, so the test #includes that TU
# directly (renaming its main) and therefore links the same objects the daemon
# does, minus daemon/main.c itself (it comes in via the #include).
DIALSRCS := tests/test_dial_budget.c daemon/utxo_live.c daemon/block_witness.c daemon/tx_accept.c daemon/mempool_cfg.c \
    daemon/upload_cap.c daemon/reorg.c daemon/undo_log.c daemon/locator_build.c \
    daemon/archive_verify.c daemon/addr_ingest.c daemon/net_policy.c daemon/node_config.c \
    bitcoin_mempool_policy.c bitcoin_txval_modern.c bitcoin_segwit.c bitcoin_taproot_sighash.c \
    daemon/tx_verify.c bitcoin_witness_v0.c bitcoin_scriptverify.c
tests/test_dial_budget: $(DIALSRCS) daemon/main.c daemon/reorg.h daemon/utxo_walk.h $(DAEMONOBJS) $(DAEMON_RPCOBJS) $(VERSION_GEN_H)
	$(CC) -no-pie -O2 -o $@ $(DIALSRCS) $(DAEMONOBJS) $(DAEMON_RPCOBJS) wallet_core.c -lpthread

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
# DAEMONOBJS is defined at the top of this file -- see the "expanded when read" note there.

tests/test_bitcoind: tests/test_bitcoind.c $(SERVETXVALSRCS) $(DAEMONOBJS) $(VERSION_GEN_H)
	$(CC) $(CFLAGS) -o $@ tests/test_bitcoind.c $(SERVETXVALSRCS) $(DAEMONOBJS)

# Full IBD client (node_sync): handshake + headers + getdata + validate + store.
# Built at -O0: the deep asm hash call chain (node_sync -> cons_verify ->
# pow_check -> block_hash -> sha256d -> sha256_full) provably works at -O0, but
# gcc -O2's main register/stack layout triggers a latent sha256_full deep-frame-
# overlap crash in this specific networked harness. The asm is identical.
tests/test_bitcoind_sync: tests/test_bitcoind_sync.c $(SERVETXVALSRCS) $(DAEMONOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_bitcoind_sync.c $(SERVETXVALSRCS) $(DAEMONOBJS)

# all-asm leveled logger (uses fd_write_all from bitcoin_net.asm)
# Built at -O0: same gcc -O2 vs deep-asm-call-chain interaction as the sync
# harness; the asm logger is identical and correct at -O0.
LOGOBJS := node_log.o bitcoin_net.o bitcoin_hash.o sha256.o
tests/test_log: tests/test_log.c $(LOGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_log.c $(LOGOBJS)

# S6 CLI (bitcoin_cli.asm): queries the store + hashing/tx primitives.
CLIOBJS := sha256.o bitcoin_hash.o bitcoin_tx.o bitcoin_store.o \
    bitcoin_cli.o
tests/test_cli: tests/test_cli.c $(CLIOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_cli.c $(CLIOBJS)

# Persistent header-chain store (bitcoin_headers.asm): appends a (header, block_hash)
# pair per entry; the harness checks continuity by computing block_hash of chain
# predecessors via the proven block_hash asm.
HEADOBJS := sha256.o bitcoin_hash.o bitcoin_headers.o
tests/test_headers: tests/test_headers.c $(HEADOBJS) $(TEST_TMPDIR_H)
	$(CC) $(CFLAGS) -o $@ tests/test_headers.c $(HEADOBJS)

# Paged persistent headers-first IBD (bitcoind.asm node_ibd_headers) over the
# asm header store. Built at -O0: same gcc -O2 vs deep-asm-call-chain interaction
# as the bitcoind sync harness; the asm is identical and correct at -O0.
# bitcoind.o bundles node_sync/node_serve_block/node_drain which reference the
# cons/store/tx symbols, so link the full DAEMONOBJS superset.
IBDOBJS := sha256.o bitcoin_hash.o bitcoin_net.o bitcoin_p2p.o \
    bitcoin_tx.o bitcoin_cons.o bitcoin_store.o bitcoind.o \
    bitcoin_headers.o bitcoin_idxscan.o
tests/test_ibd_headers: tests/test_ibd_headers.c $(IBDOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_ibd_headers.c $(IBDOBJS)

# Block-body download off the persisted header chain (bitcoind.asm node_ibd_blocks).
# node_ibd_blocks calls cons_verify/block_hash/store_append/hst_*; bitcoind.o pulls
# the transitive cons/tx symbols too. Built at -O0 (deep-asm-call-chain convention).
tests/test_ibd_blocks: tests/test_ibd_blocks.c $(IBDOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_ibd_blocks.c $(IBDOBJS)

# FULL initial-block-download as one asm pass (bitcoind.asm node_ibd =
# node_ibd_headers + node_ibd_blocks) over a whole NB-block loopback chain.
tests/test_ibd_full: tests/test_ibd_full.c $(IBDOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_ibd_full.c $(IBDOBJS)

# LARGE-SCALE full-IBD demo (default NB=20000; slow, heavy manual test, NOT in
# the `test` target). Same IBDOBJS link set as test_ibd_full. Brought under the
# Makefile so `make tests/test_ibd_scale` always relinks against CURRENT objects
# (previously it was built by hand and rotted stale, failing spuriously).
tests/test_ibd_scale: tests/test_ibd_scale.c $(IBDOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_ibd_scale.c $(IBDOBJS)

# bitcoin_addrmgr.asm: peer address book + addr v1 codec (standalone deps).
ADMRGOBJS := bitcoin_addrmgr.o
tests/test_addrmgr: tests/test_addrmgr.c $(ADMRGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_addrmgr.c $(ADMRGOBJS)

# bitcoin_keys.asm (secp256k1 pubkey derivation for wallet/BIP32).
KEYSOBJS := secp256k1_fe.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_scalar.o \
    secp256k1_scalar_c.o bitcoin_keys.o
tests/test_keys: tests/test_keys.c $(KEYSOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_keys.c $(KEYSOBJS)

# bitcoin_idx.asm: O(1) hash->height index for serving (standalone deps).
# IDXOBJS is defined at the top of this file -- see the "expanded when read" note there.
tests/test_idx: tests/test_idx.c $(IDXOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_idx.c $(IDXOBJS)

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
    bitcoin_utxo_lsm.o utxo_lsm_mm.o bitcoin_utxo_store.o bitcoin_utxo.o secp256k1_schnorr.o \
    secp256k1_taproot.o bitcoin_script.o bitcoin_sighash.o bitcoin_pubkey.o \
    secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o \
    secp256k1_scalar.o secp256k1_scalar_c.o ripemd160.o bitcoin_addr.o \
    bitcoin_interp.o bitcoin_scriptcodec.o sha1.o
# SERVETXVALSRCS is defined at the top of this file -- see the "expanded when read" note there.
tests/test_serve: tests/test_serve.c $(SERVETXVALSRCS) $(SERVEOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_serve.c $(SERVETXVALSRCS) $(SERVEOBJS)

# test_keepup: proves the inbound `block` keep-up path (.do_block) -- a peer
# pushes a block the server lacks; the server validates, stores, and indexes
# it so it becomes serveable, and survives duplicate pushes. Uses SERVEOBJS
# (needs cons_verify/store_append/idx_put from the listed objects).
tests/test_keepup: tests/test_keepup.c $(SERVETXVALSRCS) $(SERVEOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_keepup.c $(SERVETXVALSRCS) $(SERVEOBJS)

# BIP152 compact-block serving loopback e2e (sendcmpct/getblocktxn/cmpctblock).
tests/test_bip152_loop: tests/test_bip152_loop.c $(SERVETXVALSRCS) $(SERVEOBJS) tests/block_vec.h tests/cmpct_expected.h $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_bip152_loop.c $(SERVETXVALSRCS) $(SERVEOBJS)

# sendheaders (BIP130) + feefilter: announce_tip inv-vs-headers wire bytes +
# forked serve-loop outbound feefilter & negotiation parsing (loopback e2e).
tests/test_sendheaders_fee: tests/test_sendheaders_fee.c $(SERVETXVALSRCS) $(SERVEOBJS) tests/block_vec.h $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_sendheaders_fee.c $(SERVETXVALSRCS) $(SERVEOBJS)

# OUTBOUND P2P MULTIPLEXER loopback e2e: exec's the REAL daemon in serve-test
# mode (poll-multiplexed outbound node_sync + inbound serving), a mining-peer
# child that grows its chain, and an inbound client that fetches the freshly
# mined block -- proving the running node pulls+stores+serves new blocks with
# no restart. Links the server object set for the client/peer roles.
tests/test_outbound_mux: tests/test_outbound_mux.c daemon/bitcoind $(SERVETXVALSRCS) $(SERVEOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_outbound_mux.c $(SERVETXVALSRCS) $(SERVEOBJS)

# OUTBOUND MUX RE-DIAL e2e: regression for soak-defect D2 -- proves the mux
# re-dials a leg the peer rips down (POLLHUP) and recovers keep-up via a fresh
# connection to a rotated peer, instead of syncing on a dead socket forever.
tests/test_redial: tests/test_redial.c daemon/bitcoind $(SERVETXVALSRCS) $(SERVEOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_redial.c $(SERVETXVALSRCS) $(SERVEOBJS)

# OUTBOUND MUX SOAK HARNESS controlled mining peer: real process that serves the
# node_sync protocol from a GROWING chain (mines a block every N seconds) for
# unattended 24h+ soak runs; also periodically re-connects inbound to prove the
# node serves while downloading. Link set = SERVEOBJS (same as test_outbound_mux).
tests/soak_mux_peer: tests/soak_mux_peer.c $(SERVETXVALSRCS) $(SERVEOBJS)
	$(CC) -no-pie -O2 -o $@ tests/soak_mux_peer.c $(SERVETXVALSRCS) $(SERVEOBJS)

# SHA-512 (FIPS 180-4, wallet/BIP32+bech32 foundation).
tests/test_sha512: tests/test_sha512.c sha512.o
	$(CC) -no-pie -O2 -o $@ tests/test_sha512.c sha512.o

# HMAC-SHA512 (RFC 4231 / RFC 2104, BIP32+BIP39 primitive, on asm SHA-512).
HMACOBJS := sha512.o bitcoin_hmac.o
tests/test_hmac: tests/test_hmac.c $(HMACOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_hmac.c $(HMACOBJS)

# bitcoin_bip32.asm (BIP32 master + CKDpriv + full-path + extkey/fingerprint;
# secp256k1 + HMAC + SHA-512 + base58/hash160). bitcoin_bip32.o's fingerprint
# references hash160/base58check from bitcoin_addr.o, so those deps are here.
BIP32OBJS := bitcoin_bip32.o bitcoin_hmac.o sha512.o bitcoin_keys.o \
    secp256k1_fe.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_scalar.o \
    secp256k1_scalar_c.o bitcoin_addr.o sha256.o bitcoin_hash.o \
    ripemd160.o
tests/test_bip32_master: tests/test_bip32_master.c $(BIP32OBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_bip32_master.c $(BIP32OBJS)
tests/test_bip32_chain: tests/test_bip32_chain.c $(BIP32OBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_bip32_chain.c $(BIP32OBJS)

# BIP32 full-path derivation + extended key (xprv/xpub): derive_path +
# fingerprint + 78-byte serialize (all bitcoin_bip32.asm) + base58check/hash160
# (bitcoin_addr.asm). Same object set as the other bip32 tests.
EXTKEYOBJS := $(BIP32OBJS)
tests/test_bip32_extkey: tests/test_bip32_extkey.c tests/bip32_extkey_vec.h $(EXTKEYOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_bip32_extkey.c $(EXTKEYOBJS)

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
	$(CC) -no-pie -O2 -o $@ tests/test_bip39.c $(BIP39OBJS)

# regenerate the BIP39 vectors from the independent Python oracle
tests/bip39_vec.h: validation/gen_bip39_vectors.py
	python3 validation/gen_bip39_vectors.py > tests/bip39_vec.h

# ripemd160.asm (HASH160 half; needed for P2PKH address generation).
tests/test_ripemd160: tests/test_ripemd160.c ripemd160.o
	$(CC) -no-pie -O2 -o $@ tests/test_ripemd160.c ripemd160.o

tests/test_ripemd160_thread_stress: tests/test_ripemd160_thread_stress.c ripemd160.o
	$(CC) -no-pie -O2 -o $@ tests/test_ripemd160_thread_stress.c ripemd160.o -lpthread

# bitcoin_addr.asm (hash160 = RIPEMD160(SHA256), base58check P2PKH addresses).
ADDROBJS := bitcoin_addr.o sha256.o bitcoin_hash.o ripemd160.o
tests/test_addr: tests/test_addr.c $(ADDROBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_addr.c $(ADDROBJS)

# bech32.asm (BIP173) / bech32m (BIP350) address codec: polymod checksum,
# convert_bits + encode/decode, verified against the authoritative BIP173
# and BIP350 vectors plus real mainnet segwit (P2WPKH/P2WSH/P2TR) addresses.
BECH32OBJS := bech32.o
tests/test_bech32: tests/test_bech32.c $(BECH32OBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_bech32.c $(BECH32OBJS)

MEMPOOLOBJS := bitcoin_mempool.o
tests/test_mempool: tests/test_mempool.c $(MEMPOOLOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_mempool.c $(MEMPOOLOBJS)

# Mempool POLICY layer (bitcoin_mempool_policy.c -- pure C glue over the asm
# mempool + asm UTXO): fee/relay floor, double-spend, BIP125 RBF, ancestor/
# descendant limits, fee estimator. Vectors generated by an independent Python
# oracle (tests/gen_mempool_policy_vectors.py -> tests/mempool_policy_vec.h).
POLICYOBJS := bitcoin_mempool.o bitcoin_utxo.o
tests/test_mempool_policy: tests/test_mempool_policy.c tests/mempool_policy_vec.h bitcoin_mempool_policy.c $(POLICYOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_mempool_policy.c bitcoin_mempool_policy.c $(POLICYOBJS)

# regenerate the policy vectors from the independent Python oracle
tests/mempool_policy_vec.h: tests/gen_mempool_policy_vectors.py
	cd tests && python3 gen_mempool_policy_vectors.py

TXIDOBJS := sha256.o bitcoin_hash.o bitcoin_tx.o
tests/test_txtxid: tests/test_txtxid.c $(TXIDOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_txtxid.c $(TXIDOBJS)

# secp256k1 public-key parsing/decompression (affine-limb recovery for ecdsa_verify).
PUBKEYOBJS := bitcoin_pubkey.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o
tests/test_pubkey: tests/test_pubkey.c $(PUBKEYOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_pubkey.c $(PUBKEYOBJS)

# legacy SIGHASH_ALL preimage builder (tx signature digest).
SIGHASHOBJS := bitcoin_sighash.o sha256.o bitcoin_hash.o
tests/test_sighash: tests/test_sighash.c $(SIGHASHOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_sighash.c $(SIGHASHOBJS)

# legacy sighash source-bounds regression: a tx whose scriptSig length varint
# overruns the buffer must be REJECTED (not an OOB source read / SIGSEGV).
tests/test_sighash_oob: tests/test_sighash_oob.c $(SIGHASHOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_sighash_oob.c $(SIGHASHOBJS)

# legacy_sighash (Stage B: full ALL/NONE/SINGLE x ANYONECANPAY + CODESEPARATOR
# strip) against Bitcoin Core's own 500 official sighash.json vectors.
tests/test_legacy_sighash: tests/test_legacy_sighash.c tests/sighash_vec.h $(SIGHASHOBJS)
	$(CC) -no-pie -O2 -I tests -o $@ tests/test_legacy_sighash.c $(SIGHASHOBJS)

# script_flags_for_block (Stage C: activation-height flag schedule), against
# vectors re-derived independently from Core's chainparams.cpp.
tests/test_script_flags: tests/test_script_flags.c tests/flags_vec.h bitcoin_script_flags.o
	$(CC) -no-pie -O2 -I. -I tests -o $@ tests/test_script_flags.c bitcoin_script_flags.o

# script_find_and_delete / script_op_len / script_push_encode against Core's
# own FindAndDelete unit-test cases (transcribed from script_tests.cpp).
tests/test_find_and_delete: tests/test_find_and_delete.c $(SIGHASHOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_find_and_delete.c $(SIGHASHOBJS)

# script layer: DER sig parsing + full P2PKH verification.
SCRIPTOBJS := bitcoin_script.o bitcoin_sighash.o bitcoin_pubkey.o secp256k1_fe.o \
    secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o \
    secp256k1_point_ct.o bitcoin_hash.o sha256.o
tests/test_script: tests/test_script.c $(SCRIPTOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_script.c $(SCRIPTOBJS)

# end-to-end P2PKH spend validation (same object set).
tests/test_p2pkh: tests/test_p2pkh.c $(SCRIPTOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_p2pkh.c $(SCRIPTOBJS)

# UTXO set (unspent txout store for spend validation).
UTXOOBJS := bitcoin_utxo.o
tests/test_utxo: tests/test_utxo.c $(UTXOOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_utxo.c $(UTXOOBJS)

tests/test_utxo_prefetch_race: tests/test_utxo_prefetch_race.c $(UTXOOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_utxo_prefetch_race.c $(UTXOOBJS) -lpthread

# PERSISTENT UTXO store (append-only WAL utxo.dat + checkpoint index utxo.idx +
# restart-resume reload), mirroring bitcoin_store.asm's store/index pattern.
# bitcoin_utxo_store.asm wraps bitcoin_utxo.asm's in-memory table.
UTXOSTOREOBJS := bitcoin_utxo_store.o bitcoin_utxo.o
tests/test_utxo_store: tests/test_utxo_store.c $(UTXOSTOREOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_utxo_store.c $(UTXOSTOREOBJS)

# LSM-tree UTXO store (bounded memtable + per-generation WAL + sorted
# immutable run files), Phase 1: replaces the giant-pre-sized-table
# approach above for full-archive replay to fix write amplification.
# NOT wired into DAEMONOBJS -- Phase 2 (compaction) is a hard gate before
# any live-daemon use; today's only real caller is daemon/build_utxo.c.
# UTXOLSMOBJS is defined at the top of this file -- see the "expanded when read" note there.

# PERF_SCOPE.md 4.1: the mmap fast path must be indistinguishable from the
# asm path it short-circuits -- differential + concurrency, incl. the
# stale-value shape that caught e12dcbb.
tests/bench_lsm_get: tests/bench_lsm_get.c $(UTXOLSMOBJS)
	$(CC) $(CFLAGS) -o $@ tests/bench_lsm_get.c $(UTXOLSMOBJS)

tests/test_lsm_mmap_diff: tests/test_lsm_mmap_diff.c $(UTXOLSMOBJS) $(TEST_TMPDIR_H)
	$(CC) $(CFLAGS) -o $@ tests/test_lsm_mmap_diff.c $(UTXOLSMOBJS) -lpthread
tests/test_lsm_bloomsat: tests/test_lsm_bloomsat.c $(UTXOLSMOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_lsm_bloomsat.c $(UTXOLSMOBJS) -lpthread
tests/diff_real_run: tests/diff_real_run.c $(UTXOLSMOBJS)
	$(CC) $(CFLAGS) -o $@ tests/diff_real_run.c $(UTXOLSMOBJS) -lpthread
tests/test_lsm_sparse_diff: tests/test_lsm_sparse_diff.c $(UTXOLSMOBJS) $(TEST_TMPDIR_H)
	$(CC) $(CFLAGS) -o $@ tests/test_lsm_sparse_diff.c $(UTXOLSMOBJS) -lpthread
tests/soak_lsm_mm: tests/soak_lsm_mm.c $(UTXOLSMOBJS) $(TEST_TMPDIR_H)
	$(CC) $(CFLAGS) -o $@ tests/soak_lsm_mm.c $(UTXOLSMOBJS) -lpthread
# utxo_get / utxo_del must TERMINATE on a full table. Against unbounded probes
# this test HANGS rather than fails, so it forks each probe under alarm() --
# see the file header and LOG.md.
tests/test_utxo_probe_bound: tests/test_utxo_probe_bound.c bitcoin_utxo.o bitcoin_hash.o sha256.o
	$(CC) -no-pie -O2 -Wall -o $@ tests/test_utxo_probe_bound.c bitcoin_utxo.o bitcoin_hash.o sha256.o

tests/test_utxo_lsm: tests/test_utxo_lsm.c $(UTXOLSMOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_utxo_lsm.c $(UTXOLSMOBJS)

# test_utxo_live_count -- utxo_lsm_count() must be EXACT and survive restarts
# (the negative live_utxo telemetry bug): persist/restore total_live in the
# manifest, plus the one-time old-format recount. See the test's own header.
tests/test_utxo_live_count: tests/test_utxo_live_count.c $(UTXOLSMOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_utxo_live_count.c $(UTXOLSMOBJS)

# ---- UTXO set hash / gettxoutsetinfo (ASSESSMENT.md 4, FEATURE_GAPS.md) ----
# MuHash3072, byte-compatible with Core's, plus the per-coin filter and
# serialization that turn our LSM set into a figure comparable with
# `gettxoutsetinfo`. bitcoin_muhash.o needs sha256.o (SHA256 both as the
# ChaCha20 key derivation and as the final digest).
UTXOSTATSOBJS := bitcoin_utxo_stats.o bitcoin_muhash.o sha256.o

# The vectors are GENERATED from Core's own muhash.cpp/chacha20.cpp and
# committed, so `make test` needs no Core build tree; regenerate with
# `python3 validation/gen_muhash_vectors.py --out tests/muhash_vectors.h`
# after a Core upgrade. Not a Makefile rule on purpose: a rule would silently
# regenerate (or fail) on a machine with no Core checkout, and these are
# ground truth, not build output.
tests/test_muhash: tests/test_muhash.c tests/muhash_vectors.h $(UTXOSTATSOBJS)
	$(CC) $(CFLAGS) -Itests -o $@ tests/test_muhash.c $(UTXOSTATSOBJS)

tests/test_utxo_setinfo: tests/test_utxo_setinfo.c $(UTXOLSMOBJS) $(UTXOSTATSOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Itests -o $@ tests/test_utxo_setinfo.c $(UTXOLSMOBJS) $(UTXOSTATSOBJS)

daemon/utxo_setinfo: daemon/utxo_setinfo.c $(UTXOLSMOBJS) $(UTXOSTATSOBJS)
	$(CC) $(CFLAGS) -o $@ daemon/utxo_setinfo.c $(UTXOLSMOBJS) $(UTXOSTATSOBJS)

# Regression test for the 2026-08-20 compaction manifest-ordering bug (see
# tests/test_compact_manifest_order.c's own header) -- needs manifest_n to
# exceed COMPACT_MAX_RUNS(64) before compacting, which no other test does.
tests/test_compact_manifest_order: tests/test_compact_manifest_order.c $(UTXOLSMOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_compact_manifest_order.c $(UTXOLSMOBJS)

# Whole-transaction validator (test_txval.c): tx_parse + UTXO store +
# P2PKH spend verification (verify_p2pkh + its sighash/pubkey/ecdsa chain).
TXVALOBJS := bitcoin_utxo.o bitcoin_tx.o bitcoin_script.o bitcoin_sighash.o \
    bitcoin_pubkey.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o \
    secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o bitcoin_hash.o \
    sha256.o
tests/test_txval: tests/test_txval.c tests/txval_vec.h $(TXVALOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_txval.c $(TXVALOBJS)

# LIVE-WIRE end-to-end sighash test: builds a real P2PKH tx, signs it by
# invoking the ACTUAL daemon/wallet_cli binary (legacy SIGHASH_ALL), then
# validates the CLI-signed tx with the whole-transaction validator
# (tx_parse + UTXO + verify_p2pkh + fee). Ties the wallet signer and the
# validator together across a real process boundary instead of isolated
# pre-generated vectors. Requires bitcoin_keys/bitcoin_addr (for the prevout
# P2PKH script) on top of the validator set.
E2EOBJS := $(TXVALOBJS) bitcoin_keys.o bitcoin_addr.o ripemd160.o
tests/test_e2e_sighash: tests/test_e2e_sighash.c daemon/wallet_cli $(E2EOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_e2e_sighash.c $(E2EOBJS)

# "send" (createrawtx + sign-all-inputs) end-to-end: wallet_core.c builds the
# tx with the verified asm crypto (sighash/ecdsa/scalar/point/field from
# WALLETPRIMS), and the harness validates the signed tx with the
# whole-transaction validator (tx_parse + UTXO + verify_p2pkh from TXVALOBJS).
SENDOBJS = $(WALLETPRIMS) bitcoin_tx.o bitcoin_script.o
tests/test_send: tests/test_send.c wallet_core.c $(SENDOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_send.c wallet_core.c $(SENDOBJS)

# Wallet-core/RPC address surface (getnewaddress/getrawchangeaddress +
# getaddressinfo/validateaddress). wallet_core.c + WALLETPRIMS + bech32.o
# (bech32 codec for P2WPKH encode and decode).
WRPCADDR = $(WALLETPRIMS)
tests/test_wrpc_addr: tests/test_wrpc_addr.c wallet_core.c $(WRPCADDR)
	$(CC) -no-pie -O2 -o $@ tests/test_wrpc_addr.c wallet_core.c $(WRPCADDR)

# Wallet-core/RPC UTXO-query surface (gettxout + listunspent). wallet core
# (which includes bitcoin_utxo via WALLETPRIMS).
tests/test_wrpc_utxo: tests/test_wrpc_utxo.c wallet_core.c $(WALLETPRIMS)
	$(CC) -no-pie -O2 -o $@ tests/test_wrpc_utxo.c wallet_core.c $(WALLETPRIMS)

# Wallet-core/RPC decoderawtransaction. Builds a signed tx via wallet_send_tx
# then decodes it.
tests/test_wrpc_decoderaw: tests/test_wrpc_decoderaw.c wallet_core.c $(WALLETPRIMS)
	$(CC) -no-pie -O2 -o $@ tests/test_wrpc_decoderaw.c wallet_core.c $(WALLETPRIMS)

# Wallet-core/RPC signrawtransactionwithkey. wallet core + tx/script for the
# whole-tx validator.
tests/test_wrpc_sign: tests/test_wrpc_sign.c wallet_core.c $(WALLETPRIMS) bitcoin_tx.o bitcoin_script.o
	$(CC) -no-pie -O2 -o $@ tests/test_wrpc_sign.c wallet_core.c $(WALLETPRIMS) bitcoin_tx.o bitcoin_script.o

# Wallet-core/RPC sendtoaddress + getbalance (card 5 capstone). wallet core +
# tx/script for the validator.
tests/test_wrpc_send: tests/test_wrpc_send.c wallet_core.c $(WALLETPRIMS) bitcoin_tx.o bitcoin_script.o
	$(CC) -no-pie -O2 -o $@ tests/test_wrpc_send.c wallet_core.c $(WALLETPRIMS) bitcoin_tx.o bitcoin_script.o

# P2SH / multisig: p2sh_hash (RIPEMD160 of SHA256 of redeem script) +
# OP_CHECKMULTISIG verification over the existing sighash/pubkey/ecdsa chain.
MULTISIGOBJS := bitcoin_multisig.o bitcoin_script.o bitcoin_sighash.o bitcoin_pubkey.o \
    secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_ecdsa.o \
    secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o bitcoin_hash.o sha256.o \
    ripemd160.o
tests/test_multisig: tests/test_multisig.c $(MULTISIGOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_multisig.c $(MULTISIGOBJS)

# Script-level P2SH / BIP16 VerifyScript (bitcoin_verify.c): reuses the same
# sighash/pubkey/ecdsa/ripemd160 object set as test_multisig, plus the full
# C VerifyScript (two-pass + P2SH sub-script execution + CheckMultisig).
VERIFYOBJS := bitcoin_verify.c bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o \
    secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_ecdsa.o \
    secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o bitcoin_hash.o sha256.o \
    ripemd160.o
tests/verify_p2sh_shim: tests/verify_p2sh_shim.c $(VERIFYOBJS)
	$(CC) -no-pie -O2 -o $@ tests/verify_p2sh_shim.c $(VERIFYOBJS)
tests/test_verify_p2sh: tests/test_verify_p2sh.c $(VERIFYOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_verify_p2sh.c $(VERIFYOBJS)

# Full script interpreter harnesses (bitcoin_interp.asm + codec + hashing).
tests/smoke_interp: tests/smoke_interp.c $(INTERPOBJS) bitcoin_sighash.o
	$(CC) -no-pie -O2 -o $@ tests/smoke_interp.c $(INTERPOBJS) bitcoin_sighash.o
tests/test_interp: tests/test_interp.c $(INTERPOBJS) bitcoin_sighash.o
	$(CC) -no-pie -O2 -o $@ tests/test_interp.c $(INTERPOBJS) bitcoin_sighash.o
# test_stack_push_len -- regression test for the stack_push length-register
# crash (2026-08-20, real production incident): five opcodes (TOALTSTACK,
# FROMALTSTACK, 2ROT, ROLL, TUCK) read a scratch element's length via a
# 64-bit load, corrupting stack_push's byte count. Each case runs in a
# forked child since the pre-fix bug SIGSEGVs, not just returns an error.
tests/test_stack_push_len: tests/test_stack_push_len.c $(INTERPOBJS) bitcoin_sighash.o
	$(CC) -no-pie -O2 -o $@ tests/test_stack_push_len.c $(INTERPOBJS) bitcoin_sighash.o
# test_scriptverify_parity -- the asm-driven VerifyScript must agree with the
# C reference, verdict AND ScriptError code, on the genuine P2SH vectors.
# Those vectors are already differentially validated against Core, so
# agreement here is agreement with Core transitively.
tests/test_scriptverify_parity: tests/test_scriptverify_parity.c bitcoin_scriptverify.c bitcoin_verify.c bitcoin_segwit.c bitcoin_addr.o script_error_codes.h $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o
	$(CC) -no-pie -O2 -I. -I tests -o $@ tests/test_scriptverify_parity.c bitcoin_scriptverify.c bitcoin_verify.c bitcoin_segwit.c bitcoin_addr.o $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o

# test_scriptverify_thread_stress -- many pthreads hammering sv_verify_script
# concurrently, proving the 2026-08-19 TLS conversion (bitcoin_scriptverify.c
# static->__thread + bitcoin_interp.asm/bitcoin_sighash.asm .bss->.tbss) is
# actually thread-safe, not just single-thread-correct.
tests/test_scriptverify_thread_stress: tests/test_scriptverify_thread_stress.c bitcoin_scriptverify.c script_error_codes.h $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o
	$(CC) -no-pie -O2 -I. -I tests -o $@ tests/test_scriptverify_thread_stress.c bitcoin_scriptverify.c $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o -lpthread

# real-mainnet OP_NOP1/NOP4..NOP10-treated-as-bad-opcode regression (the
# exact height-212613 spend that stopped the live daemon's UTXO catch-up).
tests/test_nop1_regression: tests/test_nop1_regression.c bitcoin_scriptverify.c script_error_codes.h $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o bitcoin_script_flags.o
	$(CC) -no-pie -O2 -I. -I tests -o $@ tests/test_nop1_regression.c bitcoin_scriptverify.c $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o bitcoin_script_flags.o

# real-mainnet CHECKMULTISIG scriptCode regression (height ~290328/290329):
# a signature's own bytes reused as a decoy pubkey slot must be stripped
# from scriptCode for EVERY signature check in the multisig, not just while
# checking that one signature.
tests/test_checkmultisig_findanddelete: tests/test_checkmultisig_findanddelete.c bitcoin_scriptverify.c script_error_codes.h $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o bitcoin_script_flags.o
	$(CC) -no-pie -O2 -I. -I tests -o $@ tests/test_checkmultisig_findanddelete.c bitcoin_scriptverify.c $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o bitcoin_script_flags.o

# real-mainnet CHECKMULTISIG nKeys=0 regression (height 299916): a bare
# OP_CHECKMULTISIG run via P2SH against zero keys/zero sigs is a legitimate
# degenerate case Core accepts (only nKeys<0 is rejected), not a
# SCRIPT_ERR_PUBKEY_COUNT failure.
tests/test_checkmultisig_zero_keys: tests/test_checkmultisig_zero_keys.c bitcoin_scriptverify.c script_error_codes.h $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o bitcoin_script_flags.o
	$(CC) -no-pie -O2 -I. -I tests -o $@ tests/test_checkmultisig_zero_keys.c bitcoin_scriptverify.c $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o bitcoin_script_flags.o

# real-mainnet CHECKMULTISIGVERIFY regression (height 324663): the VERIFY
# variant never popped-and-checked interp_checkmultisig's bool result, so it
# silently degraded to plain CHECKMULTISIG and left a stray bool on the
# stack, corrupting a chained second multisig check.
tests/test_checkmultisigverify_pop: tests/test_checkmultisigverify_pop.c bitcoin_scriptverify.c script_error_codes.h $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o bitcoin_script_flags.o
	$(CC) -no-pie -O2 -I. -I tests -o $@ tests/test_checkmultisigverify_pop.c bitcoin_scriptverify.c $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o bitcoin_script_flags.o

# real-mainnet sv_push_only off-by-one regression (height 349617): the
# direct-push opcode boundary excluded 0x4b (75) itself, so a scriptSig
# push of exactly 75 bytes desynced the push-only scan and was wrongly
# rejected as SCRIPT_ERR_SIG_PUSHONLY.
tests/test_sig_pushonly_75: tests/test_sig_pushonly_75.c bitcoin_scriptverify.c script_error_codes.h $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o bitcoin_script_flags.o
	$(CC) -no-pie -O2 -I. -I tests -o $@ tests/test_sig_pushonly_75.c bitcoin_scriptverify.c $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o bitcoin_script_flags.o

# real-mainnet CHECKLOCKTIMEVERIFY/CHECKSEQUENCEVERIFY regression (height
# 388431, right at BIP65 activation): op_cltv/op_csv were unconditional
# stubs ("no tx context in pure interpreter -> unsatisfied") that rejected
# every CLTV/CSV-locked spend on the whole chain. Now implements Core's real
# CheckLockTime/CheckSequence against tx.nVersion/nLockTime and the
# spending input's nSequence, threaded in via sv_get_locktime_context.
tests/test_cltv_csv: tests/test_cltv_csv.c bitcoin_scriptverify.c script_error_codes.h $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o bitcoin_script_flags.o
	$(CC) -no-pie -O2 -I. -I tests -o $@ tests/test_cltv_csv.c bitcoin_scriptverify.c $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o bitcoin_script_flags.o

# Stage B end-to-end: genuine SIGHASH_NONE/SINGLE/ANYONECANPAY spends through
# the real interpreter (sv_verify_script), each with a tamper of a field the
# hashtype ignores (must still accept) and one it binds (must reject).
tests/test_hashtype_e2e: tests/test_hashtype_e2e.c tests/hashtype_vec.h bitcoin_scriptverify.c script_error_codes.h $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o
	$(CC) -no-pie -O2 -I. -I tests -o $@ tests/test_hashtype_e2e.c bitcoin_scriptverify.c $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o

# -I. so the test picks up the GENERATED script_error_codes.h instead of
# carrying its own copy of the interpreter's error numbering.
tests/test_tapscript_interp: tests/test_tapscript_interp.c script_error_codes.h $(INTERPOBJS) bitcoin_sighash.o
	$(CC) -no-pie -O2 -I. -o $@ tests/test_tapscript_interp.c $(INTERPOBJS) bitcoin_sighash.o
tests/test_interp_legacy_spend: tests/test_interp_legacy_spend.c wallet_core.c bitcoin_interp.o bitcoin_scriptcodec.o bitcoin_script.o sha1.o $(WALLETPRIMS)
	$(CC) -no-pie -O2 -o $@ tests/test_interp_legacy_spend.c wallet_core.c bitcoin_interp.o bitcoin_scriptcodec.o bitcoin_script.o sha1.o $(WALLETPRIMS)
tests/run_batch: tests/run_batch.c $(INTERPOBJS) bitcoin_sighash.o
	$(CC) -no-pie -O2 -o $@ tests/run_batch.c $(INTERPOBJS) bitcoin_sighash.o

# Consensus differential shim (consensus_diff.py): exposes cons_verify /
# block_hash / pow_check / diff_target / tx_parse / tx_txid over stdin so a
# Python oracle can feed the same REAL mainnet block/tx bytes to both this
# asm node and Bitcoin Core and compare verdicts byte-for-byte.
tests/consensus_shim: tests/consensus_shim.c $(CONSOBJS) bitcoin_sigops.o bitcoin_scriptcodec.o
	$(CC) -no-pie -O2 -o $@ tests/consensus_shim.c $(CONSOBJS) bitcoin_sigops.o bitcoin_scriptcodec.o

# Full-chain batch differential shim (fullchain_diff.py): same asm objects as
# consensus_shim, non-interactive batch protocol (len-prefixed frames in, one
# compact verdict line per block out) for chewing tens of thousands of blocks
# per process without per-block launch overhead.
tests/fullchain_shim: tests/fullchain_shim.c $(CONSOBJS)
	$(CC) -no-pie -O2 -o $@ tests/fullchain_shim.c $(CONSOBJS)

# Chain-context BIP30 differential shim (bip30_diff.py): maintains a persistent
# UTXO view (bitcoin_utxo.asm) across CONNECT calls and runs Core's ConnectBlock
# BIP30 duplicate-txid gate (validation.cpp, fEnforceBIP30 / IsBIP30Repeat).
tests/bip30_shim: tests/bip30_shim.c $(CONSOBJS) bitcoin_utxo.o
	$(CC) -no-pie -O2 -o $@ tests/bip30_shim.c $(CONSOBJS) bitcoin_utxo.o

# The same CONNECT protocol, driven into daemon/utxo_live.c instead of into a
# reimplementation of BIP30. See the file header and LOG.md incident #30 --
# tests/bip30_shim above contains the rule itself, so the differential that
# drove it validated the shim, not bitcoind.
tests/bip30_daemon_shim: tests/bip30_daemon_shim.c daemon/utxo_live.c daemon/block_witness.c daemon/undo_log.c daemon/node_config.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -o $@ tests/bip30_daemon_shim.c daemon/utxo_live.c daemon/block_witness.c daemon/undo_log.c daemon/node_config.c daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c $(REORGOBJS) -lpthread

# Smoke test for the chain-context BIP30 gate (drives tests/bip30_shim over
# stdin; full differential vs real Core is validation/bip30_diff.py).
tests/test_bip30: tests/test_bip30.c bitcoin_hash.o sha256.o $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_bip30.c bitcoin_hash.o sha256.o

# BIP30 in the DAEMON's apply path. tests/test_bip30 above drives
# tests/bip30_shim, which implements the rule itself and is NOT linked into
# bitcoind -- so it validated a reimplementation. This drives utxo_live.c.
# See LOG.md incident #30.
# REORGSRCS_NOMAIN was referenced by the prerequisite list below and never
# defined anywhere in this file, so the rule declared NO sources at all and
# editing any of them left the binary stale.  Defined here, and used by the
# recipe too, so the two lists cannot drift apart again.
REORGSRCS_NOMAIN := daemon/utxo_live.c daemon/block_witness.c daemon/undo_log.c \
    daemon/node_config.c daemon/tx_verify.c bitcoin_scriptverify.c \
    bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c \
    bitcoin_taproot_sighash.c
# Incident #29: a coinbase output must OVERWRITE an existing coin, as Core's
# AddCoins does (overwrite = fCoinbase). See the file header.
tests/test_bip30_overwrite: tests/test_bip30_overwrite.c $(REORGSRCS_NOMAIN) $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_bip30_overwrite.c $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

# Phase 2 slice 1: the asm parse twin vs tx_verify.c's txv_parse, over a real
# block plus synthetic segwit shapes and full truncation fuzz.
tests/test_txv_parse_diff: tests/test_txv_parse_diff.c bitcoin_txv_parse.o $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_txv_parse_diff.c bitcoin_txv_parse.o $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

# incident #36: the scriptSig-length bound wrapped for compactsizes within 4
# of 2^64, accepting a tx Core rejects. This pins the split-bound fix.
tests/test_txv_cs_maxsize: tests/test_txv_cs_maxsize.c $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_txv_cs_maxsize.c $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

# Phase 2 slice 2: the asm classify twin vs txvb_classify, full shape/flags/
# witness/maturity matrix.
tests/test_txv_classify_diff: tests/test_txv_classify_diff.c bitcoin_txv_classify.o $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_txv_classify_diff.c bitcoin_txv_classify.o $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

# Phase 2 slice 3: BIP141 classification twin (sv_classify_segwit et al).
tests/test_segwit_classify_diff: tests/test_segwit_classify_diff.c bitcoin_segwit_classify.o $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_segwit_classify_diff.c bitcoin_segwit_classify.o $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

# Phase 2 slice 4: the BLOCK path's per-tx parser twin (the parser the live
# daemon actually runs).
tests/test_txvb_parse_diff: tests/test_txvb_parse_diff.c bitcoin_txv_parse.o $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_txvb_parse_diff.c bitcoin_txv_parse.o $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

# Phase 2 slice 5: arena twins (the seams earlier slices left in C).
tests/test_txv_pools_diff: tests/test_txv_pools_diff.c bitcoin_txv_pools.o $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_txv_pools_diff.c bitcoin_txv_pools.o $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

# Phase 2 slice 6: canonical witness stripping twin.
tests/test_strip_witness_diff: tests/test_strip_witness_diff.c bitcoin_strip_witness.o $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_strip_witness_diff.c bitcoin_strip_witness.o $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

# Phase 2 slice 7: BIP341 aggregate arena twins (chain: slices 5+6 twins).
tests/test_tapagg_diff: tests/test_tapagg_diff.c bitcoin_tapagg.o bitcoin_txv_pools.o bitcoin_strip_witness.o $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_tapagg_diff.c bitcoin_tapagg.o bitcoin_txv_pools.o bitcoin_strip_witness.o $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

# Phase 2 slice 8: dispatch + legacy view twins (chain: slices 5-7 twins).
tests/test_txv_dispatch_diff: tests/test_txv_dispatch_diff.c bitcoin_txv_dispatch.o bitcoin_tapagg.o bitcoin_txv_pools.o bitcoin_strip_witness.o $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_txv_dispatch_diff.c bitcoin_txv_dispatch.o bitcoin_tapagg.o bitcoin_txv_pools.o bitcoin_strip_witness.o $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

# Phase 2 slice 9: witness-v0 driver twin (same sv_run_v + hook underneath).
tests/test_wv0_drv_diff: tests/test_wv0_drv_diff.c bitcoin_witness_v0_drv.o $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_wv0_drv_diff.c bitcoin_witness_v0_drv.o $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

# Phase 2 slice 10: legacy/P2SH driver twin.
tests/test_svs_drv_diff: tests/test_svs_drv_diff.c bitcoin_scriptverify_drv.o $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_svs_drv_diff.c bitcoin_scriptverify_drv.o $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

# Phase 2 slice 11: checksig hook twins, driven through the real interpreter.
# Phase 2 slice 13b: BIP341 TapSighash builder twin.
tests/test_bip341_diff: tests/test_bip341_diff.c bitcoin_bip341.o $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_bip341_diff.c bitcoin_bip341.o $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

# Phase 2 slice 13a: taproot verify orchestration twin.
tests/test_taproot_verify_diff: tests/test_taproot_verify_diff.c bitcoin_taproot_verify.o wallet_core.c bitcoin_keys.o bech32.o bitcoin_bip32.o bitcoin_bip39.o bitcoin_hmac.o sha512.o $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_taproot_verify_diff.c bitcoin_taproot_verify.o wallet_core.c bitcoin_keys.o bech32.o bitcoin_bip32.o bitcoin_bip39.o bitcoin_hmac.o sha512.o $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

# Phase 2 slice 12: BIP143 sighash builder twin.
tests/test_bip143_diff: tests/test_bip143_diff.c bitcoin_bip143.o $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_bip143_diff.c bitcoin_bip143.o $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

tests/test_checksig_diff: tests/test_checksig_diff.c bitcoin_checksig.o wallet_core.c bitcoin_keys.o bech32.o bitcoin_bip32.o bitcoin_bip39.o bitcoin_hmac.o sha512.o $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_checksig_diff.c bitcoin_checksig.o wallet_core.c bitcoin_keys.o bech32.o bitcoin_bip32.o bitcoin_bip39.o bitcoin_hmac.o sha512.o $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

tests/test_utxo_unspendable: tests/test_utxo_unspendable.c $(REORGSRCS_NOMAIN) $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_utxo_unspendable.c $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

tests/test_bip30_daemon: tests/test_bip30_daemon.c $(REORGSRCS_NOMAIN) $(REORGOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_bip30_daemon.c $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

bitcoin_sigops.o: bitcoin_sigops.asm bitcoin_scriptcodec.asm
	$(NASM) -f elf64 -o $@ bitcoin_sigops.asm

tests/test_sigops: tests/test_sigops.c bitcoin_sigops.o bitcoin_scriptcodec.o
	$(CC) -O1 -o $@ tests/test_sigops.c bitcoin_sigops.o bitcoin_scriptcodec.o

# BIP340 Schnorr verify + BIP341 Taproot helpers (secp256k1_schnorr.asm,
# secp256k1_taproot.asm) over the verified point/field/scalar + sha256/pubkey.
TAPRIMSOBJS := secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o \
    secp256k1_scalar_c.o sha256.o bitcoin_pubkey.o
tests/test_schnorr: tests/test_schnorr.c secp256k1_schnorr.o $(TAPRIMSOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_schnorr.c secp256k1_schnorr.o $(TAPRIMSOBJS)
# BIP340 differential vs Bitcoin Core (PERF_SCOPE.md 13). The corpus's expected
# verdicts come from libsecp256k1 through validation/core_verify_oracle.cpp's
# SCHNORR command; regenerate with the command in schnorr_diff_vec.h's header.
tests/test_schnorr_diff: tests/test_schnorr_diff.c tests/schnorr_diff_vec.h secp256k1_schnorr.o $(TAPRIMSOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_schnorr_diff.c secp256k1_schnorr.o $(TAPRIMSOBJS)
# schnorr_verify from many threads at once. This is the harness that caught the
# process-global challenge-preimage buffer (a live FALSE-REJECT bug on taproot
# key-path inputs, which tx_verify.c verifies on worker threads).
tests/test_schnorr_thread_stress: tests/test_schnorr_thread_stress.c secp256k1_schnorr.o $(TAPRIMSOBJS)
	$(CC) -no-pie -O2 -pthread -o $@ tests/test_schnorr_thread_stress.c secp256k1_schnorr.o $(TAPRIMSOBJS) -lpthread
tests/test_taproot: tests/test_taproot.c secp256k1_taproot.o $(TAPRIMSOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_taproot.c secp256k1_taproot.o $(TAPRIMSOBJS)

# The callee-saved SENTINEL PROBE over the consensus crypto layer. tests/
# bench_abi_audit runs the same probe but covers only the fourteen functions
# BENCHMARKS.md tier 1 calls; this covers every secp256k1 primitive, every
# taproot helper, the constant-time ladder and chainwork. It found
# tap_merkle_root writing its loop counter onto its own saved r12 while BOTH
# static auditors (abi-check, callee-saved-check) reported the tree clean --
# see the function's own comment and LOG.md.
ABICOVOBJS := secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o \
    secp256k1_point.o secp256k1_point_ct.o secp256k1_glv_c.o secp256k1_ecdsa.o \
    secp256k1_schnorr.o secp256k1_taproot.o bitcoin_pubkey.o bitcoin_chainwork.o \
    sha256.o bitcoin_hash.o bitcoin_addr.o ripemd160.o
tests/test_abi_coverage: tests/test_abi_coverage.c tests/bench_abi_guard.S $(ABICOVOBJS)
	$(CC) -no-pie -O2 -Wall -o $@ tests/test_abi_coverage.c tests/bench_abi_guard.S $(ABICOVOBJS)

# secp256k1_taproot.asm's staging buffers from many threads at once. They were
# process-global, which is why daemon/tx_verify.c verified taproot inputs in a
# sequential pass -- see the test's own header and PERF_SCOPE.md section 14.
# It was the gate on removing the TXV_SHAPE_P2TR skip from the worker loops;
# that skip is gone as of 2026-08-23, so this test is now what keeps the
# buffers thread-local rather than what permits the change.
tests/test_taproot_thread_stress: tests/test_taproot_thread_stress.c secp256k1_taproot.o $(TAPRIMSOBJS)
	$(CC) -no-pie -O2 -pthread -o $@ tests/test_taproot_thread_stress.c secp256k1_taproot.o $(TAPRIMSOBJS)

# BIP341/BIP342 taproot sighash + spend validation: C glue (bitcoin_taproot_sighash.c)
# over the verified asm crypto core (sha256_full, tagged_hash256, schnorr_verify,
# point/fe/scalar/pubkey). Vectors are Core-validated (bip-0341 wallet-test-vectors).
TAPSIGHASHOBJS := bitcoin_taproot_sighash.c secp256k1_schnorr.o secp256k1_taproot.o bech32.o \
    bitcoin_interp.o bitcoin_scriptcodec.o ripemd160.o bitcoin_hash.o sha1.o \
    bitcoin_sighash.o \
    $(TAPRIMSOBJS)
tests/test_taproot_sighash: tests/test_taproot_sighash.c tests/taproot_spend.h tests/taproot_vec.h $(TAPSIGHASHOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_taproot_sighash.c $(filter %.c,$(TAPSIGHASHOBJS)) $(filter %.o,$(TAPSIGHASHOBJS))

# BIP341/BIP342 script-path spend dispatch (taproot_verify_input): witness
# classification, control-block Merkle commitment, and full tapscript
# execution via the shared script_eval interpreter.
tests/test_taproot_scriptpath: tests/test_taproot_scriptpath.c tests/taproot_scriptpath_vec.h $(TAPSIGHASHOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_taproot_scriptpath.c $(filter %.c,$(TAPSIGHASHOBJS)) $(filter %.o,$(TAPSIGHASHOBJS))

# test_taproot_bounds_fuzz -- bitcoin_taproot_sighash.c must never read past
# the end of the transaction, for any byte string a peer can send. The
# transaction is copied so its LAST byte abuts a PROT_NONE guard page, then
# real mainnet taproot transactions are driven through taproot_sighash() at
# every truncation and with single bytes poisoned to 00/fd/fe/ff, across the
# hash types and both spend paths. No sanitizer: this path links hand-written
# asm that ASAN cannot instrument, so the guard page IS the instrument. The
# counterpart of tests/test_segwit_bounds_fuzz (fc4bd67) for the BIP341 path,
# and it SEGVs on main -- that file's read_cs took no `end` at all.
TAPFUZZOBJS := $(TAPSIGHASHOBJS) bitcoin_script.o secp256k1_ecdsa.o bitcoin_addr.o
tests/test_taproot_bounds_fuzz: tests/test_taproot_bounds_fuzz.c bitcoin_segwit.c $(TAPFUZZOBJS)
	$(CC) -no-pie -O2 -I tests -o $@ tests/test_taproot_bounds_fuzz.c bitcoin_segwit.c $(filter %.c,$(TAPFUZZOBJS)) $(filter %.o,$(TAPFUZZOBJS))

# bench_taproot_sighash -- CPU time per BIP341 sighash across the same five
# transaction shapes bench_segwit_sighash uses, so the two tables are directly
# comparable, for both key-path and script-path. Not part of `make test` (it
# is a benchmark, not an assertion) but built with the production -O2 so its
# numbers mean something. Run: make tests/bench_taproot_sighash && \
#   tests/bench_taproot_sighash [runs]
tests/bench_taproot_sighash: tests/bench_taproot_sighash.c $(TAPSIGHASHOBJS)
	$(CC) $(CFLAGS) -I tests -o $@ tests/bench_taproot_sighash.c $(filter %.c,$(TAPSIGHASHOBJS)) $(filter %.o,$(TAPSIGHASHOBJS))

# BIP143 segwit-v0 sighash + P2WPKH/P2WSH spend verification (bitcoin_segwit.c)
# over the verified asm primitives (sha256_full, ecdsa_verify, pubkey_parse,
# der_parse_sig, hash160). Vectors are oracle-generated genuine P2WPKH/P2WSH
# spends, oracle validated against the official BIP-0143 vector. Also covers the
# P2TR key-path spend through the same whole-tx materials.
SEGWITOBJS := bitcoin_segwit.c bitcoin_taproot_sighash.c secp256k1_schnorr.o secp256k1_taproot.o \
    bitcoin_script.o bitcoin_sighash.o bitcoin_pubkey.o secp256k1_ecdsa.o \
    secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o \
    secp256k1_scalar_c.o sha256.o bitcoin_hash.o ripemd160.o \
    bitcoin_addr.o bitcoin_interp.o bitcoin_scriptcodec.o sha1.o
tests/test_p2wpkh_real: tests/test_p2wpkh_real.c $(SEGWITOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_p2wpkh_real.c $(filter %.c,$(SEGWITOBJS)) $(filter %.o,$(SEGWITOBJS))

tests/test_segwit_sighash: tests/test_segwit_sighash.c tests/modern_vec.h tests/modern_spend.h $(SEGWITOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_segwit_sighash.c $(filter %.c,$(SEGWITOBJS)) $(filter %.o,$(SEGWITOBJS))

# bench_segwit_sighash -- CPU time per BIP143 sighash across five transaction
# shapes (1-in to 1,372-in, 2-out to 3,000-out). PERF_SCOPE.md section 7 put
# this path at 34% of live replay cycles; incident #21 then measured its
# bound fix on a throwaway harness. Not part of `make test` (it is a
# benchmark, not an assertion) but built with the production -O2 so its
# numbers mean something. Run: make tests/bench_segwit_sighash && \
#   tests/bench_segwit_sighash [runs]
tests/bench_segwit_sighash: tests/bench_segwit_sighash.c $(SEGWITOBJS)
	$(CC) $(CFLAGS) -o $@ tests/bench_segwit_sighash.c $(filter %.c,$(SEGWITOBJS)) $(filter %.o,$(SEGWITOBJS))

# ---------------------------------------------------------------------------
# BENCHMARKS.md tier 1 / tier 2 -- harnesses whose SHAPE mirrors a specific
# Bitcoin Core (or libsecp256k1) benchmark, so the two tables compare directly
# rather than merely sounding similar. Every file's header names the Core
# benchmark it is the opposite number to AND states what differs between them.
# None of these are in the `test` target: they measure, they do not assert.
# `make bench-vs-core` builds all of them; scripts/bench_vs_core.sh runs both
# sides and emits the table.
#
# These rules live down here, not next to tests/bench_ecdsa, because they use
# $(TAPRIMSOBJS)/$(CONSOBJS) -- prerequisites are expanded when the rule is
# READ, so a rule placed above the variable's definition would silently link
# against nothing.
# ---------------------------------------------------------------------------

# bench_schnorr -- BIP340 verifications/sec, opposite number to libsecp256k1's
# own `bench schnorrsig_verify`. Reads the same official BIP340 vector CSV
# tests/test_schnorr validates against, so the fixture is not hardcoded here.
# Run: make tests/bench_schnorr && tests/bench_schnorr [n] [rounds] [csv]
tests/bench_schnorr: tests/bench_schnorr.c secp256k1_schnorr.o $(TAPRIMSOBJS)
	$(CC) -no-pie -O2 -o $@ tests/bench_schnorr.c secp256k1_schnorr.o $(TAPRIMSOBJS)

# bench_hash_core -- SHA-256 / SHA-1 / SHA-512 / RIPEMD-160 in the exact buffer
# shapes Core's src/bench/crypto_hash.cpp uses (1,000,000 B; 32 B; 1024 x 64 B
# double-hash). tests/bench_hash.c compares against OpenSSL instead and stays
# as it is; this one exists purely to be comparable to Core's table.
tests/bench_hash_core: tests/bench_hash_core.c tests/bench_abi_guard.S sha256.o sha1.o sha512.o ripemd160.o bitcoin_hash.o
	$(CC) $(CFLAGS) -o $@ tests/bench_hash_core.c tests/bench_abi_guard.S sha256.o sha1.o sha512.o ripemd160.o bitcoin_hash.o

# bench_merkle -- merkle root over 9,001 leaves, Core's MerkleRoot leaf count.
# The batched merkle inner-node hash (PERF_SCOPE.md 13.2) against the
# one-node-at-a-time algorithm it replaced, over every leaf count 1..2050.
tests/test_merkle_batch: tests/test_merkle_batch.c bitcoin_hash.o sha256.o
	$(CC) $(CFLAGS) -o $@ tests/test_merkle_batch.c bitcoin_hash.o sha256.o

tests/bench_merkle: tests/bench_merkle.c bitcoin_hash.o sha256.o
	$(CC) $(CFLAGS) -o $@ tests/bench_merkle.c bitcoin_hash.o sha256.o

# bench_checkblock -- cons_verify + transaction walk over mainnet block
# 413,567, read from CORE'S OWN data file so both sides see byte-identical
# input. cons_verify does strictly LESS than Core's CheckBlock; the file
# header enumerates exactly what is missing, and BENCHMARKS.md repeats it.
#   make tests/bench_checkblock && tests/bench_checkblock \
#     /storage/bitcoin-core-source/src/bench/data/block413567.raw [rounds]
tests/bench_checkblock: tests/bench_checkblock.c tests/bench_abi_guard.S $(CONSOBJS)
	$(CC) $(CFLAGS) -o $@ tests/bench_checkblock.c tests/bench_abi_guard.S $(CONSOBJS)

# bench_abi_audit -- NOT a benchmark: the standing check that the primitives the
# suite times actually give the caller its callee-saved registers back. It is an
# assertion (exit 1 on any violation) and it currently FAILS, by design: it
# reports the three ABI violations found on 2026-08-22 (ripemd160, hash160,
# cons_verify) rather than pretending they are not there. `make abi-check`
# passes on the same build -- it audits RSP alignment, not register
# preservation, so this class of bug is invisible to it.
#   make tests/bench_abi_audit && tests/bench_abi_audit \
#     /storage/bitcoin-core-source/src/bench/data/block413567.raw
# bitcoin_script.o is in the LINK line below but was missing from these
# prerequisites, so a fresh tree (no stale .o lying around) failed here with
# "cannot find bitcoin_script.o" -- it only ever built because some LATER
# target happened to produce it first. Listed explicitly now; the recipe and
# the prerequisites must name the same objects.
tests/bench_abi_audit: tests/bench_abi_audit.c tests/bench_abi_guard.S $(CONSOBJS) \
    $(INTERPOBJS) bitcoin_multisig.o bitcoin_sighash.o secp256k1_ecdsa.o \
    bitcoin_script.o $(TAPRIMSOBJS) sha512.o bitcoin_addr.o bech32.o bitcoin_utxo.o
	$(CC) $(CFLAGS) -o $@ tests/bench_abi_audit.c tests/bench_abi_guard.S \
	    $(sort bitcoin_utxo.o $(CONSOBJS) $(INTERPOBJS) bitcoin_multisig.o bitcoin_sighash.o \
	    secp256k1_ecdsa.o bitcoin_script.o $(TAPRIMSOBJS) sha512.o bitcoin_addr.o bech32.o)

.PHONY: bench-vs-core
bench-vs-core: tests/bench_ecdsa tests/bench_schnorr tests/bench_hash_core \
    tests/bench_merkle tests/bench_checkblock tests/bench_abi_audit tests/bench_fe \
    tests/bench_segwit_sighash tests/bench_taproot_sighash tests/bench_lsm_get
	@echo "built. run ../scripts/bench_vs_core.sh from the repo root"

# test_segwit_txout_bound -- incident #21: sw_ser_txout() serialized a CTxOut
# of unbounded length into a 600-byte STACK buffer, so any output whose
# scriptPubKey reached 590 bytes smashed the verifying thread's stack during
# BIP143 sighashing. Consensus puts no limit on an output's scriptPubKey, so a
# miner can put one in a block. Every expected sighash is Bitcoin Core's own
# SignatureHash(..., WITNESS_V0), via core_verify_oracle's BIP143 command
# (validation/gen_segwit_txout_vectors.py). 75 of the vectors are real mainnet
# transactions under all five hashtypes, and their hashes are byte-identical
# before and after the fix -- that half is the proof this changed bounds and
# not behaviour.
tests/test_segwit_txout_bound: tests/test_segwit_txout_bound.c tests/segwit_txout_vec.h bitcoin_witness_v0.c bitcoin_scriptverify.c $(SEGWITOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_segwit_txout_bound.c bitcoin_witness_v0.c bitcoin_scriptverify.c $(filter %.c,$(SEGWITOBJS)) $(filter %.o,$(SEGWITOBJS))

# test_segwit_bounds_fuzz -- bitcoin_segwit.c must never read past the end of
# the transaction, for any byte string a peer can send. The transaction is
# placed so its last byte abuts a PROT_NONE guard page, then every real
# mainnet transaction in segwit_txout_vec.h is driven at every truncation and
# with single bytes poisoned to 00/fd/fe/ff. Three bounds incidents (#13,
# #19, #21) came out of this file and all three were found by reading rather
# than by a test; this is the test. It SEGVs on the pre-#21 tree and passes
# on it afterwards.
tests/test_segwit_bounds_fuzz: tests/test_segwit_bounds_fuzz.c tests/segwit_txout_vec.h $(SEGWITOBJS)
	$(CC) -no-pie -O2 -I tests -o $@ tests/test_segwit_bounds_fuzz.c $(filter %.c,$(SEGWITOBJS)) $(filter %.o,$(SEGWITOBJS))

# FULL mempool acceptance pipeline for modern outputs: mempool policy +
# whole-tx validation + ECDSA/Schnorr verify (bitcoin_txval_modern.c +
# bitcoin_segwit.c + bitcoin_taproot_sighash.c + asm utxo/mempool/tx/taproot).
MEMPACCOBJS := bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c bitcoin_mempool_policy.c \
    bitcoin_utxo.o bitcoin_mempool.o bitcoin_tx.o secp256k1_schnorr.o \
    secp256k1_taproot.o bitcoin_script.o bitcoin_sighash.o bitcoin_pubkey.o \
    secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o \
    secp256k1_scalar.o secp256k1_scalar_c.o sha256.o bitcoin_hash.o \
    ripemd160.o bitcoin_addr.o bitcoin_interp.o bitcoin_scriptcodec.o sha1.o
tests/test_mempool_accept_modern: tests/test_mempool_accept_modern.c tests/modern_vec.h tests/modern_spend.h $(MEMPACCOBJS)
	$(CC) -no-pie -O2 -o $@ tests/test_mempool_accept_modern.c $(filter %.c,$(MEMPACCOBJS)) $(filter %.o,$(MEMPACCOBJS))

# incident #37: bitcoin_txval_modern.c mv_parse had an unbounded compactsize
# reader and pointer-overflow bounds on the no-PoW inbound-tx path.
tests/test_mv_parse_bounds: tests/test_mv_parse_bounds.c $(REORGSRCS_NOMAIN) $(REORGOBJS)
	$(CC) -no-pie -O2 -Wall -I tests -o $@ tests/test_mv_parse_bounds.c $(REORGSRCS_NOMAIN) $(REORGOBJS) -lpthread

# End-to-end test of daemon/tx_accept.c's REAL pipeline (utxo_lsm_reload
# snapshot -> mempool_resolve_confirmed_utxo -> mpool_policy_add ->
# txval_modern -> tx_accept_validate's accept/reject + mempool storage) --
# NOT covered by test_mempool_accept_modern, which only exercises the old
# bitcoin_utxo.asm-backed passthrough shim, never tx_accept.c itself.
TXACCEPTOBJS := bitcoin_scriptverify.c daemon/tx_accept.c daemon/mempool_cfg.c daemon/node_config.c bitcoin_mempool_policy.c \
    bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c bitcoin_utxo_lsm.o utxo_lsm_mm.o \
    bitcoin_utxo_store.o bitcoin_utxo.o bitcoin_mempool.o bitcoin_tx.o \
    secp256k1_schnorr.o secp256k1_taproot.o bitcoin_script.o bitcoin_sighash.o \
    bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o \
    secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o sha256.o \
    bitcoin_hash.o ripemd160.o bitcoin_addr.o bitcoin_interp.o bitcoin_scriptcodec.o sha1.o
tests/test_tx_accept_e2e: tests/test_tx_accept_e2e.c tests/modern_spend.h $(TXACCEPTOBJS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_tx_accept_e2e.c $(filter %.c,$(TXACCEPTOBJS)) $(filter %.o,$(TXACCEPTOBJS))

# Wallet CLI: generate key, show address, sign a P2PKH tx, and -- via BIP39 +
# BIP32 -- produce/restore recoverable seeds.
# asm/wallet_core.c glues the VERIFIED asm primitives (scalar_to_pubkey,
# hash160, base58check_encode, sighash_all, ecdsa_verify, BIP39 mnemonic<->seed,
# BIP32 master/path/extkey) plus the verified scalar/point/field ops (sc_*,
# point_scalar_mul, fe_*) used to construct ECDSA signatures.
# WALLETPRIMS is defined at the top of this file -- see the "expanded when read" note there.
daemon/wallet_cli: daemon/wallet_cli.c wallet_core.c wallet_store.c wallet_book.c wallet_txlog.c wallet_msgsign.c $(WALLETPRIMS) bitcoin_script.o
	$(CC) -no-pie -O2 -o $@ daemon/wallet_cli.c wallet_core.c wallet_store.c wallet_book.c wallet_txlog.c wallet_msgsign.c $(WALLETPRIMS) bitcoin_script.o

tests/test_wallet_txlog: tests/test_wallet_txlog.c wallet_txlog.c
	$(CC) -no-pie -O2 -o $@ tests/test_wallet_txlog.c wallet_txlog.c

tests/test_msg_sign: tests/test_msg_sign.c wallet_msgsign.c wallet_core.c $(WALLETPRIMS) bitcoin_script.o
	$(CC) -no-pie -O2 -o $@ tests/test_msg_sign.c wallet_msgsign.c wallet_core.c $(WALLETPRIMS) bitcoin_script.o

tests/test_wallet: tests/test_wallet.c wallet_core.c $(WALLETPRIMS)
	$(CC) -no-pie -O2 -o $@ tests/test_wallet.c wallet_core.c $(WALLETPRIMS)

# ============================================================================
# bitcoin-cli RPC network layer (card t_8e5be37f): JSON-RPC 2.0 framing +
# HTTP POST transport (rpc_net.c), Core-bit-exact JSON rendering + command
# dispatch (rpc_json.c + rpc_commands.c), wired to the wallet-core command
# layer (wallet_core.c). Shared by the client binary and the loopback test;
# the production HTTP server endpoint (child card t_0ca5d72e) dispatches
# through the same rpc_dispatch().
# ============================================================================
RPCOBJS := rpc_json.o rpc_net.o rpc_commands.o
# bitcoin_utxo_lsm.o utxo_lsm_mm.o/bitcoin_utxo_store.o: rpc_commands.o's cmd_gettxout_w
# calls utxo_lsm_get unconditionally, so every rpc_commands.o-linking target
# needs them, not just daemon/bitcoin_rpcd (which additionally builds/reloads
# the store itself).
# rpc_chain.o (blockchain-query / node-status RPCs, read-only over the
# archive): bitcoin_store.o + bitcoin_store_fast.o (index.dat / blk*.dat read
# path), bitcoin_idx.o (hash->height), bitcoin_tx.o (tx_txid), bitcoin_chainwork.o
# (block_work/chainwork_add fallback when chainwork.dat is absent).
RPCCHAIN := rpc_chain.o bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_tx.o bitcoin_chainwork.o
RPCLIBS := wallet_core.c $(WALLETPRIMS) bitcoin_utxo_lsm.o utxo_lsm_mm.o bitcoin_utxo_store.o rpc_node.o $(RPCCHAIN)

rpc_json.o: rpc_json.c rpc_json.h
	$(CC) -no-pie -O2 -c -o $@ rpc_json.c
rpc_net.o: rpc_net.c rpc_net.h rpc_json.h
	$(CC) -no-pie -O2 -c -o $@ rpc_net.c
rpc_commands.o: rpc_commands.c rpc_commands.h rpc_json.h rpc_node.h
	$(CC) -no-pie -O2 -c -o $@ rpc_commands.c
rpc_chain.o: rpc_chain.c rpc_chain.h rpc_json.h rpc_commands.h version_gen.h
	$(CC) -no-pie -O2 -c -o $@ rpc_chain.c
rpc_node.o: rpc_node.c rpc_node.h rpc_json.h version_gen.h
	$(CC) -no-pie -O2 -c -o $@ rpc_node.c

daemon/bitcoin_cli: daemon/bitcoin_cli.c rpc_net.o rpc_commands.o rpc_json.o $(RPCLIBS)
	$(CC) -no-pie -O2 -o $@ daemon/bitcoin_cli.c rpc_net.o rpc_commands.o rpc_json.o $(RPCLIBS)

tests/test_rpc_json: tests/test_rpc_json.c rpc_json.o rpc_commands.o $(RPCLIBS)
	$(CC) -no-pie -O2 -o $@ tests/test_rpc_json.c rpc_json.o rpc_commands.o $(RPCLIBS)

tests/test_rpc_transport: tests/test_rpc_transport.c rpc_net.o rpc_commands.o rpc_json.o daemon/bitcoin_cli $(RPCLIBS)
	$(CC) -no-pie -O2 -o $@ tests/test_rpc_transport.c rpc_net.o rpc_commands.o rpc_json.o $(RPCLIBS) -lpthread

# ============================================================================
# HTTP JSON-RPC SERVER endpoint (card t_0ca5d72e): rpc_server.c owns the
# sockets/threads + Core-faithful HTTP/JSON-RPC behavior; daemon/bitcoin_rpcd
# is the production server binary (loads config/bitcoin.conf);
# tests/test_rpc_server forks+execs the REAL bitcoin_rpcd and drives it with
# the REAL bitcoin_cli + raw sockets. Shared render path = rpc_dispatch().
# ============================================================================
rpc_server.o: rpc_server.c rpc_server.h rpc_commands.h rpc_net.h rpc_json.h
	$(CC) -no-pie -O2 -c -o $@ rpc_server.c

daemon/bitcoin_rpcd: daemon/bitcoin_rpcd.c rpc_server.o rpc_net.o rpc_commands.o rpc_json.o $(RPCLIBS)
	$(CC) -no-pie -O2 -o $@ daemon/bitcoin_rpcd.c rpc_server.o rpc_net.o rpc_commands.o rpc_json.o $(RPCLIBS) -lpthread

tests/test_rpc_server: tests/test_rpc_server.c rpc_net.o rpc_commands.o rpc_json.o rpc_server.o daemon/bitcoin_cli daemon/bitcoin_rpcd $(RPCLIBS)
	$(CC) -no-pie -O2 -o $@ tests/test_rpc_server.c rpc_net.o rpc_commands.o rpc_json.o rpc_server.o $(RPCLIBS) -lpthread

# Blockchain-query RPCs (rpc_chain.c) against a synthetic archive built in a
# throwaway temp dir: real mainnet genesis + 3 constructed blocks (one with a
# segwit coinbase, a legacy spend and a P2WPKH spend). Exercises every method
# in-process through rpc_dispatch, plus the error paths.
tests/test_rpc_chain: tests/test_rpc_chain.c rpc_commands.o rpc_json.o $(RPCLIBS) $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_rpc_chain.c rpc_commands.o rpc_json.o $(RPCLIBS) -lpthread

# BIP37 partial merkle tree behind gettxoutproof/verifytxoutproof: a
# known-answer vector (block 100000) plus proof round-trips. No archive/oracle.
tests/test_txoutproof: tests/test_txoutproof.c rpc_commands.o rpc_json.o $(RPCLIBS)
	$(CC) -no-pie -O2 -o $@ tests/test_txoutproof.c rpc_commands.o rpc_json.o $(RPCLIBS) -lpthread

# live-node RPC module (rpc_node.c): fake node_status_t -> dispatch -> assert.
tests/test_rpc_node: tests/test_rpc_node.c rpc_node.o rpc_json.o
	$(CC) -no-pie -O2 -o $@ tests/test_rpc_node.c rpc_node.o rpc_json.o


# bitcoin_p2p.asm inv parsers (incoming protocol codecs).
P2PINVOBS := bitcoin_p2p.o bitcoin_net.o bitcoin_hash.o sha256.o
tests/test_p2p_inv: tests/test_p2p_inv.c $(P2PINVOBS)
	$(CC) -no-pie -O2 -o $@ tests/test_p2p_inv.c $(P2PINVOBS)

# daemon/bitcoind -- the runnable core node driver (sync/ibd/follow/serve/
# server-test). This is a REAL target so the daemon never goes stale or suffers
# a missing-object link, unlike the old ad-hoc manual gcc command.
#
# -O2 SINCE 2026-08-23. This rule carried `-O0 required (an -O2 rebuild
# regressed lsock's bind to EFAULT)` for a long time. Re-tested on that date:
# built at -O2, `bitcoind serve <scratch-datadir> 39333` binds and listens
# (`ss -ltn` shows 0.0.0.0:39333), and tests/test_outbound_mux and
# tests/test_redial -- which fork this exact binary in serve mode -- both pass.
# The whole suite is 159 harnesses / 0 failures at -O2 as well as at -O0. The
# real -O2 blockers were ABI/overflow bugs, now fixed: LOG.md incidents #27
# (21 functions returning the caller's callee-saved registers), #31
# (tap_merkle_root writing its loop counter onto its own saved r12) and the
# base58check_encode save-area overrun of 2026-08-23. DAEMONOBJS is defined
# once, above, near its first use (tests/test_bitcoind) -- see the note there.
# STAGE B adds daemon/reorg.c (fork choice / reorg engine), daemon/undo_log.c
# (per-block undo data, now wired into the live apply path) and
# daemon/locator_build.c (the real multi-hash block locator), plus
# bitcoin_chainwork.o for the cumulative-work primitives they run on.
DAEMONSRCS := daemon/main.c daemon/utxo_live.c daemon/block_witness.c daemon/tx_accept.c daemon/reorg.c \
    daemon/undo_log.c daemon/locator_build.c daemon/archive_verify.c daemon/addr_ingest.c \
    daemon/net_policy.c daemon/node_config.c daemon/mempool_cfg.c daemon/upload_cap.c \
    bitcoin_mempool_policy.c bitcoin_txval_modern.c bitcoin_segwit.c bitcoin_taproot_sighash.c \
    daemon/tx_verify.c bitcoin_scriptverify.c bitcoin_witness_v0.c
# Embedded RPC server (docs/RPC_LIVE_NODE.md): DAEMON_RPCOBJS is defined near
# the top (with WALLETPRIMS) so its prereqs expand for every rule that uses it.
daemon/bitcoind: $(DAEMONSRCS) daemon/utxo_walk.h daemon/reorg.h $(DAEMONOBJS) $(DAEMON_RPCOBJS) $(VERSION_GEN_H)
	$(CC) -no-pie -O2 -o $@ $(DAEMONSRCS) $(DAEMONOBJS) $(DAEMON_RPCOBJS) wallet_core.c -lpthread

# pverify -- parallel block-chain verifier, machine-adaptive worker count.
# Built at -O1 (not -O2/-O3): the deep asm call chain (cons_verify -> tx_parse
# / sha256d) misparses a block when the C driver is compiled at aggressive -O2+,
# a documented codegen interaction. -O1 is safe; the speed comes from the
# parallel workers, not C-codegen.
daemon/pverify: daemon/pverify.c $(CONSOBJS)
	$(CC) -O1 -o $@ daemon/pverify.c $(CONSOBJS) -lpthread

# bitcoin_store.asm shared-append: concurrent-safe single-store write (standalone).
tests/test_shared: tests/test_shared.c bitcoin_store.o $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_shared.c bitcoin_store.o
tests/test_shared2: tests/test_shared2.c bitcoin_store.o $(TEST_TMPDIR_H)
	$(CC) -no-pie -O2 -o $@ tests/test_shared2.c bitcoin_store.o

# BIP141 witness-commitment check (daemon/block_witness.c): real regtest segwit
# block (tests/block_vec.h), genesis, one committed small mainnet early-segwit
# block, plus optional large fixtures from validation/fetch_witness_blocks.py.
tests/test_witness_commitment: tests/test_witness_commitment.c daemon/block_witness.c daemon/block_witness.h tests/block_vec.h bitcoin_tx.o sha256.o bitcoin_hash.o bitcoin_script_flags.o
	$(CC) $(CFLAGS) -I. -I tests -o $@ tests/test_witness_commitment.c daemon/block_witness.c bitcoin_tx.o sha256.o bitcoin_hash.o bitcoin_script_flags.o

# ---------------------------------------------------------------------------
# ABI guard -- SysV AMD64 16-byte stack alignment.
#
# Incidents #18 (b18114b) and #20 are the same bug: an .asm function reserves a
# frame whose size leaves RSP at 8 mod 16, so every nested `call` breaks the
# ABI. Assembly callees never notice; the first C callee added to that path
# dies inside glibc's vsnprintf on `movaps %xmm0,-0xc0(%rbp)` (#GP -> SIGSEGV,
# si_addr == NULL).
#
# `make abi-check` abstract-interprets RSP mod 16 over every call site in every
# .asm source and fails if any call that LEAVES assembly is misaligned. Run
# against b18114b^ it flags node_serve_loop's log_block_stored_inbound call --
# i.e. it would have caught 5aea7c0 the day it landed.
#
# Drop --external-only to see the asm->asm sites too; those are latent (nothing
# in this tree uses a 16-byte-aligned stack operand) and are tracked in LOG.md.
# ---------------------------------------------------------------------------
abi-check:
	python3 ../scripts/abi_stack_audit.py --asmdir . --objdir . \
	    --format summary --check --external-only > /dev/null

# Runtime half of the same guard: drives the one place assembly calls back out
# to C through a function pointer (script_eval -> checksig_fn) and checks the
# parity directly, then does a printf from that callback -- the exact mechanism
# that killed the serve child in #18.
ABIALIGNOBJS := $(INTERPOBJS) bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o \
    secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o \
    secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o
tests/test_abi_stack_align: tests/test_abi_stack_align.c $(ABIALIGNOBJS)
	$(CC) $(CFLAGS) -I. -I tests -o $@ tests/test_abi_stack_align.c $(ABIALIGNOBJS)

# ---------------------------------------------------------------------------
# ABI guard #2 -- SysV AMD64 callee-saved register PRESERVATION.
#
# A DIFFERENT property from the alignment guard above, and invisible to it:
# `make abi-check` passed on a build in which script_eval -- entered for every
# input of every transaction on the consensus path -- returned with the
# caller's rbx, r12, r13, r14 and r15 all holding interpreter state. Thirteen
# functions had it, always the same mistake: the callee-saved pushes came AFTER
# `mov rbp,rsp`, so the save area sat at [rbp-0x08 ...] with the locals
# underneath it, and a buffer addressed from the low end wrote up through it.
# Nothing had failed in production only because every C file on that path is
# pinned to -O0 below, and -O0 keeps nothing live in a callee-saved register
# across a call. That is accidental protection; these two targets replace it.
#
#   callee-saved-check  -- static, whole tree. abstract-interprets each
#                          function's frame and fails on any register left
#                          unrestored at a `ret` or any provable write into a
#                          live save slot. Also prints a ranked "headroom" risk
#                          list (frame buffers that grow toward a save area);
#                          that list is reported, never gated, because whether
#                          a buffer reaches depends on its length.
#   tests/bench_abi_audit -- runtime. Loads six sentinels into the callee-saved
#                          registers, calls each primitive with real arguments,
#                          and reports which came back changed. MUST print
#                          "0 violating"; it exits non-zero otherwise, so a
#                          regression fails `make test` rather than printing a
#                          plausible number next to it.
#
# The block argument enables the block_hash / pow_check / tx_parse / cons_verify
# rows. It is optional so the target still runs where Core's source is absent.
# ---------------------------------------------------------------------------
ABI_AUDIT_BLOCK := $(wildcard /storage/bitcoin-core-source/src/bench/data/block413567.raw)

callee-saved-check:
	python3 ../scripts/abi_callee_saved_audit.py --asmdir . \
	    --format summary --check > /dev/null

# ---------------------------------------------------------------------------
# BUILD guard -- "the recipe uses what the rule never asked for".
#
# Twice on 2026-08-23 a recipe consumed a file its own rule never declared:
# tests/bench_abi_audit linked bitcoin_script.o without listing it (dead under
# -j with "/usr/bin/ld: cannot find bitcoin_script.o"), and the test: rule ran
# ./tests/test_bip30_daemon while a scripted edit had added the binary to a
# COMMENT instead of the prerequisite list. Both passed on this machine and
# only on this machine, because the file was already lying around.
#
# `make prereq-check` compares every rule's recipe against its own prerequisite
# closure and fails on any file the recipe uses that make was never told about.
# It asks make for both halves -- `make -qp` for the expanded prerequisites,
# `make -n -B --trace` for the expanded recipes -- so $(CONSOBJS), $(REORGOBJS)
# and $(sort $(A) $(B)) are resolved by make itself, not by a regex.
#
# Run against 8a977cb it reports 225 unlisted objects across 11 rules, every
# one of them a group variable used in a prerequisite list ABOVE its own
# assignment: prerequisites expand when make READS the line, recipes when they
# RUN, so the rule linked objects it had declared as nothing at all.
# ---------------------------------------------------------------------------
prereq-check:
	python3 ../scripts/makefile_prereq_audit.py --asmdir . \
	    --format summary --check > /dev/null


test: abi-check callee-saved-check prereq-check tests/test_abi_coverage tests/bench_abi_audit tests/test_abi_stack_align tests/test_node_config tests/test_archive_check tests/test_scriptverify_parity tests/test_sha256 tests/test_sha512 tests/test_hmac tests/test_fe tests/test_point tests/test_addm tests/test_scalarmul tests/test_scalarmul_ct tests/test_add tests/test_scalar tests/test_ecdsa tests/test_keys tests/test_bip32_master tests/test_bip32_chain tests/test_bip32_extkey tests/test_bip39 tests/test_ripemd160 tests/test_ripemd160_thread_stress tests/test_addr tests/test_bech32 tests/test_mempool tests/test_mempool_policy tests/test_txtxid tests/test_block tests/test_tx tests/test_net tests/test_p2p tests/fakepeer_headers tests/test_store tests/test_prune tests/test_cons tests/test_block_genesis tests/test_bitcoind tests/test_bitcoind_sync tests/test_log tests/test_cli tests/test_headers tests/test_ibd_headers tests/test_ibd_blocks tests/test_ibd_full tests/test_addrmgr tests/test_shared tests/test_shared2 tests/test_idx tests/test_serve tests/test_keepup tests/test_p2p_inv tests/test_bip152 tests/test_bip152_loop tests/test_sendheaders_fee tests/test_outbound_mux tests/test_redial daemon/bitcoind tests/test_pubkey tests/test_sighash tests/test_sighash_oob tests/test_script tests/test_p2pkh tests/test_utxo tests/test_utxo_store tests/test_utxo_lsm tests/test_utxo_probe_bound tests/test_utxo_prefetch_race tests/test_utxo_live_count tests/test_txval tests/test_multisig tests/test_wallet tests/test_e2e_sighash tests/test_send tests/test_wrpc_addr tests/test_wrpc_utxo tests/test_wrpc_decoderaw tests/test_wrpc_sign tests/test_wrpc_send tests/smoke_interp tests/test_interp tests/test_tapscript_interp tests/run_batch tests/consensus_shim tests/test_sigops tests/test_schnorr tests/test_taproot tests/test_taproot_thread_stress tests/test_taproot_sighash tests/test_segwit_sighash tests/test_p2wpkh_real tests/test_mempool_accept_modern tests/test_tx_accept_e2e tests/test_rpc_json tests/test_rpc_transport tests/test_rpc_server tests/test_rpc_chain tests/test_txoutproof tests/test_rpc_node tests/verify_p2sh_shim tests/test_verify_p2sh tests/bip30_shim tests/test_bip30 tests/test_bip30_daemon tests/test_bip30_overwrite tests/test_utxo_unspendable tests/test_txv_parse_diff tests/test_txv_classify_diff tests/test_segwit_classify_diff tests/test_txvb_parse_diff tests/test_txv_pools_diff tests/test_strip_witness_diff tests/test_tapagg_diff tests/test_txv_dispatch_diff tests/test_wv0_drv_diff tests/test_svs_drv_diff tests/test_checksig_diff tests/test_bip143_diff tests/test_taproot_verify_diff tests/test_point_inf tests/test_glv_split tests/test_glv_wnaf tests/test_glv_pointmul tests/test_muhash tests/test_utxo_setinfo tests/test_schnorr_diff tests/test_schnorr_thread_stress tests/test_merkle_batch tests/test_mv_parse_bounds tests/test_txv_cs_maxsize tests/test_bip341_diff \
tests/test_chainwork tests/test_locator tests/test_prevhash tests/test_truncate tests/test_undo_log tests/test_undo_asm_diff tests/test_reorg tests/test_dial_budget tests/test_legacy_sighash tests/test_find_and_delete tests/test_hashtype_e2e tests/test_script_flags tests/test_archive_repair tests/test_archive_truncate_nonmonotonic tests/test_prune_nonmonotonic tests/test_tx_verify_parallel tests/test_utxo_checkpoint tests/diff_add_ct_homog tests/test_nop1_regression tests/test_checkmultisig_findanddelete tests/test_checkmultisig_zero_keys tests/test_checkmultisigverify_pop tests/test_sig_pushonly_75 tests/test_cltv_csv tests/test_apply_block_rollback tests/test_scriptverify_thread_stress tests/test_cross_tx_verify tests/test_compact_manifest_order tests/test_tx_verify_bytepool_realloc tests/test_stack_push_len tests/test_utxo_catchup_crash_resume tests/test_taproot_scriptpath tests/test_mul_carry_regression tests/test_fe_repr tests/test_fe_inline tests/test_point_repr tests/test_ecdsa_inverse tests/test_lsm_mmap_diff tests/test_utxo_catchup_shutdown tests/test_utxo_crash_recovery tests/test_lsm_sparse_diff tests/soak_lsm_mm tests/test_ecdsa_glv_switch tests/test_witness_commitment tests/test_txvb_wprog_stable tests/test_taproot_exception_block tests/test_dersig_encoding tests/test_scriptnum_bool tests/test_segwit_real tests/test_segwit_coverage tests/test_tapscript_scale tests/test_block_481827_pool_stack tests/test_segwit_txout_bound tests/test_segwit_bounds_fuzz tests/test_taproot_bounds_fuzz tests/test_taproot_parallel_arena tests/test_taproot_block_diff
	./tests/test_abi_stack_align
	./tests/bench_abi_audit $(ABI_AUDIT_BLOCK)
	./tests/test_abi_coverage
	./tests/test_node_config
	./tests/test_archive_check
	./tests/test_archive_repair
	./tests/test_archive_truncate_nonmonotonic
	./tests/test_prune_nonmonotonic
	./tests/test_scriptverify_parity
	./tests/test_scriptverify_thread_stress
	./tests/test_nop1_regression
	./tests/test_checkmultisig_findanddelete
	./tests/test_checkmultisig_zero_keys
	./tests/test_checkmultisigverify_pop
	./tests/test_sig_pushonly_75
	./tests/test_cltv_csv
	./tests/test_sha256
	./tests/test_sha512
	./tests/test_hmac
	./tests/test_fe
	./tests/test_point
	./tests/test_point_inf
	./tests/test_addm
	./tests/test_scalarmul
	./tests/test_scalarmul_ct
	./tests/diff_add_ct_homog
	./tests/test_add
	./tests/test_scalar
	./tests/test_glv_split
	./tests/test_glv_wnaf
	./tests/test_glv_pointmul
	./tests/test_ecdsa
	./tests/test_keys
	./tests/test_bip32_master
	./tests/test_bip32_chain
	./tests/test_bip32_extkey
	./tests/test_bip39
	./tests/test_ripemd160
	./tests/test_ripemd160_thread_stress 8 8000
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
	./tests/test_utxo_probe_bound
	./tests/test_utxo_prefetch_race 8 200000
	./tests/test_utxo_live_count
	./tests/test_muhash
	./tests/test_utxo_setinfo
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
	./tests/test_sigops
	./tests/test_schnorr tests/bip340_test_vectors.csv
	./tests/test_schnorr_diff
	./tests/test_schnorr_thread_stress tests/bip340_test_vectors.csv
	./tests/test_taproot
	./tests/test_taproot_thread_stress
	./tests/test_taproot_sighash
	./tests/test_taproot_scriptpath
	./tests/test_witness_commitment
	./tests/test_merkle_batch
	./tests/test_mul_carry_regression
	./tests/test_fe_repr
	./tests/test_fe_inline
	./tests/test_point_repr
	./tests/test_ecdsa_inverse
	./tests/test_ecdsa_glv_switch
	./tests/test_lsm_mmap_diff
	./tests/test_lsm_sparse_diff
	./tests/soak_lsm_mm
	./tests/test_segwit_sighash
	./tests/test_segwit_txout_bound -q
	./tests/test_segwit_bounds_fuzz
	./tests/test_taproot_bounds_fuzz
	./tests/test_taproot_parallel_arena
# No heights: SKIPs unless validation/fetch_taproot_blocks.py has been run
# against the scratch oracle. Run it by hand with heights before deploying a
# change to the taproot path -- see the rule above.
	./tests/test_taproot_block_diff
	./tests/test_p2wpkh_real
	./tests/test_mempool_accept_modern
	./tests/test_mv_parse_bounds
	./tests/test_tx_accept_e2e
	./tests/test_rpc_json
	./tests/test_rpc_transport
	./tests/test_rpc_server
	./tests/test_rpc_chain
	./tests/test_txoutproof
	./tests/test_rpc_node
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
	./tests/test_bip30_daemon
	./tests/test_bip30_overwrite
	./tests/test_utxo_unspendable
	./tests/test_txv_parse_diff /storage/bitcoin-core-source/src/bench/data/block413567.raw
	./tests/test_txv_cs_maxsize
	./tests/test_txv_classify_diff
	./tests/test_segwit_classify_diff
	./tests/test_txvb_parse_diff /storage/bitcoin-core-source/src/bench/data/block413567.raw
	./tests/test_txv_pools_diff
	./tests/test_strip_witness_diff /storage/bitcoin-core-source/src/bench/data/block413567.raw
	./tests/test_tapagg_diff
	./tests/test_txv_dispatch_diff
	./tests/test_wv0_drv_diff
	./tests/test_svs_drv_diff
	./tests/test_checksig_diff
	./tests/test_bip143_diff /storage/bitcoin-core-source/src/bench/data/block413567.raw
	./tests/test_taproot_verify_diff
	./tests/test_bip341_diff
	./tests/test_chainwork
	./tests/test_locator
	./tests/test_prevhash
	./tests/test_truncate
	./tests/test_undo_log
	./tests/test_undo_asm_diff
	./tests/test_reorg
	./tests/test_dial_budget
	./tests/test_legacy_sighash
	./tests/test_find_and_delete
	./tests/test_hashtype_e2e
	./tests/test_script_flags
	./tests/test_taproot_exception_block
	./tests/test_dersig_encoding
	./tests/test_scriptnum_bool
	./tests/test_tx_verify_parallel
	./tests/test_segwit_real
	./tests/test_segwit_coverage
	./tests/test_tapscript_scale
	./tests/test_block_481827_pool_stack
	./tests/test_txvb_wprog_stable
	./tests/test_utxo_checkpoint
	./tests/test_apply_block_rollback
	./tests/test_utxo_catchup_crash_resume
	./tests/test_utxo_catchup_shutdown
	./tests/test_utxo_crash_recovery
	./tests/test_cross_tx_verify
	./tests/test_compact_manifest_order
	./tests/test_tx_verify_bytepool_realloc
	./tests/test_stack_push_len

clean:
	rm -f $(OBJS) secp256k1_taproot.o secp256k1_schnorr.o bitcoind.o sha512.o bitcoin_hmac.o bitcoin_keys.o bitcoin_bip39.o ripemd160.o bitcoin_addr.o tests/test_pubkey tests/test_sighash tests/test_script tests/test_p2pkh tests/test_utxo tests/test_sha256 tests/test_sha512 tests/test_hmac tests/test_fe tests/test_point tests/test_addm tests/test_scalarmul tests/test_add tests/test_scalar tests/test_ecdsa tests/test_keys tests/test_bip32_master tests/test_bip32_chain tests/test_bip32_extkey tests/test_bip39 tests/test_ripemd160 tests/test_addr tests/test_bech32 tests/test_mempool tests/test_txtxid tests/test_block tests/test_tx tests/test_net tests/test_p2p tests/fakepeer_headers tests/test_store tests/test_cons tests/test_block_genesis tests/test_bitcoind tests/test_bitcoind_sync tests/test_log tests/test_cli tests/test_headers tests/test_ibd_headers tests/test_ibd_blocks tests/test_ibd_full tests/test_addrmgr tests/test_shared tests/test_shared2 tests/test_idx tests/test_serve tests/test_keepup tests/test_p2p_inv tests/test_bip152 tests/test_bip152_loop tests/test_sendheaders_fee tests/test_pubkey tests/test_sighash tests/test_sighash_oob tests/test_script tests/test_p2pkh tests/test_utxo tests/test_utxo_store tests/test_utxo_lsm tests/test_txval tests/test_multisig tests/test_wallet tests/test_e2e_sighash tests/test_send tests/test_wrpc_addr tests/test_wrpc_utxo tests/test_wrpc_decoderaw tests/test_wrpc_sign tests/test_wrpc_send tests/test_schnorr tests/test_taproot tests/test_taproot_sighash tests/test_segwit_sighash tests/test_mempool_accept_modern tests/test_tx_accept_e2e tests/test_rpc_json tests/test_rpc_transport tests/test_rpc_server rpc_json.o rpc_net.o rpc_commands.o rpc_server.o daemon/bitcoin_cli daemon/bitcoin_rpcd daemon/wallet_cli tests/bip30_shim tests/test_bip30 bitcoin_chainwork.o daemon/locator_build.o daemon/undo_log.o tests/test_chainwork tests/test_locator tests/test_prevhash tests/test_truncate tests/test_undo_log tests/test_reorg