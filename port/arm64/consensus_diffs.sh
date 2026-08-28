#!/bin/bash
# consensus_diffs.sh -- build + run the repo's consensus twin differentials
# natively on AArch64 against the ported .S objects (asm twin vs C oracle).
set -e
cd "$(cd "$(dirname "$0")" && pwd)"   # anchor: port/arm64
P=. A=../../asm
for m in bitcoin_checksig bitcoin_bip143 bitcoin_taproot_verify bitcoin_tapagg \
         bitcoin_txv_dispatch bitcoin_strip_witness bitcoin_witness_v0_drv \
         bitcoin_scriptverify_drv bitcoin_multisig; do
  [ -f "$P/$m.o" ] || gcc -c -march=armv8.2-a+sha2 -o "$P/$m.o" "$P/$m.S"
done
REALC="$A/bitcoin_taproot_sighash.c $A/bitcoin_pow_rules.c $A/daemon/utxo_live.c $A/daemon/block_witness.c $A/daemon/undo_log.c $A/daemon/node_config.c $A/daemon/tx_verify.c $A/bitcoin_scriptverify.c $A/bitcoin_txval_modern.c $A/bitcoin_witness_v0.c $A/bitcoin_segwit.c"
REALO="$P/bitcoin_store.o $P/bitcoin_store_fast.o $P/bitcoin_idx.o $P/bitcoin_idxscan.o $P/bitcoin_chainwork.o $P/bitcoin_hash.o $P/sha256.o $P/bitcoin_tx.o $P/bitcoin_cons.o $P/bitcoin_p2p.o $P/bitcoin_net.o $P/bitcoin_mempool.o $P/bitcoin_utxo_lsm.o $P/utxo_lsm_mm.o $P/bitcoin_utxo_store.o $P/bitcoin_utxo.o $P/bitcoind.o $P/bitcoin_headers.o $P/bitcoin_interp.o $P/bitcoin_scriptcodec.o $P/bitcoin_script_flags.o $P/bitcoin_sighash.o $P/bitcoin_script.o $P/bitcoin_pubkey.o $P/secp256k1_ecdsa.o $P/secp256k1_point.o $P/secp256k1_glv_c.o $P/secp256k1_point_ct.o $P/secp256k1_fe.o $P/secp256k1_scalar.o $P/secp256k1_scalar_c.o $P/secp256k1_schnorr.o $P/secp256k1_taproot.o $P/ripemd160.o $P/bitcoin_addr.o $P/sha1.o $P/bitcoin_utxo_stats.o $P/bitcoin_muhash.o $P/bitcoin_txv_pools.o"
WAL="$A/wallet_core.c $P/bitcoin_keys.o $P/bech32.o $P/bitcoin_bip32.o $P/bitcoin_sighash_all_ext.o $P/bitcoin_bip39.o $P/bitcoin_hmac.o $P/sha512.o"
INC="-I$A/tests -I$A -I$A/daemon"
OFF=/tmp  # scratch
gcc -no-pie -O2 $INC -o $OFF/cons_bip143_diff $A/tests/test_bip143_diff.c $P/bitcoin_bip143.o $REALC $REALO -lpthread
gcc -no-pie -O2 $INC -o $OFF/cons_strip_diff $A/tests/test_strip_witness_diff.c $P/bitcoin_strip_witness.o $REALC $REALO -lpthread
gcc -no-pie -O2 $INC -o $OFF/cons_checksig_diff $A/tests/test_checksig_diff.c $P/bitcoin_checksig.o $P/bitcoin_bip143.o $WAL $REALC $REALO -lpthread
gcc -no-pie -O2 $INC -o $OFF/cons_tapagg_diff $A/tests/test_tapagg_diff.c $P/bitcoin_tapagg.o $P/bitcoin_taproot_verify.o $P/bitcoin_strip_witness.o $REALC $REALO -lpthread
gcc -no-pie -O2 $INC -o $OFF/cons_txv_dispatch $A/tests/test_txv_dispatch_diff.c $P/bitcoin_txv_dispatch.o $P/bitcoin_tapagg.o $P/bitcoin_taproot_verify.o $P/bitcoin_strip_witness.o $REALC $REALO -lpthread
gcc -no-pie -O2 $INC -o $OFF/cons_taproot_verify $A/tests/test_taproot_verify_diff.c $P/bitcoin_taproot_verify.o $WAL $REALC $REALO -lpthread
gcc -no-pie -O2 $INC -o $OFF/cons_wv0_drv $A/tests/test_wv0_drv_diff.c $P/bitcoin_witness_v0_drv.o $P/bitcoin_bip143.o $REALC $REALO -lpthread
gcc -no-pie -O2 $INC -o $OFF/cons_svs_drv $A/tests/test_svs_drv_diff.c $P/bitcoin_scriptverify_drv.o $REALC $REALO -lpthread
gcc -no-pie -O2 $INC -o $OFF/cons_multisig $A/tests/test_multisig.c $P/bitcoin_multisig.o $P/bitcoin_script.o $P/bitcoin_sighash.o $P/bitcoin_pubkey.o $P/secp256k1_fe.o $P/secp256k1_scalar.o $P/secp256k1_scalar_c.o $P/secp256k1_ecdsa.o $P/secp256k1_point.o $P/secp256k1_glv_c.o $P/secp256k1_point_ct.o $P/bitcoin_hash.o $P/sha256.o $P/ripemd160.o

"$OFF/cons_bip143_diff" || true
"$OFF/cons_strip_diff" || true
"$OFF/cons_checksig_diff" || true
"$OFF/cons_tapagg_diff" || true
"$OFF/cons_txv_dispatch" || true
"$OFF/cons_taproot_verify" || true
"$OFF/cons_wv0_drv" || true
"$OFF/cons_svs_drv" || true
"$OFF/cons_multisig" || true
echo "consensus_diffs: run complete (see per-target output above)"
