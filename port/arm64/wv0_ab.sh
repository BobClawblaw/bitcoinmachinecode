#!/bin/bash
# Build + run the WITNESS_V0 FAD A/B driver against a chosen bitcoin_interp.S.
# Usage: wv0_ab.sh <interp.S-path> <tag>
set -e
cd /repo/port/arm64
P=. A=../../asm
gcc -march=armv8.2-a+sha2 -c -o bitcoin_interp.o "$1"
REALC="$A/daemon/lsm_manifest.c $A/daemon/netperm.c $A/daemon/subnet.c $A/daemon/chainparams.c $A/daemon/signet_block.c $A/daemon/signet_verify.c $A/daemon/signet.c $A/daemon/minchainwork.c $A/daemon/locator_build.c $A/daemon/archive_verify.c $A/daemon/reorg.c $A/daemon/mempool_persist.c $A/daemon/mempool_compact.c $A/daemon/mempool_cfg.c $A/daemon/fee_hooks.c $A/daemon/fee_estimator.c $A/daemon/zmq_notify.c $A/daemon/zmq_pub.c $A/bitcoin_taproot_sighash.c $A/bitcoin_pow_rules.c $A/daemon/utxo_live.c $A/daemon/block_witness.c $A/daemon/undo_log.c $A/daemon/node_config.c $A/daemon/tx_verify.c $A/bitcoin_scriptverify.c $A/bitcoin_txval_modern.c $A/bitcoin_witness_v0.c $A/bitcoin_segwit.c $A/wallet_core.c $A/bitcoin_mempool_policy.c $A/daemon/tx_submit.c $A/daemon/tx_relay.c $A/daemon/tx_index_tail.c $A/daemon/blk_submit.c $A/daemon/txosp_tail.c $A/daemon/tx_accept.c"
REALO="bitcoin_store.o bitcoin_store_fast.o bitcoin_idx.o bitcoin_idxscan.o bitcoin_chainwork.o bitcoin_hash.o sha256.o bitcoin_tx.o bitcoin_cons.o bitcoin_p2p.o bitcoin_net.o bitcoin_mempool.o bitcoin_utxo_lsm.o utxo_lsm_mm.o bitcoin_utxo_store.o bitcoin_utxo.o bitcoind.o bitcoin_headers.o bitcoin_interp.o bitcoin_scriptcodec.o bitcoin_script_flags.o bitcoin_sighash.o bitcoin_script.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o secp256k1_schnorr.o secp256k1_taproot.o ripemd160.o bitcoin_addr.o sha1.o bitcoin_utxo_stats.o bitcoin_muhash.o bitcoin_txv_pools.o secp256k1_glv.o secp256k1_glv_mul.o bitcoin_sighash_all_ext.o bitcoin_store_ext.o bech32.o bitcoin_bip32.o bitcoin_bip39.o bitcoin_hmac.o sha512.o bitcoin_keys.o node_log.o bitcoin_strip_witness.o bitcoin_cmpct.o bitcoin_sigops.o bitcoin_addrmgr.o"
gcc -no-pie -O2 -I$A -I$A/daemon -o /tmp/wv0_fad_drv ../../validation/wv0_fad_driver.c bitcoin_witness_v0_drv.o bitcoin_bip143.o $REALC $REALO -lpthread
echo "== $2 =="
/tmp/wv0_fad_drv
