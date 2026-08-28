#!/bin/bash
# addrv2_diffs.sh -- build + run the BIP155 addrv2 oracle (asm vs Core bytes)
set -e
cd "$(cd "$(dirname "$0")" && pwd)"
A=../../asm
INC="-I$A/tests -I$A -I$A/daemon"
# test_addrmgr: address-book codec (v1 + v2) pinned to Core's serialize bytes
gcc -no-pie -O2 $INC -o ./test_addrmgr_arm $A/tests/test_addrmgr.c bitcoin_addrmgr.o
./test_addrmgr_arm | tail -1
# test_addrv2_serve: full end-to-end addrv2 negotiation + getaddr v1/v2 reply
CS="daemon/tx_accept.c daemon/tx_verify.c daemon/zmq_notify.c daemon/zmq_pub.c daemon/mempool_cfg.c daemon/node_config.c bitcoin_mempool_policy.c daemon/mempool_compact.c bitcoin_scriptverify.c bitcoin_txval_modern.c bitcoin_witness_v0.c bitcoin_segwit.c bitcoin_taproot_sighash.c daemon/block_strip.c tests/txacc_bidx_stub.c bitcoin_pow_rules.c"
OBJ="bitcoin_serve.o bitcoin_idx.o bitcoin_net.o bitcoin_p2p.o bitcoin_script_flags.o bitcoin_strip_witness.o bitcoin_store.o bitcoin_store_ext.o bitcoind.o bitcoin_headers.o bitcoin_hash.o bitcoin_addrmgr.o node_log.o bitcoin_tx.o bitcoin_cons.o sha256.o bitcoin_mempool.o bitcoin_cmpct.o bitcoin_idxscan.o bitcoin_utxo_lsm.o utxo_lsm_mm.o bitcoin_utxo_store.o bitcoin_utxo.o secp256k1_schnorr.o secp256k1_taproot.o bitcoin_script.o bitcoin_sighash.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_glv_c.o secp256k1_point_ct.o secp256k1_fe.o secp256k1_scalar.o secp256k1_scalar_c.o bitcoin_bip341.o bitcoin_taproot_verify.o bitcoin_tapagg.o bitcoin_txv_dispatch.o bitcoin_txv_pools.o bitcoin_chainwork.o ripemd160.o sha1.o bitcoin_addr.o bitcoin_keys.o bitcoin_interp.o bitcoin_sigops.o bitcoin_scriptcodec.o"
for m in $(for o in $OBJ; do echo ${o%.o}; done); do
  if [ ! -f "$m.o" ] && [ -f "$m.S" ]; then gcc -c -march=armv8.2-a+sha2 -o "$m.o" "$m.S"; fi
done
C_BASE=$(printf '%s\n' $(for f in $CS; do echo "$A/$f"; done))
gcc -no-pie -O2 $INC -o ./test_addrv2_serve_arm $A/tests/test_addrv2_serve.c $C_BASE $OBJ -lpthread
./test_addrv2_serve_arm | tail -1
