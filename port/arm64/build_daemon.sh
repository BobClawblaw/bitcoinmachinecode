#!/bin/bash
# Native AArch64 build of the x86 serve daemon (daemon/bitcoind).
# Mirrors asm/Makefile's daemon/bitcoind rule exactly, but compiles the
# ported .S objects natively and the arch-neutral daemon C with gcc.
set -u
cd "$(dirname "$0")"            # port/arm64
mkdir -p daemon_out
LOG=daemon_out/build.log
: > "$LOG"

# ---- 1. DAEMONOBJS: build each asm object natively (.S port, else x86 C) ----
DAEMONOBJS="sha256 bitcoin_hash bitcoin_net bitcoin_p2p bitcoin_tx bitcoin_cons bitcoin_store bitcoind node_log bitcoin_headers bitcoin_addrmgr bitcoin_idx bitcoin_serve bitcoin_mempool bitcoin_sigops bitcoin_cmpct bitcoin_idxscan bitcoin_utxo_lsm utxo_lsm_mm bitcoin_utxo_store bitcoin_utxo bitcoin_store_fast secp256k1_schnorr secp256k1_taproot bitcoin_script bitcoin_sighash bitcoin_pubkey secp256k1_ecdsa secp256k1_point secp256k1_glv_c secp256k1_point_ct secp256k1_glv secp256k1_glv_mul secp256k1_fe secp256k1_scalar secp256k1_scalar_c ripemd160 bitcoin_addr bitcoin_chainwork bitcoin_interp bitcoin_scriptcodec bitcoin_script_flags sha1 bitcoin_utxo_stats bitcoin_muhash bitcoin_strip_witness bitcoin_store_ext bech32 bitcoin_bip32 bitcoin_bip39 bitcoin_hmac sha512 bitcoin_keys bitcoin_sighash_all_ext"
FAIL=0
for m in $DAEMONOBJS; do
    src=""
    if [ -f "$m.S" ]; then src="$m.S"; 
    elif [ -f "../../asm/$m.c" ]; then src="../../asm/$m.c";
    else echo "NO SOURCE for $m" >> "$LOG"; FAIL=1; continue; fi
    if [ ! -f "$m.o" ] || [ "$src" -nt "$m.o" ]; then
        gcc -no-pie -O2 -march=armv8.2-a+sha2 -I../../asm -I../../asm/daemon -c "$src" -o "$m.o" >>"$LOG" 2>&1 \
          || { echo "OBJECT FAIL $m" >> "$LOG"; FAIL=1; }
    fi
done

# ---- 2. DAEMONSRCS + DAEMON_RPCOBJS + main + wallet_core: single native link ----
DAEMONSRCS="../../asm/daemon/main.c ../../asm/daemon/utxo_live.c ../../asm/daemon/block_witness.c ../../asm/daemon/tx_accept.c ../../asm/daemon/zmq_notify.c ../../asm/daemon/zmq_pub.c ../../asm/daemon/reorg.c ../../asm/daemon/undo_log.c ../../asm/daemon/locator_build.c ../../asm/daemon/archive_verify.c ../../asm/daemon/addr_ingest.c ../../asm/daemon/net_policy.c ../../asm/daemon/node_config.c ../../asm/daemon/chainparams.c ../../asm/daemon/mempool_cfg.c ../../asm/daemon/upload_cap.c ../../asm/daemon/tx_submit.c ../../asm/daemon/tx_relay.c ../../asm/daemon/tx_index_tail.c ../../asm/daemon/blk_submit.c ../../asm/daemon/utxo_setinfo_rpc.c ../../asm/daemon/coinstats_index.c ../../asm/daemon/addr_self.c ../../asm/daemon/bfilter_index.c ../../asm/daemon/addr_index_tail.c ../../asm/daemon/block_strip.c ../../asm/wallet_store.c ../../asm/bitcoin_mempool_policy.c ../../asm/daemon/mempool_compact.c ../../asm/bitcoin_txval_modern.c ../../asm/bitcoin_segwit.c ../../asm/bitcoin_taproot_sighash.c ../../asm/daemon/tx_verify.c ../../asm/bitcoin_scriptverify.c ../../asm/bitcoin_witness_v0.c ../../asm/daemon/serve_cfilters.c ../../asm/wallet_msgsign.c"
RPCSRCS="../../asm/rpc_server.c ../../asm/rpc_commands.c ../../asm/rpc_chain.c ../../asm/bitcoin_pow_rules.c ../../asm/block_filter.c ../../asm/utxo_snapshot.c ../../asm/rpc_signer.c ../../asm/bip32_ckdpub.c ../../asm/rpc_json.c ../../asm/rpc_net.c ../../asm/rpc_node.c ../../asm/daemon/mempool_persist.c ../../asm/rpc_wallet_ops.c ../../asm/wallet_labels.c ../../asm/wallet_scan.c ../../asm/wallet_scan_hash.c ../../asm/daemon/wallet_enc_state.c ../../asm/daemon/wallet_crypter.c ../../asm/bitcoin_aes.c ../../asm/wallet_txlog.c ../../asm/wallet_bnb.c"

OBJBUNDLE="$DAEMONOBJS"
# ---- 3. NEWSRCS: C files added by main since the ARM build was written ----
# (all arch-neutral C: addrbook, netaddr/net6, asmap, dialer/proxies, netperm,
#  rpc_acl, notify, signet, reorg-min-work, subnet, torcontrol, v2transport,
#  txrecon, wallet_pass + the BIP324/crypto primitives they pull in)
NEWSRCS="../../asm/daemon/addrbook.c ../../asm/daemon/asmap.c ../../asm/daemon/dialer.c ../../asm/daemon/i2psam.c ../../asm/daemon/minchainwork.c ../../asm/daemon/net6.c ../../asm/daemon/netaddr.c ../../asm/daemon/netperm.c ../../asm/daemon/notify.c ../../asm/daemon/serve_addr.c ../../asm/daemon/serve_invbounds.c ../../asm/daemon/signet.c ../../asm/daemon/signet_block.c ../../asm/daemon/signet_verify.c ../../asm/daemon/socks5.c ../../asm/daemon/subnet.c ../../asm/daemon/torcontrol.c ../../asm/daemon/txrecon.c ../../asm/daemon/v2transport.c ../../asm/daemon/wallet_pass.c ../../asm/base32.c ../../asm/bitcoin_sha3.c ../../asm/crypto_chacha20.c ../../asm/crypto_hkdf.c ../../asm/crypto_poly1305.c ../../asm/crypto_ellswift.c ../../asm/crypto_ellswift_ecdh.c ../../asm/crypto_ellswift_enc.c ../../asm/crypto_fe_sqrt.c ../../asm/crypto_bip324.c ../../asm/crypto_bip324_fs.c ../../asm/crypto_bip324_transport.c ../../asm/daemon/rpc_acl.c ../../asm/daemon/cli_conf.c ../../asm/daemon/lsm_manifest.c ../../asm/daemon/archive_reindex.c"
gcc -no-pie -O2 -lpthread -I../../asm -I../../asm/daemon -I../.. \
    -o daemon_out/bitcoind $DAEMONSRCS $RPCSRCS $NEWSRCS ../../asm/wallet_core.c \
    $(for m in $OBJBUNDLE; do echo "${m}.o"; done) 2>> "$LOG"
RC=$?
echo "=== LINK RC=$RC ===" >> "$LOG"
echo "=== undefined symbols (first 60) ===" >> "$LOG"
grep -aoE 'undefined reference to `[^'"'"']+'"'"'' "$LOG" | sort -u | head -60 >> "$LOG"
echo "BUILD DONE rc=$RC (see $LOG)"