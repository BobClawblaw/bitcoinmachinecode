#!/bin/bash
# build_daemon.sh -- native macOS bmcbitcoind link attempt (bmc_osx).
# Compiles every daemon-referenced C source natively (clang, arm64), links
# against the port/osx objects, and reports undefined symbols -- the exact
# remaining port gap.  Objects land in port/osx/daemon_out.
# Usage: build_daemon.sh [link|compile|clean]   (default: compile+link)
set -u
cd "$(dirname "$0")/../../asm"     # asm/
OUT=../port/osx/daemon_out
mkdir -p "$OUT"
CC="cc -O2 -arch arm64 -I. -Idaemon -Itests -I../port/osx/compat -D_DARWIN_C_SOURCE -Dst_mtim=st_mtimespec -Dst_atim=st_atimespec -Dst_ctim=st_ctimespec"
ERRLOG="$OUT/compile_errors.log"
: > "$ERRLOG"

# ---- version header ----
[ -f version_gen.h ] || python3 gen_version_header.py --out version_gen.h --version-inc version.inc

# ---- build stamp (rpc_node.c includes build_gen.h since the 09-10 RPC
# parity wave; mirror the x86 Makefile's build-stamp rule) ----
c=$(git -C .. rev-parse --short HEAD 2>/dev/null || echo unknown)
d=$(git -C .. diff --quiet HEAD 2>/dev/null && echo 0 || echo 1)
printf '/* build_gen.h -- GENERATED. Do not edit. */\n#ifndef BMC_BUILD_GEN_H\n#define BMC_BUILD_GEN_H\n#define BMC_BUILD_COMMIT "%s"\n#define BMC_BUILD_DIRTY %s\n#endif\n' "$c" "$d" > build_gen.h.tmp
cmp -s build_gen.h.tmp build_gen.h 2>/dev/null || mv build_gen.h.tmp build_gen.h
rm -f build_gen.h.tmp

# ---- the arch-neutral C the daemon links (from DAEMONSRCS + DAEMON_RPCOBJS) ----
CSRC=(
  daemon/main.c daemon/private_broadcast.c daemon/fee_estimator.c daemon/fee_hooks.c
  daemon/archive_reindex.c daemon/utxo_live.c daemon/lsm_manifest.c daemon/block_witness.c
  daemon/tx_accept.c daemon/zmq_notify.c daemon/zmq_pub.c daemon/reorg.c daemon/minchainwork.c
  daemon/notify.c daemon/undo_log.c daemon/locator_build.c daemon/archive_verify.c
  daemon/addr_ingest.c daemon/net_policy.c daemon/node_config.c daemon/netperm.c daemon/subnet.c
  daemon/ctl_dial.c daemon/chainparams.c daemon/mempool_cfg.c daemon/upload_cap.c daemon/tx_submit.c
  daemon/rpc_acl.c
  daemon/tx_relay.c daemon/tx_index_tail.c daemon/txosp_tail.c daemon/blk_submit.c
  daemon/utxo_setinfo_rpc.c daemon/coinstats_index.c daemon/addr_self.c daemon/bfilter_index.c
  daemon/serve_cfilters.c daemon/serve_addr.c daemon/serve_rejects.c daemon/addr_index_tail.c
  daemon/block_strip.c wallet_store.c bitcoin_mempool_policy.c daemon/mempool_compact.c
  bitcoin_txval_modern.c bitcoin_segwit.c bitcoin_taproot_sighash.c daemon/tx_verify.c
  bitcoin_scriptverify.c bitcoin_witness_v0.c wallet_msgsign.c daemon/serve_invbounds.c
  daemon/relay_policy.c daemon/wallet_pass.c daemon/v2transport.c crypto_bip324_transport.c
  crypto_bip324.c crypto_bip324_fs.c crypto_chacha20.c crypto_poly1305.c crypto_ellswift_ecdh.c
  crypto_ellswift.c crypto_ellswift_enc.c crypto_fe_sqrt.c daemon/stale_tip.c daemon/peer_timeout.c
  daemon/txann.c daemon/inbound_evict.c daemon/anchors.c daemon/archive_seed.c daemon/ibd_pipeline.c
  daemon/hdr_lowwork.c daemon/invalid_set.c daemon/cmpct_recv.c daemon/banlist.c
  daemon/addrbook.c daemon/addr_hist.c daemon/netaddr.c
  daemon/asmap.c daemon/dialer.c
  daemon/socks5.c daemon/torcontrol.c daemon/serve_hdrctx.c bitcoin_sha3.c daemon/i2psam.c daemon/net6.c

  daemon/ctl_dial.c
  rpc_server.c rpc_esplora.c rest.c daemon/rpc_acl.c crypto_hkdf.c rpc_commands.c rpc_chain.c
  bitcoin_pow_rules.c block_filter.c utxo_snapshot.c rpc_signer.c bip32_ckdpub.c descriptor.c
  psbt_update.c miniscript.c miniscript_sign.c bip340_sign.c musig2.c rpc_json.c rpc_net.c
  rpc_node.c daemon/mempool_persist.c rpc_wallet_ops.c wallet_labels.c wallet_scan.c
  wallet_scan_hash.c wallet_txlog.c daemon/wallet_enc_state.c daemon/wallet_crypter.c
  bitcoin_aes.c wallet_bnb.c wallet_coinsel.c wallet_core.c
  secp256k1_glv_c.c secp256k1_scalar_c.c
  # signet sources (SIGNETSRCS) -- check Makefile if these change
)
# discover SIGNETSRCS from the Makefile
SIGNET=$(grep -m1 '^SIGNETSRCS' Makefile | sed 's/^SIGNETSRCS *:= *//' | tr ' ' '\n' | grep '\.c$')
for f in $SIGNET; do CSRC+=("$f"); done

fail=0
for f in "${CSRC[@]}"; do
  obj="$OUT/$(basename ${f%.c}).o"
  if [ ! -f "$obj" ] || [ "$f" -nt "$obj" ]; then
    if ! $CC -c -o "$obj" "$f" 2>>"$ERRLOG"; then
      echo "COMPILE FAIL: $f" | tee -a "$ERRLOG"
      fail=1
    fi
  fi
done
if [ "${1:-}" = "compile" ]; then exit $fail; fi

# ---- compile every port/osx twin/asm module into an object ----
# bitcoin_hmac_c.c excluded: reference-only C twin, duplicates bitcoin_hmac.S
for f in ../port/osx/*.c ../port/osx/*.S; do
  case "$f" in *bitcoin_hmac_c.c) continue;; esac
  base=$(basename "$f"); obj="$OUT/px_${base%.*}.o"
  if [ ! -f "$obj" ] || [ "$f" -nt "$obj" ]; then
    if ! $CC -c -o "$obj" "$f" 2>>"$ERRLOG"; then echo "PORTOBJ FAIL: $f" >> "$ERRLOG"; fi
  fi
done
# secp256k1_glv_c + scalar_c built already via CSRC; bitcoin_tx.S etc. included above
# NOTE: bitcoin_net/bitcoin_p2p/bitcoin_headers/bitcoin_addrmgr/bitcoin_idx/
# bitcoin_store*/bitcoin_utxo* are covered by the C twins in port/osx (they
# compiled above as px_* objects); the x86 .asm versions are NOT rebuilt.

# ---- addrbook archive from the osx-compiled object ----
ar rcs "$OUT/addrbook.a" "$OUT/addrbook.o" 2>>"$ERRLOG" || { echo "ar fail"; exit 1; }

# ---- port/osx objects (asm + twins) ----
OSXOBJS=$(ls ../port/osx/*.o 2>/dev/null | grep -v daemon_out)

# ---- link ----
ALLOBJ="$OUT/"*.o
$CC -o "$OUT/bmcbitcoind" $ALLOBJ "$OUT/addrbook.a" -lpthread 2> "$OUT/link_errors.log"
rc=$?
if [ $rc -ne 0 ]; then
  echo "--- undefined symbols:"
  grep -o "undefined symbol[s]* for architecture arm64:.*" "$OUT/link_errors.log" | head -1
  grep -o '^  "_[A-Za-z0-9_]*"' "$OUT/link_errors.log" | sort -u | head -80
  grep -c "Undefined symbols" "$OUT/link_errors.log"
else
  echo "LINK OK: $OUT/bmcbitcoind"
fi
exit $rc
