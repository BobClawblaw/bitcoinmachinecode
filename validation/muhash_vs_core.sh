#!/bin/sh
# muhash_vs_core.sh -- is this node's UTXO set byte-identical to Bitcoin Core's?
#
# Asks our node for `gettxoutsetinfo muhash` (height, muhash, txouts,
# total_amount), then asks the Core oracle for the same at THAT height
# (the oracle runs coinstatsindex=1, so any height is answerable), and
# compares all four fields. Exit 0 only when both sides produced values AND
# every field matches. An empty side is a FAIL, never a PASS: on 2026-09-04
# validation/fresh_install_ibd.sh compared two empty strings and printed PASS.
# This script exists so the claim can be re-made, by anyone, at any time.
#
#   validation/muhash_vs_core.sh [-datadir=<ours>] [oracle-cli command...]
#
# Defaults: our datadir /storage/bitcoinmachinecode/data; oracle
# /storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli with
# /storage/core-oracle. Override the oracle with, e.g.:
#   validation/muhash_vs_core.sh -datadir=/x bitcoin-cli -datadir=/y
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
CLI="$HERE/asm/daemon/bmc_cli"
DD="/storage/bitcoinmachinecode/data"
case "${1:-}" in -datadir=*) DD="${1#-datadir=}"; shift;; esac
if [ $# -gt 0 ]; then ORACLE="$*"; else ORACLE="/storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli -conf=/storage/core-oracle/bitcoin.conf -datadir=/storage/core-oracle"; fi
[ -x "$CLI" ] || { echo "FAIL: no $CLI (build asm/daemon/bmc_cli)"; exit 2; }
O=$("$CLI" -datadir="$DD" gettxoutsetinfo muhash 2>&1) || { echo "FAIL: our gettxoutsetinfo failed: $(printf '%s' "$O" | head -1)"; exit 1; }
H=$(printf '%s' "$O" | python3 -c 'import sys,json; print(json.load(sys.stdin)["height"])' 2>/dev/null) || H=""
OM=$(printf '%s' "$O" | python3 -c 'import sys,json; r=json.load(sys.stdin); print(r["muhash"], r["txouts"], r.get("total_amount"))' 2>/dev/null) || OM=""
[ -n "$H" ] && [ -n "$OM" ] || { echo "FAIL: could not read our own gettxoutsetinfo (h='$H' ours='$OM')"; exit 1; }
C=$($ORACLE gettxoutsetinfo muhash "$H" 2>&1) || { echo "FAIL: the oracle failed at height $H: $(printf '%s' "$C" | head -1)"; exit 1; }
CM=$(printf '%s' "$C" | python3 -c 'import sys,json; r=json.load(sys.stdin); print(r["muhash"], r["txouts"], r.get("total_amount"))' 2>/dev/null) || CM=""
[ -n "$CM" ] || { echo "FAIL: the oracle returned nothing readable at height $H -- nothing was compared"; exit 1; }
echo "height $H"
echo "ours   $OM"
echo "oracle $CM"
if [ "$OM" = "$CM" ]; then echo "PASS: muhash, txouts and total_amount identical to Core at height $H"; exit 0
else echo "FAIL: differs from Core at height $H"; exit 1; fi
