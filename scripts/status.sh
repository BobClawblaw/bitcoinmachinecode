#!/usr/bin/env bash
# 100% AI-generated
# Check Bitcoin node status

set -euo pipefail

BITCOIN_DATA_DIR="${BITCOIN_DATA_DIR:-/storage/bitcoinmachinecode/data}"

if pgrep bitcoind > /dev/null; then
  echo "bitcoind is RUNNING"
  bitcoin-cli -datadir="$BITCOIN_DATA_DIR" getblockchaininfo
else
  echo "bitcoind is STOPPED"
fi