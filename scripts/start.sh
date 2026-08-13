#!/usr/bin/env bash
# 100% AI-generated
# Start the Bitcoin node daemon

set -euo pipefail

BITCOIN_DATA_DIR="${BITCOIN_DATA_DIR:-/storage/bitcoinmachinecode/data}"
BITCOIN_CONF="${BITCOIN_CONF:-/storage/bitcoinmachinecode/config/bitcoin.conf}"

echo "Starting bitcoind..."
bitcoind \
  -daemon \
  -conf="$BITCOIN_CONF" \
  -datadir="$BITCOIN_DATA_DIR"

echo "Bitcoin node started. PID: $(pgrep bitcoind || echo 'checking...')"