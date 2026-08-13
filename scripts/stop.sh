#!/usr/bin/env bash
# 100% AI-generated
# Stop the Bitcoin node daemon

set -euo pipefail

echo "Stopping bitcoind..."
bitcoin-cli -datadir="${BITCOIN_DATA_DIR:-/storage/bitcoinmachinecode/data}" stop || \
  killall bitcoind

echo "Bitcoin node stopped."