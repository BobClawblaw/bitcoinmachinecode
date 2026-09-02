#!/bin/sh
# Build Core's script evaluator as a line oracle (see core_script_oracle.cpp).
# Needs the scratch Core source + CMake build; not part of the gate.
set -e
CORE=${CORE:-/storage/bitcoin-core-source}; B=${COREBUILD:-$CORE/build-zmq}
cd "$(dirname "$0")"
g++ -std=c++20 -O2 -I "$CORE/src" -I "$B/src" -o core_script_oracle core_script_oracle.cpp \
  "$B/lib/libbitcoin_consensus.a" "$B/lib/libbitcoin_util.a" "$B/lib/libbitcoin_crypto.a" \
  "$B/src/secp256k1/lib/libsecp256k1.a" -lpthread
echo "built $(pwd)/core_script_oracle"
