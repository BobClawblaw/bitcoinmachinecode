#!/bin/sh
# Build Core's script evaluator / verifier / signer as line oracles (see the
# two .cpp files). Needs the scratch Core source + CMake build; not in the gate.
set -e
CORE=${CORE:-/storage/bitcoin-core-source}; B=${COREBUILD:-$CORE/build-zmq}
cd "$(dirname "$0")"
LIBS="$B/lib/libbitcoin_clientversion.a $B/lib/libbitcoin_consensus.a $B/lib/libbitcoin_common.a $B/lib/libbitcoin_util.a $B/lib/libbitcoin_crypto.a $B/src/secp256k1/lib/libsecp256k1.a"
for t in core_script_oracle core_verify_oracle; do
  g++ -std=c++20 -O2 -I "$CORE/src" -I "$B/src" -o $t $t.cpp $LIBS $B/lib/libbitcoin_consensus.a $B/lib/libbitcoin_util.a -lpthread
  echo "built $(pwd)/$t"
done
