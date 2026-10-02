#!/usr/bin/env bash
# validation/ecdh_core_diff.sh -- build validation/ecdh_core_diff.c against
# Core v31.1's libsecp256k1 and our objects, and run it: the constant-time
# k*P multiplies and the BIP324 ECDH compared with Core's, then timed on one
# pinned core. Usage: ecdh_core_diff.sh [random-cases] [cpu]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ASM="$HERE/../asm"
CORE="${CORE_SRC:-/storage/bitcoin-core-v31.1/source}"
LIB="$CORE/build/src/secp256k1/lib/libsecp256k1.a"
INC="$CORE/src/secp256k1/include"
[ -f "$LIB" ] || { echo "no libsecp256k1.a at $LIB (set CORE_SRC)"; exit 2; }
OUT="${TMPDIR:-/tmp}/ecdh_core_diff.$$"
make -s -C "$ASM" secp256k1_fe.o secp256k1_point.o secp256k1_point_ct.o secp256k1_glv_c.o \
    secp256k1_scalar.o sha256.o bitcoin_hash.o
cd "$ASM"
gcc -no-pie -O2 -Wall -Werror -I"$INC" -I. -o "$OUT" "$HERE/ecdh_core_diff.c" \
    crypto_ellswift_ecdh.c crypto_ellswift.c crypto_ellswift_enc.c crypto_fe_sqrt.c \
    secp256k1_fe.o secp256k1_point.o secp256k1_point_ct.o secp256k1_glv_c.o secp256k1_scalar.o \
    sha256.o bitcoin_hash.o "$LIB"
rc=0; "$OUT" "${1:-20000}" "${2:-2}" || rc=$?
rm -f "$OUT"
exit $rc
