#!/usr/bin/env bash
# formal/parsers/confirm/run.sh -- reproduce each CBMC divergence on the REAL
# compiled code: every driver is built with the tree's own C flags
# (asm/Makefile CFLAGS: -no-pie -O2 -fstack-protector-strong
# -D_FORTIFY_SOURCE=2 -Wall -Werror) against the unmodified product source
# (and, where a parser calls into NASM, the assembled object from make), then
# run on the concrete input the counterexample gave. Exits 0 when every
# finding reproduces. Builds and runs are memory-capped like the proofs.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../../.." && pwd)"
A="$ROOT/asm"; D="$A/daemon"; BIN="$HERE/bin"; mkdir -p "$BIN"
SCR="$(mktemp -d)"; trap 'rm -rf "$SCR"' EXIT
CF="-no-pie -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Werror -I$D -I$A"
capr(){ systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 timeout 120 "$@"; }
fails=0
one(){ local name="$1"; shift; local srcs="$1"; shift
  if ! capr gcc $CF -o "$BIN/$name" "$HERE/$name.c" $srcs >"$BIN/$name.build.log" 2>&1; then
    echo "BUILD-FAIL $name (see bin/$name.build.log)"; fails=$((fails+1)); return; fi
  echo "== $name"; if ! capr "$BIN/$name" "$SCR" "$@"; then fails=$((fails+1)); fi; }
# the NASM objects a driver links (built by the tree's own rule)
capr make -s -C "$A" bitcoin_addrmgr.o secp256k1_fe.o secp256k1_point_ct.o sha256.o secp256k1_point.o secp256k1_glv_c.o secp256k1_scalar.o chacha20_avx2.o >/dev/null || { echo "make of the asm objects failed"; exit 1; }
. "$HERE/cases.sh"
echo "confirm: failures: $fails"; [ $fails = 0 ]
