#!/usr/bin/env bash
# Assemble/compile the REAL product objects the limits differential tests
# run, into .build/ (never via make in asm/).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
a=$(cd "$here/../../../asm" && pwd)
. "$here/../lib/runlib.sh"
b=$here/.build; mkdir -p "$b"
for f in bitcoin_tx bitcoin_sigops bitcoin_scriptcodec bitcoin_cons bitcoin_hash sha256; do
    _lim timeout 300 nasm -f elf64 -I"$a/" -Werror -o "$b/$f.o" "$a/$f.asm"
done
CC="_lim timeout 300 gcc -no-pie -O2 -Wall -Werror"
$CC -o "$b/cs_txparse_diff" "$here/cs/cs_txparse_diff.c" "$b/bitcoin_tx.o" "$b/bitcoin_hash.o" "$b/sha256.o"
$CC -o "$b/sg_diff" "$here/sigops/sg_diff.c" "$b/bitcoin_sigops.o" "$b/bitcoin_scriptcodec.o"
$CC -o "$b/empty_block_confirm" "$here/weight/empty_block_confirm.c" \
    "$b/bitcoin_cons.o" "$b/bitcoin_hash.o" "$b/bitcoin_tx.o" "$b/sha256.o"
