#!/usr/bin/env bash
# Assemble/compile the REAL product objects the PoW checks run, into .build/
# (never via make in asm/, so nothing in the product tree is touched).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
a=$(cd "$here/../../../asm" && pwd)
. "$here/../lib/runlib.sh"
b=$here/.build; mkdir -p "$b"
for f in bitcoin_hash bitcoin_chainwork sha256; do
    _lim timeout 300 nasm -f elf64 -I"$a/" -Werror -o "$b/$f.o" "$a/$f.asm"
done
_lim timeout 300 gcc -no-pie -O2 -Wall -Werror -c -o "$b/bitcoin_pow_rules.o" "$a/bitcoin_pow_rules.c"
_lim timeout 300 gcc -no-pie -O2 -Wall -Werror -I"$here" -o "$b/diff_pow" "$here/diff_pow.c" \
    "$b/bitcoin_hash.o" "$b/bitcoin_chainwork.o" "$b/sha256.o" "$b/bitcoin_pow_rules.o"
_lim timeout 300 gcc -no-pie -O2 -Wall -Werror -Wno-unused-function -I"$here" -o "$b/confirm_p3c" "$here/confirm_p3c.c" "$b/bitcoin_pow_rules.o"
