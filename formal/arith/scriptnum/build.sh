#!/usr/bin/env bash
# Assemble/link the REAL interpreter objects into .build/ (never via make in asm/).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
a=$(cd "$here/../../../asm" && pwd)
. "$here/../lib/runlib.sh"
b=$here/.build; mkdir -p "$b"
OBJS="bitcoin_interp bitcoin_scriptcodec bitcoin_sighash bitcoin_sigops bitcoin_tx bitcoin_hash ripemd160 sha1 sha256"
for f in $OBJS; do
    _lim timeout 300 nasm -f elf64 -I"$a/" -Werror -o "$b/$f.o" "$a/$f.asm"
done
o=(); for f in $OBJS; do o+=("$b/$f.o"); done
_lim timeout 300 gcc -no-pie -O2 -Wall -Werror -o "$b/sn_diff" "$here/sn_diff.c" "${o[@]}"
_lim timeout 300 gcc -no-pie -O2 -o "$b/lift_bin" "$here/lift_main.c" "$b/bitcoin_scriptcodec.o"
