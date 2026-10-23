#!/bin/bash
# Build crash_storage against the worktree's real objects (the link set of
# asm/Makefile's tests/test_utxo_ghost_resume). Usage: build.sh <out-binary>
set -e
here=$(cd "$(dirname "$0")" && pwd)
asm=$(cd "$here/../../../asm" && pwd)
out=$1
lim="systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice -n15 timeout 900"
$lim make -C "$asm" -j4 tests/test_utxo_ghost_resume >/dev/null
# the ghost test's own compile line, with its source swapped for ours
line=$(make -C "$asm" -n -B tests/test_utxo_ghost_resume | grep -E '^gcc .* -o tests/test_utxo_ghost_resume ')
line=${line/-o tests\/test_utxo_ghost_resume tests\/test_utxo_ghost_resume.c/-I$here -o $out $here/crash_storage.c}
cd "$asm" && $lim $line
