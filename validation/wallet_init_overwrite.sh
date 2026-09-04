#!/usr/bin/env bash
# wallet_init_overwrite.sh -- WAL-5 (audit 2026-09-03): `wallet_cli init` must
# not silently replace an existing wallet.
#
# init generated a fresh mnemonic and truncated the destination
# UNCONDITIONALLY. Worse, on the encrypted branch wallet_store.c opens the file
# "w" and then remove()s it BEFORE the sealed write, so a failure there --
# /dev/urandom unavailable, disk full -- left NO wallet at all.
#
# An operator re-running init out of muscle memory, from a script, or to
# "re-encrypt" a funded wallet lost the old mnemonic with no prompt and no
# backup. createwallet over RPC already checked for existence; the CLI, which
# is what a human runs by hand, did not.
#
# Three checks, because the refusal alone is not the property: the wallet must
# also be BYTE-IDENTICAL afterwards (a refusal that still truncated would pass
# a "returns non-zero" test), and --force must still work so scripted
# re-initialisation remains possible.
set -u
BIN="${BIN:-$(cd "$(dirname "$0")/.." && pwd)/asm/daemon/wallet_cli}"
[ -x "$BIN" ] || { echo "FAIL: no wallet_cli at $BIN (make daemon/wallet_cli)"; exit 1; }

D=$(mktemp -d /tmp/wal5XXXXXX) || exit 1
trap 'rm -rf "$D"' EXIT
W="$D/w.dat"

fails=0
ck(){ if [ "$2" = "0" ]; then echo "ok  : $1"; else echo "FAIL: $1"; fails=$((fails+1)); fi; }

"$BIN" init "" "$W" >/dev/null 2>&1
[ -f "$W" ]; ck "a fresh init creates the wallet" $?
before=$(md5sum "$W" | cut -d' ' -f1)

out=$("$BIN" init "" "$W" 2>&1)
echo "$out" | grep -q "already exists"
ck "a second init is REFUSED and says why" $?

after=$(md5sum "$W" | cut -d' ' -f1)
[ "$before" = "$after" ]
ck "the existing wallet is byte-identical afterwards (not truncated)" $?

"$BIN" init "" "$W" --force >/dev/null 2>&1
forced=$(md5sum "$W" | cut -d' ' -f1)
[ "$before" != "$forced" ]
ck "--force does replace it (scripted re-init still possible)" $?

# ---- WAL-4: the write is durable and never world-readable ----------------
# store_write_atomic had no fsync at all, and the plaintext branch did not use
# it: it fopen()ed the FINAL path and chmod'ed 0600 only AFTER writing the
# mnemonic. So the seed phrase existed world-readable, and a power loss during
# the unattended v2->v3 upgrade at boot could leave a zero-length wallet where
# the only copy had been.
W2="$D/w2.dat"
if command -v strace >/dev/null 2>&1; then
    strace -f -e trace=fsync,rename,openat -o "$D/tr.txt"         "$BIN" init "" "$W2" >/dev/null 2>&1
    grep -q 'fsync' "$D/tr.txt"
    ck "WAL-4 the wallet write issues fsync (it used to issue none)" $?
    grep -qE 'openat.*w2\.dat\.tmp.*0600' "$D/tr.txt"
    ck "WAL-4 the temp file is created 0600, not chmod'ed after the write" $?
    # fsync must come before the rename that publishes it
    fl=$(grep -n 'fsync' "$D/tr.txt" | head -1 | cut -d: -f1)
    rl=$(grep -n 'rename' "$D/tr.txt" | head -1 | cut -d: -f1)
    [ -n "$fl" ] && [ -n "$rl" ] && [ "$fl" -lt "$rl" ]
    ck "WAL-4 the fsync precedes the rename that publishes it" $?
else
    echo "skip: strace unavailable -- cannot observe the syscalls"
fi
[ "$(stat -c '%a' "$W2" 2>/dev/null)" = "600" ]
ck "WAL-4 the finished wallet is mode 0600" $?

echo
if [ "$fails" = "0" ]; then echo "ALL CHECKS PASSED"; exit 0; fi
echo "$fails CHECK(S) FAILED"; exit 1
