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

echo
if [ "$fails" = "0" ]; then echo "ALL CHECKS PASSED"; exit 0; fi
echo "$fails CHECK(S) FAILED"; exit 1
