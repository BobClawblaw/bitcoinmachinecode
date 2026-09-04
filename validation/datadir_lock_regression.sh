#!/usr/bin/env bash
# datadir_lock_regression.sh -- DMN-1 (audit 2026-09-03): a second daemon on
# the same datadir must be refused, the way Core's LockDataDirectory refuses.
#
# WHY THIS IS A TEST AND NOT AN INSPECTION. Before the guard, BOTH instances
# booted completely (the audit reproduced it): both logged a download worker,
# and the only thing the second one could not do was bind the P2P port -- and
# the RPC bind failure is deliberately non-fatal, so it carried on. Boot then
# runs archive_trim_derived_tails, which truncate()s the index.dat /
# headers.dat / chainwork.dat tails from an index snapshot, zeroes duplicate
# records, and forks the worker that owns the single-writer LSM UTXO set.
# Instance B doing that under instance A's writer is how main.c's own
# 2026-08-31 note -- "a stale co-resident daemon was SIGKILLed and the
# survivor stopped applying blocks" -- comes about.
#
# regtest, so nothing dials the network and the run is hermetic.
#
# Exit 0 = the guard holds. Any other exit is a failure with a reason.
set -u
BIN="${BIN:-$(cd "$(dirname "$0")/.." && pwd)/asm/daemon/bitcoind}"
[ -x "$BIN" ] || { echo "FAIL: no daemon at $BIN (make daemon/bitcoind)"; exit 1; }

D=$(mktemp -d /tmp/dmn1lockXXXXXX) || exit 1
cleanup(){ [ -n "${A_PID:-}" ] && kill "$A_PID" 2>/dev/null; sleep 1;
           [ -n "${A_PID:-}" ] && kill -9 "$A_PID" 2>/dev/null; rm -rf "$D"; }
trap cleanup EXIT

printf 'regtest=1\n[regtest]\nlisten=0\ndnsseed=0\n' > "$D/bitcoin.conf"

fails=0
ck(){ if [ "$2" = "0" ]; then echo "ok  : $1"; else echo "FAIL: $1"; fails=$((fails+1)); fi; }

# ---- instance A: must boot and keep running ------------------------------
"$BIN" -conf="$D/bitcoin.conf" serve "$D" 19555 > "$D/a.log" 2>&1 &
A_PID=$!
sleep 5

kill -0 "$A_PID" 2>/dev/null; ck "instance A is running" $?
grep -q 'FATAL' "$D/a.log" && ck "instance A booted without a FATAL" 1 \
                           || ck "instance A booted without a FATAL" 0
[ -f "$D/regtest/.lock" ]; ck "instance A created <datadir>/regtest/.lock" $?

# ---- instance B: must be refused ----------------------------------------
"$BIN" -conf="$D/bitcoin.conf" serve "$D" 19556 > "$D/b.log" 2>&1
B_RC=$?

[ "$B_RC" = "1" ]; ck "instance B exits 1 (got $B_RC)" $?
grep -qi 'cannot obtain a lock on data directory' "$D/b.log"
ck "instance B prints Core's 'cannot obtain a lock on data directory'" $?
grep -q 'download worker pid' "$D/b.log"
if [ $? -eq 0 ]; then ck "instance B never reached the worker fork" 1
                 else ck "instance B never reached the worker fork" 0; fi

# ---- and the lock must be released when A goes away ----------------------
kill "$A_PID" 2>/dev/null; wait "$A_PID" 2>/dev/null; A_PID=
sleep 2
"$BIN" -conf="$D/bitcoin.conf" serve "$D" 19556 > "$D/c.log" 2>&1 &
C_PID=$!
sleep 5
kill -0 "$C_PID" 2>/dev/null
ck "a later instance boots once the first has exited (no stale lock)" $?
kill "$C_PID" 2>/dev/null; wait "$C_PID" 2>/dev/null

echo
if [ "$fails" = "0" ]; then echo "ALL CHECKS PASSED"; exit 0; fi
echo "$fails CHECK(S) FAILED"; exit 1
