#!/usr/bin/env bash
# validation/serve_rules_regtest_e2e.sh -- the 2026-10-24 serve and
# mempool.dat changes, end to end against real Bitcoin Core v31.1 nodes on
# regtest.
#
#     Core A (wallet, miner, listens)  <-- outbound leg --  bmc  <-- inbound --  Core B
#
# B has connect= bmc only, so everything B learns came through bmc. Checks:
#   1. a block mined at the tip reaches B, and bmc serves it to B as a
#      cmpctblock when B asks for one (B's debug=net log); a block 6 or more
#      below the tip is not served compact (the unit test covers that side);
#   2. a reorg: A invalidates its tip-1 and mines a longer branch; bmc
#      reorgs, and B -- whose locator still names the old branch -- follows
#      bmc onto the new branch (best hash equal to A's);
#   3. mempool.dat torn inside its last transaction: bmc restarted on it
#      (with no peers, so nothing re-relays) loads every transaction before
#      the cut, as Core's LoadMempool keeps what it read;
#   4. -minimumchainwork above bmc's chain work: a fresh Core C that can
#      only reach bmc gets an empty headers message and stays at height 0;
#      with whitelist=download@127.0.0.1 the same C syncs to bmc's tip.
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-v31.1/bin}
ROOT=${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
BMC_BIN=${BMC_BIN:-$ROOT/asm/daemon/bmcbitcoind}
WORK=${WORK:-${CLAUDE_JOB_DIR:-/tmp}/tmp/serve-rules/e2e-$$}
# Core binds an onion listener on P2P+1 even with listenonion=0 and no bind=
PB=${PORT_BASE:-22200}; A_P2P=$((PB+0)); A_RPC=$((PB+2)); BMC_P2P=$((PB+4)); BMC_RPC=$((PB+5))
B_P2P=$((PB+6)); B_RPC=$((PB+8)); C_P2P=$((PB+10)); C_RPC=$((PB+12))
A_DIR=$WORK/core-a; B_DIR=$WORK/core-b; C_DIR=$WORK/core-c; BMC_DIR=$WORK/bmc
WAIT=${WAIT:-90}
FAILURES=0; PASSES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; PASSES=$((PASSES+1)); }
ca(){ "$CORE_BIN/bitcoin-cli" -datadir="$A_DIR" -rpcport=$A_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
caw(){ ca -rpcwallet=w "$@"; }
cb(){ "$CORE_BIN/bitcoin-cli" -datadir="$B_DIR" -rpcport=$B_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
cc(){ "$CORE_BIN/bitcoin-cli" -datadir="$C_DIR" -rpcport=$C_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmc(){ curl -s -m 10 --user e2e:e2epw -H 'content-type:text/plain' --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$1\",\"params\":${2:-[]}}" http://127.0.0.1:$BMC_RPC/; }
res(){ python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["result"] if not d.get("error") else "ERR "+d["error"]["message"])' 2>/dev/null; }
BMC_PID=""
bmc_stop(){ [ -n "$BMC_PID" ] || return 0; kill "$BMC_PID" 2>/dev/null
            for i in $(seq 60); do kill -0 "$BMC_PID" 2>/dev/null || break; sleep 1; done; BMC_PID=""; }
cleanup(){ bmc_stop; cc stop >/dev/null 2>&1; cb stop >/dev/null 2>&1; ca stop >/dev/null 2>&1; sleep 2; [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
for port in $A_P2P $A_RPC $BMC_P2P $BMC_RPC $B_P2P $B_RPC $C_P2P $C_RPC; do ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }; done
mkdir -p "$A_DIR" "$B_DIR" "$C_DIR" "$BMC_DIR"

core_conf(){ printf 'regtest=1\n[regtest]\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlistenonion=0\ndebug=net\nfallbackfee=0.0002\n%b' "$1" "$2" "$3"; }
core_conf $A_P2P $A_RPC 'listen=1\n' > "$A_DIR/bitcoin.conf"
core_conf $B_P2P $B_RPC "connect=127.0.0.1:$BMC_P2P\n" > "$B_DIR/bitcoin.conf"
core_conf $C_P2P $C_RPC "connect=127.0.0.1:$BMC_P2P\n" > "$C_DIR/bitcoin.conf"
# bmc's conf: $1 = extra lines
bmc_conf(){ printf 'chain=regtest\nprinttoconsole=1\n[regtest]\nport=%s\nrpcport=%s\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=1\nlistenonion=0\n%b' \
                   $BMC_P2P $BMC_RPC "$1" > "$BMC_DIR/bitcoin.conf"; }
bmc_start(){ ( cd "$ROOT/asm" && exec "$BMC_BIN" serve "$BMC_DIR" >> "$WORK/bmc.log" 2>&1 ) & BMC_PID=$!
             for i in $(seq 60); do [ -n "$(bmc getblockcount | res)" ] && return 0; sleep 1; done; echo "bmc RPC never came up"; tail -20 "$WORK/bmc.log"; exit 2; }
same_tip(){ [ "$("$@" getbestblockhash 2>/dev/null)" = "$(ca getbestblockhash)" ]; }
wait_tip(){ for i in $(seq $WAIT); do same_tip "$@" && return 0; sleep 1; done; return 1; }

"$CORE_BIN/bitcoind" -datadir="$A_DIR" -daemon >/dev/null 2>&1
for i in $(seq 40); do ca getblockcount >/dev/null 2>&1 && break; sleep 1; done
ca getblockcount >/dev/null 2>&1 || { echo "core A never came up"; exit 2; }
caw createwallet w >/dev/null 2>&1 || ca createwallet w >/dev/null
ADDR=$(caw getnewaddress)
caw generatetoaddress 120 "$ADDR" >/dev/null
echo "== Core A at $(ca getblockcount)"
bmc_conf "connect=127.0.0.1:$A_P2P\n"
bmc_start
for i in $(seq 120); do [ "$(bmc getblockcount | res)" = "$(ca getblockcount)" ] && break; sleep 1; done
[ "$(bmc getblockcount | res)" = "$(ca getblockcount)" ] || { echo "bmc never synced (tip $(bmc getblockcount | res))"; tail -20 "$WORK/bmc.log"; exit 2; }
"$CORE_BIN/bitcoind" -datadir="$B_DIR" -daemon >/dev/null 2>&1
wait_tip cb || { echo "core B never synced through bmc"; exit 2; }
echo "== bmc and Core B at $(cb getblockcount)"

echo "== 1. a block at the tip, served to B"
B_LOG=$B_DIR/regtest/debug.log
caw sendtoaddress "$(caw getnewaddress)" 1.0 >/dev/null
caw generatetoaddress 1 "$ADDR" >/dev/null
wait_tip cb && ok "B followed bmc to $(cb getblockcount)" || fail "B did not reach A's tip through bmc"
# B chooses the form it asks for; report what bmc answered (not a check)
if grep -aq "received: cmpctblock" "$B_LOG"; then echo "  note: bmc served B a cmpctblock (B's log)"
else echo "  note: B fetched the tip as a full block"; fi

echo "== 2. a reorg, followed by B through bmc"
OLD=$(cb getbestblockhash); OLDH=$(ca getblockcount)   # the old branch's tip as B holds it
ca invalidateblock "$(ca getblockhash $((OLDH - 1)))" >/dev/null
# a fresh address: mined to $ADDR in the same second, the first new block
# would be the invalidated one again (same coinbase, same txs), and Core
# refuses a block it holds as invalid
caw generatetoaddress 3 "$(caw getnewaddress)" >/dev/null
echo "  A: invalidated $((OLDH - 1)), new branch to $(ca getblockcount)"
bmc_best(){ bmc getbestblockhash | res; }
# 240 s, not $WAIT: with one quiet peer the reorg waits for the worker's
# probe, one every 30 s. Until 2026-10-25 the probe was deferred while no
# leg had received anything for 20 s, and on regtest that held for two
# minutes (122 s on the 2026-10-25 production build; 32 s since).
t0=$(date +%s)
for i in $(seq 240); do [ "$(bmc_best)" = "$(ca getbestblockhash)" ] && break; sleep 1; done
[ "$(bmc_best)" = "$(ca getbestblockhash)" ] && ok "bmc reorged onto A's new branch (after $(( $(date +%s) - t0 )) s)" || fail "bmc did not reorg (tip $(bmc_best))"
wait_tip cb && ok "B followed bmc onto the new branch ($(cb getblockcount), best hash = A's)" \
    || fail "B is not on A's branch: $(cb getbestblockhash) at $(cb getblockcount)"
[ "$(cb getblockheader "$OLD" 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin)["confirmations"])' 2>/dev/null)" = "-1" ] \
    && ok "the old tip is off B's active chain" || fail "the old tip is still on B's chain"

echo "== 3. mempool.dat torn inside its last transaction"
for i in 1 2 3 4 5; do caw sendtoaddress "$(caw getnewaddress)" 0.1 >/dev/null; done
N=0
for i in $(seq $WAIT); do N=$(bmc getmempoolinfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["size"])' 2>/dev/null || echo 0)
                          [ "$N" -ge 5 ] 2>/dev/null && break; sleep 1; done
echo "  bmc's mempool holds $N"
bmc_stop
MPD=$(find "$BMC_DIR" -name mempool.dat | head -1)
if [ -z "$MPD" ] || [ "$N" -lt 2 ]; then fail "no mempool.dat after the stop, or too few transactions ($N)"
else
    SZ=$(stat -c %s "$MPD")
    # the file ends: ... last tx | time(8) delta(8) | delta-map count(1) | unbroadcast count(1)
    truncate -s $((SZ - 20)) "$MPD"
    echo "  $MPD: $SZ bytes, cut to $((SZ - 20)) (2 bytes into the last transaction's end)"
    bmc_conf "connect=0\n"
    bmc_start
    M=-1
    for i in $(seq 60); do M=$(bmc getmempoolinfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["size"])' 2>/dev/null || echo -1)
                           grep -aq 'mempool\] loaded' "$WORK/bmc.log" && break; sleep 1; done
    sleep 2; M=$(bmc getmempoolinfo | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["size"])' 2>/dev/null || echo -1)
    grep -a 'mempool.dat is malformed\|mempool\] loaded' "$WORK/bmc.log" | tail -2 | sed 's/^/  log: /'
    [ "$M" = $((N - 1)) ] && ok "restarted on the torn file: $M of $N loaded (all before the cut)" \
        || fail "restarted on the torn file: $M loaded, expected $((N - 1))"
    # importmempool on the same torn file: bmc answers what Core A answers
    cp "$MPD" "$WORK/torn-mempool.dat"
    imp(){ curl -s -m 30 --user e2e:e2epw -H 'content-type:text/plain' \
             --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"importmempool\",\"params\":[\"$WORK/torn-mempool.dat\"]}" \
             "http://127.0.0.1:$1/" | python3 -c 'import sys,json;e=json.load(sys.stdin).get("error");print(e and "%d %s" % (e["code"], e["message"]))' 2>/dev/null; }
    IB=$(imp $BMC_RPC); IA=$(imp $A_RPC)
    [ -n "$IA" ] && [ "$IB" = "$IA" ] && ok "importmempool of the torn file: bmc's error is Core's ($IA)" \
        || fail "importmempool of the torn file: bmc '$IB', Core '$IA'"
    bmc_stop
fi

echo "== 4. -minimumchainwork above bmc's chain"
bmc_conf "connect=0\nminimumchainwork=0000000000000000000000000000000000000000000000000000000001000000\n"
bmc_start
TIP=$(bmc getblockcount | res)
"$CORE_BIN/bitcoind" -datadir="$C_DIR" -daemon >/dev/null 2>&1
for i in $(seq 40); do cc getblockcount >/dev/null 2>&1 && break; sleep 1; done
C_LOG=$C_DIR/regtest/debug.log
for i in $(seq 30); do grep -aq 'received: headers (1 bytes)' "$C_LOG" && break; sleep 1; done
grep -aq 'received: headers (1 bytes)' "$C_LOG" && ok "C got an empty headers message from bmc (C's log)" \
    || fail "C never got an empty headers message"
sleep 5
[ "$(cc getblockcount)" = 0 ] && ok "C stays at height 0 (bmc at $TIP, below the floor)" || fail "C synced to $(cc getblockcount) from a below-floor bmc"
cc stop >/dev/null 2>&1; for i in $(seq 30); do cc getblockcount >/dev/null 2>&1 || break; sleep 1; done
bmc_stop
bmc_conf "connect=0\nminimumchainwork=0000000000000000000000000000000000000000000000000000000001000000\nwhitelist=download@127.0.0.1\n"
bmc_start
"$CORE_BIN/bitcoind" -datadir="$C_DIR" -daemon >/dev/null 2>&1
for i in $(seq 40); do cc getblockcount >/dev/null 2>&1 && break; sleep 1; done
for i in $(seq $WAIT); do [ "$(cc getblockcount 2>/dev/null)" = "$TIP" ] && break; sleep 1; done
[ "$(cc getblockcount)" = "$TIP" ] && ok "with whitelist=download@127.0.0.1, C synced to bmc's tip $TIP" \
    || fail "with the download permission, C is at $(cc getblockcount), bmc at $TIP"

echo
echo "$PASSES passed, $FAILURES failed"
[ $FAILURES = 0 ] && echo "ALL TESTS PASSED" || echo "TESTS FAILED"
exit $FAILURES
