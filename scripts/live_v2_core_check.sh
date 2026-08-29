#!/bin/bash
# live_v2_core_check.sh -- prove BIP324 interoperates with real Bitcoin Core.
#
# Starts a THROWAWAY regtest Core in a temp datadir (never the production
# install, never /storage/bitcoin) and runs three checks:
#
#   1. outbound  -- we dial Core over v2; session ids must match
#   2. inbound   -- Core dials us over v2; session ids must match
#   3. fallback  -- Core dials us with v2 disabled; we must detect v1 AND
#                   still be able to read the version message it sent
#
# Check 3 is the one that matters most: detection has to peek rather than
# read, or the v1 peer's first message is swallowed and the connection dies
# on a timeout with nothing in the log to explain it.
#
# Usage: scripts/live_v2_core_check.sh [path-to-bitcoind]
set -u
CORE=${1:-/storage/bitcoin-core-source/build/bin/bitcoind}
CLI=$(dirname "$CORE")/bitcoin-cli
ASM=$(cd "$(dirname "$0")/../asm" && pwd)
D=$(mktemp -d)
PORT=19444; MINE_V2=19555; MINE_V1=19556
fails=0
say(){ printf '%s\n' "$*"; }
ok(){ say "  ok  $1"; }
bad(){ say "  FAIL $1"; fails=$((fails+1)); }

[ -x "$CORE" ] || { say "no bitcoind at $CORE"; exit 2; }

cleanup(){ "$CLI" -datadir="$D" stop >/dev/null 2>&1; sleep 1; rm -rf "$D"; }
trap cleanup EXIT

cat > "$D/bitcoin.conf" <<CONF
regtest=1
listen=1
v2transport=1
dnsseed=0
[regtest]
bind=127.0.0.1:$PORT
port=$PORT
rpcport=$((PORT+1))
CONF

LIBS="daemon/v2transport.c crypto_bip324_transport.c crypto_bip324.c crypto_bip324_fs.c
      crypto_chacha20.c crypto_poly1305.c crypto_hkdf.c crypto_ellswift_ecdh.c
      crypto_ellswift.c crypto_ellswift_enc.c crypto_fe_sqrt.c
      secp256k1_fe.o secp256k1_point_ct.o sha256.o bitcoin_net.o bitcoin_hash.o"
( cd "$ASM" && make -s secp256k1_fe.o secp256k1_point_ct.o sha256.o bitcoin_net.o bitcoin_hash.o >/dev/null 2>&1
  gcc -no-pie -O2 -I. -o "$D/dial"   tests/live_v2_core.c   $LIBS 2>&1 | grep -E '\berror\b'
  gcc -no-pie -O2 -I. -o "$D/accept" tests/live_v2_accept.c $LIBS 2>&1 | grep -E '\berror\b' ) || true
[ -x "$D/dial" ] && [ -x "$D/accept" ] || { say "build failed"; exit 2; }

"$CORE" -datadir="$D" -daemon -noconnect >/dev/null 2>&1
for i in $(seq 30); do "$CLI" -datadir="$D" getblockcount >/dev/null 2>&1 && break; sleep 1; done
say "== 1. we dial Core over BIP324 =="
"$D/dial" $PORT > "$D/o1" 2>&1
grep -q "^PASS" "$D/o1" && ok "version + verack over v2" || { bad "outbound v2"; cat "$D/o1"; }
OURS=$(grep -o 'our session_id: [0-9a-f]*' "$D/o1" | awk '{print $3}')

say "== 2. Core dials us over BIP324 =="
HOLD=5 "$D/accept" $MINE_V2 > "$D/o2" 2>&1 &
sleep 1; "$CLI" -datadir="$D" addnode "127.0.0.1:$MINE_V2" onetry true >/dev/null 2>&1
sleep 3
THEIRS=$("$CLI" -datadir="$D" getpeerinfo 2>/dev/null | grep -A2 "$MINE_V2" | grep session_id | grep -o '[0-9a-f]\{64\}')
TYPE=$("$CLI" -datadir="$D" getpeerinfo 2>/dev/null | grep -A3 "$MINE_V2" | grep -o '"v[12]"' | head -1)
wait
MINE=$(grep -o 'our session_id: [0-9a-f]*' "$D/o2" | awk '{print $3}')
grep -q "^PASS" "$D/o2" && ok "version received over v2" || { bad "inbound v2"; cat "$D/o2"; }
[ -n "$MINE" ] && [ "$MINE" = "$THEIRS" ] && ok "session id matches Core byte for byte ($TYPE)" \
    || bad "session id mismatch: ours=$MINE core=$THEIRS"

say "== 3. Core dials us with v2 disabled =="
HOLD=3 "$D/accept" $MINE_V1 > "$D/o3" 2>&1 &
sleep 1; "$CLI" -datadir="$D" addnode "127.0.0.1:$MINE_V1" onetry false >/dev/null 2>&1
wait
grep -q "peer chose v1" "$D/o3" && ok "v1 detected in band" || { bad "v1 not detected"; cat "$D/o3"; }
grep -q "^PASS" "$D/o3" && ok "and the version message was NOT swallowed" \
    || { bad "the v1 peer's version message was lost"; cat "$D/o3"; }

say ""
[ $fails -eq 0 ] && say "ALL LIVE CHECKS PASSED" || say "LIVE FAILURES: $fails"
exit $((fails > 0))
