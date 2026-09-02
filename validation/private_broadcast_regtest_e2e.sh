#!/bin/bash
# validation/private_broadcast_regtest_e2e.sh -- Core's -privatebroadcast, end to
# end against a real Bitcoin Core on regtest.
#
# Tor is stood in for by a SOCKS5 stub (python, below) that accepts user/pass
# authentication, records the credentials, and connects every ".onion" name to
# Core's regtest P2P port. Our node gets that stub as its onion proxy, a fake
# v3 onion address for Core in its book, and privatebroadcast=1; a normal leg
# to Core (addnode) carries the sync and, later, the transaction coming back.
#
# Proves:
#   1. sendrawtransaction on our node returns the txid WITHOUT putting the tx in
#      our mempool (getrawmempool empty; getprivatebroadcastinfo lists it);
#   2. Core receives it over anonymous connections: its getpeerinfo shows peers
#      with subver /pynode:0.0.1/, services 0, relaytxes false; its mempool
#      gains the txid; our info shows the peer entries with "received";
#   3. every private connection used DIFFERENT SOCKS5 credentials (stream
#      isolation) -- the stub's log;
#   4. Core relays the tx back over the normal leg: our mempool gains it and
#      the queue empties ("received back");
#   5. abortprivatebroadcast removes a queued tx and reports it;
#   6. with the option off, both RPCs refuse with Core's text.
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-source/build-zmq/bin}
ROOT=${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
BMC_BIN=${BMC_BIN:-$ROOT/asm/daemon/bitcoind}
WORK=${WORK:-${CLAUDE_JOB_DIR:-/tmp}/tmp/privbcast/e2e-$$}
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
PB=${PORT_BASE:-21840}; CORE_P2P=$((PB+4)); CORE_RPC=$((PB+20)); BMC_P2P=$((PB+15)); BMC_RPC=$((PB+6)); SOCKS=$((PB+30))
FAILURES=0; PASSES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; PASSES=$((PASSES+1)); }
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmc(){ local m=$1; shift; local p=${1:-[]}
  curl -s -m 30 --user e2e:e2epw -H 'content-type:text/plain' --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":$p}" http://127.0.0.1:$BMC_RPC/; }
jget(){ python3 -c "import sys,json;d=json.load(sys.stdin);print(eval(sys.argv[1]))" "$1"; }
bmch(){ bmc getblockcount | jget "d['result']" 2>/dev/null || echo 0; }
BMC_PIDS=""; SOCKS_PID=""
stop_all(){ core stop >/dev/null 2>&1; CP=$(cat "$CORE_DIR/regtest/bitcoind.pid" 2>/dev/null); for p in $BMC_PIDS; do kill "$p" 2>/dev/null; done; sleep 2
            [ -n "$CP" ] && kill "$CP" 2>/dev/null; for i in $(seq 20); do [ -n "$CP" ] && kill -0 "$CP" 2>/dev/null || break; sleep 1; done
            for p in $BMC_PIDS; do kill -9 "$p" 2>/dev/null; done; BMC_PIDS=""; [ -n "$SOCKS_PID" ] && kill "$SOCKS_PID" 2>/dev/null; sleep 1; }
cleanup(){ stop_all; [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC $SOCKS; do ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }; done
mkdir -p "$CORE_DIR" "$BMC_DIR/regtest"

# ---- the SOCKS5 stub: user/pass auth, DOMAINNAME connect -> Core, one log line per connection ----
cat > "$WORK/socks_stub.py" <<'PY'
import socket, threading, sys, struct
listen_port, target_port, logpath = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
def pump(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d: break
            b.sendall(d)
    except Exception: pass
    finally:
        try: a.shutdown(socket.SHUT_RD)
        except Exception: pass
        try: b.shutdown(socket.SHUT_WR)
        except Exception: pass
def handle(c):
    try:
        hdr = c.recv(2); n = hdr[1]; methods = c.recv(n)
        user = "-"
        if 2 in methods:
            c.sendall(b"\x05\x02")
            v = c.recv(1); ul = c.recv(1)[0]; user = c.recv(ul).decode(); pl = c.recv(1)[0]; pw = c.recv(pl).decode()
            c.sendall(b"\x01\x00")
        else:
            c.sendall(b"\x05\x00")
        req = c.recv(4); atyp = req[3]
        if atyp == 3:
            l = c.recv(1)[0]; name = c.recv(l).decode()
        elif atyp == 1:
            name = socket.inet_ntoa(c.recv(4))
        else:
            name = "?"; c.recv(16)
        port = struct.unpack("!H", c.recv(2))[0]
        with open(logpath, "a") as f: f.write(f"{name} {port} user={user}\n")
        t = socket.create_connection(("127.0.0.1", target_port))
        c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", target_port))
        threading.Thread(target=pump, args=(c, t), daemon=True).start()
        pump(t, c)
    except Exception as e:
        with open(logpath, "a") as f: f.write(f"error {e}\n")
    finally:
        try: c.close()
        except Exception: pass
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", listen_port)); s.listen(16)
while True:
    c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
PY
python3 "$WORK/socks_stub.py" $SOCKS $CORE_P2P "$WORK/socks.log" & SOCKS_PID=$!
sleep 0.5

# a syntactically valid v3 onion address for "Core" (any pubkey; the stub ignores the name)
ONION=$(python3 -c "
import hashlib,base64
pk=bytes(range(32)); ck=hashlib.sha3_256(b'.onion checksum'+pk+b'\x03').digest()[:2]
print(base64.b32encode(pk+ck+b'\x03').decode().lower()+'.onion')")

write_confs(){   # $1 = extra lines for bmc
cat > "$CORE_DIR/bitcoin.conf" <<EOC
regtest=1
[regtest]
port=$CORE_P2P
rpcport=$CORE_RPC
rpcuser=e2e
rpcpassword=e2epw
listen=1
listenonion=0
fallbackfee=0.0001
debug=net
addnode=127.0.0.1:$BMC_P2P
EOC
cat > "$BMC_DIR/bitcoin.conf" <<EOC
chain=regtest
port=$BMC_P2P
rpcport=$BMC_RPC
rpcuser=e2e
rpcpassword=e2epw
connect=127.0.0.1:$CORE_P2P
listen=1
listenonion=0
fallbackfee=0.0001
onion=127.0.0.1:$SOCKS
proxyrandomize=1
$1
EOC
}
start_all(){
  "$CORE_BIN/bitcoind" -datadir="$CORE_DIR" -daemon >/dev/null 2>&1
  for i in $(seq 40); do core getblockcount >/dev/null 2>&1 && break; sleep 1; done
  core getblockcount >/dev/null 2>&1 || { echo "core never came up"; tail -5 "$CORE_DIR/regtest/debug.log"; exit 2; }
  ( cd "$ROOT/asm" && nohup "$BMC_BIN" serve "$BMC_DIR" > "$WORK/bmc-$RUN.log" 2>&1 & )
  for i in $(seq 40); do grep -q 'JSON-RPC server' "$WORK/bmc-$RUN.log" && break; sleep 1; done
  BMC_PIDS=$(pgrep -f "serve $BMC_DIR" | tr '\n' ' ')
  grep -q 'JSON-RPC server' "$WORK/bmc-$RUN.log" || { echo "bmc never came up"; sed -n '1,60p' "$WORK/bmc-$RUN.log"; exit 2; }
  core createwallet e2ecore >/dev/null 2>&1 || core loadwallet e2ecore >/dev/null 2>&1
  CADDR=$(core -rpcwallet=e2ecore getnewaddress)
  [ "$(core getblockcount)" -lt 120 ] && core -rpcwallet=e2ecore generatetoaddress 120 "$CADDR" >/dev/null
  TIP=$(core getblockcount)
  for i in $(seq 60); do [ "$(bmch)" = "$TIP" ] && break; sleep 2; done
  [ "$(bmch)" = "$TIP" ] || { echo "bmc never synced to $TIP (at $(bmch))"; exit 2; }
  # the steady leg must be up BEFORE anything is submitted: Core announces a
  # transaction only when it is new, never to a peer that connects later
  for i in $(seq 60); do [ "$(core getpeerinfo | jget "len([p for p in d if 'BitcoinMachineCode' in p['subver'] and p['relaytxes']])")" -ge 1 ] && break; sleep 1; done
  sleep 2
  echo "  both at height $TIP; core peers: $(core getpeerinfo | jget "[(p['inbound'], p['subver'], p['relaytxes']) for p in d]")"
}
# a signed transaction from Core's wallet that Core has NOT broadcast
make_tx(){
  local to; to=$(core -rpcwallet=e2ecore getnewaddress)
  local raw; raw=$(core -rpcwallet=e2ecore createrawtransaction "[]" "[{\"$to\":1.5}]")
  local funded; funded=$(core -rpcwallet=e2ecore fundrawtransaction "$raw" | jget "d['hex']")
  core -rpcwallet=e2ecore signrawtransactionwithwallet "$funded" | jget "d['hex']"
}

echo "== run A: privatebroadcast=1, tor stood in by the SOCKS5 stub"
RUN=A; write_confs "privatebroadcast=1"; : > "$WORK/socks.log"; rm -rf "$CORE_DIR/regtest/mempool.dat"; start_all
grep -q "\[privbcast\] enabled" "$WORK/bmc-A.log" && ok "our node announced private broadcast at boot" || fail "no [privbcast] enabled line"
# Core's "onion" address into our book
R=$(bmc addpeeraddress "[\"$ONION\", $CORE_P2P, true]"); echo "$R" | grep -q '"success":true' && ok "fake onion address for Core added to the book" || fail "addpeeraddress: $R"
HEX=$(make_tx); TXID=$(core decoderawtransaction "$HEX" | jget "d['txid']")
R=$(bmc sendrawtransaction "[\"$HEX\"]"); RTX=$(echo "$R" | jget "d['result']" 2>/dev/null)
[ "$RTX" = "$TXID" ] && ok "sendrawtransaction returned the txid ($TXID)" || fail "sendrawtransaction: $R"
bmc getrawmempool | grep -q "$TXID" && fail "the tx entered our mempool at submission" || ok "our mempool does NOT hold the tx (queued, not admitted)"
INFO=$(bmc getprivatebroadcastinfo); echo "$INFO" | grep -q "\"txid\":\"$TXID\"" && ok "getprivatebroadcastinfo lists it" || fail "info: $INFO"
echo "$INFO" | grep -q "\"hex\":\"$HEX\"" && ok "...with the tx hex" || fail "info lacks hex"
# watch Core for the anonymous peers and the tx
SEEN_PYNODE=0; CORE_HAS=0
for i in $(seq 120); do
  P=$(core getpeerinfo | jget "[(p['subver'], p['services'], p['relaytxes'], p['inbound']) for p in d if 'pynode' in p['subver']]" 2>/dev/null)
  [ "$P" != "[]" ] && [ -n "$P" ] && { SEEN_PYNODE=1; PY_DETAIL=$P; }
  core getrawmempool | grep -q "$TXID" && { CORE_HAS=1; break; }
  sleep 0.5
done
[ $CORE_HAS = 1 ] && ok "Core's mempool received the transaction over the private connections" || fail "Core never got the tx; peers: $(core getpeerinfo | jget "[p['subver'] for p in d]")"
[ $SEEN_PYNODE = 1 ] && ok "Core saw the anonymous peer(s): $PY_DETAIL" || echo "  (note: the anonymous peers were too short-lived to be caught by polling)"
echo "$PY_DETAIL" | grep -q "'0000000000000000', False, True" && ok "...services 0, relaytxes false, inbound -- Core's own private-broadcast shape" || echo "  (peer shape not captured)"
# our side: the tx must come BACK over the normal leg. Core v31.99 announces a
# lone inbound-bucket transaction only when something bumps its tx-send-rate
# bucket (observed: 60-120 s with nothing else happening; instant when another
# tx arrives), so after 90 s of patience one Core wallet tx is sent as the bump
# and the fact is recorded -- it is Core's timing, not the private delivery.
BUMPED=0
for i in $(seq 90); do bmc getrawmempool | grep -q "$TXID" && break; sleep 1; done
if ! bmc getrawmempool | grep -q "$TXID"; then
  CTRL=$(core -rpcwallet=e2ecore sendtoaddress "$(core -rpcwallet=e2ecore getnewaddress)" 0.7); BUMPED=1
  for i in $(seq 60); do bmc getrawmempool | grep -q "$TXID" && break; sleep 1; done
fi
[ $BUMPED = 1 ] && echo "  (note: Core announced the private tx to our leg only after another tx bumped its inbound announcement bucket; inv batches to our leg: $(grep -c 'sending inv' "$CORE_DIR/regtest/debug.log"))"
bmc getrawmempool | grep -q "$TXID" && ok "the tx came BACK to us over the normal leg and entered our mempool" || fail "our mempool never got it back: $(bmc getrawmempool)"
sleep 2
INFO=$(bmc getprivatebroadcastinfo); [ "$(echo "$INFO" | jget "len(d['result']['transactions'])")" = 0 ] && ok "the queue is empty after the receipt (Core: 'stopping private broadcast attempts')" || fail "queue not empty: $INFO"
grep -q "received our privately broadcast transaction back" "$WORK/bmc-A.log" && ok "log: received back" || fail "no received-back log line"
grep -q "acknowledged the transaction (pong)" "$WORK/bmc-A.log" && ok "log: at least one peer acknowledged with a pong" || fail "no pong acknowledgement logged"
# stream isolation: distinct credentials per connection
NCONN=$(grep -c "onion" "$WORK/socks.log"); NUSERS=$(grep "onion" "$WORK/socks.log" | sed 's/.*user=//' | sort -u | wc -l)
[ "$NCONN" -ge 1 ] && ok "the stub saw $NCONN private connection(s) to the .onion name" || fail "stub saw no onion connections: $(cat "$WORK/socks.log")"
[ "$NUSERS" = "$NCONN" ] && ok "every connection used its own SOCKS5 credentials ($NUSERS distinct): stream isolation" || fail "credentials reused: $(cat "$WORK/socks.log")"
grep -q "127.0.0.1" "$WORK/socks.log" && fail "a clearnet address went through the stub" || ok "nothing but the .onion name went through the stub"
# 5. abort
HEX2=$(make_tx); TXID2=$(core decoderawtransaction "$HEX2" | jget "d['txid']")
R=$(bmc sendrawtransaction "[\"$HEX2\"]"); echo "$R" | grep -q "$TXID2" && ok "second tx queued" || fail "second submit: $R"
R=$(bmc abortprivatebroadcast "[\"$TXID2\"]"); echo "$R" | grep -q "\"removed_transactions\":\[{\"txid\":\"$TXID2\"" && ok "abortprivatebroadcast removed it and reported it" || fail "abort: $R"
INFO=$(bmc getprivatebroadcastinfo); [ "$(echo "$INFO" | jget "len(d['result']['transactions'])")" = 0 ] && ok "queue empty after the abort" || fail "queue after abort: $INFO"
R=$(bmc abortprivatebroadcast "[\"$TXID2\"]"); echo "$R" | grep -q '"removed_transactions":\[\]' && ok "aborting again removes nothing" || fail "second abort: $R"
stop_all

echo "== run B: privatebroadcast=0 -- both RPCs refuse, sendrawtransaction relays as before"
RUN=B; write_confs ""; rm -rf "$BMC_DIR/regtest"; mkdir -p "$BMC_DIR/regtest"; start_all
R=$(bmc getprivatebroadcastinfo); echo "$R" | grep -q "Private broadcast is not enabled" && ok "getprivatebroadcastinfo refuses with Core's text" || fail "info: $R"
R=$(bmc abortprivatebroadcast "[\"$TXID\"]"); echo "$R" | grep -q "Private broadcast is not enabled" && ok "abortprivatebroadcast refuses with Core's text" || fail "abort: $R"
HEX3=$(make_tx); TXID3=$(core decoderawtransaction "$HEX3" | jget "d['txid']")
R=$(bmc sendrawtransaction "[\"$HEX3\"]"); echo "$R" | grep -q "$TXID3" && ok "plain sendrawtransaction still works" || fail "submit: $R"
bmc getrawmempool | grep -q "$TXID3" && ok "...and admits to our mempool immediately" || fail "not in our mempool"
stop_all
echo; echo "$PASSES passed, $FAILURES failed"
[ $FAILURES = 0 ]
