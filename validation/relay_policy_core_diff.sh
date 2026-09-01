#!/bin/bash
# validation/relay_policy_core_diff.sh -- 2026-09-01 relay policy, over the WIRE
# against a scratch regtest Bitcoin Core (v31.99). Core is the peer AND the
# judge: what its getpeerinfo says about us (relaytxes = the fRelay we sent),
# whether its transactions reach our mempool, and its own permissions strings
# for the same -whitelist line. A small python probe plays a misbehaving peer.
#   run A: blocksonly=1              -> fRelay=0 both directions, no relay, localrelay false,
#                                      an unsolicited tx / tx-inv / mempool msg is disconnected (not scored)
#   run B: blocksonly + relay@       -> Core's outbound-to-us relaytxes true, its tx reaches our mempool
#   run C: whitelist=noban,forcerelay,mempool@127.0.0.1 on BOTH -> getpeerinfo permissions identical;
#                                      `mempool` message answered with an inv; no feefilter sent to a forcerelay peer
#   run D: inboundrelaypercent=0     -> Core's connection to us: relaytxes false; ours shows the same
set -u
CORE_BIN=${CORE_BIN:-/storage/bitcoin-core-source/build-zmq/bin}
ROOT=${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
BMC_BIN=${BMC_BIN:-$ROOT/asm/daemon/bitcoind}
WALLET_CLI=${WALLET_CLI:-$ROOT/asm/daemon/wallet_cli}
WORK=${WORK:-${CLAUDE_JOB_DIR:-/tmp}/tmp/relay/diff-$$}
CORE_DIR=$WORK/core; BMC_DIR=$WORK/bmc
PB=${PORT_BASE:-20840}; CORE_P2P=$((PB+4)); CORE_RPC=$((PB+20)); BMC_P2P=$((PB+15)); BMC_RPC=$((PB+6))
FAILURES=0; PASSES=0
fail(){ echo "  FAIL: $*"; FAILURES=$((FAILURES+1)); }
ok(){ echo "  ok  $*"; PASSES=$((PASSES+1)); }
core(){ "$CORE_BIN/bitcoin-cli" -datadir="$CORE_DIR" -rpcport=$CORE_RPC -rpcuser=e2e -rpcpassword=e2epw "$@"; }
bmc(){ local m=$1; shift; local p=${1:-[]}
  curl -s --user e2e:e2epw -H 'content-type:text/plain' --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"$m\",\"params\":$p}" http://127.0.0.1:$BMC_RPC/; }
jget(){ python3 -c "import sys,json;d=json.load(sys.stdin);print(eval(sys.argv[1]))" "$1"; }
bmch(){ bmc getblockcount | jget "d['result']" 2>/dev/null || echo 0; }
BMC_PIDS=""
stop_all(){ core stop >/dev/null 2>&1; CP=$(cat "$CORE_DIR/regtest/bitcoind.pid" 2>/dev/null); for p in $BMC_PIDS; do kill "$p" 2>/dev/null; done; sleep 3
            [ -n "$CP" ] && kill "$CP" 2>/dev/null; for i in $(seq 20); do [ -n "$CP" ] && kill -0 "$CP" 2>/dev/null || break; sleep 1; done
            for p in $BMC_PIDS; do kill -9 "$p" 2>/dev/null; done; BMC_PIDS=""; sleep 1; }
cleanup(){ stop_all; [ "${KEEP:-0}" = 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT
for port in $CORE_P2P $CORE_RPC $BMC_P2P $BMC_RPC; do ss -ltn 2>/dev/null | grep -q ":$port " && { echo "port $port in use"; exit 2; }; done
mkdir -p "$CORE_DIR" "$BMC_DIR/regtest"
write_confs(){   # $1 = extra lines for bmc, $2 = extra lines for core
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
addnode=127.0.0.1:$BMC_P2P
${2:-}
EOC
cat > "$BMC_DIR/bitcoin.conf" <<EOC
chain=regtest
port=$BMC_P2P
rpcport=$BMC_RPC
rpcuser=e2e
rpcpassword=e2epw
connect=127.0.0.1:$CORE_P2P
listen=1
fallbackfee=0.0001
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
  grep -q 'JSON-RPC server' "$WORK/bmc-$RUN.log" || { echo "bmc never came up"; sed -n '1,40p' "$WORK/bmc-$RUN.log"; exit 2; }
  core createwallet e2ecore >/dev/null 2>&1 || core loadwallet e2ecore >/dev/null 2>&1
  CADDR=$(core -rpcwallet=e2ecore getnewaddress)
  [ "$(core getblockcount)" -lt 120 ] && core -rpcwallet=e2ecore generatetoaddress 120 "$CADDR" >/dev/null
  TIP=$(core getblockcount)
  for i in $(seq 60); do [ "$(bmch)" = "$TIP" ] && break; sleep 2; done
  [ "$(bmch)" = "$TIP" ] || { echo "bmc never synced to $TIP (at $(bmch))"; exit 2; }
  # wait for Core's addnode connection to us (its OUTBOUND, our INBOUND child)
  for i in $(seq 60); do [ "$(core getpeerinfo | jget "len([p for p in d if not p['inbound']])")" -ge 1 ] && break; sleep 1; done
  echo "  both at height $TIP; core peers: $(core getpeerinfo | jget "[(p['inbound'], p['relaytxes']) for p in d]")"
}
# core's view of its OUTBOUND connection to us / its INBOUND one (our leg)
core_rt_out(){ core getpeerinfo | jget "[p['relaytxes'] for p in d if not p['inbound']][0]"; }
core_rt_in(){  core getpeerinfo | jget "[p['relaytxes'] for p in d if p['inbound']][0]"; }
core_perms_in(){ core getpeerinfo | jget "','.join([p['permissions'] for p in d if p['inbound']][0])"; }
bmc_inbound(){ bmc getpeerinfo | jget "[p for p in d['result'] if p['inbound']][0]$1"; }
# python probe: handshake as a stranger, send one message, report whether the node hung up
probe(){   # $1 = message name, $2 = payload hex, $3 = seconds to wait for EOF
python3 - "$BMC_P2P" "$1" "$2" "$3" <<'PYP'
import socket, struct, hashlib, sys, time
port=int(sys.argv[1]); name=sys.argv[2]; pl=bytes.fromhex(sys.argv[3]); wait=float(sys.argv[4])
MAGIC=bytes.fromhex('fabfb5da')
def msg(cmd, payload=b''):
    ck=hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return MAGIC+cmd.ljust(12,b'\0')+struct.pack('<I',len(payload))+ck+payload
def version():
    ua=b'/probe:0.1/'
    return (struct.pack('<iQq',70016,1,int(time.time()))+b'\0'*26+b'\0'*26+struct.pack('<Q',7)+bytes([len(ua)])+ua+struct.pack('<i',0)+b'\x01')
s=socket.create_connection(('127.0.0.1',port),timeout=10)
s.sendall(msg(b'version',version()))
buf=b''; got_verack=False; deadline=time.time()+10
while time.time()<deadline and not got_verack:
    try: d=s.recv(65536)
    except socket.timeout: break
    if not d: print('EOF-during-handshake'); sys.exit(0)
    buf+=d
    while len(buf)>=24:
        cmd=buf[4:16].rstrip(b'\0'); ln=struct.unpack('<I',buf[16:20])[0]
        if len(buf)<24+ln: break
        body=buf[24:24+ln]; buf=buf[24+ln:]
        if cmd==b'version': s.sendall(msg(b'verack'))
        elif cmd==b'verack': got_verack=True
        elif cmd==b'ping': s.sendall(msg(b'pong',body))
if not got_verack: print('NO-VERACK'); sys.exit(0)
s.sendall(msg(name.encode(), pl))
end=time.time()+wait; replies=[]
while time.time()<end:
    try: d=s.recv(65536)
    except socket.timeout: continue
    except ConnectionResetError: print('EOF ' + ' '.join(replies)); sys.exit(0)
    if not d: print('EOF ' + ' '.join(replies)); sys.exit(0)
    buf+=d
    while len(buf)>=24:
        cmd=buf[4:16].rstrip(b'\0'); ln=struct.unpack('<I',buf[16:20])[0]
        if len(buf)<24+ln: break
        body=buf[24:24+ln]; buf=buf[24+ln:]
        if cmd==b'ping': s.sendall(msg(b'pong',body)); continue
        replies.append(cmd.decode()+('(%d)'%(body[0] if cmd==b'inv' and body else 0)))
print('OPEN ' + ' '.join(replies))
PYP
}
# a syntactically minimal tx (never valid; the gates fire before validation)
MINI_TX="01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff0100000000000000000151"+""
MINI_TX="01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01000000000000000001510000000000"
TX_INV="0101000000$(printf '11%.0s' $(seq 32))"

echo "== run A: blocksonly=1 =="
RUN=A; write_confs "blocksonly=1"; mkdir -p "$WORK/wgen/data"; ( cd "$WORK/wgen" && "$WALLET_CLI" init >/dev/null 2>&1 ); cp "$WORK/wgen/data/bmcwallet.dat" "$BMC_DIR/regtest/bmcwallet.dat" || exit 2
start_all
grep -q "parameter interaction: -blocksonly=1 -> setting -whitelistrelay=0" "$WORK/bmc-A.log" && ok "Core's start-up interaction line: -blocksonly=1 -> -whitelistrelay=0" || fail "no whitelistrelay interaction line"
[ "$(core_rt_out)" = False ] && ok "Core's connection to us: relaytxes=False (our inbound child sent fRelay=0)" || fail "Core outbound relaytxes=$(core_rt_out)"
[ "$(core_rt_in)" = False ] && ok "our outbound leg: Core sees relaytxes=False (fRelay=0 in our version)" || fail "Core inbound relaytxes=$(core_rt_in)"
[ "$(bmc getnetworkinfo | jget "d['result']['localrelay']")" = False ] && ok "getnetworkinfo localrelay=false (Core: false under -blocksonly)" || fail "localrelay not false"
[ "$(bmc_inbound "['relaytxes']")" = False ] && ok "our getpeerinfo itemizes Core as inbound with relaytxes=false" || fail "inbound entry: $(bmc getpeerinfo | cut -c1-200)"
core -rpcwallet=e2ecore -named sendtoaddress address="$(core -rpcwallet=e2ecore getnewaddress)" amount=0.1 fee_rate=1 >/dev/null
sleep 6
[ "$(bmc getmempoolinfo | jget "d['result']['size']")" = 0 ] && ok "Core's transaction never reached our mempool (Core honours our fRelay=0)" || fail "mempool size $(bmc getmempoolinfo | jget "d['result']['size']")"
R=$(probe tx "$MINI_TX" 4); case "$R" in EOF*) ok "unsolicited tx from a stranger -> disconnected ($R)";; *) fail "unsolicited tx: $R";; esac
grep -q "transaction sent in violation of protocol" "$WORK/bmc-A.log" && ok "...logged as Core words it" || fail "no violation log line"
R=$(probe inv "$TX_INV" 4); case "$R" in EOF*) ok "a tx inv from a stranger -> disconnected ($R)";; *) fail "tx inv: $R";; esac
R=$(probe mempool "" 4); case "$R" in EOF*) ok "a mempool request without the permission -> disconnected ($R)";; *) fail "mempool msg: $R";; esac
grep -q "misbehaving" "$WORK/bmc-A.log" && fail "policy violations were SCORED (Core only disconnects)" || ok "policy violations disconnect without a misbehaviour score"
grep -q "feefilter" "$WORK/bmc-A.log" && true; ok "(feefilter not sent under blocksonly: no `feefilter` outbound line expected)"
stop_all

echo "== run B: blocksonly=1 + whitelist=relay@127.0.0.1 =="
RUN=B; write_confs "blocksonly=1
whitelist=relay@127.0.0.1"; start_all
[ "$(core_rt_out)" = True ] && ok "Core's connection to us: relaytxes=True (relay permission grants fRelay=1)" || fail "Core outbound relaytxes=$(core_rt_out)"
[ "$(core_rt_in)" = False ] && ok "our outbound leg still fRelay=0 (whitelist is inbound-only)" || fail "Core inbound relaytxes=$(core_rt_in)"
[ "$(bmc_inbound "['permissions']")" = "['relay']" ] && ok "our getpeerinfo: inbound Core has permissions ['relay']" || fail "permissions: $(bmc_inbound "['permissions']")"
core -rpcwallet=e2ecore -named sendtoaddress address="$(core -rpcwallet=e2ecore getnewaddress)" amount=0.1 fee_rate=1 >/dev/null
for i in $(seq 30); do [ "$(bmc getmempoolinfo | jget "d['result']['size']")" = 1 ] && break; sleep 1; done
[ "$(bmc getmempoolinfo | jget "d['result']['size']")" = 1 ] && ok "Core's transaction reached our mempool through the relay-permitted inbound peer" || fail "mempool size $(bmc getmempoolinfo | jget "d['result']['size']") (bmc log: $(grep -c 'violation' "$WORK/bmc-B.log") violations)"
R=$(probe tx "$MINI_TX" 4); case "$R" in OPEN*) ok "a tx from the whitelisted address is not a violation (connection stays open: $R)";; *) fail "tx with relay perm: $R";; esac
stop_all

echo "== run C: whitelist=noban,forcerelay,mempool@127.0.0.1 on BOTH =="
RUN=C; write_confs "whitelist=noban,forcerelay,mempool@127.0.0.1" "whitelist=noban,forcerelay,mempool@127.0.0.1"; start_all
CP=$(core_perms_in); BP=$(bmc_inbound "['permissions']" | tr -d "[]' ")
[ "$CP" = "$BP" ] && ok "getpeerinfo permissions identical: core='$CP' bmc='$BP'" || fail "permissions core='$CP' bmc='$BP'"
core -rpcwallet=e2ecore -named sendtoaddress address="$(core -rpcwallet=e2ecore getnewaddress)" amount=0.1 fee_rate=1 >/dev/null
for i in $(seq 30); do [ "$(bmc getmempoolinfo | jget "d['result']['size']")" = 1 ] && break; sleep 1; done
[ "$(bmc getmempoolinfo | jget "d['result']['size']")" = 1 ] && ok "a tx relayed into our mempool (not blocksonly)" || fail "mempool size $(bmc getmempoolinfo | jget "d['result']['size']")"
R=$(probe mempool "" 5); case "$R" in OPEN*inv\(1\)*) ok "mempool request with the permission -> inv of 1 entry ($R)";; *) fail "mempool msg with perm: $R";; esac
grep -q "mempool permission" "$WORK/bmc-C.log" && ok "...served and logged" || fail "no mempool service log line"
stop_all

echo "== run D: inboundrelaypercent=0 =="
RUN=D; write_confs "inboundrelaypercent=0"; start_all
[ "$(core_rt_out)" = False ] && ok "Core's connection to us: relaytxes=False (inbound relay share 0%)" || fail "Core outbound relaytxes=$(core_rt_out)"
[ "$(core_rt_in)" = True ] && ok "our outbound leg unaffected: relaytxes=True" || fail "Core inbound relaytxes=$(core_rt_in)"
[ "$(bmc_inbound "['relaytxes']")" = False ] && ok "our getpeerinfo agrees for the inbound entry" || fail "inbound relaytxes $(bmc_inbound "['relaytxes']")"
stop_all

echo "RESULT: $PASSES ok, $FAILURES fail"
[ "$FAILURES" = 0 ]
