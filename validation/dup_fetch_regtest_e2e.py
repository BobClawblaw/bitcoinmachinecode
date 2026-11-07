#!/usr/bin/env python3
"""validation/dup_fetch_regtest_e2e.py -- one fetch per block across bmc's legs,
on regtest. 2026-11-07.

Four Core v31.1 regtest nodes, each with bmc as its ONLY peer (they are kept on
one chain by submitblock, not by connecting to each other), so every block
message a Core sends goes to bmc. With -debug=net each Core logs every message
it sends; the test counts the block payloads -- `blocktxn` and full `block`
replies -- the four sent while bmc caught up.

Each round stops bmc, mines BLOCKS blocks carrying transactions bmc has never
seen (each needs a getblocktxn round trip), and starts bmc again: its four
legs come up together and each leg's first pass finds the same new blocks.

  A  all four legs direct: the passes ask for the blocks at about the same
     time. Before 2026-11-07 each pass ran in a forked helper that claimed
     blocks in its OWN copy of the in-flight table, so every pass fetched
     them (19 payloads for 8 blocks on deploy-20261106g).
  B  three legs behind a relay that delays what Core sends by DELAY s: their
     passes ask after the direct leg's pass has stored the blocks and
     released its claims, from helpers forked before the store whose index
     of stored blocks is a stale copy -- production's costly case on
     2026-11-06 (six late passes refetched one 2,900-tx block whole). Only
     the stored mark (inflight_mark_stored) refuses them.

PASS = every new block's payload was sent exactly once in each stage, and bmc
reached Core's tip every round.

Usage: python3 validation/dup_fetch_regtest_e2e.py
       env: CORE_BIN, BMC_BIN, WORK (default $TMPDIR/bmc-dupf-<pid>), KEEP=1,
            ROUNDS (per stage, default 3), BLOCKS (per round, default 2),
            DELAY (stage B, seconds, default 1.5)
"""
import base64, json, os, re, shutil, socket, subprocess, sys, threading, time, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
from diffguard import require_cases

CORE_BIN = os.environ.get('CORE_BIN', '/storage/bitcoin-core-v31.1/bin')
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BMC_BIN = os.path.abspath(os.environ.get('BMC_BIN', os.path.join(ROOT, 'asm/daemon/bmcbitcoind')))
WORK = os.path.abspath(os.environ.get('WORK', os.path.join(os.environ.get('TMPDIR', '/tmp'), 'bmc-dupf-%d' % os.getpid())))
ROUNDS = int(os.environ.get('ROUNDS', '3'))
BLOCKS = int(os.environ.get('BLOCKS', '2'))
DELAY = float(os.environ.get('DELAY', '1.5'))
NC = 4
C_P2P = [19311 + 10 * i for i in range(NC)]     # 19311 19321 19331 19341 (no other validation script uses 193x1/193x2)
C_RPC = [19312 + 10 * i for i in range(NC)]
B_P2P, B_RPC = 19361, 19362
# one loopback address each: bmc keeps one leg per host, so four Cores on
# 127.0.0.1 would be one leg (Linux answers on all of 127/8)
C_IP = ['127.0.0.%d' % (2 + i) for i in range(NC)]
R_IP = ['127.0.0.%d' % (12 + i) for i in range(NC)]    # stage B's relays, on Core's port
AUTH = 'Basic ' + base64.b64encode(b'e2e:e2epw').decode()

def post(port, body, wallet=None):
    url = 'http://127.0.0.1:%d/%s' % (port, 'wallet/' + wallet if wallet else '')
    req = urllib.request.Request(url, body.encode(), {'Content-Type': 'application/json', 'Authorization': AUTH})
    try:
        with urllib.request.urlopen(req, timeout=60) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()

def call(port, method, params=None, wallet=None):
    s, b = post(port, json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': params or []}), wallet)
    r = json.loads(b)
    if r.get('error'): raise RuntimeError('%s: %s' % (method, r['error']))
    return r['result']

def wait_for(pred, secs, step=1.0):
    t = time.time()
    while time.time() - t < secs:
        try:
            if pred(): return True
        except Exception: pass
        time.sleep(step)
    return False

class DelayRelay:
    """listen on (ip, port); forward each connection to `dst`. Bytes from bmc
    go through at once; bytes from Core are held DELAY s, in order."""
    def __init__(self, ip, port, dst, delay):
        self.dst, self.delay = dst, delay
        self.ls = socket.socket(); self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ls.bind((ip, port)); self.ls.listen(8)
        threading.Thread(target=self.accept, daemon=True).start()
    def accept(self):
        while True:
            try: c, _ = self.ls.accept()
            except OSError: return
            try: u = socket.create_connection(self.dst, timeout=10)
            except OSError: c.close(); continue
            u.settimeout(None)
            threading.Thread(target=self.pump, args=(c, u, 0), daemon=True).start()
            threading.Thread(target=self.pump, args=(u, c, self.delay), daemon=True).start()
    @staticmethod
    def pump(src, dst, delay):
        q, cv, done = [], threading.Condition(), [False]
        def writer():
            while True:
                with cv:
                    while not q and not done[0]: cv.wait()
                    if not q: break
                    due, data = q.pop(0)
                wait = due - time.time()
                if wait > 0: time.sleep(wait)
                try: dst.sendall(data)
                except OSError: break
            try: dst.shutdown(socket.SHUT_WR)
            except OSError: pass
        w = threading.Thread(target=writer, daemon=True); w.start()
        while True:
            try: data = src.recv(65536)
            except OSError: data = b''
            with cv:
                if not data: done[0] = True; cv.notify(); break
                q.append((time.time() + delay, data)); cv.notify()
        w.join(60)

def write_bmc_conf(hosts):
    open(os.path.join(WORK, 'bmc', 'bitcoin.conf'), 'w').write(
        'chain=regtest\nprinttoconsole=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\n' % (B_P2P, B_RPC)
        + ''.join('connect=%s:%d\n' % h for h in hosts))

def bmc_start():
    log = open(os.path.join(WORK, 'bmc.log'), 'a')
    p = subprocess.Popen([BMC_BIN, 'serve', os.path.join(WORK, 'bmc')], cwd=os.path.join(ROOT, 'asm'),
                         stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
    if not wait_for(lambda: post(B_RPC, '{"method":"getblockcount","id":0}')[0] == 200, 120): raise RuntimeError('bmc did not start')
    return p

def bmc_stop(p):
    try: post(B_RPC, '{"method":"stop","id":0}')
    except Exception: pass
    try: p.wait(90)
    except subprocess.TimeoutExpired: p.kill(); p.wait()

SEND_RE = re.compile(r'sending (blocktxn|block) \((\d+) bytes\) peer=\d+')
def core_log(i): return os.path.join(WORK, 'c%d' % i, 'regtest', 'debug.log')
def log_offsets(): return [os.path.getsize(core_log(i)) for i in range(NC)]
def sends_since(offsets):
    """block payloads each Core sent since `offsets`: [(core, kind, bytes)]"""
    out = []
    for i in range(NC):
        with open(core_log(i), 'rb') as fh:
            fh.seek(offsets[i]); txt = fh.read().decode('utf-8', 'replace')
        out += [(i, m.group(1), int(m.group(2))) for m in SEND_RE.finditer(txt)]
    return out

cases = fails = 0
def check(what, got, want):
    global cases, fails
    cases += 1
    ok = got == want
    if not ok: fails += 1
    print('  %s %s: %r%s' % ('ok  ' if ok else 'FAIL', what, got, '' if ok else ' (want %r)' % (want,)))
    return ok

bmc_proc = None
def cleanup():
    if bmc_proc and bmc_proc.poll() is None: bmc_stop(bmc_proc)
    for i in range(NC):
        try: call(C_RPC[i], 'stop')
        except Exception: pass
    time.sleep(3)
    if os.environ.get('KEEP') != '1': shutil.rmtree(WORK, ignore_errors=True)

def main():
    global bmc_proc
    for i in range(NC):
        d = os.path.join(WORK, 'c%d' % i); os.makedirs(d)
        open(os.path.join(d, 'bitcoin.conf'), 'w').write(
            'regtest=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\nbind=%s\nlistenonion=0\n'
            'debug=net\nfallbackfee=0.0001\ndnsseed=0\nfixedseeds=0\n' % (C_P2P[i], C_RPC[i], C_IP[i]))
        subprocess.run([CORE_BIN + '/bitcoind', '-datadir=' + d, '-daemon'], check=True, stdout=subprocess.DEVNULL)
    for i in range(NC):
        if not wait_for(lambda: post(C_RPC[i], '{"method":"getblockcount","id":0}')[0] == 200, 120): print('FAIL: Core %d did not start' % i); return 2
    os.makedirs(os.path.join(WORK, 'bmc', 'regtest'))
    call(C_RPC[0], 'createwallet', ['w'])
    addr = call(C_RPC[0], 'getnewaddress', wallet='w')
    def mine(n):
        hashes = call(C_RPC[0], 'generatetoaddress', [n, addr], wallet='w')
        for h in hashes:
            raw = call(C_RPC[0], 'getblock', [h, 0])
            for i in range(1, NC): call(C_RPC[i], 'submitblock', [raw])
        return hashes
    mine(110)
    tip = call(C_RPC[0], 'getbestblockhash')
    check('the four Cores agree on one tip', len({call(C_RPC[i], 'getbestblockhash') for i in range(NC)}), 1)

    direct = [(C_IP[i], C_P2P[i]) for i in range(NC)]
    write_bmc_conf(direct)
    bmc_proc = bmc_start()
    check('bmc follows to the first tip', wait_for(lambda: call(B_RPC, 'getbestblockhash') == tip, 120), True)
    wait_for(lambda: all(call(C_RPC[i], 'getconnectioncount') >= 1 for i in range(NC)), 60)
    check('bmc holds a leg to each of the four Cores', sum(1 for i in range(NC) if call(C_RPC[i], 'getconnectioncount') >= 1), NC)

    def stage(name, hosts):
        global bmc_proc
        write_bmc_conf(hosts)
        sent = mined = 0
        for rnd in range(ROUNDS):
            bmc_stop(bmc_proc); bmc_proc = None
            off = log_offsets()
            hs = []
            for b in range(BLOCKS):
                for k in range(4): call(C_RPC[0], 'sendtoaddress', [call(C_RPC[0], 'getnewaddress', wallet='w'), 0.25], wallet='w')
                hs += mine(1)
            bmc_proc = bmc_start()
            reached = wait_for(lambda: call(B_RPC, 'getbestblockhash') == hs[-1], 120)
            time.sleep(10 + 2 * DELAY)      # a late pass still fetching lands in Core's log
            # a blocktxn carries every transaction bmc lacked: all but the
            # coinbase, so at least half the block; smaller sends are not payloads
            floor = min(call(C_RPC[0], 'getblock', [h, 1])['size'] for h in hs) // 2
            pay = [s for s in sends_since(off) if s[2] >= floor]
            print('  %s round %d: %d new block(s); Core sent %d block payload(s): %s' % (
                name, rnd + 1, len(hs), len(pay), ', '.join('c%d %s %d B' % s for s in pay)))
            check('%s round %d: bmc reached Core\'s tip' % (name, rnd + 1), reached, True)
            sent += len(pay); mined += len(hs)
        check('%s: each of the %d new blocks fetched exactly once across the legs' % (name, mined), sent, mined)

    print('A  all four legs direct')
    stage('A', direct)
    print('B  legs 1-3 behind a relay that delays what Core sends by %.1f s' % DELAY)
    for i in range(1, NC): DelayRelay(R_IP[i], C_P2P[i], (C_IP[i], C_P2P[i]), DELAY)
    stage('B', [direct[0]] + [(R_IP[i], C_P2P[i]) for i in range(1, NC)])
    wait_for(lambda: all(call(C_RPC[i], 'getconnectioncount') >= 1 for i in range(NC)), 60)
    check('B: bmc holds a leg to each of the four Cores (three through the relay)', sum(1 for i in range(NC) if call(C_RPC[i], 'getconnectioncount') >= 1), NC)

    require_cases(cases, 'checks', 6 + 2 * ROUNDS)
    print('%d checks, %d failed' % (cases, fails))
    return 1 if fails else 0

if __name__ == '__main__':
    rc = 2
    try: rc = main()
    finally: cleanup()
    sys.exit(rc)
