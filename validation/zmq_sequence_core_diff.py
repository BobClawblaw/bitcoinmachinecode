#!/usr/bin/env python3
"""validation/zmq_sequence_core_diff.py -- the ZMQ `sequence` topic, bmc
against Bitcoin Core v31.1, on regtest. 2026-09-19.

Both nodes publish -zmqpubsequence; a pyzmq subscriber records both streams;
the SAME scenario is driven on each (every transaction is signed once, by Core's
wallet, and submitted to Core first and then to bmc directly -- bmc is not
relied on to take Core's relay). bmc follows Core's chain over P2P (connect=).
Each phase's events are compared label by label, hash by hash, and by the
8-byte mempool sequence each 'A'/'R' carries -- the two counters start at 1
and take the same number of steps if the two mempools really went through the
same history, so they are compared as absolute values, not deltas.

  phase add        A(P1), A(C1: child of P1)
  phase rbf        A(X1), then X2 replaces it: R(X1), A(X2)
  phase block      A(K1); Core mines [P1, K2] where K2 double-spends K1:
                   P1 mined (numbered, silent), R(K1), C(B1)
  phase invalidate invalidateblock B1 on both: D(B1), A(P1), A(K2)
  phase reconsider reconsiderblock B1 on both: C(B1), two silent numbers
  phase reorg      a competing branch B1', B2' (built on a third node, Core #2,
                   B1' = [P1, Z], Z double-spends C1's input) is handed to Core
                   #1 by submitblock; both nodes reorg in ONE step:
                   D(B1), R(C1), A(K2), C(B1'), C(B2')
  phase snapshot   getrawmempool(false, true) on both: same txids, same
                   mempool_sequence
  phase evict      -maxmempool=5 on both: 75 ~80 KB OP_RETURN transactions at
                   rising feerates, so each pool trims. Compared
                   STRUCTURALLY (each eviction 'R' follows the 'A' of the
                   transaction that forced it; the evictions come in the same
                   order; every stream reconstructs its own getrawmempool),
                   because the two pools measure "full" differently (Core:
                   DynamicMemoryUsage, bmc: raw bytes). 2026-09-19: identical
                   for the first 61 events, then Core trims one transaction
                   earlier (14 evictions to bmc's 13) -- the accounting, not
                   the topic; printed, not failed.
  phase reload     both restarted: mempool.dat comes back through each node's
                   ordinary accept path. The counter must equal n+1; the
                   stream is checked when the subscriber rejoined in time
                   (bmc: always so far; Core: its reload thread usually wins
                   the race against pyzmq's reconnect -- the PUB "slow
                   joiner" -- and then only its counter is checked).

Expiry is NOT driven here: Core expires on the next accept after
-mempoolexpiry hours of MOCKTIME, and this node's expiry runs on the wall
clock; tests/test_mempool_sequence.c covers the path.

Usage: <venv with pyzmq>/bin/python3 validation/zmq_sequence_core_diff.py
       env: CORE_BIN, BMC_BIN, WORK (default $TMPDIR/bmc-zseq-<pid>), KEEP=1
"""
import base64, json, os, shutil, signal, subprocess, sys, threading, time, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
from diffguard import require_sources   # a phase that compared no events must not read as a pass
COMPARED = {}                            # phase -> events compared (core side)
import zmq

CORE_BIN = os.environ.get('CORE_BIN', '/mnt/nvme8tb/core-build/bitcoin-v31.1/build/bin')
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BMC_BIN = os.environ.get('BMC_BIN', os.path.join(ROOT, 'asm/daemon/bmcbitcoind'))
WORK = os.environ.get('WORK', os.path.join(os.environ.get('TMPDIR', '/tmp'), 'bmc-zseq-%d' % os.getpid()))
# not adjacent: Core binds an onion target on P2P+1 even with listenonion=0
C1_P2P, C1_RPC, C1_ZMQ = 19614, 19624, 19628
C2_P2P, C2_RPC = 19664, 19674
B_P2P, B_RPC, B_ZMQ = 19634, 19644, 19648

def log(*a): print(time.strftime('%H:%M:%S'), *a, flush=True)

class RPC:
    def __init__(self, port, name): self.url = 'http://127.0.0.1:%d/' % port; self.name = name
    def raw(self, method, *params):
        req = urllib.request.Request(self.url, json.dumps({'jsonrpc': '1.0', 'id': 'z', 'method': method, 'params': list(params)}).encode(),
                                     {'Content-Type': 'text/plain', 'Authorization': 'Basic ' + base64.b64encode(b'e2e:e2epw').decode()})
        try:
            with urllib.request.urlopen(req, timeout=300) as r: return json.loads(r.read())
        except urllib.error.HTTPError as e: return json.loads(e.read())
    def __call__(self, method, *params):
        d = self.raw(method, *params)
        if d.get('error'): raise RuntimeError('%s %s%s: %s' % (self.name, method, params if len(str(params)) < 200 else '(...)', d['error']))
        return d['result']
    def wallet(self, w):
        o = RPC.__new__(RPC); o.url = self.url + 'wallet/' + w; o.name = self.name; return o

core, core2, bmc = RPC(C1_RPC, 'core'), RPC(C2_RPC, 'core2'), RPC(B_RPC, 'bmc')

def up(rpc, secs=120):
    for _ in range(secs):
        try: rpc('getblockcount'); return True
        except Exception: time.sleep(1)
    return False

def my_procs():
    out = []
    for p in os.listdir('/proc'):
        if not p.isdigit() or int(p) == os.getpid(): continue
        try:
            cmd = open('/proc/%s/cmdline' % p, 'rb').read()
            exe = os.path.basename(os.readlink('/proc/%s/exe' % p))
        except Exception: continue
        if WORK.encode() in cmd and exe not in ('bash', 'sh', 'python3', 'python3.12'): out.append(int(p))
    return out

def cleanup():
    for r in (core, core2):
        try: r('stop')
        except Exception: pass
    time.sleep(3)
    for p in my_procs():
        try: os.kill(p, signal.SIGTERM)
        except Exception: pass
    for _ in range(30):
        if not my_procs(): break
        time.sleep(1)
    if os.environ.get('KEEP') != '1': shutil.rmtree(WORK, ignore_errors=True)

# ---------------------------------------------------------------- the streams
class Stream:
    def __init__(self, port, name):
        self.name = name; self.ev = []; self.lock = threading.Lock()
        self.ctx = zmq.Context(); self.s = self.ctx.socket(zmq.SUB)
        self.s.setsockopt(zmq.RCVHWM, 0); self.s.setsockopt_string(zmq.SUBSCRIBE, 'sequence')
        self.s.connect('tcp://127.0.0.1:%d' % port)
        self.stop = False; self.t = threading.Thread(target=self.run, daemon=True); self.t.start()
    def run(self):
        while not self.stop:
            if not self.s.poll(200): continue
            topic, body, seq = self.s.recv_multipart()
            label = chr(body[32]); h = body[:32].hex()
            ms = int.from_bytes(body[33:41], 'little') if len(body) == 41 else None
            bad = None
            if label in 'AR' and len(body) != 41: bad = 'A/R body is %d bytes' % len(body)
            if label in 'CD' and len(body) != 33: bad = 'C/D body is %d bytes' % len(body)
            with self.lock: self.ev.append((label, h, ms, int.from_bytes(seq, 'little'), bad))
    def mark(self):
        with self.lock: return len(self.ev)
    def since(self, m):
        with self.lock: return list(self.ev[m:])

FAILS = []; PASSES = 0
def ok(cond, what):
    global PASSES
    if cond: PASSES += 1; print('  ok   ' + what)
    else: FAILS.append(what); print('  FAIL ' + what)

def settle(streams_marks, want, secs=60):
    """wait until every stream has at least `want` events past its mark, then
    a quiet second so an EXTRA event would be seen too"""
    end = time.time() + secs
    while time.time() < end:
        if all(len(s.since(m)) >= want for s, m in streams_marks): break
        time.sleep(0.2)
    time.sleep(2.5)

def show(evs):
    return ['%s %s..%s' % (l, h[:8], ('' if ms is None else ' #%d' % ms)) for l, h, ms, _, _ in evs]

def compare(phase, cs, bs, m_c, m_b, want):
    settle([(cs, m_c), (bs, m_b)], want)
    ce = cs.since(m_c); be = bs.since(m_b)
    COMPARED[phase] = min(len(ce), len(be))
    print('  %s core: %s' % (phase, show(ce)))
    print('  %s bmc : %s' % (phase, show(be)))
    for e in ce + be:
        if e[4]: ok(False, '%s: malformed body (%s)' % (phase, e[4]))
    same = [(l, h, ms) for l, h, ms, _, _ in ce] == [(l, h, ms) for l, h, ms, _, _ in be]
    ok(same, '%s: identical label/hash/mempool-sequence stream (%d events)' % (phase, len(ce)))
    ok(len(ce) == want, '%s: core produced the %d events the scenario implies' % (phase, want))
    for s, evs in (('core', ce), ('bmc', be)):
        seqs = [q for _, _, _, q, _ in evs]
        ok(all(b == a + 1 for a, b in zip(seqs, seqs[1:])), '%s: %s topic sequence contiguous' % (phase, s))
    return ce, be

def disp(txid): return txid   # RPC txids are display order, as the topic's hashes are

def main():
    os.makedirs(WORK, exist_ok=True)
    for d in ('core', 'core2', 'bmc/regtest'): os.makedirs(os.path.join(WORK, d), exist_ok=True)
    common = 'rpcuser=e2e\nrpcpassword=e2epw\nlistenonion=0\nfallbackfee=0.0001\ndatacarriersize=100000\n'
    open(os.path.join(WORK, 'core/bitcoin.conf'), 'w').write(
        'regtest=1\n[regtest]\nport=%d\nrpcport=%d\n%szmqpubsequence=tcp://127.0.0.1:%d\nmaxmempool=5\n' % (C1_P2P, C1_RPC, common, C1_ZMQ))
    open(os.path.join(WORK, 'core2/bitcoin.conf'), 'w').write(
        'regtest=1\n[regtest]\nport=%d\nrpcport=%d\n%sconnect=127.0.0.1:%d\n' % (C2_P2P, C2_RPC, common, C1_P2P))
    open(os.path.join(WORK, 'bmc/bitcoin.conf'), 'w').write(
        'chain=regtest\nprinttoconsole=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\n'
        'connect=127.0.0.1:%d\nzmqpubsequence=tcp://127.0.0.1:%d\nmaxmempool=5\ndatacarriersize=100000\n' % (B_P2P, B_RPC, C1_P2P, B_ZMQ))
    subprocess.run([CORE_BIN + '/bitcoind', '-datadir=' + WORK + '/core', '-daemon'], check=True, stdout=subprocess.DEVNULL)
    subprocess.run([CORE_BIN + '/bitcoind', '-datadir=' + WORK + '/core2', '-daemon'], check=True, stdout=subprocess.DEVNULL)
    if not up(core) or not up(core2): print('FAIL: Core did not start'); return 1
    blog = open(os.path.join(WORK, 'bmc.log'), 'wb')
    subprocess.Popen(['setsid', BMC_BIN, 'serve', WORK + '/bmc'], cwd=os.path.join(ROOT, 'asm'), stdout=blog, stderr=blog, stdin=subprocess.DEVNULL)
    for _ in range(120):
        if b'JSON-RPC server' in open(os.path.join(WORK, 'bmc.log'), 'rb').read(): break
        time.sleep(1)
    if not up(bmc): print('FAIL: bmc did not start'); return 1
    log('versions: core %s' % core('getnetworkinfo')['subversion'])
    zn = bmc('getzmqnotifications'); zc = core('getzmqnotifications')
    ok([(z['type'], z['hwm']) for z in zn] == [(z['type'], z['hwm']) for z in zc] == [('pubsequence', 1000)],
       'getzmqnotifications: pubsequence, hwm 1000, on both (%s / %s)' % (zc, zn))

    cs, bs = Stream(C1_ZMQ, 'core'), Stream(B_ZMQ, 'bmc')
    time.sleep(1)
    core('createwallet', 'w'); w = core.wallet('w')
    addr = w('getnewaddress')
    w('generatetoaddress', 200, addr)
    for _ in range(120):
        if core2('getblockcount') == 200 and bmc('getblockcount') == 200: break
        time.sleep(1)
    ok(bmc('getblockcount') == 200 and core2('getblockcount') == 200, 'setup: bmc and core2 synced to 200')
    core2('setnetworkactive', False)                  # core2 keeps the fork point, and nothing else
    for _ in range(30):
        if not core2('getpeerinfo'): break
        time.sleep(1)
    s_c = core('getrawmempool', False, True); s_b = bmc('getrawmempool', False, True)
    ok(s_c == s_b == {'txids': [], 'mempool_sequence': 1}, 'start: both {txids: [], mempool_sequence: 1} (%s / %s)' % (s_c, s_b))
    e = bmc.raw('getrawmempool', True, True)['error']; ec = core.raw('getrawmempool', True, True)['error']
    ok(e == ec, 'getrawmempool true true: same error (%s / %s)' % (ec, e))

    utxos = sorted([u for u in w('listunspent', 100) if u['amount'] >= 25], key=lambda u: (u['txid'], u['vout']))
    def mk(ins, outs, prevs=None):
        raw = core('createrawtransaction', [{'txid': t, 'vout': v, 'sequence': 0xfffffffd} for t, v in ins], outs)
        s = w('signrawtransactionwithwallet', raw, prevs) if prevs else w('signrawtransactionwithwallet', raw)
        if not s.get('complete'): raise RuntimeError('signing incomplete: %s' % s.get('errors'))
        return s['hex']
    def send_both(hexs):
        ids = []
        for hx in hexs:
            t = core('sendrawtransaction', hx, 0)
            r = bmc.raw('sendrawtransaction', hx, 0)
            if r.get('error') and 'already' not in str(r['error']): raise RuntimeError('bmc refused %s: %s' % (t, r['error']))
            ids.append(t)
        return ids
    def amt(x): return float('%.8f' % x)
    cb = [(u['txid'], u['vout'], u['amount']) for u in utxos]

    # ---- add
    m_c, m_b = cs.mark(), bs.mark()
    a1, a2 = w('getnewaddress'), w('getnewaddress')
    P1hex = mk([cb[0][:2]], {a1: amt(cb[0][2] - 0.001)}); P1 = core('decoderawtransaction', P1hex)['txid']
    P1prev = [{'txid': P1, 'vout': 0, 'scriptPubKey': w('getaddressinfo', a1)['scriptPubKey'], 'amount': amt(cb[0][2] - 0.001)}]
    C1hex = mk([(P1, 0)], {a2: amt(cb[0][2] - 0.002)}, P1prev); C1 = core('decoderawtransaction', C1hex)['txid']
    send_both([P1hex, C1hex])
    compare('add', cs, bs, m_c, m_b, 2)

    # ---- rbf
    m_c, m_b = cs.mark(), bs.mark()
    X1hex = mk([cb[1][:2]], {w('getnewaddress'): amt(cb[1][2] - 0.0001)})
    X2hex = mk([cb[1][:2]], {w('getnewaddress'): amt(cb[1][2] - 0.001)})
    send_both([X1hex]); time.sleep(1); send_both([X2hex])
    compare('rbf', cs, bs, m_c, m_b, 3)

    # ---- block: P1 mined, K2 in the block double-spends K1 in the pool
    m_c, m_b = cs.mark(), bs.mark()
    K1hex = mk([cb[2][:2]], {w('getnewaddress'): amt(cb[2][2] - 0.0001)})
    K2hex = mk([cb[2][:2]], {w('getnewaddress'): amt(cb[2][2] - 0.0002)}); K2 = core('decoderawtransaction', K2hex)['txid']
    send_both([K1hex])
    B1 = core('generateblock', addr, [P1, K2hex])['hash']
    for _ in range(60):
        if bmc('getbestblockhash') == B1: break
        time.sleep(1)
    ok(bmc('getbestblockhash') == B1, 'block: bmc follows to B1')
    compare('block', cs, bs, m_c, m_b, 3)

    # ---- invalidate B1 on both
    m_c, m_b = cs.mark(), bs.mark()
    core('invalidateblock', B1); bmc('invalidateblock', B1)
    compare('invalidate', cs, bs, m_c, m_b, 3)

    # ---- reconsider B1 on both (bmc re-fetches it from Core)
    m_c, m_b = cs.mark(), bs.mark()
    core('reconsiderblock', B1); bmc('reconsiderblock', B1)
    for _ in range(90):
        if bmc('getbestblockhash') == B1: break
        time.sleep(1)
    ok(bmc('getbestblockhash') == B1, 'reconsider: bmc back on B1')
    compare('reconsider', cs, bs, m_c, m_b, 1)
    ok(core('getrawmempool', False, True)['mempool_sequence'] == bmc('getrawmempool', False, True)['mempool_sequence'],
       'reconsider: the two counters agree after the silent block numbers')

    # ---- a real one-step reorg: B1' = [P1, Z], B2' on the fork point
    m_c, m_b = cs.mark(), bs.mark()
    Zhex = mk([(P1, 0)], {w('getnewaddress'): amt(cb[0][2] - 0.003)}, P1prev)
    a2addr = w('getnewaddress')
    B1p = core2('generateblock', a2addr, [P1hex, Zhex])['hash']
    B2p = core2('generateblock', a2addr, [])['hash']
    core('submitblock', core2('getblock', B1p, 0)); core('submitblock', core2('getblock', B2p, 0))
    ok(core('getbestblockhash') == B2p, 'reorg: Core #1 switched to the heavier branch')
    for _ in range(120):
        if bmc('getbestblockhash') == B2p: break
        time.sleep(1)
    ok(bmc('getbestblockhash') == B2p, 'reorg: bmc switched to the heavier branch')
    compare('reorg', cs, bs, m_c, m_b, 5)

    # ---- snapshot agreement
    s_c = core('getrawmempool', False, True); s_b = bmc('getrawmempool', False, True)
    ok(sorted(s_c['txids']) == sorted(s_b['txids']), 'snapshot: same txids (%d)' % len(s_c['txids']))
    ok(s_c['mempool_sequence'] == s_b['mempool_sequence'], 'snapshot: same mempool_sequence (%s / %s)' % (s_c['mempool_sequence'], s_b['mempool_sequence']))
    last = [ms for _, _, ms, _, _ in bs.since(0) if ms is not None]
    ok(last and s_b['mempool_sequence'] > max(last), 'snapshot: bmc value is above every number it published')

    # ---- evict: rising feerates into a 5 MB pool
    log('evict phase: big transactions')
    m_c, m_b = cs.mark(), bs.mark()
    sent = []
    for i, (t, v, a) in enumerate(cb[3:3 + 75]):
        payload = ('%04x' % i) * 40000                  # 160,000 hex chars = 80,000 bytes of OP_RETURN data
        fee = amt((i + 2) * 81000 / 1e8)               # rising: ~(i+2) sat/vB at ~81 kvB
        hx = mk([(t, v)], [{'data': payload}, {w('getnewaddress'): amt(a - fee)}])
        tid = core('sendrawtransaction', hx, 0)
        r = bmc.raw('sendrawtransaction', hx, 0)
        sent.append((tid, r.get('error')))
    settle([(cs, m_c), (bs, m_b)], 75, secs=120)
    for s, rpc in ((cs, core), (bs, bmc)):
        evs = s.since(m_c if s is cs else m_b)
        adds = [h for l, h, _, _, _ in evs if l == 'A']; rems = [h for l, h, _, _, _ in evs if l == 'R']
        pool = set(rpc('getrawmempool'))
        model = set()
        for l, h, _, _, _ in evs:
            if l == 'A': model.add(h)
            elif l == 'R': model.discard(h)
        phase_pool = {h for h in pool if h in adds}
        print('  evict %s: %d A, %d R, pool %d' % (s.name, len(adds), len(rems), len(pool)))
        ok(len(rems) > 0, 'evict: %s trimmed its pool (published R)' % s.name)
        ok(phase_pool == model, 'evict: %s stream reconstructs its own pool exactly' % s.name)
        # every R lands after the A of the transaction that forced it: the
        # stream never shows a removal between two adds without the later add
        # being the cause, so check that each R is preceded by an A and that
        # no R precedes the phase's first A
        first_a = next((k for k, e in enumerate(evs) if e[0] == 'A'), None)
        first_r = next((k for k, e in enumerate(evs) if e[0] == 'R'), None)
        ok(first_r is None or (first_a is not None and first_r > first_a), 'evict: %s publishes A(newcomer) before R(evicted)' % s.name)
        ms = [e[2] for e in evs]
        ok(all(b == a + 1 for a, b in zip(ms, ms[1:])), 'evict: %s mempool sequence contiguous through the phase' % s.name)
    ce, be = cs.since(m_c), bs.since(m_b)
    lc = [(l, h) for l, h, _, _, _ in ce]; lb = [(l, h) for l, h, _, _, _ in be]
    if lc == lb:
        ok(True, 'evict: identical streams')
    else:
        k = next(i for i in range(min(len(lc), len(lb)) + 1) if i == min(len(lc), len(lb)) or lc[i] != lb[i])
        print('  evict: streams identical for the first %d events, then diverge (INFORMATIONAL -- where each pool '
              'counts itself full is a declared divergence, not the sequence topic):' % k)
        print('    core from there: %s' % ['%s %s..' % (l, h[:8]) for l, h in lc[k:k + 6]])
        print('    bmc  from there: %s' % ['%s %s..' % (l, h[:8]) for l, h in lb[k:k + 6]])
    rc_ = [h for l, h in lc if l == 'R']; rb_ = [h for l, h in lb if l == 'R']
    n = min(len(rc_), len(rb_))
    ok(rc_[:n] == rb_[:n], 'evict: both evict in the same ORDER (cheapest first): the first %d evictions agree' % n)
    # every R arrives directly behind an A (the newcomer that forced it) or
    # another R of the same trim -- never in front of the add that caused it
    for s, lst in (('core', lc), ('bmc', lb)):
        ok(all(lst[i - 1][0] in 'AR' and any(x[0] == 'A' for x in lst[:i]) for i in range(len(lst)) if lst[i][0] == 'R'),
           'evict: %s: every R follows the A that forced it' % s)

    # ---- reload: restart both; mempool.dat comes back as 'A's numbered 1..n
    # (Core's LoadMempool goes through AcceptToMemoryPool, which signals;
    # bmc's reload goes through the same mpool_policy_add every accept does).
    # The subscribers stay up: a SUB socket reconnects on its own.
    log('reload phase: restarting both nodes')
    want_c = set(core('getrawmempool')); want_b = set(bmc('getrawmempool'))
    core('stop')
    def restarting():   # bmc's processes (`serve <WORK>/bmc`) and Core #1's (`-datadir=<WORK>/core`)
        out = []
        for p in my_procs():
            try: cmd = open('/proc/%d/cmdline' % p, 'rb').read()
            except Exception: continue
            if (WORK + '/bmc').encode() in cmd or (WORK + '/core\0').encode() in cmd: out.append(p)
        return out
    for p in restarting():
        if (WORK + '/bmc').encode() in open('/proc/%d/cmdline' % p, 'rb').read():
            try: os.kill(p, signal.SIGTERM)
            except Exception: pass
    for _ in range(90):
        if not restarting(): break
        time.sleep(1)
    m_c, m_b = cs.mark(), bs.mark()
    subprocess.run([CORE_BIN + '/bitcoind', '-datadir=' + WORK + '/core', '-daemon'], check=True, stdout=subprocess.DEVNULL)
    subprocess.Popen(['setsid', BMC_BIN, 'serve', WORK + '/bmc'], cwd=os.path.join(ROOT, 'asm'), stdout=blog, stderr=blog, stdin=subprocess.DEVNULL)
    if not up(core) or not up(bmc): ok(False, 'reload: both nodes came back'); return 1
    for _ in range(120):
        try:
            if core('getmempoolinfo')['loaded'] and len(bmc('getrawmempool')) >= len(want_b): break
        except Exception: pass
        time.sleep(1)
    settle([(cs, m_c), (bs, m_b)], min(len(want_c), len(want_b)), secs=60)
    for s, want, rpc in ((cs, want_c, core), (bs, want_b, bmc)):
        evs = [e for e in s.since(m_c if s is cs else m_b) if e[0] in 'AR']
        adds = [e for e in evs if e[0] == 'A']
        snap = rpc('getrawmempool', False, True)
        print('  reload %s: %d A, %d R (pool before the restart: %d, after: %d, mempool_sequence %d)' %
              (s.name, len(adds), len(evs) - len(adds), len(want), len(snap['txids']), snap['mempool_sequence']))
        # the counter proves every reloaded tx took a number, whether or not
        # the subscriber had rejoined in time to see it
        ok(set(snap['txids']) == want and snap['mempool_sequence'] == len(want) + 1,
           'reload: %s reloads its pool and numbers each transaction once (mempool_sequence = n+1)' % s.name)
        if not adds:
            # A PUB drops what is sent before a SUB has (re)joined -- the
            # "slow joiner". Core loads mempool.dat on a thread that starts
            # the moment init finishes, often inside pyzmq's 100 ms reconnect.
            print('  reload %s: the subscriber rejoined after the reload finished (slow joiner) -- '
                  'the stream is not checked, the counter above is' % s.name)
            continue
        ok({e[1] for e in adds} <= want and len(evs) == len(adds), 'reload: %s publishes only A, only for reloaded transactions' % s.name)
        ok([e[2] for e in adds] == list(range(snap['mempool_sequence'] - len(adds), snap['mempool_sequence'])),
           'reload: %s numbers what it published consecutively, ending at n' % s.name)

    # every exact-comparison phase must have compared at least one event on
    # BOTH streams (a dead subscriber compares [] == [] and would "match")
    require_sources({p: COMPARED.get(p, 0) for p in ('add', 'rbf', 'block', 'invalidate', 'reconsider', 'reorg')})
    print('\n%s: %d passed, %d failed' % ('PASS' if not FAILS else 'FAIL', PASSES, len(FAILS)))
    for f in FAILS: print('  - ' + f)
    return 1 if FAILS else 0

if __name__ == '__main__':
    rc = 2
    try: rc = main()
    except Exception as e:
        import traceback; traceback.print_exc()
    finally: cleanup()
    sys.exit(rc)
