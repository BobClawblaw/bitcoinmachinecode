#!/usr/bin/env python3
"""validation/zmq_reload_burst_core_diff.py -- hashtx / rawtx / sequence 'A'
under a transaction BURST and a mempool.dat RELOAD, bmc against Bitcoin Core
v31.1, on regtest. 2026-09-19.

WHY. Production (deploy-20260919a, 11:52-11:56Z) reloaded 72,952 transactions
from mempool.dat and logged "[zmq] notification ring overrun ... (total
61,836)": the worker accepted up to 2,048 submissions per rotation into a
64-slot staging ring that it drained once per rotation. The subscriber saw no
gap -- the hashtx topic sequence ran on contiguously over the missing
messages. Core publishes the reload (init.cpp registers the ZMQ notification
interface before LoadMempool, which goes through AcceptToMemoryPool, which
signals TransactionAddedToMempool), so every reloaded transaction owes one
hashtx, one rawtx and one sequence 'A'.

WHAT IS COUNTED, per node and per phase:
  published  -- from the PUBLISHER's own per-topic sequence (the 4-byte third
               frame): last seen + 1 - first seen, plus the first seen number
               itself when the phase starts at a fresh counter (a restart). A
               PUB drops what it sends before a SUB has (re)joined (the slow
               joiner), so what the subscriber missed at the START of the
               reload is still counted as published by the number it resumes
               at, and anything missing in the MIDDLE shows as a gap.
  received   -- distinct txids seen on hashtx / rawtx, 'A's on sequence
  gaps       -- per-topic sequence jumps inside the phase
  expected   -- the transactions that entered the pool: the burst's accepted
               count, or the reloaded pool (getrawmempool after the reload)

  phase burst   N one-in-one-out transactions (default 6,000: well past the
                old 64-slot ring and the worker's 2,048-per-rotation budget),
                sendrawtransaction to both nodes as fast as RPC takes them
  phase reload  both stopped and restarted on the same datadir; each reloads
                its mempool.dat through its ordinary accept path

PASS: on each node, published == expected on hashtx, rawtx and sequence 'A'
for both phases, no gaps, and every received txid is a pool member. bmc and
Core are also compared with each other (same counts).

Usage: <venv with pyzmq>/bin/python3 validation/zmq_reload_burst_core_diff.py
       env: CORE_BIN, BMC_BIN, WORK (default $TMPDIR/bmc-zburst-<pid>), N,
            KEEP=1 (keep the datadirs)
"""
import base64, json, os, shutil, signal, subprocess, sys, threading, time, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
from diffguard import require_sources   # a phase whose stream stayed empty must not read as a pass
import zmq

CORE_BIN = os.environ.get('CORE_BIN', '/mnt/nvme8tb/core-build/bitcoin-v31.1/build/bin')
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BMC_BIN = os.environ.get('BMC_BIN', os.path.join(ROOT, 'asm/daemon/bmcbitcoind'))
WORK = os.environ.get('WORK', os.path.join(os.environ.get('TMPDIR', '/tmp'), 'bmc-zburst-%d' % os.getpid()))
N = int(os.environ.get('N', '6000'))
# not adjacent: Core binds an onion target on P2P+1 even with listenonion=0
C_P2P, C_RPC, C_ZMQ = 19852, 19856, 19858
B_P2P, B_RPC, B_ZMQ = 19862, 19866, 19868

def log(*a): print(time.strftime('%H:%M:%S'), *a, flush=True)

class RPC:
    def __init__(self, port, name, path=''): self.url = 'http://127.0.0.1:%d/%s' % (port, path); self.name = name
    def _post(self, payload, timeout=600):
        req = urllib.request.Request(self.url, json.dumps(payload).encode(),
                                     {'Content-Type': 'text/plain', 'Authorization': 'Basic ' + base64.b64encode(b'e2e:e2epw').decode()})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r: return json.loads(r.read())
        except urllib.error.HTTPError as e: return json.loads(e.read())
    def raw(self, method, *params): return self._post({'jsonrpc': '1.0', 'id': 'z', 'method': method, 'params': list(params)})
    def batch(self, calls):
        out = self._post([{'jsonrpc': '1.0', 'id': i, 'method': m, 'params': list(p)} for i, (m, p) in enumerate(calls)])
        out = sorted(out, key=lambda d: d['id'])
        for d in out:
            if d.get('error'): raise RuntimeError('%s batch: %s' % (self.name, d['error']))
        return [d['result'] for d in out]
    def __call__(self, method, *params):
        d = self.raw(method, *params)
        if d.get('error'): raise RuntimeError('%s %s: %s' % (self.name, method, d['error']))
        return d['result']
    def wallet(self, w): return RPC(int(self.url.split(':')[2].split('/')[0]), self.name, 'wallet/' + w)

core, bmc = RPC(C_RPC, 'core'), RPC(B_RPC, 'bmc')

def up(rpc, secs=180):
    for _ in range(secs):
        try: rpc('getblockcount'); return True
        except Exception: time.sleep(1)
    return False

def my_procs(tag=None):
    out = []
    for p in os.listdir('/proc'):
        if not p.isdigit() or int(p) == os.getpid(): continue
        try:
            cmd = open('/proc/%s/cmdline' % p, 'rb').read()
            exe = os.path.basename(os.readlink('/proc/%s/exe' % p))
        except Exception: continue
        if (tag or WORK).encode() in cmd and exe not in ('bash', 'sh', 'python3', 'python3.12'): out.append(int(p))
    return out

def stop_bmc():
    for p in my_procs(WORK + '/bmc'):
        try: os.kill(p, signal.SIGTERM)
        except Exception: pass
    for _ in range(120):
        if not my_procs(WORK + '/bmc'): return True
        time.sleep(1)
    return False

def cleanup():
    try: core('stop')
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
    """every message on hashtx, rawtx and sequence, with its topic sequence"""
    def __init__(self, port, name):
        self.name = name; self.msgs = []; self.lock = threading.Lock()
        self.ctx = zmq.Context(); self.s = self.ctx.socket(zmq.SUB)
        self.s.setsockopt(zmq.RCVHWM, 0)
        self.s.setsockopt(zmq.RECONNECT_IVL, 20)
        for t in ('hashtx', 'rawtx', 'sequence'): self.s.setsockopt_string(zmq.SUBSCRIBE, t)
        self.s.connect('tcp://127.0.0.1:%d' % port)
        self.stop = False; self.t = threading.Thread(target=self.run, daemon=True); self.t.start()
    def run(self):
        while not self.stop:
            if not self.s.poll(200): continue
            topic, body, seq = self.s.recv_multipart()
            with self.lock: self.msgs.append((topic.decode(), body, int.from_bytes(seq, 'little')))
    def mark(self):
        with self.lock: return len(self.msgs)
    def since(self, m):
        with self.lock: return list(self.msgs[m:])

def txid_of_raw(rpc, rawhex): return rpc('decoderawtransaction', rawhex)['txid']

def account(msgs, fresh_counter):
    """per topic: published (by the publisher's own numbering), received, gaps"""
    out = {}
    for topic in ('hashtx', 'rawtx', 'sequence'):
        seqs = [q for t, b, q in msgs if t == topic and (topic != 'sequence' or chr(b[32]) == 'A')]
        allseq = [q for t, b, q in msgs if t == topic]
        gaps = sum(b - a - 1 for a, b in zip(allseq, allseq[1:]) if b != a + 1)
        if not allseq: out[topic] = {'published': None, 'received': 0, 'gaps': 0, 'first': None}; continue
        pub = allseq[-1] + 1 - (0 if fresh_counter else allseq[0])
        out[topic] = {'received': len(seqs), 'gaps': gaps, 'first': allseq[0], 'published_all': pub}
    return out

FAILS = []; PASSES = 0; PUBLISHED = {}
def ok(cond, what):
    global PASSES
    if cond: PASSES += 1; print('  ok   ' + what)
    else: FAILS.append(what); print('  FAIL ' + what)

def quiesce(streams, secs=300, quiet=4.0):
    """wait until no stream has grown for `quiet` seconds"""
    end = time.time() + secs; last = [s.mark() for s in streams]; t_last = time.time()
    while time.time() < end:
        time.sleep(0.5)
        now = [s.mark() for s in streams]
        if now != last: last = now; t_last = time.time()
        elif time.time() - t_last >= quiet: return

def judge(phase, name, msgs, pool, fresh_counter):
    raws = [b for t, b, q in msgs if t == 'rawtx']
    adds = [b[:32].hex() for t, b, q in msgs if t == 'sequence' and chr(b[32]) == 'A']
    acc = account(msgs, fresh_counter)
    hs = [b.hex() for t, b, q in msgs if t == 'hashtx']
    want = len(pool)
    print('  %-6s %-5s pool %6d | hashtx recv %6d gaps %d first#%s | rawtx recv %6d gaps %d first#%s | sequence A recv %6d gaps %d first#%s' % (
        phase, name, want,
        len(hs), acc['hashtx']['gaps'], acc['hashtx'].get('first'),
        len(raws), acc['rawtx']['gaps'], acc['rawtx'].get('first'),
        len(adds), acc['sequence']['gaps'], acc['sequence'].get('first')))
    return {'pool': want, 'hashtx': len(set(hs)), 'rawtx': len(raws), 'A': len(set(adds)),
            'gaps': {t: acc[t]['gaps'] for t in acc}, 'first': {t: acc[t].get('first') for t in acc},
            'hs': set(hs), 'adds': set(adds)}

def main():
    os.makedirs(os.path.join(WORK, 'core'), exist_ok=True); os.makedirs(os.path.join(WORK, 'bmc/regtest'), exist_ok=True)
    zc = 'zmqpubhashtx=tcp://127.0.0.1:%d\nzmqpubrawtx=tcp://127.0.0.1:%d\nzmqpubsequence=tcp://127.0.0.1:%d\n' \
         'zmqpubhashtxhwm=0\nzmqpubrawtxhwm=0\nzmqpubsequencehwm=0\n'
    open(os.path.join(WORK, 'core/bitcoin.conf'), 'w').write(
        'regtest=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\nlistenonion=0\nfallbackfee=0.0001\n'
        'maxmempool=300\n' % (C_P2P, C_RPC) + zc % (C_ZMQ, C_ZMQ, C_ZMQ))
    open(os.path.join(WORK, 'bmc/bitcoin.conf'), 'w').write(
        'chain=regtest\nprinttoconsole=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\n'
        'connect=127.0.0.1:%d\nmaxmempool=300\n' % (B_P2P, B_RPC, C_P2P) + zc % (B_ZMQ, B_ZMQ, B_ZMQ))
    subprocess.run([CORE_BIN + '/bitcoind', '-datadir=' + WORK + '/core', '-daemon'], check=True, stdout=subprocess.DEVNULL)
    if not up(core): print('FAIL: Core did not start'); return 1
    blog = open(os.path.join(WORK, 'bmc.log'), 'ab')
    def start_bmc():
        subprocess.Popen(['setsid', BMC_BIN, 'serve', WORK + '/bmc'], cwd=os.path.join(ROOT, 'asm'), stdout=blog, stderr=blog, stdin=subprocess.DEVNULL)
    start_bmc()
    if not up(bmc): print('FAIL: bmc did not start'); return 1
    log('versions: core %s; bmc %s' % (core('getnetworkinfo')['subversion'], BMC_BIN))
    cs, bs = Stream(C_ZMQ, 'core'), Stream(B_ZMQ, 'bmc')

    # ---- setup: N confirmed one-output coins
    core('createwallet', 'w'); w = core.wallet('w')
    addr = w('getnewaddress')
    w('generatetoaddress', 101 + (N + 499) // 500, addr)
    coins = sorted([u for u in w('listunspent', 100) if u['amount'] >= 25], key=lambda u: (u['txid'], u['vout']))
    fan = []
    for i in range(0, N, 500):
        c = coins[len(fan)]; k = min(500, N - i)
        addrs = w.batch([('getnewaddress', ())] * k)
        each = float('%.8f' % ((c['amount'] - 0.01) / k))
        raw = core('createrawtransaction', [{'txid': c['txid'], 'vout': c['vout']}], {a: each for a in addrs})
        fan.append(core('sendrawtransaction', w('signrawtransactionwithwallet', raw)['hex']))
    w('generatetoaddress', 1, addr)
    tip = core('getbestblockhash')
    for _ in range(180):
        if bmc('getbestblockhash') == tip: break
        time.sleep(1)
    ok(bmc('getbestblockhash') == tip, 'setup: bmc synced to Core (%d blocks)' % core('getblockcount'))
    small = [u for u in w('listunspent', 1) if u['txid'] in set(fan)]
    small = sorted(small, key=lambda u: (u['txid'], u['vout']))[:N]
    dest = w.batch([('getnewaddress', ())] * len(small))
    raws = core.batch([('createrawtransaction', ([{'txid': u['txid'], 'vout': u['vout']}], {d: float('%.8f' % (u['amount'] - 0.00002))}))
                       for u, d in zip(small, dest)])
    signed = []
    for i in range(0, len(raws), 500):
        signed += [s['hex'] for s in w.batch([('signrawtransactionwithwallet', (r,)) for r in raws[i:i + 500]])]
    log('setup: %d signed transactions' % len(signed))

    # ---- burst: as fast as RPC takes them, to both nodes (bmc also hears
    # them from Core over P2P; whichever path accepts first publishes)
    ok(core('getrawmempool') == [] and bmc('getrawmempool') == [], 'burst: both pools start empty')
    m_c, m_b = cs.mark(), bs.mark()
    t0 = time.time()
    for i in range(0, len(signed), 500):
        core.batch([('sendrawtransaction', (h,)) for h in signed[i:i + 500]])
    t1 = time.time()
    brej = 0
    for h in signed:
        r = bmc.raw('sendrawtransaction', h)
        if r.get('error') and 'already' not in str(r['error']).lower() and 'txn-already' not in str(r['error']): brej += 1
    t2 = time.time()
    log('burst: core took %d in %.1fs, bmc in %.1fs (%d refused)' % (len(signed), t1 - t0, t2 - t1, brej))
    quiesce([cs, bs])
    pools = {'core': set(core('getrawmempool')), 'bmc': set(bmc('getrawmempool'))}
    res = {}
    for s, name in ((cs, 'core'), (bs, 'bmc')):
        res[name] = judge('burst', name, s.since(m_c if s is cs else m_b), pools[name], False)
    for name in ('core', 'bmc'):
        r = res[name]
        ok(r['pool'] == N, 'burst: %s accepted all %d' % (name, N))
        ok(r['hashtx'] == r['pool'] and r['rawtx'] == r['pool'] and r['A'] == r['pool'],
           'burst: %s published hashtx/rawtx/sequence-A for every accepted tx (%d/%d/%d of %d)' % (name, r['hashtx'], r['rawtx'], r['A'], r['pool']))
        ok(r['hs'] <= pools[name] and r['adds'] <= pools[name],
           'burst: %s published only pool members' % name)
        ok(all(g == 0 for g in r['gaps'].values()), 'burst: %s no topic-sequence gaps %s' % (name, r['gaps']))

    ok((res['core']['hashtx'], res['core']['rawtx'], res['core']['A']) == (res['bmc']['hashtx'], res['bmc']['rawtx'], res['bmc']['A']),
       'burst: bmc and Core published the same counts')

    # ---- reload: stop both, restart on the same datadirs
    log('reload: restarting both nodes')
    core('stop')
    ok(stop_bmc(), 'reload: bmc stopped')
    for _ in range(90):
        if not my_procs(WORK + '/core'): break
        time.sleep(1)
    m_c, m_b = cs.mark(), bs.mark()
    t0 = time.time()
    subprocess.run([CORE_BIN + '/bitcoind', '-datadir=' + WORK + '/core', '-daemon'], check=True, stdout=subprocess.DEVNULL)
    start_bmc()
    if not up(core) or not up(bmc): ok(False, 'reload: both nodes came back'); return 1
    for _ in range(600):
        try:
            if core('getmempoolinfo')['loaded'] and len(bmc('getrawmempool')) >= len(pools['bmc']): break
        except Exception: pass
        time.sleep(1)
    quiesce([cs, bs], quiet=6.0)
    log('reload: both loaded (%.0fs)' % (time.time() - t0))
    after = {'core': set(core('getrawmempool')), 'bmc': set(bmc('getrawmempool'))}
    for s, name in ((cs, 'core'), (bs, 'bmc')):
        msgs = s.since(m_c if s is cs else m_b)
        r = judge('reload', name, msgs, after[name], True)
        ok(after[name] == pools[name], 'reload: %s reloaded its whole pool (%d)' % (name, len(after[name])))
        # what the publisher numbered: a fresh counter starts at 0, so the
        # first number seen is how many were sent before the subscriber rejoined
        for topic, got in (('hashtx', r['hashtx']), ('rawtx', r['rawtx']), ('sequence', r['A'])):
            first = r['first'][topic] or 0
            published = first + got + r['gaps'][topic]
            PUBLISHED[(name, topic)] = published
            print('         %s %s: publisher numbered %d (slow-joiner prefix %d, received %d, gaps %d)' %
                  (name, topic, published, first, got, r['gaps'][topic]))
            ok(published == len(after[name]) and r['gaps'][topic] == 0,
               'reload: %s published %s for every reloaded tx, no gap (%d of %d)' % (name, topic, published, len(after[name])))
        ok(r['hs'] <= after[name], 'reload: %s published only reloaded txids' % name)
        res['reload_' + name] = r
    ok(all(PUBLISHED[('core', t)] == PUBLISHED[('bmc', t)] for t in ('hashtx', 'rawtx', 'sequence')),
       'reload: bmc and Core numbered the same count on every topic')
    # every node x phase must have delivered messages: a dead subscriber
    # counts 0 received and would "agree" with a publisher that sent nothing
    require_sources({'%s %s' % (ph, nm): len(res[k]['hs'])
                     for ph, nm, k in (('burst', 'core', 'core'), ('burst', 'bmc', 'bmc'),
                                       ('reload', 'core', 'reload_core'), ('reload', 'bmc', 'reload_bmc'))})
    print('\n%s: %d passed, %d failed' % ('PASS' if not FAILS else 'FAIL', PASSES, len(FAILS)))
    for f in FAILS: print('  - ' + f)
    return 1 if FAILS else 0

if __name__ == '__main__':
    rc = 2
    try: rc = main()
    except Exception:
        import traceback; traceback.print_exc()
    finally: cleanup()
    sys.exit(rc)
