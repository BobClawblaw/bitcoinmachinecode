#!/usr/bin/env python3
"""validation/unbroadcast_core_diff.py -- the unbroadcast set, bmc against
Bitcoin Core v31.1, on regtest. 2026-11-06.

Core keeps the transactions it submitted itself (sendrawtransaction, the
wallet) in an "unbroadcast" set until a peer fetches one with getdata, re-
announces the set every 10-15 minutes, persists it in mempool.dat, and
reports it as getmempoolinfo.unbroadcastcount and each entry's `unbroadcast`.
This node reported 0 / false until 2026-11-06.

Topology: a Core PEER with the wallet and the chain; two SUBJECTS, bmc and a
second Core, each connected only to the peer. Each subject gets its own
transactions (one relayed from the other would arrive as already-in-mempool,
which Core does not add). Each step runs on both subjects, and their answers
are compared with each other and with what Core's code says they must be:

  A  sendrawtransaction with the peer connected: unbroadcast at once, then
     cleared when the peer fetches it.
  B  networking off: a submission stays unbroadcast; unbroadcastcount 1.
  C  savemempool: the file's unbroadcast section holds exactly that txid.
  D  restart with networking off: the reload restores the flag (Core's
     startup load applies the set).
  E  networking back on: no announcement until the 10-15 minute reattempt,
     which the peer answers with getdata -- the flag clears and the peer has
     the transaction. Takes up to ~16 minutes.
  F  importmempool of the OTHER subject's file: options.apply_unbroadcast_set
     false leaves the set alone, true adds the file's txid (now in the pool by
     relay); a non-bool option gets Core's error.

Usage: python3 validation/unbroadcast_core_diff.py
       env: CORE_BIN, BMC_BIN, WORK (default $TMPDIR/bmc-unbcast-<pid>), KEEP=1
"""
import base64, json, os, shutil, signal, subprocess, sys, time, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
from diffguard import require_cases

CORE_BIN = os.environ.get('CORE_BIN', '/storage/bitcoin-core-v31.1/bin')
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BMC_BIN = os.environ.get('BMC_BIN', os.path.join(ROOT, 'asm/daemon/bmcbitcoind'))
WORK = os.environ.get('WORK', os.path.join(os.environ.get('TMPDIR', '/tmp'), 'bmc-unbcast-%d' % os.getpid()))
# not adjacent: Core binds an onion target on P2P+1 even with listenonion=0
P_P2P, P_RPC = 19714, 19724          # the peer (Core, wallet)
B_P2P, B_RPC = 19734, 19744          # subject: bmc
S_P2P, S_RPC = 19754, 19764          # subject: Core
AUTH = 'Basic ' + base64.b64encode(b'e2e:e2epw').decode()
W = '/wallet/w'

def post(port, body, path='/'):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (port, path), body.encode(),
                                 {'Content-Type': 'application/json', 'Authorization': AUTH})
    try:
        with urllib.request.urlopen(req, timeout=120) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()

def rpc(port, method, params=None, path='/'):
    """(result, error) -- error is Core's {code, message} or None"""
    s, b = post(port, json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': params or []}), path)
    r = json.loads(b)
    return r.get('result'), r.get('error')

def call(port, method, params=None, path='/'):
    res, err = rpc(port, method, params, path)
    if err: raise RuntimeError('%s %s: %s' % (method, params, err))
    return res

def up(port, secs=180):
    for _ in range(secs):
        try:
            if post(port, '{"method":"getblockcount","id":0}')[0] == 200: return True
        except Exception: pass
        time.sleep(1)
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

def down(port, secs=120):
    for _ in range(secs):
        try: post(port, '{"method":"getblockcount","id":0}')
        except Exception: return True
        time.sleep(1)
    return False

def cleanup():
    for port in (B_RPC, S_RPC, P_RPC):
        try: post(port, '{"method":"stop","id":0}')
        except Exception: pass
    time.sleep(3)
    for p in my_procs():
        try: os.kill(p, signal.SIGTERM)
        except Exception: pass
    for _ in range(30):
        if not my_procs(): break
        time.sleep(1)
    if os.environ.get('KEEP') != '1': shutil.rmtree(WORK, ignore_errors=True)

def bmc_conf(netactive):
    open(os.path.join(WORK, 'bmc/bitcoin.conf'), 'w').write(
        'chain=regtest\nprinttoconsole=1\n%s[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\n'
        'connect=127.0.0.1:%d\n' % ('' if netactive else 'networkactive=0\n', B_P2P, B_RPC, P_P2P))

def start_bmc():
    blog = open(os.path.join(WORK, 'bmc.log'), 'ab')
    subprocess.Popen(['setsid', BMC_BIN, 'serve', WORK + '/bmc'], cwd=os.path.join(ROOT, 'asm'),
                     stdout=blog, stderr=blog, stdin=subprocess.DEVNULL)
    return up(B_RPC)

def start_core(d, extra=()):
    subprocess.run([CORE_BIN + '/bitcoind', '-datadir=' + os.path.join(WORK, d), '-daemon'] + list(extra),
                   check=True, stdout=subprocess.DEVNULL)

SUBJ = (('bmc', B_RPC), ('core', S_RPC))
cases = fails = 0
def check(what, got, want):
    global cases, fails
    cases += 1
    ok = got == want
    if not ok: fails += 1
    print('  %s %s: %r%s' % ('ok  ' if ok else 'FAIL', what, got, '' if ok else ' (want %r)' % (want,)))
    return ok

def ub_state(port, txid):
    e, err = rpc(port, 'getmempoolentry', [txid])
    v, _ = rpc(port, 'getrawmempool', [True])
    return (None if err else e['unbroadcast'], (v or {}).get(txid, {}).get('unbroadcast'),
            call(port, 'getmempoolinfo')['unbroadcastcount'])

def wait_for(pred, secs, step=2):
    t = time.time()
    while time.time() - t < secs:
        try:
            if pred(): return True
        except Exception: pass
        time.sleep(step)
    return False

def conns(port): return call(port, 'getconnectioncount')

def file_unbroadcast(path):
    """the unbroadcast section of a v1 or v2 mempool.dat, as display txids"""
    b = open(path, 'rb').read()
    ver = int.from_bytes(b[0:8], 'little'); p = 8
    if ver == 2:                     # Core's default: XOR by absolute file position after the key
        kl, p = _cs(b, p); key = b[p:p+kl]; p += kl
        b = b[:p] + bytes(c ^ key[i % len(key)] for i, c in enumerate(b[p:], start=p))
    n = int.from_bytes(b[p:p+8], 'little'); p += 8
    for _ in range(n): p = _skip_tx(b, p) + 16          # the tx, then nTime and nFeeDelta
    nd, p = _cs(b, p); p += nd * 40
    nu, p = _cs(b, p)
    return [b[p+32*i:p+32*i+32][::-1].hex() for i in range(nu)]

def _cs(b, p):
    x = b[p]
    if x < 253: return x, p + 1
    n = {253: 2, 254: 4, 255: 8}[x]
    return int.from_bytes(b[p+1:p+1+n], 'little'), p + 1 + n

def _skip_tx(b, p):
    p += 4
    seg = b[p] == 0 and b[p+1] == 1
    if seg: p += 2
    nin, p = _cs(b, p)
    for _ in range(nin):
        p += 36; l, p = _cs(b, p); p += l + 4
    nout, p = _cs(b, p)
    for _ in range(nout):
        p += 8; l, p = _cs(b, p); p += l
    if seg:
        for _ in range(nin):
            k, p = _cs(b, p)
            for _ in range(k): l, p = _cs(b, p); p += l
    return p + 4

def main():
    for d in ('peer', 'core', 'bmc/regtest'): os.makedirs(os.path.join(WORK, d), exist_ok=True)
    open(os.path.join(WORK, 'peer/bitcoin.conf'), 'w').write(
        'regtest=1\nfallbackfee=0.0002\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\n'
        'bind=127.0.0.1\nlistenonion=0\n' % (P_P2P, P_RPC))
    open(os.path.join(WORK, 'core/bitcoin.conf'), 'w').write(
        'regtest=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\n'
        'bind=127.0.0.1\nlistenonion=0\nconnect=127.0.0.1:%d\n' % (S_P2P, S_RPC, P_P2P))
    bmc_conf(True)
    start_core('peer')
    if not up(P_RPC): print('FAIL: peer did not start'); return 2
    start_core('core')
    if not up(S_RPC): print('FAIL: Core subject did not start'); return 2
    if not start_bmc(): print('FAIL: bmc did not start'); return 2

    call(P_RPC, 'createwallet', ['w'])
    A = call(P_RPC, 'getnewaddress', [], W)
    call(P_RPC, 'generatetoaddress', [110, A])
    H = call(P_RPC, 'getbestblockhash')
    for name, port in SUBJ:
        if not wait_for(lambda: call(port, 'getbestblockhash') == H, 180):
            print('FAIL: %s did not sync' % name); return 2
    coins = call(P_RPC, 'listunspent', [1], W)
    def make_tx(i):
        c = coins[i]
        raw = call(P_RPC, 'createrawtransaction', [[{'txid': c['txid'], 'vout': c['vout']}],
                                                    {A: round(c['amount'] - 0.001, 8)}], W)
        h = call(P_RPC, 'signrawtransactionwithwallet', [raw], W)['hex']
        return h, call(P_RPC, 'decoderawtransaction', [h])['txid']
    txs = {name: [make_tx(2*k + j) for k in range(2)] for j, (name, _) in enumerate(SUBJ)}

    print('A  sendrawtransaction, peer connected')
    for name, port in SUBJ:
        h, t = txs[name][0]
        call(port, 'sendrawtransaction', [h])
        e, v, n = ub_state(port, t)
        check('%s entry unbroadcast at submission' % name, e, True)
        check('%s verbose getrawmempool agrees' % name, v, True)
        check('%s unbroadcastcount at submission' % name, n, 1)
    for name, port in SUBJ:
        t = txs[name][0][1]
        got = wait_for(lambda: t in call(P_RPC, 'getrawmempool'), 60)
        check('%s: the peer fetched it' % name, got, True)
        wait_for(lambda: ub_state(port, t)[0] is False, 30, 1)
        check('%s after the fetch (entry, verbose, count)' % name, ub_state(port, t), (False, False, 0))

    print('B  networking off')
    for name, port in SUBJ:
        call(port, 'setnetworkactive', [False])
        wait_for(lambda: conns(port) == 0, 60)
        check('%s connections' % name, conns(port), 0)
        h, t = txs[name][1]
        call(port, 'sendrawtransaction', [h])
    time.sleep(15)
    for name, port in SUBJ:
        check('%s 15 s later (entry, verbose, count)' % name, ub_state(port, txs[name][1][1]), (True, True, 1))

    print('C  savemempool')
    files = {}
    for name, port in SUBJ:
        r = call(port, 'savemempool')
        files[name] = r['filename']
        check('%s file unbroadcast section' % name, file_unbroadcast(r['filename']), [txs[name][1][1]])

    print('D  restart with networking off')
    for name, port in SUBJ:
        call(port, 'stop'); down(port)
    time.sleep(3)
    bmc_conf(False)
    start_core('core', ['-networkactive=0'])
    if not up(S_RPC) or not start_bmc(): print('FAIL: restart'); return 2
    for name, port in SUBJ:
        t = txs[name][1][1]
        wait_for(lambda: t in call(port, 'getrawmempool') and ub_state(port, t)[0] is True, 120)
        check('%s after the reload (entry, verbose, count)' % name, ub_state(port, t), (True, True, 1))

    print('E  networking on: the 10-15 minute reattempt')
    t0 = time.time()
    for name, port in SUBJ: call(port, 'setnetworkactive', [True])
    for name, port in SUBJ:
        t = txs[name][1][1]
        got = wait_for(lambda: t in call(P_RPC, 'getrawmempool') and ub_state(port, t)[0] is False, 1080, 10)
        check('%s: fetched and cleared by the reattempt' % name, got, True)
        print('      (%s: %.0f s after networking came back)' % (name, time.time() - t0))
        check('%s count after' % name, call(port, 'getmempoolinfo')['unbroadcastcount'], 0)

    print('F  importmempool of the other subject\'s file')
    other = {'bmc': 'core', 'core': 'bmc'}
    for name, port in SUBJ:
        t = txs[other[name]][1][1]
        wait_for(lambda: t in call(port, 'getrawmempool'), 60)
        call(port, 'importmempool', [files[other[name]]])
        check('%s apply_unbroadcast_set default (false)' % name, ub_state(port, t)[0], False)
        call(port, 'importmempool', [files[other[name]], {'apply_unbroadcast_set': True}])
        check('%s apply_unbroadcast_set true' % name, ub_state(port, t), (True, True, 1))
    errs = [rpc(port, 'importmempool', [files['bmc'], {'apply_unbroadcast_set': 'yes'}])[1] for _, port in SUBJ]
    check('non-bool option: bmc vs Core error', errs[0], errs[1])

    require_cases(cases, 'checks', 27)
    print('%d checks, %d failed' % (cases, fails))
    return 1 if fails else 0

if __name__ == '__main__':
    try: rc = main()
    finally: cleanup()
    sys.exit(rc)
