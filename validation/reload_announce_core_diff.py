#!/usr/bin/env python3
"""validation/reload_announce_core_diff.py -- what a mempool.dat load tells
the peers, bmc against Bitcoin Core v31.1, on regtest. 2026-11-06.

Core's LoadMempool (the startup load and importmempool) admits each entry
with AcceptToMemoryPool and never calls RelayTransaction: a reload announces
nothing, and only the file's unbroadcast set goes out, at the 10-15 minute
reattempt. Until 2026-11-06 this node re-submitted every entry through the
sendrawtransaction channel and announced all of them to every peer (37,200
on one production boot).

Topology: a Core PEER with the wallet and the chain; two SUBJECTS, bmc and a
second Core, each dialling only the peer (their outbound leg); a Core
OBSERVER that dials both subjects (their inbound peer). The peer and the
observer run with -debug=net and log every inv they receive ("got inv: wtx
<wtxid>  have|new peer=N"); "receive version message" names the sender. The
subjects' invs naming the test's transactions are counted after each step:

  A  the peer makes N wallet transactions; both subjects (and the observer)
     get them by relay. Their own unbroadcast sets are empty.
  B  restart both subjects: the startup load restores N, and neither subject
     announces any of them to the peer or the observer. (On regtest bmc's load
     ends within ~40 ms of its first leg's handshake, before the leg takes
     announcements, so this step alone did not catch the defect; C and D run
     the same loader with the legs already up.)
  C  restart again with the file moved aside, so the pool starts empty; with
     both peers connected, importmempool of that file restores N and
     announces none.
  D  importmempool of the same file again (all N already in the pool):
     nothing is announced again.
  E  control: one sendrawtransaction on each subject IS announced to both its
     peers, so the zero counts above come from a counter that sees invs.

Each window is WINDOW seconds (default 60) after the step, an order of
magnitude past both nodes' 2 s outbound / 5 s inbound trickle means.

Usage: python3 validation/reload_announce_core_diff.py
       env: CORE_BIN, BMC_BIN, WORK (default $TMPDIR/bmc-reloadann-<pid>), KEEP=1,
            NTX (default 60), WINDOW (default 60)
"""
import base64, json, os, re, shutil, signal, subprocess, sys, time, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
from diffguard import require_cases

CORE_BIN = os.environ.get('CORE_BIN', '/storage/bitcoin-core-v31.1/bin')
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BMC_BIN = os.environ.get('BMC_BIN', os.path.join(ROOT, 'asm/daemon/bmcbitcoind'))
WORK = os.environ.get('WORK', os.path.join(os.environ.get('TMPDIR', '/tmp'), 'bmc-reloadann-%d' % os.getpid()))
NTX = int(os.environ.get('NTX', '60'))
WINDOW = int(os.environ.get('WINDOW', '60'))
# not adjacent: Core binds an onion target on P2P+1 even with listenonion=0
P_P2P, P_RPC = 19714, 19724          # the peer (Core, wallet)
B_P2P, B_RPC = 19734, 19744          # subject: bmc
S_P2P, S_RPC = 19754, 19764          # subject: Core
O_P2P, O_RPC = 19774, 19784          # the observer (Core)
AUTH = 'Basic ' + base64.b64encode(b'e2e:e2epw').decode()
W = '/wallet/w'
SUBJ = (('bmc', B_RPC), ('core', S_RPC))

def post(port, body, path='/'):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (port, path), body.encode(),
                                 {'Content-Type': 'application/json', 'Authorization': AUTH})
    try:
        with urllib.request.urlopen(req, timeout=120) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()

def rpc(port, method, params=None, path='/'):
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

def down(port, secs=120):
    for _ in range(secs):
        try: post(port, '{"method":"getblockcount","id":0}')
        except Exception: return True
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

def cleanup():
    for port in (B_RPC, S_RPC, O_RPC, P_RPC):
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

def wait_for(pred, secs, step=1):
    t = time.time()
    while time.time() - t < secs:
        try:
            if pred(): return True
        except Exception: pass
        time.sleep(step)
    return False

def start_core(d):
    subprocess.run([CORE_BIN + '/bitcoind', '-datadir=' + os.path.join(WORK, d), '-daemon'],
                   check=True, stdout=subprocess.DEVNULL)

def start_bmc():
    blog = open(os.path.join(WORK, 'bmc.log'), 'ab')
    subprocess.Popen(['setsid', BMC_BIN, 'serve', WORK + '/bmc'], cwd=os.path.join(ROOT, 'asm'),
                     stdout=blog, stderr=blog, stdin=subprocess.DEVNULL)
    return up(B_RPC)

def start_subjects():
    start_core('core')
    return up(S_RPC) and start_bmc()

def stop_subjects():
    for _, port in SUBJ:
        call(port, 'stop')
    for _, port in SUBJ:
        down(port)
    wait_for(lambda: not [p for p in my_procs() if b'/bmc' in open('/proc/%d/cmdline' % p, 'rb').read()
                          or b'/core' in open('/proc/%d/cmdline' % p, 'rb').read()], 60)
    time.sleep(2)

LOGS = {'peer': 'peer/regtest/debug.log', 'observer': 'observer/regtest/debug.log'}
def log_marks():
    return {k: os.path.getsize(os.path.join(WORK, v)) for k, v in LOGS.items()}

VER = re.compile(r'receive version message: (/[^:]+):.* peer=(\d+)')
INV = re.compile(r'got inv: w?tx ([0-9a-f]{64}) +(?:have|new) peer=(\d+)')
def invs_since(marks, ids):
    """{(listener, subject): number of invs naming one of `ids`} since marks"""
    out = {(l, s): 0 for l in LOGS for s in ('bmc', 'core')}
    for l, rel in LOGS.items():
        text = open(os.path.join(WORK, rel), errors='replace').read()
        who = {}
        for m in VER.finditer(text):           # the whole log: ids are never reused
            who[m.group(2)] = 'bmc' if 'BitcoinMachineCode' in m.group(1) else 'core'
        for m in INV.finditer(text[marks[l]:]):
            s = who.get(m.group(2))
            if s and m.group(1) in ids: out[(l, s)] += 1
    return out

def both_peers(name, port):
    """the subject has its outbound peer and the observer connected"""
    got = wait_for(lambda: call(port, 'getconnectioncount') >= 2, 120)
    check('%s connected to the peer and the observer' % name, got, True)

cases = fails = 0
def check(what, got, want):
    global cases, fails
    cases += 1
    ok = got == want
    if not ok: fails += 1
    print('  %s %s: %r%s' % ('ok  ' if ok else 'FAIL', what, got, '' if ok else ' (want %r)' % (want,)))
    return ok

def report(marks, ids, label):
    time.sleep(WINDOW)
    got = invs_since(marks, ids)
    for s in ('bmc', 'core'):
        for l, leg in (('peer', 'outbound'), ('observer', 'inbound')):
            check('%s: invs to its %s peer %s' % (s, leg, label), got[(l, s)], 0)

def main():
    for d in ('peer', 'core', 'observer', 'bmc/regtest'): os.makedirs(os.path.join(WORK, d), exist_ok=True)
    base = 'regtest=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\nbind=127.0.0.1\nlistenonion=0\n'
    open(os.path.join(WORK, 'peer/bitcoin.conf'), 'w').write(
        'fallbackfee=0.0002\n' + base % (P_P2P, P_RPC) + 'debug=net\n')
    open(os.path.join(WORK, 'core/bitcoin.conf'), 'w').write(
        base % (S_P2P, S_RPC) + 'listen=1\nconnect=127.0.0.1:%d\n' % P_P2P)
    open(os.path.join(WORK, 'observer/bitcoin.conf'), 'w').write(
        base % (O_P2P, O_RPC) + 'debug=net\nconnect=127.0.0.1:%d\nconnect=127.0.0.1:%d\n' % (B_P2P, S_P2P))
    open(os.path.join(WORK, 'bmc/bitcoin.conf'), 'w').write(
        'chain=regtest\nprinttoconsole=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\n'
        'listen=1\nconnect=127.0.0.1:%d\n' % (B_P2P, B_RPC, P_P2P))   # connect= turns listen off, as in Core
    start_core('peer')
    if not up(P_RPC): print('FAIL: peer did not start'); return 2
    if not start_subjects(): print('FAIL: subjects did not start'); return 2
    start_core('observer')
    if not up(O_RPC): print('FAIL: observer did not start'); return 2

    print('A  %d wallet transactions, relayed to both subjects' % NTX)
    call(P_RPC, 'createwallet', ['w'])
    A = call(P_RPC, 'getnewaddress', [], W)
    call(P_RPC, 'generatetoaddress', [110, A])
    call(P_RPC, 'sendmany', ['', {call(P_RPC, 'getnewaddress', [], W): 0.5 for _ in range(NTX + 2)}], W)
    call(P_RPC, 'generatetoaddress', [1, A])
    H = call(P_RPC, 'getbestblockhash')
    for name, port in SUBJ + (('observer', O_RPC),):
        if not wait_for(lambda: call(port, 'getbestblockhash') == H, 180):
            print('FAIL: %s did not sync' % name); return 2
    coins = [c for c in call(P_RPC, 'listunspent', [1], W) if abs(c['amount'] - 0.5) < 1e-9]
    def signed(c):
        raw = call(P_RPC, 'createrawtransaction', [[{'txid': c['txid'], 'vout': c['vout']}], {A: 0.499}], W)
        return call(P_RPC, 'signrawtransactionwithwallet', [raw], W)['hex']
    control = [signed(c) for c in coins[NTX:NTX + 2]]      # step E's, one per subject
    ids = set()
    for c in coins[:NTX]:
        t = call(P_RPC, 'sendrawtransaction', [signed(c)])
        ids.add(t); ids.add(call(P_RPC, 'getmempoolentry', [t])['wtxid'])
    txids = [x for x in ids if x in call(P_RPC, 'getrawmempool')]
    for name, port in SUBJ:
        got = wait_for(lambda: set(txids) <= set(call(port, 'getrawmempool')), 120)
        check('%s has all %d by relay' % (name, NTX), got, True)
    wait_for(lambda: call(P_RPC, 'getmempoolinfo')['unbroadcastcount'] == 0, 60)
    for name, port in SUBJ:
        check('%s unbroadcastcount' % name, call(port, 'getmempoolinfo')['unbroadcastcount'], 0)

    print('B  restart: the startup load')
    files = {name: call(port, 'savemempool')['filename'] for name, port in SUBJ}
    stop_subjects()
    marks = log_marks()
    if not start_subjects(): print('FAIL: restart'); return 2
    for name, port in SUBJ:
        got = wait_for(lambda: set(txids) <= set(call(port, 'getrawmempool')), 120)
        check('%s reloaded all %d' % (name, NTX), got, True)
        both_peers(name, port)
    report(marks, ids, 'after the startup load')

    print('C  importmempool into an empty pool, peers connected')
    stop_subjects()
    moved = {}
    for name, f in files.items():
        moved[name] = f + '.moved'; os.replace(f, moved[name])
    if not start_subjects(): print('FAIL: restart'); return 2
    for name, port in SUBJ:
        both_peers(name, port)
        check('%s pool empty before the import' % name, call(port, 'getmempoolinfo')['size'], 0)
    time.sleep(5)
    marks = log_marks()
    for name, port in SUBJ:
        call(port, 'importmempool', [moved[name]])
        check('%s imported all %d' % (name, NTX), set(txids) <= set(call(port, 'getrawmempool')), True)
    report(marks, ids, 'after importmempool')

    print('D  importmempool again: every entry already in the pool')
    marks = log_marks()
    for name, port in SUBJ:
        call(port, 'importmempool', [moved[name]])
        check('%s pool size unchanged' % name, call(port, 'getmempoolinfo')['size'], NTX)
    report(marks, ids, 'after a second importmempool')

    print('E  control: a sendrawtransaction on each subject is announced to both peers')
    marks = log_marks()
    cids = {}                                # each subject's own: the other's reaches it by relay
    for (name, port), h in zip(SUBJ, control):
        d = call(port, 'decoderawtransaction', [h])
        cids[name] = {d['txid'], d['hash']}
        call(port, 'sendrawtransaction', [h])
    time.sleep(WINDOW)
    for s in ('bmc', 'core'):
        got = invs_since(marks, cids[s])
        for l, leg in (('peer', 'outbound'), ('observer', 'inbound')):
            check('%s: its own tx announced to its %s peer' % (s, leg), got[(l, s)] >= 1, True)

    require_cases(cases, 'checks', 32)
    print('%d checks, %d failed' % (cases, fails))
    return 1 if fails else 0

if __name__ == '__main__':
    rc = 2
    try: rc = main()
    finally: cleanup()
    sys.exit(rc)
