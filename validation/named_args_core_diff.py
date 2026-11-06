#!/usr/bin/env python3
"""validation/named_args_core_diff.py -- named JSON-RPC arguments (params as
an object, `bitcoin-cli -named`), bmc against Bitcoin Core v31.1, on regtest.
2026-11-06.

Core converts a params object to positions for every method
(transformNamedArguments); this node did it only for the echo methods until
asm/rpc_argnames.h. Three kinds of case:

  * equivalence: a named request and its positional twin. Each node must
    give the named one the same reply as the positional one, byte for byte,
    and the named reply is compared with Core's. Where the POSITIONAL replies
    already differ between the nodes (a parity difference that has nothing to
    do with names) the case is printed "known" and not counted as a failure.
  * errors: unknown, repeated and conflicting names, `args` against a named
    position, an alias given twice, a scalar params, an unknown method --
    HTTP status and reply bytes must equal Core's.
  * Core's own bitcoin-cli -named against both: stdout and exit code.

Usage: python3 validation/named_args_core_diff.py
       env: CORE_BIN, BMC_BIN, WORK (default $TMPDIR/bmc-named-<pid>), KEEP=1
"""
import base64, json, os, shutil, signal, subprocess, sys, time, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
from diffguard import require_cases

CORE_BIN = os.environ.get('CORE_BIN', '/storage/bitcoin-core-v31.1/bin')
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BMC_BIN = os.environ.get('BMC_BIN', os.path.join(ROOT, 'asm/daemon/bmcbitcoind'))
WORK = os.environ.get('WORK', os.path.join(os.environ.get('TMPDIR', '/tmp'), 'bmc-named-%d' % os.getpid()))
# not adjacent: Core binds an onion target on P2P+1 even with listenonion=0
C_P2P, C_RPC = 19714, 19724
B_P2P, B_RPC = 19734, 19744
AUTH = 'Basic ' + base64.b64encode(b'e2e:e2epw').decode()

def post(port, body, path='/'):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (port, path), body.encode(),
                                 {'Content-Type': 'application/json', 'Authorization': AUTH})
    try:
        with urllib.request.urlopen(req, timeout=60) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()

def call(port, method, params, path='/'):
    s, b = post(port, json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': params}), path)
    r = json.loads(b)
    if r.get('error'): raise RuntimeError('%s %s: %s' % (method, params, r['error']))
    return r['result']

def up(port, secs=120):
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

def cleanup():
    for port in (B_RPC, C_RPC):
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

def body(method, params):
    return '{"jsonrpc":"1.0","id":1,"method":"%s","params":%s}' % (method, params)

def main():
    for d in ('core', 'bmc/regtest'): os.makedirs(os.path.join(WORK, d), exist_ok=True)
    open(os.path.join(WORK, 'core/bitcoin.conf'), 'w').write(
        'regtest=1\ntxindex=1\nfallbackfee=0.0002\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\n'
        'bind=127.0.0.1\nlistenonion=0\n' % (C_P2P, C_RPC))
    open(os.path.join(WORK, 'bmc/bitcoin.conf'), 'w').write(
        'chain=regtest\nprinttoconsole=1\ntxindex=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\n'
        'connect=127.0.0.1:%d\n' % (B_P2P, B_RPC, C_P2P))
    subprocess.run([CORE_BIN + '/bitcoind', '-datadir=' + WORK + '/core', '-daemon'], check=True, stdout=subprocess.DEVNULL)
    if not up(C_RPC): print('FAIL: Core did not start'); return 2
    blog = open(os.path.join(WORK, 'bmc.log'), 'wb')
    subprocess.Popen(['setsid', BMC_BIN, 'serve', WORK + '/bmc'], cwd=os.path.join(ROOT, 'asm'),
                     stdout=blog, stderr=blog, stdin=subprocess.DEVNULL)
    if not up(B_RPC): print('FAIL: bmc did not start'); return 2

    # a chain: 101 blocks, a confirmed spend, then an unconfirmed one
    call(C_RPC, 'createwallet', ['w'])
    W = '/wallet/w'
    A = call(C_RPC, 'getnewaddress', [], W)
    call(C_RPC, 'generatetoaddress', [101, A])
    T = call(C_RPC, 'sendtoaddress', [A, 1.0], W)
    call(C_RPC, 'generatetoaddress', [1, A])
    M = call(C_RPC, 'sendtoaddress', [A, 0.5], W)
    H = call(C_RPC, 'getbestblockhash', [])
    MHEX = call(C_RPC, 'getrawtransaction', [M])
    for _ in range(120):
        try:
            if call(B_RPC, 'getbestblockhash', []) == H: break
        except Exception: pass
        time.sleep(1)
    try: call(B_RPC, 'sendrawtransaction', [MHEX])   # handed over, not relied on to relay
    except RuntimeError as e: print('  (sendrawtransaction to bmc: %s)' % e)
    for _ in range(30):
        try:
            if call(B_RPC, 'getbestblockhash', []) == H and M in call(B_RPC, 'getrawmempool', []): break
        except Exception: pass
        time.sleep(1)
    else: print('FAIL: bmc did not follow Core'); return 2
    X = call(C_RPC, 'getrawtransaction', [T])
    mtx = call(C_RPC, 'getrawtransaction', [M, 1])
    SPENT = {'txid': mtx['vin'][0]['txid'], 'vout': mtx['vin'][0]['vout']}
    D = call(C_RPC, 'getdescriptorinfo', ['addr(%s)' % A])['descriptor']
    print('chain: tip %s.., confirmed %s.., mempool %s..' % (H[:12], T[:12], M[:12]))

    j = json.dumps
    EQUIV = [   # (method, named params, positional params)
        ('getblockhash', {'height': 1}, [1]),
        ('getblock', {'blockhash': H}, [H]),
        ('getblock', {'blockhash': H, 'verbosity': 0}, [H, 0]),
        ('getblock', {'blockhash': H, 'verbose': 0}, [H, 0]),                 # Core's alias
        ('getblock', {'verbosity': 2, 'args': [H]}, [H, 2]),                  # args + a name
        ('getblockheader', {'blockhash': H, 'verbose': False}, [H, False]),
        ('gettxout', {'txid': T, 'n': 0}, [T, 0]),
        ('gettxout', {'n': 0, 'txid': T, 'include_mempool': False}, [T, 0, False]),
        ('getrawtransaction', {'txid': T, 'verbosity': 1}, [T, 1]),
        ('getrawtransaction', {'txid': T, 'blockhash': H}, [T, None, H]),     # a hole before a name: null
        ('decoderawtransaction', {'hexstring': X}, [X]),
        ('validateaddress', {'address': A}, [A]),
        ('getdescriptorinfo', {'descriptor': 'addr(%s)' % A}, ['addr(%s)' % A]),
        ('deriveaddresses', {'descriptor': D}, [D]),
        ('createrawtransaction', {'inputs': [{'txid': T, 'vout': 0}], 'outputs': [{A: 0.1}], 'locktime': 7},
                                 [[{'txid': T, 'vout': 0}], [{A: 0.1}], 7]),
        ('createrawtransaction', {'outputs': [{A: 0.1}], 'locktime': 7}, [None, [{A: 0.1}], 7]),
        ('estimatesmartfee', {'conf_target': 6}, [6]),
        ('getmempoolentry', {'txid': M}, [M]),
        ('getmempoolancestors', {'txid': M, 'verbose': True}, [M, True]),
        ('gettxspendingprevout', {'outputs': [SPENT]}, [[SPENT]]),
        ('gettxspendingprevout', {'outputs': [SPENT], 'return_spending_tx': True}, [[SPENT], {'return_spending_tx': True}]),   # named-only -> options
        ('getblockstats', {'hash_or_height': 101, 'stats': ['height', 'txs']}, [101, ['height', 'txs']]),
        ('getchaintxstats', {'nblocks': 5}, [5]),
        ('getblockcount', {}, []),
    ]
    ERRORS = [
        body('getblockhash', '{"height":1,"bogus":2}'),                    # unknown name
        body('getblockhash', '{"height":1,"height":2}'),                   # repeated
        body('getblock', '{"args":["%s"],"blockhash":"%s"}' % (H, H)),     # positional and named
        body('getblock', '{"verbose":0,"verbosity":1,"blockhash":"%s"}' % H),   # both alias names
        body('getblockhash', '"x"'),                                       # neither array nor object
        body('getblockhash', '{"args":"x","height":1}'),                   # args not an array
        body('gettxspendingprevout', '{"outputs":[%s],"return_spending_tx":true,"options":{}}' % j(SPENT)),   # conflicts
        body('gettxspendingprevout', '{"outputs":[%s],"mempool_only":true,"mempool_only":false}' % j(SPENT)),
        body('nosuchmethod', '{"a":1}'),                                   # an unknown method stays -32601
        '{"jsonrpc":"2.0","id":3,"method":"getblockhash","params":{"heigth":1}}',
        '[{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":{"height":2}},{"jsonrpc":"2.0","id":2,"method":"getblockcount","params":{}}]',
    ]
    fails = known = 0; cases = 0
    for method, named, pos in EQUIV:
        cases += 1
        cn, bn = post(C_RPC, body(method, j(named))), post(B_RPC, body(method, j(named)))
        cp, bp = post(C_RPC, body(method, j(pos))), post(B_RPC, body(method, j(pos)))
        tag = '%s %s' % (method, j(named))[:150]
        if cn != cp: print('  CORE  named != positional: %s' % tag)          # the reference itself must agree
        if bn != bp:
            fails += 1; print('  FAIL  bmc named != positional: %s\n          named %s\n          posit %s' % (tag, bn[1][:160], bp[1][:160])); continue
        if bn == cn: print('  match %s' % tag)
        elif bp != cp: known += 1; print('  known %s (the positional replies differ too: not names)' % tag)
        else: fails += 1; print('  FAIL  %s\n          core %s\n          bmc  %s' % (tag, cn[1][:160], bn[1][:160]))
    for b in ERRORS:
        cases += 1
        c, m = post(C_RPC, b), post(B_RPC, b)
        if c == m: print('  match %s -> %d %s' % (b[:110], c[0], c[1][:90].decode(errors='replace')))
        else: fails += 1; print('  FAIL  %s\n          core %d %s\n          bmc  %d %s' % (b[:110], c[0], c[1][:160], m[0], m[1][:160]))
    CLI = [['-named', 'getblockhash', 'height=1'],
           ['-named', 'getblock', 'blockhash=' + H, 'verbosity=0'],
           ['-named', 'getblockheader', 'blockhash=' + H, 'verbose=false'],
           ['-named', 'gettxout', 'txid=' + T, 'n=0', 'include_mempool=false'],
           ['-named', 'getblockhash', 'height=1', 'bogus=2']]
    for args in CLI:
        cases += 1
        outs = []
        for port in (C_RPC, B_RPC):
            p = subprocess.run([CORE_BIN + '/bitcoin-cli', '-rpcport=%d' % port, '-rpcuser=e2e', '-rpcpassword=e2epw'] + args,
                               capture_output=True, text=True)
            outs.append((p.returncode, p.stdout, p.stderr))
        if outs[0] == outs[1]: print('  match cli rc=%d %s' % (outs[0][0], ' '.join(args)[:100]))
        else: fails += 1; print('  FAIL  cli %s\n          core %s\n          bmc  %s' % (' '.join(args)[:100], outs[0], outs[1]))
    require_cases(cases, 'named-argument cases')
    print('\n%s: %d cases, %d failed, %d known (positional replies differ too)' % ('ALL MATCH' if not fails else 'FAILED', cases, fails, known))
    return 1 if fails else 0

if __name__ == '__main__':
    try: rc = main()
    finally: cleanup()
    sys.exit(rc)
