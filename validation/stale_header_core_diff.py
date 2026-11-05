#!/usr/bin/env python3
"""validation/stale_header_core_diff.py -- getblockheader for a block this
node no longer has on its active chain, bmc against Bitcoin Core v31.1, on
regtest. 2026-11-04.

LND's wallet (btcwallet) processes a reorg by fetching the header of the block
it last saw and walking its prev links back to the fork. Core answers for a
replaced block with confirmations -1; bmc answered -5 "Block not found", and
LND stopped following the chain (validation/lightning_regtest_e2e.py, phase
reorg). Here the same blocks are asked of both nodes:

  phase reorg2     bmc follows Core over P2P; Core invalidates the block at
                   tip-1 and mines a heavier branch, so both nodes reorg two
                   blocks deep. getblockheader (verbose and raw) for both
                   replaced blocks, and for the fork point, must be identical.
  phase reorgback  Core reconsiders the original branch and extends it; both
                   nodes reorg back onto it. The original blocks (in the fork
                   tree and active again) answer as active, the replacement
                   branch's as replaced, identically on both.

getblock for a replaced block is printed, not compared: Core keeps the body
and returns it, this node truncates it and answers -1 "Block not available
(pruned data)" (docs/FEATURE_GAPS.md).

Usage: python3 validation/stale_header_core_diff.py
       env: CORE_BIN, BMC_BIN, WORK (default $TMPDIR/bmc-stale-<pid>), KEEP=1
"""
import base64, json, os, shutil, signal, subprocess, sys, time, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
from diffguard import require_cases

CORE_BIN = os.environ.get('CORE_BIN', '/storage/bitcoin-core-v31.1/bin')
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BMC_BIN = os.environ.get('BMC_BIN', os.path.join(ROOT, 'asm/daemon/bmcbitcoind'))
WORK = os.environ.get('WORK', os.path.join(os.environ.get('TMPDIR', '/tmp'), 'bmc-stale-%d' % os.getpid()))
# not adjacent: Core binds an onion target on P2P+1 even with listenonion=0
C_P2P, C_RPC = 19914, 19924
B_P2P, B_RPC = 19934, 19944

def log(*a): print(time.strftime('%H:%M:%S'), *a, flush=True)

class RPC:
    def __init__(self, port, name, path=''): self.url = 'http://127.0.0.1:%d/%s' % (port, path); self.name = name
    def raw(self, method, *params):
        req = urllib.request.Request(self.url, json.dumps({'jsonrpc': '1.0', 'id': 's', 'method': method, 'params': list(params)}).encode(),
                                     {'Content-Type': 'text/plain', 'Authorization': 'Basic ' + base64.b64encode(b'e2e:e2epw').decode()})
        try:
            with urllib.request.urlopen(req, timeout=120) as r: return json.loads(r.read())
        except urllib.error.HTTPError as e: return json.loads(e.read())
    def __call__(self, method, *params):
        d = self.raw(method, *params)
        if d.get('error'): raise RuntimeError('%s %s%s: %s' % (self.name, method, params, d['error']))
        return d['result']

core, bmc = RPC(C_RPC, 'core'), RPC(B_RPC, 'bmc')

def wait(pred, what, secs=120):
    for _ in range(secs * 2):
        try:
            if pred(): return True
        except Exception: pass
        time.sleep(0.5)
    log('  (timed out waiting for %s)' % what); return False

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

def cleanup(keep):
    try: core('stop')
    except Exception: pass
    time.sleep(2)
    for p in my_procs():
        try: os.kill(p, signal.SIGTERM)
        except Exception: pass
    for _ in range(30):
        if not my_procs(): break
        time.sleep(1)
    if not keep: shutil.rmtree(WORK, ignore_errors=True)
    else: log('kept %s' % WORK)

FAILS = []; COMPARED = [0]
def same(method, *params):
    c, b = core.raw(method, *params), bmc.raw(method, *params)
    COMPARED[0] += 1
    cr, br = (c.get('result'), c.get('error')), (b.get('result'), b.get('error'))
    if cr == br: log('  match  %s %s' % (method, ' '.join(str(p)[:16] for p in params))); return True
    FAILS.append('%s %s' % (method, params))
    log('  DIFF   %s %s\n    core %s\n    bmc  %s' % (method, params, json.dumps(cr)[:700], json.dumps(br)[:700]))
    return False

def synced():
    # the tip by name AND by hash lookup: after a reorg bmc's getbestblockhash
    # moves a moment before its hash index has folded the new heights in
    best = core('getbestblockhash')
    return bmc('getbestblockhash') == best and not bmc.raw('getblockheader', best).get('error')

def main():
    for d in ('core', 'bmc/regtest'): os.makedirs(os.path.join(WORK, d), exist_ok=True)
    open(os.path.join(WORK, 'core/bitcoin.conf'), 'w').write(
        'regtest=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\nlistenonion=0\nbind=127.0.0.1\n' % (C_P2P, C_RPC))
    open(os.path.join(WORK, 'bmc/bitcoin.conf'), 'w').write(
        'chain=regtest\nprinttoconsole=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\nconnect=127.0.0.1:%d\n' % (B_P2P, B_RPC, C_P2P))
    subprocess.run([CORE_BIN + '/bitcoind', '-datadir=' + WORK + '/core', '-daemon'], check=True, stdout=subprocess.DEVNULL)
    if not wait(lambda: core('getblockcount') is not None, 'Core'): return 2
    blog = open(os.path.join(WORK, 'bmc.log'), 'wb')
    subprocess.Popen(['setsid', BMC_BIN, 'serve', WORK + '/bmc'], cwd=os.path.join(ROOT, 'asm'),
                     stdout=blog, stderr=blog, stdin=subprocess.DEVNULL)
    if not wait(lambda: bmc('getblockcount') is not None, 'bmc'): return 2
    core('createwallet', 'w'); addr = RPC(C_RPC, 'core', 'wallet/w')('getnewaddress')
    core('generatetoaddress', 110, addr)
    if not wait(synced, 'bmc at 110'): return 2

    log('phase reorg2')
    h = core('getblockcount')
    a1, a2 = core('getblockhash', h - 1), core('getblockhash', h)
    fork = core('getblockhash', h - 2)
    core('invalidateblock', a1)
    addr2 = RPC(C_RPC, 'core', 'wallet/w')('getnewaddress')   # another coinbase, or Core re-mines the invalidated block
    core('generatetoaddress', 3, addr2)             # 108 + 3 = 111 > 110: heavier
    if not wait(synced, 'bmc to follow the two-block reorg'): FAILS.append('bmc did not reorg'); return 1
    log('  both at %d; replaced %s.. %s..' % (core('getblockcount'), a1[:12], a2[:12]))
    for blk in (a2, a1, fork):
        same('getblockheader', blk)
        same('getblockheader', blk, False)
    # LND's walk: from the replaced tip by prev links to the fork, raw headers only
    cur = a2; steps = 0
    while True:
        b = bmc.raw('getblockheader', cur)
        if b.get('error') or b['result']['confirmations'] != -1: break
        cur = b['result']['previousblockhash']; steps += 1
    COMPARED[0] += 1
    if cur == fork and steps == 2: log('  match  walk from the replaced tip by previousblockhash reaches the fork in 2 steps')
    else: FAILS.append('walk'); log('  DIFF   walk ended at %s after %d steps (fork %s)' % (cur, steps, fork))
    g = bmc.raw('getblock', a2, 0)
    log('  known  getblock of a replaced block: core returns it, bmc %s' % (g.get('error'),))
    COMPARED[0] += 1
    if not (g.get('error') or {}).get('message') == 'Block not available (pruned data)':
        FAILS.append('getblock stale'); log('  DIFF   expected bmc -1 "Block not available (pruned data)"')
    same('getblock', '00' * 32, 0)                  # an unknown hash is still -5 on both

    log('phase reorgback')
    # the original branch wins again: Core reconsiders it and extends it past
    # the replacement, so both nodes reorg back onto a1/a2. Blocks that sit in
    # the fork tree AND on the active chain again must answer as active, and
    # the replacement branch's blocks now answer as replaced.
    b1 = core('getblockhash', h - 1); b3 = core('getbestblockhash')
    core('reconsiderblock', a1)                       # the a-branch is valid again but lighter (110 < 111)
    core('invalidateblock', b1)                       # so Core steps onto it ...
    core('generatetoaddress', 3, addr)                # ... and extends it: 110 + 3 = 113 > 111
    core('reconsiderblock', b1)                       # the b-branch stays behind, valid and lighter
    if not wait(synced, 'bmc to reorg back onto the original branch'): FAILS.append('reorg back'); return 1
    on_a = core('getblockhash', h) == a2 and core('getblockhash', h - 1) == a1
    COMPARED[0] += 1
    if not on_a: FAILS.append('setup'); log('  DIFF   Core is not back on the original branch'); return 1
    log('  both at %d with %s.. and %s.. active again' % (core('getblockcount'), a1[:12], a2[:12]))
    for blk in (a1, a2, b1, b3):
        same('getblockheader', blk)
        same('getblockheader', blk, False)
    require_cases(COMPARED[0], 'comparisons', minimum=18)
    return 1 if FAILS else 0

if __name__ == '__main__':
    rc = 2
    try: rc = main()
    except Exception as e:
        log('ABORT: %s' % e); FAILS.append(str(e)); rc = 1
    finally: cleanup(os.environ.get('KEEP') == '1' or rc != 0)
    log('RESULT: %s' % ('ALL %d MATCH' % COMPARED[0] if rc == 0 else 'FAIL: %s' % '; '.join(FAILS)[:500]))
    sys.exit(rc)
