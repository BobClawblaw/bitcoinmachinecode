#!/usr/bin/env python3
"""validation/tip_header_window.py -- after a reorg, can bmc name a tip that
getblockheader cannot find yet? Regtest, bmc following Bitcoin Core v31.1.
2026-11-20.

docs/FEATURE_GAPS.md (2026-11-04) recorded that right after a reorg
getbestblockhash named the new tip about 0.3 s before getblockheader could
resolve it (-5). This drives Core-made reorgs, one and three blocks deep,
while four connections poll bmc with no pause: two ask getbestblockhash, two
ask getblockcount then getblockhash, and each passes the answer straight to
getblockheader. Any error on that second call is a miss.

A round counts only if bmc reorged: its tip reaches Core's and the block it
replaced answers getblockheader with confirmations -1. Exit 0 = every round
reorged and nothing missed, 1 = a miss or a round bmc did not follow, 2 =
too few rounds or polls to say anything.

Usage: python3 validation/tip_header_window.py
       env: CORE_BIN, BMC_BIN, WORK (default $TMPDIR/bmc-tipwin-<pid>),
            ROUNDS (default 10), KEEP=1
"""
import os, subprocess, sys, threading, time
os.environ.setdefault('WORK', os.path.join(os.environ.get('TMPDIR', '/tmp'), 'bmc-tipwin-%d' % os.getpid()))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stale_header_core_diff as H          # node setup, ports and cleanup shared with that harness
from diffguard import require_cases

core, bmc, log = H.core, H.bmc, H.log
ROUNDS = int(os.environ.get('ROUNDS', '10'))
MISSES = []; POLLS = [0]; STOP = threading.Event(); POLL_MU = threading.Lock()

def poller(by_height):
    while not STOP.is_set():
        if by_height:
            c = bmc.raw('getblockcount')
            if c.get('error'): continue
            b = bmc.raw('getblockhash', c['result'])
        else:
            b = bmc.raw('getbestblockhash')
        if b.get('error'): continue
        r = bmc.raw('getblockheader', b['result'])
        with POLL_MU:
            POLLS[0] += 1
            if r.get('error'): MISSES.append((time.time(), b['result'], r['error']))

def bmc_at(best, secs=60):
    end = time.time() + secs
    while time.time() < end:
        if bmc.raw('getbestblockhash').get('result') == best: return True
        time.sleep(0.05)
    return False

def main():
    for d in ('core', 'bmc/regtest'): os.makedirs(os.path.join(H.WORK, d), exist_ok=True)
    open(os.path.join(H.WORK, 'core/bitcoin.conf'), 'w').write(
        'regtest=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\nlistenonion=0\nbind=127.0.0.1\n' % (H.C_P2P, H.C_RPC))
    open(os.path.join(H.WORK, 'bmc/bitcoin.conf'), 'w').write(
        'chain=regtest\nprinttoconsole=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\nconnect=127.0.0.1:%d\n' % (H.B_P2P, H.B_RPC, H.C_P2P))
    subprocess.run([H.CORE_BIN + '/bitcoind', '-datadir=' + H.WORK + '/core', '-daemon'], check=True, stdout=subprocess.DEVNULL)
    if not H.wait(lambda: core('getblockcount') is not None, 'Core'): return 2
    blog = open(os.path.join(H.WORK, 'bmc.log'), 'wb')
    subprocess.Popen(['setsid', H.BMC_BIN, 'serve', H.WORK + '/bmc'], cwd=os.path.join(H.ROOT, 'asm'),
                     stdout=blog, stderr=blog, stdin=subprocess.DEVNULL)
    if not H.wait(lambda: bmc('getblockcount') is not None, 'bmc'): return 2
    core('createwallet', 'w'); w = H.RPC(H.C_RPC, 'core', 'wallet/w')
    core('generatetoaddress', 110, w('getnewaddress'))
    if not H.wait(H.synced, 'bmc at 110'): return 2

    threads = [threading.Thread(target=poller, args=(k % 2 == 1,), daemon=True) for k in range(4)]
    for t in threads: t.start()
    reorged = 0
    for i in range(ROUNDS):
        depth = 1 if i % 2 == 0 else 3
        h = core('getblockcount')
        first, old_tip = core('getblockhash', h - depth + 1), core('getbestblockhash')
        core('invalidateblock', first)
        core('generatetoaddress', depth + 1, w('getnewaddress'))   # a fresh address: Core must not re-mine the same blocks
        best = core('getbestblockhash')
        ok = bmc_at(best) and (bmc.raw('getblockheader', old_tip).get('result') or {}).get('confirmations') == -1
        core('reconsiderblock', first)                             # the replaced branch stays valid but lighter
        log('round %d: %d deep, %s' % (i + 1, depth, 'bmc reorged' if ok else 'bmc DID NOT REORG'))
        if not ok: break
        reorged += 1
        time.sleep(1.0)
        core('generatetoaddress', 1, w('getnewaddress'))           # a plain extension between reorgs
        bmc_at(core('getbestblockhash'))
        time.sleep(0.5)
    STOP.set()
    for t in threads: t.join(5)

    log('rounds reorged %d of %d, polls %d, misses %d' % (reorged, ROUNDS, POLLS[0], len(MISSES)))
    for t, best, err in MISSES[:40]: log('  MISS %.3f %s.. %s' % (t, best[:16], err))
    if reorged < ROUNDS: return 1
    require_cases(reorged, 'reorgs', minimum=2)
    require_cases(POLLS[0], 'polls', minimum=1000)
    return 1 if MISSES else 0

if __name__ == '__main__':
    rc = 2
    try: rc = main()
    except Exception as e:
        log('ABORT: %s' % e); rc = 1
    finally: H.cleanup(os.environ.get('KEEP') == '1' or rc != 0)
    sys.exit(rc)
