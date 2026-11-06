#!/usr/bin/env python3
"""validation/watchdog_regtest_e2e.py -- systemd's watchdog on a real bmc, on
regtest. 2026-11-06.

bmc runs as a transient systemd USER unit with WatchdogSec=WD (default 20 s),
Restart=no, following a Core v31.1 regtest peer that mines:

  A  healthy: the unit stays active for 5 x WD while the peer mines; bmc
     follows each block; the log names the watchdog. A build without the
     pings (pass BMC_BIN=<an older binary>) fails here: systemd kills a
     healthy node it never hears from.
  B  the worker frozen (SIGSTOP), the serve parent still running: systemd's
     watchdog fires within WD plus a quarter of WD -- the parent does not
     ping on its own -- and the unit ends with Result=watchdog.

Usage: python3 validation/watchdog_regtest_e2e.py
       env: CORE_BIN, BMC_BIN, WORK (default $TMPDIR/bmc-wd-<pid>), KEEP=1, WD (seconds)
"""
import base64, json, os, re, shutil, signal, subprocess, sys, time, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
from diffguard import require_cases

CORE_BIN = os.environ.get('CORE_BIN', '/storage/bitcoin-core-v31.1/bin')
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BMC_BIN = os.path.abspath(os.environ.get('BMC_BIN', os.path.join(ROOT, 'asm/daemon/bmcbitcoind')))
WORK = os.path.abspath(os.environ.get('WORK', os.path.join(os.environ.get('TMPDIR', '/tmp'), 'bmc-wd-%d' % os.getpid())))
WD = int(os.environ.get('WD', '20'))
UNIT = 'bmc-wd-e2e-%d' % os.getpid()
P_P2P, P_RPC = 19714, 19724          # the peer (Core)
B_P2P, B_RPC = 19734, 19744          # bmc
AUTH = 'Basic ' + base64.b64encode(b'e2e:e2epw').decode()

def post(port, body):
    req = urllib.request.Request('http://127.0.0.1:%d/' % port, body.encode(),
                                 {'Content-Type': 'application/json', 'Authorization': AUTH})
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()

def call(port, method, params=None):
    s, b = post(port, json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': params or []}))
    r = json.loads(b)
    if r.get('error'): raise RuntimeError('%s: %s' % (method, r['error']))
    return r['result']

def up(port, secs=180):
    for _ in range(secs):
        try:
            if post(port, '{"method":"getblockcount","id":0}')[0] == 200: return True
        except Exception: pass
        time.sleep(1)
    return False

def wait_for(pred, secs, step=1):
    t = time.time()
    while time.time() - t < secs:
        try:
            if pred(): return True
        except Exception: pass
        time.sleep(step)
    return False

def unit_prop(p):
    return subprocess.run(['systemctl', '--user', 'show', UNIT, '-p', p, '--value'],
                          capture_output=True, text=True).stdout.strip()

def cleanup():
    subprocess.run(['systemctl', '--user', 'stop', UNIT], capture_output=True)
    subprocess.run(['systemctl', '--user', 'reset-failed', UNIT], capture_output=True)
    try: post(P_RPC, '{"method":"stop","id":0}')
    except Exception: pass
    time.sleep(3)
    if os.environ.get('KEEP') != '1': shutil.rmtree(WORK, ignore_errors=True)

cases = fails = 0
def check(what, got, want):
    global cases, fails
    cases += 1
    ok = got == want
    if not ok: fails += 1
    print('  %s %s: %r%s' % ('ok  ' if ok else 'FAIL', what, got, '' if ok else ' (want %r)' % (want,)))
    return ok

def main():
    os.makedirs(os.path.join(WORK, 'peer')); os.makedirs(os.path.join(WORK, 'bmc/regtest'))
    open(os.path.join(WORK, 'peer/bitcoin.conf'), 'w').write(
        'regtest=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\nbind=127.0.0.1\nlistenonion=0\n' % (P_P2P, P_RPC))
    open(os.path.join(WORK, 'bmc/bitcoin.conf'), 'w').write(
        'chain=regtest\nprinttoconsole=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\n'
        'connect=127.0.0.1:%d\n' % (B_P2P, B_RPC, P_P2P))
    subprocess.run([CORE_BIN + '/bitcoind', '-datadir=' + os.path.join(WORK, 'peer'), '-daemon'], check=True, stdout=subprocess.DEVNULL)
    if not up(P_RPC): print('FAIL: peer did not start'); return 2
    D = call(P_RPC, 'getdescriptorinfo', ['raw(51)'])['descriptor']   # OP_TRUE: no wallet needed
    call(P_RPC, 'generatetodescriptor', [101, D])

    log = os.path.join(WORK, 'bmc.log')
    t_start = time.time()
    subprocess.run(['systemd-run', '--user', '--unit=' + UNIT,
                    '-p', 'WatchdogSec=%ds' % WD, '-p', 'Restart=no', '-p', 'TimeoutStopSec=15s',
                    '-p', 'StandardOutput=append:' + log, '-p', 'StandardError=append:' + log,
                    '--working-directory=' + os.path.join(ROOT, 'asm'),
                    BMC_BIN, 'serve', WORK + '/bmc'], check=True, capture_output=True)
    if not up(B_RPC): print('FAIL: bmc did not start'); return 2

    print('A  healthy, %d s (5 x WatchdogSec=%ds) while the peer mines' % (5 * WD, WD))
    end = t_start + 5 * WD
    while time.time() < end and unit_prop('ActiveState') == 'active':
        call(P_RPC, 'generatetodescriptor', [1, D])
        H = call(P_RPC, 'getbestblockhash')
        wait_for(lambda: call(B_RPC, 'getbestblockhash') == H, 30)
        time.sleep(WD / 4)
    check('unit still active after 5 x WatchdogSec', unit_prop('ActiveState'), 'active')
    check('bmc follows the peer', wait_for(lambda: call(B_RPC, 'getbestblockhash') == call(P_RPC, 'getbestblockhash'), 30), True)
    text = open(log, errors='replace').read()
    check('the log names the watchdog', bool(re.search(r'\[watchdog\] systemd watchdog %ds' % WD, text)), True)

    print('B  the download worker frozen (SIGSTOP); the serve parent keeps running')
    m = re.search(r'\[serve\] download worker pid (\d+)', text)
    if not m or unit_prop('ActiveState') != 'active':
        check('a running worker to freeze', False, True)
    else:
        wpid = int(m.group(1))
        t0 = time.time()
        os.kill(wpid, signal.SIGSTOP)
        fired = wait_for(lambda: unit_prop('ActiveState') != 'active', 3 * WD, 0.5)
        dt = time.time() - t0
        print('      (the unit left "active" %.1f s after the freeze)' % dt)
        check('systemd stopped the unit', fired, True)
        check('within WatchdogSec + WatchdogSec/4 (+2 s)', dt <= WD + WD / 4 + 2, True)
        wait_for(lambda: unit_prop('ActiveState') in ('failed', 'inactive'), 60)
        check('unit Result', unit_prop('Result'), 'watchdog')

    require_cases(cases, 'checks', 6)
    print('%d checks, %d failed' % (cases, fails))
    return 1 if fails else 0

if __name__ == '__main__':
    rc = 2
    try: rc = main()
    finally: cleanup()
    sys.exit(rc)
