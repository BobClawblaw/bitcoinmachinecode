#!/usr/bin/env python3
"""validation/echo_core_diff.py -- echo / echojson / echoipc, bmc against
Bitcoin Core v31.1, on regtest. 2026-11-04.

Core Lightning's bcli plugin runs `bitcoin-cli echo` before anything else to
learn that the node answers; this node did not serve the method, so CLN could
not start against it. The same raw JSON-RPC bodies go to both nodes and the
HTTP status and the reply BYTES are compared, then Core's own bitcoin-cli runs
the shapes bcli and an operator use (`echo`, `echo a 1 {..}`, `echojson`,
`-named`) against both and its stdout and exit code are compared.

One case is skipped on purpose and printed: arg9 == "trigger_internal_bug" is
Core's self-test of its own bug reporting (an "Internal bug detected" body
naming Core's source file); this node echoes the string.

Usage: python3 validation/echo_core_diff.py
       env: CORE_BIN, BMC_BIN, WORK (default $TMPDIR/bmc-echo-<pid>), KEEP=1
"""
import base64, json, os, shutil, signal, subprocess, sys, time, urllib.request
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib'))
from diffguard import require_cases

CORE_BIN = os.environ.get('CORE_BIN', '/storage/bitcoin-core-v31.1/bin')
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BMC_BIN = os.environ.get('BMC_BIN', os.path.join(ROOT, 'asm/daemon/bmcbitcoind'))
WORK = os.environ.get('WORK', os.path.join(os.environ.get('TMPDIR', '/tmp'), 'bmc-echo-%d' % os.getpid()))
# not adjacent: Core binds an onion target on P2P+1 even with listenonion=0
C_P2P, C_RPC = 19714, 19724
B_P2P, B_RPC = 19734, 19744
AUTH = 'Basic ' + base64.b64encode(b'e2e:e2epw').decode()

def post(port, body):
    req = urllib.request.Request('http://127.0.0.1:%d/' % port, body.encode(),
                                 {'Content-Type': 'application/json', 'Authorization': AUTH})
    try:
        with urllib.request.urlopen(req, timeout=60) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()

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
    try: post(C_RPC, '{"method":"stop","id":0}')
    except Exception: pass
    time.sleep(2)
    for p in my_procs():
        try: os.kill(p, signal.SIGTERM)
        except Exception: pass
    for _ in range(30):
        if not my_procs(): break
        time.sleep(1)
    if os.environ.get('KEEP') != '1': shutil.rmtree(WORK, ignore_errors=True)

TEN = '[0,1,2,3,4,5,6,7,8,9]'
ELEVEN = '[0,1,2,3,4,5,6,7,8,9,10]'
BODIES = [
    # bcli's own call, and the params shapes that mean "no arguments"
    '{"jsonrpc":"1.0","id":"bcli","method":"echo"}',
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":[]}',
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":null}',
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":{}}',
    # values are returned verbatim, number text included
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":["a",1,{"x":[1,2.50]},null,true]}',
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":["a",null,null]}',
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":[1e3,0.10000000,-0,"\\u00e9\\n"]}',
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":%s}' % TEN,
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":%s}' % ELEVEN,
    '{"jsonrpc":"1.0","id":1,"method":"echojson","params":[1,"b"]}',
    '{"jsonrpc":"1.0","id":1,"method":"echojson","params":%s}' % ELEVEN,
    # named arguments
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":{"arg2":"c","arg0":"a"}}',
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":{"arg3":null}}',
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":{"arg10":"c"}}',
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":{"arg0":"a","arg0":"b"}}',
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":{"args":["a"]}}',
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":{"args":["a"],"arg2":"x"}}',
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":{"args":["a","b"],"arg1":"x"}}',
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":{"args":"a"}}',
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":{"args":%s}}' % ELEVEN,
    # params that are neither array nor object
    '{"jsonrpc":"1.0","id":1,"method":"echo","params":"str"}',
    # JSON-RPC 2.0, a notification, a batch
    '{"jsonrpc":"2.0","id":7,"method":"echo","params":["x"]}',
    '{"jsonrpc":"2.0","id":7,"method":"echo","params":%s}' % ELEVEN,
    '{"jsonrpc":"2.0","method":"echo","params":["x"]}',
    '[{"jsonrpc":"2.0","id":1,"method":"echo","params":[1]},{"jsonrpc":"1.0","id":2,"method":"echojson","params":{"arg1":2}}]',
    # echoipc: exactly one string
    '{"jsonrpc":"1.0","id":1,"method":"echoipc","params":["x"]}',
    '{"jsonrpc":"1.0","id":1,"method":"echoipc","params":[""]}',
    '{"jsonrpc":"1.0","id":1,"method":"echoipc","params":{"arg":"z"}}',
    '{"jsonrpc":"1.0","id":1,"method":"echoipc"}',
    '{"jsonrpc":"1.0","id":1,"method":"echoipc","params":["x","y"]}',
    '{"jsonrpc":"1.0","id":1,"method":"echoipc","params":[5]}',
    '{"jsonrpc":"1.0","id":1,"method":"echoipc","params":[null]}',
    '{"jsonrpc":"1.0","id":1,"method":"echoipc","params":{"argx":"z"}}',
]
CLI = [
    ['echo'],
    ['echo', 'a', '1', '{"x":1}'],
    ['echojson', '1', '{"x":1}', '[2,"b"]'],
    ['-named', 'echo', 'arg1=b'],
    ['-named', 'echojson', 'arg0=[1]', 'arg3=true'],
    ['echo'] + [str(i) for i in range(11)],
    ['echoipc', 'hello'],
    ['echoipc'],
]

def main():
    for d in ('core', 'bmc/regtest'): os.makedirs(os.path.join(WORK, d), exist_ok=True)
    open(os.path.join(WORK, 'core/bitcoin.conf'), 'w').write(
        'regtest=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\nlisten=0\nlistenonion=0\n' % (C_P2P, C_RPC))
    open(os.path.join(WORK, 'bmc/bitcoin.conf'), 'w').write(
        'chain=regtest\nprinttoconsole=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\n' % (B_P2P, B_RPC))
    subprocess.run([CORE_BIN + '/bitcoind', '-datadir=' + WORK + '/core', '-daemon'], check=True, stdout=subprocess.DEVNULL)
    blog = open(os.path.join(WORK, 'bmc.log'), 'wb')
    subprocess.Popen(['setsid', BMC_BIN, 'serve', WORK + '/bmc'], cwd=os.path.join(ROOT, 'asm'),
                     stdout=blog, stderr=blog, stdin=subprocess.DEVNULL)
    if not up(C_RPC): print('FAIL: Core did not start'); return 2
    if not up(B_RPC): print('FAIL: bmc did not start'); return 2

    fails = compared = 0
    for body in BODIES:
        c, b = post(C_RPC, body), post(B_RPC, body)
        compared += 1
        if c == b: print('  match  %-4d %s' % (c[0], body[:100]))
        else:
            fails += 1
            print('  DIFF   %s\n    core %d %r\n    bmc  %d %r' % (body, c[0], c[1][:400], b[0], b[1][:400]))
    skip = '{"jsonrpc":"1.0","id":1,"method":"echo","params":[0,1,2,3,4,5,6,7,8,"trigger_internal_bug"]}'
    print('  skipped (Core self-test hook): %s\n    bmc  %r' % (skip, post(B_RPC, skip)[1]))

    for args in CLI:
        out = []
        for port in (C_RPC, B_RPC):
            r = subprocess.run([CORE_BIN + '/bitcoin-cli', '-rpcport=%d' % port, '-rpcuser=e2e', '-rpcpassword=e2epw'] + args,
                               capture_output=True, timeout=60)
            out.append((r.returncode, r.stdout, r.stderr))
        compared += 1
        if out[0] == out[1]: print('  match  cli rc=%d %s' % (out[0][0], ' '.join(args)[:100]))
        else:
            fails += 1
            print('  DIFF   cli %s\n    core %r\n    bmc  %r' % (' '.join(args), out[0], out[1]))

    require_cases(compared, 'echo cases', minimum=len(BODIES) + len(CLI))
    print('ALL %d MATCH' % compared if not fails else '%d of %d DIFFER' % (fails, compared))
    return 1 if fails else 0

if __name__ == '__main__':
    try: rc = main()
    finally: cleanup()
    sys.exit(rc)
