#!/usr/bin/env python3
"""validation/lightning_regtest_e2e.py -- LND and Core Lightning, both backed
by bmc alone, on regtest. 2026-11-04.

The question: can a Lightning node use this daemon in place of Bitcoin Core?
Both implementations are pointed at bmc and at nothing else -- LND through its
`bitcoind` backend (JSON-RPC plus the rawblock/rawtx ZMQ topics), CLN through
its bcli plugin (Core's own bitcoin-cli against bmc's RPC port, starting with
`echo`). Core v31.1 is in the picture only as the miner and the faucet: bmc
follows it over P2P (bmc has no generate* RPCs), and the Lightning nodes'
transactions reach it through bmc's relay -- nothing is handed to Core
directly, so a funding, closing or sweep transaction that confirms went
LN -> bmc -> P2P -> Core.

  phase start      Core (miner), bmc (connect=Core), LND, CLN; both LN
                   nodes report synced to bmc's tip
  phase fund       Core pays each LN wallet; both see the confirmed coins
  phase open       LND opens a channel to CLN; 6 blocks; active on both sides
  phase pay        CLN invoice paid by LND, LND invoice paid by CLN
  phase coopclose  CLN closes cooperatively; the close confirms; both list it
                   closed and the coins are back on chain
  phase forceclose CLN opens a channel to LND and pays over it; LND
                   force-closes; LND's output is swept after the CSV delay and
                   nothing is left pending; CLN sees the unilateral close
  phase reorg      CLN opens a third channel; its funding block is
                   invalidated on Core and replaced by a longer branch (the
                   funding transaction re-mined one block later); bmc follows
                   the reorg and still answers for the replaced block; both LN
                   nodes follow and bring the channel up at the new height.
                   2026-11-04: FAILS -- bmc answers -5 for the replaced block,
                   and LND's wallet ("Unable to process chain reorg: unable to
                   get block header") stops following the chain.

Usage: python3 validation/lightning_regtest_e2e.py
       env: CORE_BIN, BMC_BIN, LND_DIR (lnd, lncli), CLN_DIR (the release's
            usr/ tree), CLN_LIBS (extra LD_LIBRARY_PATH for lightningd),
            WORK (default $TMPDIR/bmc-ln-<pid>), KEEP=1
"""
import base64, json, os, shutil, signal, subprocess, sys, time, urllib.request

HOME = os.path.expanduser('~')
CORE_BIN = os.environ.get('CORE_BIN', '/storage/bitcoin-core-v31.1/bin')
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
BMC_BIN = os.environ.get('BMC_BIN', os.path.join(ROOT, 'asm/daemon/bmcbitcoind'))
LND_DIR = os.environ.get('LND_DIR', os.path.join(HOME, '.local/opt/lnd-v0.21.6-beta'))
CLN_DIR = os.environ.get('CLN_DIR', os.path.join(HOME, '.local/opt/cln-v26.06.9/usr'))
CLN_LIBS = os.environ.get('CLN_LIBS', os.path.join(HOME, '.local/opt/cln-v26.06.9/libpq/usr/lib/x86_64-linux-gnu'))
WORK = os.environ.get('WORK', os.path.join(os.environ.get('TMPDIR', '/tmp'), 'bmc-ln-%d' % os.getpid()))
# not adjacent: Core binds an onion target on P2P+1 even with listenonion=0
C_P2P, C_RPC = 19814, 19824
B_P2P, B_RPC, B_ZBLK, B_ZTX = 19834, 19844, 19846, 19848
L_P2P, L_RPC, L_REST = 19851, 19853, 19855
N_P2P = 19857

def log(*a): print(time.strftime('%H:%M:%S'), *a, flush=True)
FAILS = []
def ok(cond, what):
    log(('  ok   ' if cond else '  FAIL ') + what)
    if not cond: FAILS.append(what)
    return cond

class RPC:
    def __init__(self, port, name): self.url = 'http://127.0.0.1:%d/' % port; self.name = name
    def raw(self, method, *params):
        req = urllib.request.Request(self.url, json.dumps({'jsonrpc': '1.0', 'id': 'ln', 'method': method, 'params': list(params)}).encode(),
                                     {'Content-Type': 'text/plain', 'Authorization': 'Basic ' + base64.b64encode(b'e2e:e2epw').decode()})
        try:
            with urllib.request.urlopen(req, timeout=300) as r: return json.loads(r.read())
        except urllib.error.HTTPError as e: return json.loads(e.read())
    def __call__(self, method, *params):
        d = self.raw(method, *params)
        if d.get('error'): raise RuntimeError('%s %s%s: %s' % (self.name, method, params, d['error']))
        return d['result']
    def wallet(self, w):
        o = RPC.__new__(RPC); o.url = self.url + 'wallet/' + w; o.name = self.name; return o

core, bmc = RPC(C_RPC, 'core'), RPC(B_RPC, 'bmc')

def run(cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if check and r.returncode != 0:
        raise RuntimeError('%s -> rc %d\n%s\n%s' % (' '.join(cmd[:4]), r.returncode, r.stdout[-2000:], r.stderr[-2000:]))
    return r

LNCLI = [os.path.join(LND_DIR, 'lncli'), '--network=regtest', '--rpcserver=127.0.0.1:%d' % L_RPC]
def lncli(*a):
    out = run(LNCLI + ['--lnddir=' + WORK + '/lnd'] + list(a)).stdout
    return json.loads(out) if out.strip() else {}
CLI = [os.path.join(CLN_DIR, 'bin/lightning-cli'), '--network=regtest']
def cln(*a):
    out = run(CLI + ['--lightning-dir=' + WORK + '/cln'] + list(a)).stdout
    out = '\n'.join(l for l in out.splitlines() if not l.startswith('#'))   # progress notifications
    return json.loads(out) if out.strip() else {}

def wait(pred, what, secs=120, step=1.0):
    t0 = time.time(); last = None
    while time.time() - t0 < secs:
        try:
            v = pred()
            if v: return v
        except Exception as e: last = e
        time.sleep(step)
    log('  (timed out after %d s waiting for %s; last error: %s)' % (secs, what, last))
    return None

def up(rpc, secs=120):
    return wait(lambda: rpc('getblockcount') is not None, rpc.name + ' RPC', secs)

ADDR = None
def mine(n):
    core('generatetoaddress', n, ADDR)
    h = core('getblockcount')
    if not wait(lambda: bmc('getbestblockhash') == core('getbestblockhash'), 'bmc to follow Core to %d' % h, 120, 0.5):
        raise RuntimeError('bmc did not follow Core to height %d (bmc at %s)' % (h, bmc('getblockcount')))
    return h

def ln_synced(h):
    li, ci = lncli('getinfo'), cln('getinfo')
    return li.get('synced_to_chain') and li.get('block_height') == h and ci.get('blockheight') == h

def mine_synced(n):
    h = mine(n)
    if not wait(lambda: ln_synced(h), 'LND and CLN at height %d' % h, 120):
        raise RuntimeError('LN nodes not at %d: lnd %s, cln %s' % (h, lncli('getinfo').get('block_height'), cln('getinfo').get('blockheight')))
    return h

def in_core_mempool(txid):
    return wait(lambda: txid in core('getrawmempool'), 'tx %s to reach Core through bmc' % txid[:16], 60)

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
    for f in (lambda: cln('stop'), lambda: lncli('stop'), lambda: core('stop')):
        try: f()
        except Exception: pass
    time.sleep(3)
    for p in my_procs():
        try: os.kill(p, signal.SIGTERM)
        except Exception: pass
    for _ in range(30):
        if not my_procs(): break
        time.sleep(1)
    if os.environ.get('KEEP') != '1' and not FAILS: shutil.rmtree(WORK, ignore_errors=True)
    elif FAILS: log('logs kept in %s' % WORK)

def lnd_pay(bolt11):
    """LND's router can lag the link by a moment after a channel comes up
    ("insufficient local balance" with the link already holding the funds),
    so an attempt that fails is retried, for up to a minute."""
    last = None
    for _ in range(12):
        r = run(LNCLI + ['--lnddir=' + WORK + '/lnd', 'payinvoice', '--force', '--json', bolt11], check=False)
        try: last = json.loads(r.stdout)
        except Exception: last = {'status': 'rc %d: %s' % (r.returncode, (r.stderr or r.stdout).strip()[-200:])}
        if last.get('status') == 'SUCCEEDED': return last
        time.sleep(5)
    return last
def cln_pay(bolt11):
    last = None
    for _ in range(12):
        r = run(CLI + ['--lightning-dir=' + WORK + '/cln', 'pay', bolt11], check=False)
        try: last = json.loads('\n'.join(l for l in r.stdout.splitlines() if not l.startswith('#')))
        except Exception: last = {'status': 'rc %d' % r.returncode}
        if last.get('status') == 'complete': return last
        time.sleep(5)
    return last

def lnd_chan(chan_point):
    for c in lncli('listchannels').get('channels', []):
        if c['channel_point'] == chan_point: return c
    return None
def cln_chan(funding_txid):
    for c in cln('listpeerchannels').get('channels', []):
        if c.get('funding_txid') == funding_txid: return c
    return None

def main():
    global ADDR
    for d in ('core', 'bmc/regtest', 'lnd', 'cln'): os.makedirs(os.path.join(WORK, d), exist_ok=True)
    open(os.path.join(WORK, 'core/bitcoin.conf'), 'w').write(
        'regtest=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\nlistenonion=0\nfallbackfee=0.0002\n'
        'bind=127.0.0.1\n' % (C_P2P, C_RPC))
    open(os.path.join(WORK, 'bmc/bitcoin.conf'), 'w').write(
        'chain=regtest\nprinttoconsole=1\n[regtest]\nport=%d\nrpcport=%d\nrpcuser=e2e\nrpcpassword=e2epw\nconnect=127.0.0.1:%d\n'
        'txindex=1\nzmqpubrawblock=tcp://127.0.0.1:%d\nzmqpubhashblock=tcp://127.0.0.1:%d\n'
        'zmqpubrawtx=tcp://127.0.0.1:%d\nzmqpubhashtx=tcp://127.0.0.1:%d\n' % (B_P2P, B_RPC, C_P2P, B_ZBLK, B_ZBLK, B_ZTX, B_ZTX))
    subprocess.run([CORE_BIN + '/bitcoind', '-datadir=' + WORK + '/core', '-daemon'], check=True, stdout=subprocess.DEVNULL)
    if not up(core): print('FAIL: Core did not start'); return 2
    blog = open(os.path.join(WORK, 'bmc.log'), 'wb')
    subprocess.Popen(['setsid', BMC_BIN, 'serve', WORK + '/bmc'], cwd=os.path.join(ROOT, 'asm'),
                     stdout=blog, stderr=blog, stdin=subprocess.DEVNULL)
    if not up(bmc): print('FAIL: bmc did not start'); return 2
    log('core %s, bmc %s' % (core('getnetworkinfo')['subversion'], bmc('getnetworkinfo')['subversion']))
    core('createwallet', 'miner')
    core.url += 'wallet/miner'      # node methods answer on the wallet endpoint too
    ADDR = core('getnewaddress')
    mine(101)

    # ---------------------------------------------------------------- start
    log('phase start')
    open(os.path.join(WORK, 'lnd/lnd.conf'), 'w').write(
        '[Application Options]\nnoseedbackup=true\nlisten=127.0.0.1:%d\nrpclisten=127.0.0.1:%d\nrestlisten=127.0.0.1:%d\n'
        'alias=lnd-on-bmc\ndebuglevel=info\nnobootstrap=true\n'
        '[Bitcoin]\nbitcoin.regtest=true\nbitcoin.node=bitcoind\n'
        '[Bitcoind]\nbitcoind.rpchost=127.0.0.1:%d\nbitcoind.rpcuser=e2e\nbitcoind.rpcpass=e2epw\n'
        'bitcoind.zmqpubrawblock=tcp://127.0.0.1:%d\nbitcoind.zmqpubrawtx=tcp://127.0.0.1:%d\nbitcoind.estimatemode=CONSERVATIVE\n'
        % (L_P2P, L_RPC, L_REST, B_RPC, B_ZBLK, B_ZTX))
    llog = open(os.path.join(WORK, 'lnd.out'), 'wb')
    subprocess.Popen(['setsid', os.path.join(LND_DIR, 'lnd'), '--lnddir=' + WORK + '/lnd'],
                     stdout=llog, stderr=llog, stdin=subprocess.DEVNULL)
    open(os.path.join(WORK, 'cln/config'), 'w').write(
        'network=regtest\nbind-addr=127.0.0.1:%d\nalias=cln-on-bmc\nlog-level=debug\nlog-file=%s/cln/log\n'
        'bitcoin-cli=%s/bitcoin-cli\nbitcoin-rpcconnect=127.0.0.1\nbitcoin-rpcport=%d\nbitcoin-rpcuser=e2e\nbitcoin-rpcpassword=e2epw\n'
        'bitcoin-datadir=%s/cln\n' % (N_P2P, WORK, CORE_BIN, B_RPC, WORK))
    env = dict(os.environ, LD_LIBRARY_PATH=CLN_LIBS + (':' + os.environ['LD_LIBRARY_PATH'] if os.environ.get('LD_LIBRARY_PATH') else ''))
    nlog = open(os.path.join(WORK, 'cln.out'), 'wb')
    subprocess.Popen(['setsid', os.path.join(CLN_DIR, 'bin/lightningd'), '--lightning-dir=' + WORK + '/cln'],
                     stdout=nlog, stderr=nlog, stdin=subprocess.DEVNULL, env=env)
    h = bmc('getblockcount')
    ok(wait(lambda: lncli('getinfo').get('synced_to_chain') and lncli('getinfo')['block_height'] == h, 'LND synced', 180) is not None,
       'LND (bitcoind backend -> bmc RPC + ZMQ) starts and reports synced_to_chain at %d' % h)
    ok(wait(lambda: cln('getinfo').get('blockheight') == h, 'CLN synced', 180) is not None,
       'CLN (bcli -> bitcoin-cli echo/getblockchaininfo/... -> bmc) starts and reaches %d' % h)
    if FAILS: return 1
    lpub = lncli('getinfo')['identity_pubkey']; npub = cln('getinfo')['id']

    # ---------------------------------------------------------------- fund
    log('phase fund')
    la = lncli('newaddress', 'p2wkh')['address']; na = cln('newaddr')['bech32']
    core('sendtoaddress', la, 1.0); core('sendtoaddress', na, 1.0)
    mine_synced(6)
    ok(wait(lambda: int(lncli('walletbalance')['confirmed_balance']) == 100000000, 'LND balance', 60) is not None,
       'LND sees its 1 BTC confirmed')
    ok(wait(lambda: sum(o['amount_msat'] for o in cln('listfunds')['outputs'] if o['status'] == 'confirmed') == 100000000000,
            'CLN balance', 60) is not None, 'CLN sees its 1 BTC confirmed')
    if FAILS: return 1

    # ---------------------------------------------------------------- open
    log('phase open')
    lncli('connect', '%s@127.0.0.1:%d' % (npub, N_P2P))
    r = lncli('openchannel', '--node_key=' + npub, '--local_amt=1000000', '--sat_per_vbyte=2')
    ftx = r['funding_txid']
    ok(in_core_mempool(ftx) is not None, 'LND funding tx %s.. reached Core through bmc relay' % ftx[:16])
    mine_synced(6)
    cp = wait(lambda: next((c['channel_point'] for c in lncli('listchannels')['channels']
                            if c['channel_point'].startswith(ftx) and c['active']), None), 'LND channel active', 90)
    ok(cp is not None, 'LND -> CLN channel active on LND')
    ok(wait(lambda: (cln_chan(ftx) or {}).get('state') == 'CHANNELD_NORMAL', 'CLN CHANNELD_NORMAL', 90) is not None,
       '...and CHANNELD_NORMAL on CLN')
    if FAILS: return 1

    # ---------------------------------------------------------------- pay
    log('phase pay')
    inv = cln('invoice', '100000000', 'ln2cln', 'lnd pays cln')['bolt11']
    pr = lnd_pay(inv)
    ok(pr.get('status') == 'SUCCEEDED' and cln('listinvoices', 'ln2cln')['invoices'][0]['status'] == 'paid',
       'LND paid a 100,000 sat CLN invoice (%s)' % pr.get('status'))
    linv = lncli('addinvoice', '--amt=25000', '--memo=cln2lnd')
    pay = cln_pay(linv['payment_request'])
    ok(pay.get('status') == 'complete', 'CLN paid a 25,000 sat LND invoice (%s)' % pay.get('status'))
    ok(wait(lambda: lncli('lookupinvoice', linv['r_hash'])['state'] == 'SETTLED', 'lnd invoice settled', 30) is not None,
       '...and LND shows it SETTLED')

    # ---------------------------------------------------------------- coopclose
    log('phase coopclose')
    cr = cln('close', lpub)
    ctx = cr.get('txid') or (cr.get('txids') or [None])[-1]     # CLN 26 reports a list
    ok(cr.get('type') == 'mutual' and ctx, 'CLN mutual close (%s)' % cr.get('type'))
    ok(in_core_mempool(ctx) is not None, 'closing tx %s.. reached Core through bmc relay' % (ctx or '')[:16])
    mine_synced(6)
    ok(wait(lambda: any(c['closing_tx_hash'] == ctx for c in lncli('closedchannels')['channels']), 'LND closedchannels', 60) is not None,
       'LND lists the channel closed by that transaction')
    ok(wait(lambda: (cln_chan(ftx) or {}).get('state') in ('ONCHAIN', 'CLOSINGD_COMPLETE', 'FUNDING_SPEND_SEEN', None), 'CLN closed', 60) is not None,
       'CLN shows the channel closed (%s)' % ((cln_chan(ftx) or {}).get('state')))
    ok(int(lncli('walletbalance')['confirmed_balance']) > 99000000 - 1000000 and
       sum(o['amount_msat'] for o in cln('listfunds')['outputs'] if o['status'] == 'confirmed') > 100000000000,
       'both wallets hold their channel balances on chain again')

    # ---------------------------------------------------------------- forceclose
    log('phase forceclose')
    rr = cln('fundchannel', lpub, '800000', '2000perkw')
    ftx2 = rr['txid']
    ok(in_core_mempool(ftx2) is not None, 'CLN funding tx %s.. reached Core through bmc relay' % ftx2[:16])
    mine_synced(6)
    cp2 = wait(lambda: next((c['channel_point'] for c in lncli('listchannels')['channels']
                             if c['channel_point'].startswith(ftx2) and c['active']), None), 'LND channel 2 active', 90)
    ok(cp2 is not None, 'CLN -> LND channel active on LND')
    ok(wait(lambda: (cln_chan(ftx2) or {}).get('state') == 'CHANNELD_NORMAL', 'CLN chan 2 normal', 90) is not None,
       '...and CHANNELD_NORMAL on CLN')
    linv2 = lncli('addinvoice', '--amt=200000', '--memo=to-lnd-2')
    pay2 = cln_pay(linv2['payment_request'])
    ok(pay2.get('status') == 'complete', 'CLN paid 200,000 sat to LND over it, so LND has an output to sweep (%s)' % pay2.get('status'))
    if FAILS: return 1
    txid2, idx2 = cp2.split(':')
    bal0 = int(lncli('walletbalance')['confirmed_balance'])
    ef = {'core': core('estimatesmartfee', 6), 'bmc': bmc('estimatesmartfee', 6)}
    ok(ef['core'] == ef['bmc'], 'estimatesmartfee 6 is the same on both nodes (%s)' % ef['bmc'])
    fc = lncli('closechannel', '--force', '--funding_txid=' + txid2, '--output_index=' + idx2)
    ctx2 = fc.get('closing_txid')
    ok(ctx2 and in_core_mempool(ctx2) is not None, 'LND force-close tx %s.. reached Core through bmc relay' % (ctx2 or '')[:16])
    mine_synced(3)              # LND waits for 3 confirmations of the close before it resolves outputs
    def fc_entry():
        for e in lncli('pendingchannels')['pending_force_closing_channels']:
            if e['channel']['channel_point'] == cp2 and int(e.get('blocks_til_maturity', 0)) > 0: return e
        return None
    e = wait(fc_entry, 'LND pending force-close entry with a maturity', 60)
    mat = int(e['blocks_til_maturity']) if e else None
    ok(mat is not None, 'LND holds its 200,000 sat output behind the CSV delay (%s blocks to maturity, limbo %s sat)'
       % (mat, e and e.get('limbo_balance')))
    if FAILS: return 1
    left = mat
    while left > 0:
        mine_synced(min(left, 50)); left -= 50
    def swept():
        mine_synced(1)
        return not any(x['channel']['channel_point'] == cp2 for x in lncli('pendingchannels')['pending_force_closing_channels'])
    ok(wait(swept, 'LND to sweep its matured output', 120, 0.1) is not None,
       'LND swept its matured output through bmc and the channel left pending_force_closing')
    bal1 = int(lncli('walletbalance')['confirmed_balance'])
    ok(bal1 - bal0 > 190000, 'LND\'s on-chain balance rose by %d sat (the 200,000 sat output, less fees)' % (bal1 - bal0))
    ok(wait(lambda: any(c['closing_tx_hash'] == ctx2 for c in lncli('closedchannels')['channels']), 'closed', 30) is not None,
       'LND lists the force-closed channel')
    ok(wait(lambda: (cln_chan(ftx2) or {}).get('state') in ('ONCHAIN', 'FUNDING_SPEND_SEEN', None), 'CLN onchain', 60) is not None,
       'CLN saw the unilateral close (%s)' % ((cln_chan(ftx2) or {}).get('state')))
    if FAILS: return 1

    # ---------------------------------------------------------------- reorg
    # last: until this node can answer for a block it reorged off, LND's
    # wallet cannot process the reorg and stops following the chain
    log('phase reorg')
    rr = cln('fundchannel', lpub, '800000', '2000perkw')
    ftx3 = rr['txid']
    ok(in_core_mempool(ftx3) is not None, 'CLN funding tx %s.. reached Core through bmc relay' % ftx3[:16])
    h1 = mine_synced(1)
    blk = core('getbestblockhash')
    ok(ftx3 in core('getblock', blk)['tx'], 'funding tx mined at %d' % h1)
    core('invalidateblock', blk)
    ok(ftx3 in core('getrawmempool'), 'Core put the funding tx back in its mempool after invalidating its block')
    core('prioritisetransaction', ftx3, 0, -100000000)   # keep it out of the first replacement block
    core('generatetoaddress', 1, ADDR)
    core('prioritisetransaction', ftx3, 0, 100000000)
    h2 = mine(1)
    nb = core('getblock', core('getbestblockhash'))
    ok(ftx3 in nb['tx'] and h2 == h1 + 1, 'replacement branch: funding tx re-mined one block later, at %d' % h2)
    ok(bmc('getblockhash', h1) != blk, 'bmc reorged off the old funding block (height %d now names another block)' % h1)
    # LND's wallet (btcwallet) processes a reorg by asking for the header of
    # the block it last saw and walking back to the fork; Core answers for a
    # replaced block with confirmations -1
    gh = bmc.raw('getblockheader', blk)
    ok(not gh.get('error') and gh['result'].get('confirmations') == -1,
       'getblockheader answers for the replaced block with confirmations -1, as Core does (bmc: %s)'
       % (gh.get('error') or gh.get('result', {}).get('confirmations')))
    ok(wait(lambda: ln_synced(h2), 'LN at the reorged tip', 120) is not None, 'LND and CLN followed bmc to the new tip %d' % h2)
    mine_synced(6)
    cp3 = wait(lambda: next((c['channel_point'] for c in lncli('listchannels')['channels']
                             if c['channel_point'].startswith(ftx3) and c['active']), None), 'LND channel 3 active', 90)
    ok(cp3 is not None, 'channel funded across the reorg is active on LND')
    ok(wait(lambda: (cln_chan(ftx3) or {}).get('state') == 'CHANNELD_NORMAL', 'CLN chan 3 normal', 90) is not None,
       '...and CHANNELD_NORMAL on CLN')
    sc = (cln_chan(ftx3) or {}).get('short_channel_id', '')
    ok(sc.startswith('%dx' % h2), 'CLN\'s short_channel_id names the NEW funding height (%s)' % sc)
    inv3 = cln('invoice', '50000000', 'ln2cln-3', 'after reorg')['bolt11']
    pr = lnd_pay(inv3)
    ok(pr.get('status') == 'SUCCEEDED' and cln('listinvoices', 'ln2cln-3')['invoices'][0]['status'] == 'paid',
       'a payment across the reorged channel completes (%s)' % pr.get('status'))
    log('bmc: %d blocks, mempool %d' % (bmc('getblockcount'), len(bmc('getrawmempool'))))
    return 1 if FAILS else 0

if __name__ == '__main__':
    rc = 2
    try: rc = main()
    except Exception as e:
        log('ABORT: %s' % e); FAILS.append(str(e)); rc = 1
    finally: cleanup()
    log('RESULT: %s' % ('PASS' if rc == 0 else 'FAIL (%d): %s' % (len(FAILS), '; '.join(FAILS)[:600])))
    sys.exit(rc)
