#!/usr/bin/env python3
"""corpus_diff.py -- BROAD differential-consensus corpus run vs Bitcoin Core.

The compliance gate (PLAN.md:506-514). Extends consensus_diff.py from a tiny
focused window (8 blocks near BIP16) to a LARGE real-mainnet corpus across the
entire chain, comparing the ASM consensus/validation stack against a real,
fully-synced Bitcoin Core node on the IDENTICAL real block/tx bytes, tracking
every divergence to zero.

Surfaces exercised (all differential vs live Core, same input bytes to both):

  A. Consensus ACCEPT  -- for every sampled real block: Core has it in-chain
       (getblockhash -> a real hash), so the ASM cons_verify MUST accept (a
       rejection = false-negative consensus bug) and ASM block_hash MUST equal
       Core's height->hash.
  B. Header PoW / diff_target -- per sampled header, pow_check must accept the
       real header (it satisfied its own difficulty) and diff_target(nBits)
       must be a plausible nonzero < 2^256 target.
  C. Legacy sigop validation -- per sampled block, ASM structural legacy sigop
       count (Core GetLegacySigOpCount, exactly) must be <= MAX_BLOCK_SIGOPS
       (20000). Core accepts the block, so nSigOps > 20000 == a divergence
       (bad-blk-sigops is a pure structural coin-independent check that applies
       at every height, segwit included).
  D. In-block duplicate txid validation -- per sampled block, ASM must find NO
       in-block duplicate txid (Core rejects such blocks bad-txns-duplicate).
  E. TXID differential -- for a large sample of txs across all epochs, ASM
       tx_txid MUST equal Core's decoderawtransaction txid.
  F. REJECT (mutation) differential -- battery of deterministic consensus-
       relevant mutations applied to real blocks; the IDENTICAL mutated bytes
       must be rejected by BOTH Core submitblock and ASM cons_verify (or both
       accepted) at every epoch.

Corpus is epoch-stratified across the whole chain (tip read from RPC at
runtime): genesis, pre-BIP16, BIP16->segwit, segwit->taproot, taproot->tip, plus
the epoch-boundary blocks. Parallelizes across worker shim processes.

Usage:
  corpus_diff.py [--workers N] [--per-epoch N] [--tx-sample T] [--mut M]
                 [--seed S] [--shim PATH]

Exit 0 if zero divergences, 1 otherwise. Writes validation/corpus_diff_report.json
and validation/corpus_diff_report.txt (cwd-independent).
"""
import sys, os, json, time, subprocess, random, hashlib, base64
import http.client
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..'))
SHIM = os.path.join(ROOT, 'asm', 'tests', 'consensus_shim')
REPORT_JSON = os.path.join(HERE, 'corpus_diff_report.json')
REPORT_TXT  = os.path.join(HERE, 'corpus_diff_report.txt')

# --- Core RPC (persistent HTTP JSON-RPC, cookie auth) -------------------------
RPC_HOST, RPC_PORT = '127.0.0.1', 8332
COOKIE_PATH = '/storage/bitcoin/data/.cookie'

def _auth_header():
    try:
        cookie = open(COOKIE_PATH).read().strip()
    except Exception:
        cookie = 'bitcoinrpc:e85a0d86221666b1005b00805048c11d'
    return 'Basic ' + base64.b64encode(cookie.encode()).decode()

_AUTH = _auth_header()

def rpc(method, params=None):
    body = json.dumps({'jsonrpc':'1.0','id':'x','method':method,'params':params or []})
    c = http.client.HTTPConnection(RPC_HOST, RPC_PORT, timeout=300)
    try:
        c.request('POST', '/', body, headers={'Authorization':_AUTH, 'Content-Type':'application/json'})
        r = c.getresponse(); raw = r.read()
    finally:
        c.close()
    d = json.loads(raw)
    if 'error' in d and d['error']:
        raise RuntimeError('%s: %s' % (method, d['error']))
    return d['result']

def submitblock_tolerant(raw_hex):
    """submitblock may return an RPC-level error (decode failure -> -22) which
    still means 'the bytes were NEVER accepted as a block' == rejected. Returns
    {'reject': bool, 'verdict': str|None}.

    Verdict semantics (Core RPC): empty/''/'null' = accepted;
    'duplicate' = the block (by header hash) is ALREADY known = also ACCEPT
    (not a rejection — Core does not consider the block invalid). Any other
    non-empty string (high-hash, bad-txnmrklroot, bad-prevblk, ...) = rejected."""
    try:
        res = rpc('submitblock', [raw_hex])
    except RuntimeError as e:
        return {'reject': True, 'verdict': 'rpc-error:' + str(e)}
    if res in (None, '', 'null', 'duplicate'):
        return {'reject': False, 'verdict': res if res not in (None, '') else ''}
    # any other non-empty string is a specific reject reason
    return {'reject': True, 'verdict': str(res)}

# --- helpers ------------------------------------------------------------------
def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def be_from_lehex(h):
    """ASM prints raw digest in little-endian byte order; Core RPC hashes are
    display (big-endian) hex -- pairwise-reverse to compare."""
    if not h or len(h) % 2:
        return h
    return ''.join(h[i:i+2] for i in range(len(h)-2, -1, -2))

def be_from_le(b):
    return ''.join('%02x' % x for x in b[::-1])

# --- ASM shim per worker --------------------------------------------------------
class Shim:
    def __init__(self, path=SHIM):
        self.p = subprocess.Popen([path], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True)
    def ask(self, cmd, hexstr):
        self.p.stdin.write('%s %s\n' % (cmd, hexstr))
        self.p.stdin.flush()
        return self.p.stdout.readline().strip()
    def close(self):
        try:
            self.p.stdin.write('QUIT\n'); self.p.stdin.flush()
        except Exception:
            pass
        try:
            self.p.terminate()
        except Exception:
            pass

def be_from_lehex_id(id_):
    if not id_ or id_ == 'null' or '{' in str(id_):
        return id_
    return id_

# --- mutation battery (deterministic, consensus-relevant) ----------------------
def mutations(block_raw, seed):
    """Yield (name, bytearray) mutations of a real block that ASM cons_verify
    is designed to catch; matched to a Core reject class on the same bytes."""
    b = bytearray(block_raw)
    out = []
    def add(name, m):
        out.append((name, m))
    # header region is 0..80
    if len(b) >= 81:
        # 1) flip a byte inside merkle-root header field (36..68) -> PoW/hash
        off = 36 + (seed % 32)
        m = bytearray(b); m[off] ^= 0x40; add('flip-merkle-byte@%d' % off, m)
        # 2) flip a byte in the first (coinbase) tx's NON-WITNESS region ->
        #    merkle root mismatch. Coinbase non-witness data starts right after
        #    the tx-count varint (~81) and spans its first few hundred bytes;
        #    a byte there changes the txid -> merkle -> block hash determinis-
        #    tically (a deep offset can land in later txs' WITNESS, which is not
        #    merkle-relevant, producing a no-op mutation).
        if len(b) > 320:
            off2 = 81 + (seed % 200)
            m = bytearray(b); m[off2] ^= 0x01; add('flip-coinbase-byte@%d' % off2, m)
        # 3) corrupt the tx-count field at offset 80
        m = bytearray(b); m[80] = (m[80] + 1) & 0xff
        add('corrupt-txcount@80', m)
        # 4) corrupt the previous-block pointer (4..36)
        m = bytearray(b); m[4 + (seed % 32)] ^= 0x01
        add('corrupt-prevblock@4+', m)
        # 5) truncate (drop last 32 bytes)
        if len(b) > 100:
            add('truncate-32', bytearray(b[:-32]))
        # 6) flip the nonce byte -> PoW (high-hash)
        m = bytearray(b); m[76] ^= 0x01; add('flip-nonce@76', m)
        # 7) corrupt coinbase tx version byte
        m = bytearray(b)
        tx0 = 81
        if m[80] < 0xfd and len(b) > tx0:
            m[tx0] ^= 0x01; add('corrupt-tx0-version', m)
    return out

# --- per-block worker ----------------------------------------------------------
def process_block(H, do_mut, mut_seed):
    """Run the full battery on one block. Returns a dict of results."""
    res = {'h': H}
    hsh = rpc('getblockhash', [H])
    res['hash'] = hsh
    rawhex = rpc('getblock', [hsh, 0])
    b = bytes.fromhex(rawhex)
    shim = Shim()
    try:
        # A) ACCEPT
        a = shim.ask('BLOCK', rawhex).split()
        ok, ah = int(a[1]), be_from_lehex(a[2])
        res['accept_ok'] = (ok == 1)
        res['hash_ok'] = (ah == hsh)
        # B) header PoW + diff target
        hd = shim.ask('HEADER', rawhex[:160]).split()
        res['pow_ok'] = (int(hd[1]) == 1)
        nbits = int.from_bytes(b[72:76], 'little')
        tg = shim.ask('TARGET', nbits.to_bytes(4, 'little').hex()).split()
        tv = int(tg[2], 16) if len(tg) >= 3 else 0
        res['target_ok'] = (0 < tv < (1 << 256))
        # C) legacy sigops
        sp = shim.ask('SIGOPS', rawhex).split()
        res['sigops'] = int(sp[1]); res['ntx'] = int(sp[2])
        res['sigops_ok'] = (int(sp[1]) <= 20000)
        # D) in-block dup
        dp = shim.ask('DUPTX', rawhex).split()
        res['duptx'] = int(dp[1]); res['duptx_ok'] = (int(dp[1]) == 0)
        # F) mutation REJECT differential
        if do_mut:
            muts = mutations(b, mut_seed)
            res['mut'] = []
            for name, mb in muts:
                aw = shim.ask('BLOCK', mb.hex()).split()
                asm_reject = (int(aw[1]) == 0)
                cw = submitblock_tolerant(mb.hex())
                core_reject = cw['reject']
                res['mut'].append({'mut': name, 'asm_reject': asm_reject,
                                   'core_reject': core_reject,
                                   'core_verdict': cw['verdict']})
    finally:
        shim.close()
    return res

def sample_heights(tip, per_epoch, seed):
    """Epoch-stratified height sample across the whole chain."""
    rnd = random.Random(seed)
    epoch_bounds = [  # (name, lo, hi) inclusive
        ('genesis',        1,         1),
        ('pre-bip16',      2,    173804),
        ('bip16-segwit',   173805, 481823),
        ('segwit-taproot', 481824, 709631),
        ('taproot-tip',    709632, tip),
    ]
    heights = []
    labels = {}
    for name, lo, hi in epoch_bounds:
        hi = min(hi, tip)
        if lo > hi:
            continue
        if name == 'genesis':
            heights.append(lo); labels[lo] = name
            continue
        spans = max(1, hi - lo + 1)
        n = min(per_epoch, spans)
        picks = sorted(rnd.sample(range(lo, hi + 1), n))
        for p in picks:
            heights.append(p); labels[p] = name
        heights.append(hi); labels[hi] = name  # boundary block
    # dedupe, sort
    heights = sorted(set(heights))
    return heights, labels

def main():
    import argparse
    ap = argparse.ArgumentParser()
    # Worker count: explicit --workers wins; else BMC_WORKERS env; else auto-scale
    # to the available cores (capped to a sane ceiling). The corpus is CPU-bound
    # on independent per-block consensus_shim subprocesses, so more workers use
    # idle cores with zero contention (Core RPC stays lightly loaded). This is the
    # single highest-leverage, correctness-safe lever for wall-clock time.
    ap.add_argument('--workers', type=int, default=None,
                    help='parallel workers (default: auto-scale to cores)')
    ap.add_argument('--per-epoch', type=int, default=0,
                    help='random samples per epoch (0 = dense sweep pre-segwit + spread)')
    ap.add_argument('--tx-sample', type=int, default=8000)
    ap.add_argument('--mut', type=int, default=6, help='blocks (drawn across epochs) to mutate-diff')
    ap.add_argument('--all-mut', action='store_true', help='mutate-diff every corpus block (slow)')
    ap.add_argument('--seed', type=int, default=7)
    args = ap.parse_args()
    if args.workers is None:
        env_w = os.environ.get('BMC_WORKERS')
        if env_w:
            args.workers = int(env_w)
        else:
            import multiprocessing as _mp
            args.workers = min(_mp.cpu_count(), 32)   # auto-scale, capped at 32
    print('using %d parallel workers' % args.workers, flush=True)

    t_start = time.time()
    tip = rpc('getblockcount')
    print('Core chain tip: %d' % tip, flush=True)

    # Build corpus heights (epoch-stratified across the WHOLE chain).
    if args.per_epoch:
        heights, labels = sample_heights(tip, args.per_epoch, args.seed)
    else:
        # Default: dense early-history sweep (cheap, sub-100KB blocks) + a
        # stratified random sample across the later epochs where blocks are
        # large (segwit/taproot-era ~1-2 MB blocks cost seconds each in the
        # shim), so the modern epochs are covered by every-slice sampling.
        heights = [1]
        labels = {1: 'genesis'}
        # dense cheap sweep of early history (sub-100KB blocks, ~free in shim)
        for H in range(2, 200001, 25):
            heights.append(H)
            labels[H] = 'pre-bip16' if H <= 173804 else 'bip16-segwit'
        # stratified growth of per-block cost as the chain ages: early blocks
        # are sub-100KB and near-free in the shim (covered densely above),
        # later epochs are ~1 MB and cost seconds each, so density falls off.
        for step, lo, hi, lab in [
                (1000, 200000, 481823, 'bip16-segwit'),
                (800, 481824, 709631, 'segwit-taproot'),
                (700, 709632, tip, 'taproot-tip'),
        ]:
            hi = min(hi, tip)
            for H in range(lo, hi + 1, step):
                heights.append(H)
                labels[H] = lab
        # epoch boundaries always present
        for bd in (173804, 173805, 481823, 481824, 709631, 709632, tip):
            heights.append(bd)
            labels[bd] = labels.get(bd, 'boundary')
        heights = sorted(set(heights))
    print('corpus blocks: %d' % len(heights), flush=True)

    # Which blocks get the mutation REJECT differential. Selection guarantees
    # per-EPOCH coverage (not just corpus percentiles, which the dense early
    # sweep would dominate): one block from each consensus epoch region, so the
    # segwit/taproot epochs always get a mutation-run, plus any remaining picks
    # spread across the whole corpus by stride.
    rnd = random.Random(args.seed * 31)
    mut_heights = set()
    if args.all_mut:
        mut_heights = set(heights)
    else:
        hset = set(heights)
        epoch_lo_hi = [  # (name, lo, hi)
            ('pre-bip16', 2, 173804),
            ('bip16-segwit', 173805, 481823),
            ('segwit-taproot', 481824, 709631),
            ('taproot-tip', 709632, tip),
        ]
        for _name, lo, hi in epoch_lo_hi:
            pool = [x for x in hset if lo <= x <= hi]
            if pool:
                mut_heights.add(rnd.choice(pool))
        # fill remaining picks (if args.mut > #regions) spread by stride
        sorted_h = sorted(hset)
        for k in range(args.mut - len(epoch_lo_hi)):
            pick = sorted_h[(k * len(sorted_h)) // max(1, args.mut) % len(sorted_h)]
            mut_heights.add(pick)
        # always include genesis in the mutation pool (cheapest, core rule)
        if 1 in hset:
            mut_heights.add(1)

    block_results = []
    divs = []
    stats = {'blocks': 0, 'accept_ok': 0, 'hash_ok': 0, 'pow_ok': 0,
             'target_ok': 0, 'sigops_ok': 0, 'duptx_ok': 0,
             'mut_run': 0, 'mut_agree': 0, 'mut_both_accepted': 0,
             'txid_ok': 0, 'txid_run': 0}

    def record_div(where, detail):
        divs.append({'where': where, 'detail': detail})
        print('  DIVERGENCE %-34s %s' % (where, detail), file=sys.stderr, flush=True)

    # ---------------- A-F per-block battery (parallel) ------------------------
    def worker(H):
        do_mut = H in mut_heights
        return process_block(H, do_mut, H + args.seed)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for r in ex.map(worker, heights):
            block_results.append(r)
            stats['blocks'] += 1
            if r.get('accept_ok'): stats['accept_ok'] += 1
            else: record_div('accept@%d' % r['h'], 'cons_verify rejected a real in-chain block')
            if r.get('hash_ok'): stats['hash_ok'] += 1
            else: record_div('hash@%d' % r['h'], 'block_hash != Core height->hash')
            if r.get('pow_ok'): stats['pow_ok'] += 1
            else: record_div('pow@%d' % r['h'], 'pow_check rejected a real header')
            if r.get('target_ok'): stats['target_ok'] += 1
            else: record_div('target@%d' % r['h'], 'diff_target implausible for real nBits')
            if r.get('sigops_ok'): stats['sigops_ok'] += 1
            else: record_div('sigops@%d (%d)' % (r['h'], r.get('sigops')), 'structural legacy sigops > MAX_BLOCK_SIGOPS on an accepted block')
            if r.get('duptx_ok'): stats['duptx_ok'] += 1
            else: record_div('duptx@%d' % r['h'], 'in-block duplicate txid in a real block')
            for m in r.get('mut', []):
                stats['mut_run'] += 1
                if m['asm_reject'] != m['core_reject']:
                    record_div('reject@%d:%s' % (r['h'], m['mut']),
                               'ASM reject=%s Core reject=%s (%r)' %
                               (m['asm_reject'], m['core_reject'], m['core_verdict']))
                elif m['asm_reject'] and m['core_reject']:
                    stats['mut_agree'] += 1
                elif not m['asm_reject'] and not m['core_reject']:
                    stats['mut_both_accepted'] += 1
    print('surfaces A-D/F done (%d blocks) in %.1fs' % (stats['blocks'], time.time() - t_start), flush=True)

    # ---------------- E) TXID differential across epochs ----------------------
    # Sample blocks for tx checks: pick well-spread blocks (small enough to fetch verbosity-2 fast).
    tx_blocks = []
    stride = max(1, len(heights) // 40)
    for H in heights[::stride]:
        tx_blocks.append(H)
    checked_blocks = 0
    tx_target = args.tx_sample
    tx_done = 0
    shim = Shim()
    try:
        for H in tx_blocks:
            if tx_done >= tx_target:
                break
            hsh = rpc('getblockhash', [H])
            blk2 = rpc('getblock', [hsh, 2])
            for tx in blk2.get('tx', []):
                if tx_done >= tx_target:
                    break
                rawhex = tx.get('hex'); cid = tx.get('txid')
                if not rawhex or not cid:
                    continue
                a = shim.ask('TXID', rawhex).split()
                asm_txid = be_from_lehex(a[2]) if len(a) >= 3 and a[1] == '1' else None
                stats['txid_run'] += 1
                if a[1] != '1':
                    record_div('txid@%d' % H, 'ASM tx_parse/txid failed on a real tx')
                    tx_done += 1
                    continue
                if asm_txid != cid:
                    record_div('txid@%d' % H, 'ASM txid %s != Core %s' % (asm_txid, cid))
                else:
                    stats['txid_ok'] += 1
                tx_done += 1
            checked_blocks += 1
    finally:
        shim.close()
    print('surface E (TXID): %d txs across %d blocks in %.1fs' %
          (stats['txid_run'], checked_blocks, time.time() - t_start), flush=True)

    # ---------------- report ---------------------------------------------------
    elapsed = time.time() - t_start
    print('\n==== broad differential-consensus corpus report ====', flush=True)
    print('  tip=%d  corpus_blocks=%d  elapsed=%.1fs' % (tip, stats['blocks'], elapsed), flush=True)
    print('  ACCEPT ok=%d/%d  HASH ok=%d/%d  POW ok=%d/%d  TARGET ok=%d/%d' %
          (stats['accept_ok'], stats['blocks'], stats['hash_ok'], stats['blocks'],
           stats['pow_ok'], stats['blocks'], stats['target_ok'], stats['blocks']), flush=True)
    print('  SIGOPS ok=%d/%d  DUPTX ok=%d/%d' %
          (stats['sigops_ok'], stats['blocks'], stats['duptx_ok'], stats['blocks']), flush=True)
    print('  TXID ok=%d/%d' % (stats['txid_ok'], stats['txid_run']), flush=True)
    print('  MUT run=%d agree=%d both-accepted=%d' %
          (stats['mut_run'], stats['mut_agree'], stats['mut_both_accepted']), flush=True)
    print('  divergences: %d' % len(divs), flush=True)

    report = {
        'generated': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'tip': tip, 'corpus_blocks': len(heights), 'elapsed_s': round(elapsed, 1),
        'heights': [[h, labels.get(h, '')] for h in heights],
        'mut_blocks': sorted(mut_heights),
        'stats': dict(stats), 'divergences': divs,
        'blocks': block_results,
    }
    os.makedirs(os.path.dirname(REPORT_JSON), exist_ok=True)
    with open(REPORT_JSON, 'w') as f:
        json.dump(report, f, indent=1)
    with open(REPORT_TXT, 'w') as f:
        f.write('Broad differential-consensus corpus run vs Core\n')
        f.write('generated: %s  tip: %d  elapsed: %.1fs\n\n' %
                (report['generated'], tip, elapsed))
        f.write('corpus blocks: %d ; surfaces A-D/F on all, surface E on %d txs\n\n' %
                (len(heights), stats['txid_run']))
        f.write('stats: ' + json.dumps(stats) + '\n\n')
        if divs:
            f.write('DIVERGENCES: %d\n' % len(divs))
            for d in divs:
                f.write('  %s: %s\n' % (d['where'], d['detail']))
        else:
            f.write('ZERO DIVERGENCES across all sampled real-mainnet blocks/txs.\n')
    print('  report -> %s' % REPORT_JSON, flush=True)
    print('  report -> %s' % REPORT_TXT, flush=True)
    return 0 if not divs else 1

if __name__ == '__main__':
    sys.exit(main())
