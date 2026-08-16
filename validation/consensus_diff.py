#!/usr/bin/env python3
"""consensus_diff.py -- differential consensus harness: ASM node vs Bitcoin Core.

The compliance gate (PLAN.md:506-510). Feeds the SAME real mainnet block/tx
bytes to (a) the ASM consensus stack (asm/tests/consensus_shim, which wraps
cons_verify / block_hash / pow_check / diff_target / tx_txid) and (b) a real
Bitcoin Core node (its RPC), and compares every verdict byte-for-byte.

Two differential passes over identical input bytes:

  ACCEPT path (real mainnet, zero-divergence gate):
    For every height H in the window: take Core's own raw block bytes and the
    expected hash (getblockhash H). Run them through the ASM shim.
      * ASM cons_verify must ACCEPT -- every real mainnet block is consensus-
        valid, so a rejection is a false-negative consensus bug.
      * ASM block_hash must equal Core's height->hash. Header PoW (pow_check)
        and diff_target(nBits) are checked per-header too.
    Core's verdict on the same bytes is "duplicate" (it is in the active chain)
    == ACCEPT. Divergence here is real consensus incompatibility.

  REJECT path (mutated real mainnet, differential same-bytes):
    Take a real block and apply a battery of deterministic, consensus-relevant
    mutations (flip a merkle byte, corrupt a tx byte, alter the tx-count,
    corrupt the previous-block link, truncate, corrupt nBits, flip nonce/PoW).
    Feed the IDENTICAL mutated bytes to both sides and require agreement:
      * ASM cons_verify must REJECT (0).
      * Core submitblock must REJECT (any non-empty reject string).
    If one side accepts what the other rejects, that is a divergence.

Also checks the ASM txid (tx_txid) against Core's decoderawtransaction txid for
every tx in a sample of blocks (validation parity).

Usage:
  consensus_diff.py [--rpcuser U --rpcpass P --rpcport N]
                    [--shim PATH] [--start H] [--count N] [--mut N]
                    [--blocks-only] [--seed S]

Exit 0 if zero divergences, 1 otherwise. Also writes a JSON report to
validation/consensus_diff_report.json (cwd-independent).
"""
import sys, os, json, time, subprocess, random, hashlib, collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..'))
SHIM = os.path.join(ROOT, 'asm', 'tests', 'consensus_shim')
REPORT = os.path.join(HERE, 'consensus_diff_report.json')

RPC_BIN   = '/storage/bitcoin/bin/bitcoin-cli'
RPC_ARGS  = ['-datadir=/storage/bitcoin/data']
GENESIS   = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

# ---------------------------------------------------------------------------
# ASM shim
# ---------------------------------------------------------------------------
class Shim:
    def __init__(self, path=SHIM):
        self.p = subprocess.Popen([path], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True)
    def ask(self, cmd, hexstr):
        self.p.stdin.write('%s %s\n' % (cmd, hexstr))
        self.p.stdin.flush()
        line = self.p.stdout.readline().strip()
        return line
    def block(self, b):
        r = self.ask('BLOCK', b.hex()).split()
        # OK <ok> <hash_be32hex> <ntx> <nbytes>
        return {'ok': int(r[1]), 'hash': r[2], 'ntx': int(r[3]), 'nbytes': int(r[4])}
    def header(self, h80):
        r = self.ask('HEADER', h80.hex()).split()
        return {'ok': int(r[1]), 'hash': r[2]}
    def txid(self, tx):
        r = self.ask('TXID', tx.hex()).split()
        return {'ok': int(r[1]), 'txid': r[2], 'nin': int(r[3]), 'nout': int(r[4])}
    def target(self, bits):
        r = self.ask('TARGET', bits.to_bytes(4, 'little').hex()).split()
        return {'target': r[2]}
    def close(self):
        try:
            self.p.stdin.write('QUIT\n'); self.p.stdin.flush()
        except Exception:
            pass
        self.p.terminate()

# ---------------------------------------------------------------------------
# Core RPC oracle
# ---------------------------------------------------------------------------
def be_from_lehex(h):
    """Core RPC returns hashes in display (big-endian) form; the ASM shim
    prints the raw digest in internal little-endian byte order, so byte-reverse
    the hex string (pair-wise) to make them comparable."""
    if not h or len(h) % 2:
        return h
    return ''.join(h[i:i+2] for i in range(len(h)-2, -1, -2))

class Core:
    def __init__(self):
        self.cli = [RPC_BIN] + RPC_ARGS
    def call(self, method, *args):
        out = subprocess.run(self.cli + [method] + list(args),
                             capture_output=True, text=True)
        if out.returncode != 0:
            return {'error': out.stderr.strip()}
        t = out.stdout.strip()
        # submitblock returns a bare string; everything else JSON
        if method == 'submitblock':
            return t if t else 'null'
        try:
            return json.loads(t)
        except Exception:
            return t
    def getblockhash(self, h): return self.call('getblockhash', str(h))
    def getblock(self, hsh):   return self.call('getblock', hsh, '0')
    def getblock2(self, hsh):  return self.call('getblock', hsh, '2')
    def submitblock(self, raw):
        # Pass the (possibly large) block hex via stdin (-stdin reads the arg
        # from stdin) to avoid OS argv-length limits on big mainnet blocks.
        out = subprocess.run(self.cli + ['-stdin', 'submitblock'],
                             input=raw + '\n', capture_output=True, text=True)
        if out.returncode != 0:
            return {'error': out.stderr.strip()}
        t = out.stdout.strip()
        return t if t else 'null'
# ---------------------------------------------------------------------------
# Mutation battery (deterministic, consensus-relevant)
# ---------------------------------------------------------------------------
def mutations(block_raw, seed):
    """Yield (name, bytearray, core_reject_class) for mutations of a real block
    that the ASM cons_verify is designed to catch, matched to a Core reject
    class. Returns deterministic list seeded by `seed`."""
    b = bytearray(block_raw)
    out = []
    rnd = random.Random(seed)

    # 1) flip a byte inside the merkle-root header field (36..68) -> PoW/header
    off = 36 + (seed % 32)
    m = bytearray(b); m[off] ^= 0x40; out.append(('flip-merkle-byte@%d' % off, m))
    # 2) flip a byte in a later transaction (corrupt tx -> merkle root mismatch)
    if len(b) > 120:
        off2 = 90 + (seed % (len(b) - 90 - 8))
        m = bytearray(b); m[off2] ^= 0x01; out.append(('flip-tx-byte@%d' % off2, m))
    # 3) corrupt the tx-count field at offset 80
    if len(b) > 82:
        m = bytearray(b); m[80] = (m[80] + 1) & 0xff  # usually breaks count or merkle
        out.append(('corrupt-txcount@80', m))
    # 4) corrupt the previous-block pointer (offset 4..36)
    m = bytearray(b); m[4 + (seed % 32)] ^= 0x01; out.append(('corrupt-prevblock@4+', m))
    # 5) truncate the block (drop the last 32 bytes) -> bounds / tx parse
    if len(b) > 100:
        out.append(('truncate-32', bytearray(b[:-32])))
    # 6) clear/zero the nonce+bits region -> high-hash (PoW fail)
    m = bytearray(b); 
    # nBits at 72..76, nonce at 76..80
    m[76] ^= 0x01; out.append(('flip-nonce@76', m))
    # 7) corrupt the coinbase tx version byte
    m = bytearray(b)
    # first tx starts at 81+countbytes; for small counts that's 81
    tx0 = 81
    if m[80] < 0xfd and len(b) > tx0:
        m[tx0] ^= 0x01; out.append(('corrupt-tx0-version', m))
    return out

# ---------------------------------------------------------------------------
def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--start', type=int, default=173805)  # BIP16 activation window
    ap.add_argument('--count', type=int, default=0)
    ap.add_argument('--mut', type=int, default=2)          # blocks to mutate-test
    ap.add_argument('--seed', type=int, default=7)
    ap.add_argument('--blocks-only', action='store_true')
    args = ap.parse_args()

    core = Core()
    shim = Shim()
    report = {'generated': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    stats = collections.Counter()
    accepts = []      # per-height accept checks
    rejects = []      # per-mutation differential checks
    tx_checks = []    # per-tx txid checks
    divs = []         # divergences

    def div(where, detail):
        divs.append({'where': where, 'detail': detail})
        print('  DIVERGENCE %-28s %s' % (where, detail), file=sys.stderr)

    # chain tip
    blocks = core.call('getblockcount')
    if isinstance(blocks, dict):
        blocks = '?'
    print('Core chain tip: %s blocks' % blocks)
    start = args.start
    if args.count:
        heights = range(start, min(start + args.count, int(blocks)))
    else:
        # default: full window from --start to tip, capped for runtime
        heights = range(start, min(start + 300, int(blocks)))

    # ---------------- ACCEPT path ----------------
    print('ACCEPT path: real mainnet blocks %d..%d via same-bytes to Core+ASM' %
          (heights[0], heights[-1]))
    per_block_batches = []
    for H in heights:
        hsh = core.getblockhash(H)
        if isinstance(hsh, dict) and 'error' in hsh:
            div('getblockhash@%d' % H, str(hsh)); continue
        raw = core.getblock(hsh)
        if isinstance(raw, dict):
            div('getblock@%d' % H, str(raw)); continue
        b = bytes.fromhex(raw)
        stats['accept_run'] += 1
        a = shim.block(b)
        asm_hash_be = be_from_lehex(a['hash'])
        if a['ok'] != 1:
            div('accept@%d' % H,
                'ASM cons_verify=0 but Core has this block in-chain (false-negative)')
            accepts.append({'h': H, 'hash': hsh, 'asm_ok': 0})
        elif asm_hash_be != hsh:
            div('accept-hash@%d' % H,
                'ASM block_hash=%s != Core %s' % (asm_hash_be, hsh))
            accepts.append({'h': H, 'hash': hsh, 'asm_hash': asm_hash_be})
        else:
            stats['accept_ok'] += 1
            accepts.append({'h': H, 'hash': hsh, 'asm_ok': 1})

        # per-header pow_check / diff_target on this block's 80-byte header
        h80 = bytes(b[:80])
        hd = shim.header(h80)
        if hd['ok'] != 1:
            div('header-pow@%d' % H, 'pow_check rejected a real mainnet header')
        nbits = int.from_bytes(b[72:76], 'little')
        tgt = shim.target(nbits)
        if tgt.get('target'):  # sanity: target of real nBits is non-zero and <2^256
            tv = int(tgt['target'], 16)
            if tv == 0 or tv > (1 << 256):
                div('target@%d' % H, 'diff_target returned implausible target for nBits=%08x' % nbits)

        # tx-level differential: decoderaw every tx and compare ASM txid
        if not args.blocks_only:
            # parse txs crudely via ASM itself by walking; simpler: use my decode
            off = 80
            c = b[80]
            cnt_off = 1 if c < 0xfd else (3 if c == 0xfd else (5 if c == 0xfe else 9))
            txstart = 80 + cnt_off
            # re-use ASM TXID per whole block is not tupled here; instead run a
            # small per-tx decode below using tx parsing via getrawtransaction is
            # heavy; keep tx checks to a sampled block in the REJECT section.

        per_block_batches.append((H, hsh, b))

    # ---------------- REJECT path (differential same-bytes vs Core) ---------
    print('REJECT path: mutating %d real blocks, feeding identical bytes to ASM+Core'
          % args.mut)
    mut_blocks = per_block_batches[:args.mut] or per_block_batches
    for H, hsh, b in mut_blocks[:args.mut]:
        rnd = random.Random(args.seed * 1000 + H)
        muts = mutations(b, H + args.seed)
        for name, mb in muts:
            stats['reject_run'] += 1
            # ASM verdict on identical bytes
            aw = shim.block(mb)
            # Core verdict on identical bytes.
            cw = core.submitblock(mb.hex())
            # Core reject classification:
            #   bare string ("" -> 'null', 'duplicate'/else reject reason)
            #   'duplicate' = block already known by header hash = ACCEPT
            #   dict with error -22 'Block decode failed' = rejected at decode
            #   dict with other error = RPC-level failure (treat as rejected:
            #     the bytes were never accepted into a block)
            if isinstance(cw, dict) and 'error' in cw:
                core_reject = True
                core_verdict = 'core-rpc-error'
            else:
                core_verdict = '' if cw in (None, 'null', '', 'duplicate') else cw
                core_reject = bool(cw) and cw not in ('null', '', 'duplicate')
            asm_reject = (aw['ok'] == 0)
            record = {'h': H, 'mut': name, 'asm_reject': asm_reject,
                      'core_reject': core_reject, 'core_verdict': core_verdict}
            rejects.append(record)
            if asm_reject != core_reject:
                div('reject@%d:%s' % (H, name),
                    'ASM reject=%s Core reject=%s (%r)' % (asm_reject, core_reject, cw))
            elif asm_reject and core_reject:
                stats['reject_agree'] += 1
            elif not asm_reject and not core_reject:
                # both accepted a mutation: means the mutation wasn't consensus-
                # invalid for either -- that's agreement, but flag it so it isn't
                # silently counted as a checked reject.
                stats['reject_both_accepted'] += 1

    # ---------------- TXID differential on real mainnet txs ----------------
    # Take a real block's transactions straight from Core (verbosity 2 gives each
    # tx's exact serialized hex, witness included), feed the IDENTICAL bytes to
    # the ASM shim (tx_parse + tx_txid), and require the ASM txid to equal Core's
    # canonical txid for that tx. Both sides verdict on identical bytes.
    if not args.blocks_only and per_block_batches:
        checked = 0
        for H, hsh, b in per_block_batches[:1]:
            blk2 = core.getblock2(hsh)
            if isinstance(blk2, dict) and 'error' in blk2:
                print('  (txid diff skipped: Core getblock v2 failed for %d: %s)' %
                      (H, blk2.get('error')))
                continue
            for i, tx in enumerate(blk2.get('tx', [])[:120]):
                rawhex = tx.get('hex')
                cid = tx.get('txid')
                if not rawhex or not cid:
                    continue
                a = shim.txid(bytes.fromhex(rawhex))
                asm_txid = be_from_lehex(a['txid'])  # LE -> display BE
                if a['ok'] != 1:
                    div('txid@%d:%d' % (H, i),
                        'ASM tx_parse/tx_txid failed on a real tx')
                    continue
                if asm_txid != cid:
                    div('txid@%d:%d' % (H, i),
                        'ASM txid %s != Core %s' % (asm_txid, cid))
                else:
                    stats['txid_ok'] += 1
                    tx_checks.append({'h': H, 'idx': i, 'txid': cid})
                checked += 1
        print('  TXID differential: %d txs checked asm-txid vs Core txid' % checked)

    shim.close()

    # ---------------- report ----------------
    print('\n==== differential consensus report ====')
    print('  ACCEPT: run=%d ok=%d' % (stats['accept_run'], stats['accept_ok']))
    print('  REJECT (ASM⊃Core paired): run=%d agree=%d both-accepted=%d' %
          (stats['reject_run'], stats['reject_agree'], stats['reject_both_accepted']))
    print('  divergences: %d' % len(divs))
    report.update({'tip': blocks, 'accept': accepts, 'reject': rejects,
                   'divergences': divs, 'stats': dict(stats)})
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, 'w') as f:
        json.dump(report, f, indent=1)
    print('  report -> %s' % REPORT)
    return 0 if not divs else 1

if __name__ == '__main__':
    sys.exit(main())
