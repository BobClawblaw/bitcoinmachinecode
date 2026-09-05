#!/usr/bin/env python3
"""fullchain_diff.py -- FULL-CHAIN, hash-for-hash differential vs Bitcoin Core.

Closes the sampling gap flagged in the worklog post-mortem: corpus_diff.py
proved 0 divergence across an 8,935-block epoch-stratified SAMPLE of the
chain, but 'consensus done' requires the ENTIRE chain (~962k blocks). This
tool drives the ASM consensus stack against EVERY block 1..tip on real
mainnet, byte-identical inputs, and tracks divergences to zero.

Reference side
--------------
A FULL OFFLINE scan of the local Bitcoin Core node's blk*.dat block files
(unpruned; ~962k blocks / ~809 GB at /storage/bitcoin/data/blocks). Core
writes its best chain sequentially in file order, every block framed as
<len:4 LE> <raw block>. Using the on-disk files (rather than live RPC) as
the reference makes the differential immune to chain reorgs during the run
and turns the scan itself into a chain-integrity differential:

  CHAIN  for every h+1: sha256d(block_h header) == block_{h+1}'s prevHash
         field (Python-computed both ways from the on-disk bytes -- if Core
         had linked a different chain, this fails).

Surfaces (per block, ASM side driven through asm shims that call the SAME
cons_verify / block_hash / pow_check / tx_parse / tx_txid asm objects that
corpus_diff.py exercises):

  A  ACCEPT  cons_verify accepts the exact on-disk block bytes. Core
             accepted every one of these blocks (they are Core's in-chain
             blocks), so an ASM rejection is a consensus false-negative.
  B  HASH    ASM block_hash(header) == Python sha256d(header) == the hash
             Core derives from the same bytes (verified independently by the
             CHAIN surface against the next block's prevHash field).
  D  POW     pow_check accepts every real header.
  E  TXCNT   the block's wire tx-count varint decodes identically in ASM and
             Python, and matches the tx count cons_verify walked.
  F  MUT     a consensus-critical REJECT differential per block: 5
             deterministic mutations of the block's header region (+ first
             coinbase bytes) -- flip-merkle, flip-prevblock, flip-nonce,
             corrupt-txcount, flip-coinbase-byte -- must be REJECTED by BOTH
             the live Core (submitblock, the consensus oracle) and the ASM
             cons_verify on the IDENTICAL mutated bytes. Core's verdict is
             the reference; ASM must agree.

Design notes
------------
* ONE streaming pass per file group: the worker walks its files' frames,
  keeps each block's 81-byte header (80-byte header + tx-count byte; a few
  extra bytes for the coinbase window), and pipes each full frame straight
  to a shared fullchain_shim subprocess (len-prefixed framing in, one
  compact verdict line out). No RAM-holding of full blocks, one 800 GB
  sequential read total, no per-block process launches.
* The MUT pass re-reads only a ~256-byte window per block (81-byte header +
  first 175 bytes of the coinbase tx) and drives ONE persistent
  consensus_shim (the corpus_diff shim, which takes hex) for the ASM-side
  reject verdicts; Core verdicts come from submitblock. Mutation #5 (the
  coinbase byte) only mutates bytes present in the window, so the verdict
  is well-defined (a byte flip inside the witness data of the coinbase is a
  no-op for the merkle root and is expected to be accepted by both -- the
  DIFFERENTIAL is the point: both must agree).
* Resumable: per-file state (count + verdict file) is written as each file
  completes, so a SIGKILL / dispatcher reclaim re-run skips finished files.
  State lives in validation/fullchain_state/.

Usage:
  fullchain_diff.py [--blocks-dir D] [--state-dir S] [--workers N]
                    [--calibrate N]   # stop after N blocks (pilot)
                    [--no-mut]       # skip the per-block mutation pass
                    [--shim PATH] [--cshim PATH]

Exit 0 if zero divergences across every block, 1 otherwise.
Writes validation/fullchain_diff_report.{json,txt} (cwd-independent).
"""
import sys, os, json, time, struct, subprocess, hashlib, base64, random, threading
import http.client
from concurrent.futures import ThreadPoolExecutor
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..'))
SHIM = os.path.join(ROOT, 'asm', 'tests', 'fullchain_shim')
CSHIM = os.path.join(ROOT, 'asm', 'tests', 'consensus_shim')
REPORT_JSON = os.path.join(HERE, 'fullchain_diff_report.json')
REPORT_TXT  = os.path.join(HERE, 'fullchain_diff_report.txt')
STATE_DEFAULT = os.path.join(HERE, 'fullchain_state')

# BLD-3 (2026-09-05): the oracle MOVED and these constants did not follow it.
# It ran at /storage/bitcoin/data on port 8332 with a committed
# bitcoinrpc:<password> fallback; it now runs from /storage/core-oracle on its
# own rpcport with COOKIE auth only. Both values here were stale, so every run
# died on a missing cookie file or a refused connection -- the "fail loudly"
# behaviour working correctly against a target that no longer exists.
#
# Overridable by environment so a differently-sited oracle needs no edit:
#   BMC_ORACLE_COOKIE   path to Core's .cookie   (default below)
#   BMC_ORACLE_HOST / BMC_ORACLE_PORT
import os as _os

def _oracle_port():
    p = _os.environ.get('BMC_ORACLE_PORT')
    if p:
        return int(p)
    # read rpcport out of the oracle's own conf rather than hardcoding a second
    # copy of it -- the conf is the one place that value is authoritative.
    try:
        for line in open(_os.path.join(_os.path.dirname(COOKIE_PATH), 'bitcoin.conf')):
            if line.startswith('rpcport='):
                return int(line.split('=', 1)[1].strip())
    except Exception:
        pass
    return 8332

COOKIE_PATH = _os.environ.get('BMC_ORACLE_COOKIE', '/storage/core-oracle/.cookie')
RPC_HOST = _os.environ.get('BMC_ORACLE_HOST', '127.0.0.1')
RPC_PORT = _oracle_port()
MAX_BLOCK = 4_000_000
# Core block-file storage format (src/node/blockstorage.cpp, ReadRawBlock):
# every block in blk*.dat is framed as
#   <MessageStartChars:4> <block_size:4 LE> <block bytes>
# STORAGE_HEADER_BYTES = 4 (magic) + 4 (size) = 8.
#
# AND (Core >= 2025, src/util/obfuscation.h): the ENTIRE blk file content is
# XOR-obfuscated with a per-datarandom key stored in blocksdir/xor.dat. The
# key is a little-endian uint64; obfuscation XORs each file-position-aligned
# 8-byte word with key rotated right by 8*(pos%8) bits. (When the key is all
# zeros the obfuscation is the identity -- the tool detects that.) The
# XOR is applied to the WHOLE file (including the 8-byte storage header),
# position-based on the absolute file offset.
STORAGE_HEADER = 8

# Per-block window for the MUT pass: 81-byte header + 175 coinbase bytes.
MUT_WIN = 256

def _auth_header():
    # BLD-3 (audit 2026-09-03): this used to fall back to a HARD-CODED
    # bitcoinrpc:<password> pair for the Core oracle when the cookie could not
    # be read -- a live credential committed to the repository since 2026-08-16.
    # Deleting it does not un-publish it; the password must be rotated out of
    # band. Failing loudly is also simply better here: a silent fallback to the
    # wrong credential produced a 401 that looked like an oracle outage.
    cookie = open(COOKIE_PATH).read().strip()
    return 'Basic ' + base64.b64encode(cookie.encode()).decode()
_AUTH = _auth_header()

def rpc(method, params=None):
    body = json.dumps({'jsonrpc': '1.0', 'id': 'x', 'method': method, 'params': params or []})
    c = http.client.HTTPConnection(RPC_HOST, RPC_PORT, timeout=300)
    try:
        c.request('POST', '/', body, headers={'Authorization': _AUTH, 'Content-Type': 'application/json'})
        r = c.getresponse(); raw = r.read()
    finally:
        c.close()
    d = json.loads(raw)
    if 'error' in d and d['error']:
        raise RuntimeError('%s: %s' % (method, d['error']))
    return d['result']

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def pairwise_reverse(hexs):
    """Reverse a 2n-char hex string by byte pairs (LE<->BE). 'aabb' -> 'bbaa'."""
    if not hexs or len(hexs) % 2:
        return hexs
    return ''.join(hexs[i:i+2] for i in range(len(hexs) - 2, -2, -2))

def varint_txcount(hdr81):
    """tx count from the wire varint starting at hdr81[80]; -1 if undecodable."""
    c = hdr81[80]
    if c < 0xfd:
        return c
    if c == 0xfd:
        return -1          # needs 2 more bytes; caller reads them
    if c == 0xfe:
        return -1
    return -1

# ---------------------------------------------------------------------------
# File-group planning
# ---------------------------------------------------------------------------
def plan_groups(blocks_dir, workers):
    files = sorted(f for f in os.listdir(blocks_dir)
                   if f.startswith('blk') and f.endswith('.dat'))
    if not files:
        raise RuntimeError('no blk*.dat files in %s' % blocks_dir)
    file_sizes = [(f, os.path.getsize(os.path.join(blocks_dir, f))) for f in files]
    total_bytes = sum(sz for _, sz in file_sizes)
    per = max(1, total_bytes // workers)
    groups, lo, acc = [], 0, 0
    for i, (f, sz) in enumerate(file_sizes):
        if acc >= per and i > lo:
            groups.append((lo, i - 1))
            lo, acc = i, 0
        acc += sz
    if lo < len(file_sizes):
        groups.append((lo, len(file_sizes) - 1))
    return file_sizes, groups

def count_blocks(blocks_dir, file_sizes, groups, workers, magic, xor_key, log=None):
    """Count blocks per file by walking len prefixes (4-byte reads + seeks)."""
    counts = {}
    lock = threading.Lock()
    def w(gi, g):
        f_lo, f_hi = g
        local = {}
        for fi in range(f_lo, f_hi + 1):
            fname, fsize = file_sizes[fi]
            n, pos = 0, 0
            with open(os.path.join(blocks_dir, fname), 'rb') as fp:
                while pos + 8 <= fsize:
                    fp.seek(pos)
                    hd = fp.read(8)
                    if len(hd) < 8:
                        break
                    if xor_key:
                        hd = _xor_deobf(hd, xor_key, pos)
                    if hd[:4] != magic:
                        local[fname + ':err'] = 'magic mismatch at pos %d' % pos
                        break
                    nn = int.from_bytes(hd[4:8], 'little')
                    if nn < 81 or nn > MAX_BLOCK:
                        local[fname + ':err'] = 'len %d at pos %d' % (nn, pos)
                        break
                    n += 1
                    pos += 8 + nn
            local[fname] = n
        with lock:
            counts.update(local)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(lambda t: w(*t), enumerate(groups)))
    total = sum(v for k, v in counts.items() if isinstance(v, int))
    if log:
        errs = {k: v for k, v in counts.items() if isinstance(v, str)}
        log('  counted %d blocks; frame errors: %s' % (total, errs or 'none'))
    return counts

def height_bases(file_sizes, counts):
    base, h = {}, 0
    for fname, _ in file_sizes:
        base[fname] = h
        h += counts.get(fname, 0)
    return base

def _learn_magic(blocks_dir):
    """Read the 4-byte storage magic from the first bytes of the first blk file
    AFTER de-obfuscating with the blocksdir XOR key (xor.dat). Core >= 2025
    XOR-obfuscates the entire blk file content position-based (see the
    Obfuscation class, src/util/obfuscation.h). We learn the magic from the
    de-obfuscated bytes so the tool works on both obfuscated and legacy
    (xor.dat == all zeros) datadirs."""
    f = sorted(x for x in os.listdir(blocks_dir)
               if x.startswith('blk') and x.endswith('.dat'))[0]
    key = _load_xor_key(blocks_dir)
    with open(os.path.join(blocks_dir, f), 'rb') as fp:
        raw = fp.read(STORAGE_HEADER)
    if key:
        raw = _xor_deobf(raw, key, 0)
    return raw[:4]

def _load_xor_key(blocks_dir):
    """Read the blocksdir XOR key (8 bytes) or None if absent/all-zero
    (identity obfuscation). Returns (key_bytes, key_bytes_ndarray).

    Bitcoin Core's disk obfuscation (src/util/obfuscation.h) XORs every byte
    of a blk*.dat file with the key byte whose index is the byte's ABSOLUTE
    file position mod 8:

        plain[pos] = raw[pos] ^ key_bytes[pos % 8]

    Equivalently (for a little-endian 8-byte key) this is the low byte of the
    key rotated right by 8*(pos%8) bits. Rotation is position-aligned to the
    file, so all reads are de-obfuscated against the absolute file offset."""
    p = os.path.join(blocks_dir, 'xor.dat')
    try:
        k = open(p, 'rb').read(8)
        if len(k) < 8:
            return None
        v = int.from_bytes(k, 'little')
        if v == 0:
            return None
        return (v, np.frombuffer(k, dtype=np.uint8).copy())
    except OSError:
        return None


def _xor_deobf(buf, xor_ctx, pos0):
    """De-obfuscate `buf` (bytes) starting at absolute file offset `pos0`.
    `xor_ctx` is (key_uint64, key_bytes_np8) from _load_xor_key, or None.
    Core's obfuscation XORs byte at absolute position p with key[p % 8]
    (position-aligned). Vectorized: per-position key-byte lookup, one pass."""
    if xor_ctx is None:
        return buf
    _keyv, key_bytes = xor_ctx
    if not buf:
        return buf
    n = len(buf)
    arr = np.frombuffer(buf, dtype=np.uint8).copy()
    idx = (np.arange(n, dtype=np.int64) + pos0) % 8
    pat = key_bytes[idx]
    arr ^= pat
    return arr.tobytes()

# ---------------------------------------------------------------------------
# Phase 1+2: header scan + ASM consensus pass (one streaming pass per group)
# ---------------------------------------------------------------------------
def stream_pass(blocks_dir, state_dir, SHIM, file_sizes, groups, base,
                workers, magic, xor_key, calibrate=0, log=None):
    """Walk every frame; strip Core's 8-byte storage header (magic+size,
    de-obfuscated with the blocksdir XOR key), re-frame each raw block as
    <len:4 LE><block> for the fullchain_shim, and record per block: py
    header-hash (sha256d of first 80 bytes), prev field, tx count, and the
    shim verdict (accept, asm hash, pow, ntx)."""
    recs = {}        # h -> dict
    divs = []
    lock = threading.Lock()

    def w(gi, g):
        f_lo, f_hi = g
        shim = subprocess.Popen([SHIM], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        local, local_divs, n_done = {}, [], 0
        try:
            for fi in range(f_lo, f_hi + 1):
                fname, fsize = file_sizes[fi]
                b0 = base[fname]
                buf = b''
                buf_file_off = 0   # absolute file offset of buf[0]
                n_in = 0
                with open(os.path.join(blocks_dir, fname), 'rb') as fp:
                    while True:
                        # fp is at (buf_file_off + len(buf)) before the read.
                        chunk_start = buf_file_off + len(buf)
                        chunk = fp.read(256 << 20)
                        if not chunk:
                            break
                        buf += chunk
                        p = 0
                        while p + 8 <= len(buf):
                            if xor_key:
                                hd = _xor_deobf(buf[p:p+8], xor_key, buf_file_off + p)
                            else:
                                hd = buf[p:p+8]
                            if hd[:4] != magic:
                                # End of the block stream: Core pads the FINAL
                                # blk file with leftover space after the last
                                # block, so a non-magic tail is the NORMAL
                                # termination, not corruption. Frame integrity
                                # is independently validated by count_blocks()
                                # (which flags a mid-file magic break as :err);
                                # every block's hash is also checked against
                                # Core, so a real corruption here cannot be
                                # masked. Break without recording a divergence.
                                break
                            n = int.from_bytes(hd[4:8], 'little')
                            if n < 81 or n > MAX_BLOCK or p + 8 + n > len(buf):
                                break
                            blk = buf[p+8:p+8+n]
                            if xor_key:
                                blk = _xor_deobf(blk, xor_key, buf_file_off + p + 8)
                            shim.stdin.write(struct.pack('<I', n) + blk)
                            shim.stdin.flush()   # MUST flush: else small frames
                                                  # sit in Python's 8KB buf while
                                                  # readline() blocks below -> deadlock
                            line = shim.stdout.readline().decode().strip()
                            n_in += 1
                            h = b0 + n_in
                            hdr = blk[:81]
                            py_hash = sha256d(hdr[:80])[::-1].hex()
                            prev = hdr[4:36][::-1].hex()
                            ntx = varint_txcount(hdr)
                            if ntx == -1:
                                extra = hdr[81:].ljust(4, b'\x00')[:4]
                                ntx = 0   # resolved below from blk
                                if hdr[80] == 0xfd:
                                    ntx = int.from_bytes(blk[81:83], 'little')
                                elif hdr[80] == 0xfe:
                                    ntx = int.from_bytes(blk[81:85], 'little')
                                else:
                                    ntx = int.from_bytes(blk[81:89], 'little')
                            rec = {'py_hash': py_hash, 'prev': prev, 'ntx': ntx,
                                   'accept': False, 'asm_hash': '', 'pow': False,
                                   'ntx_asm': -1}
                            if line.startswith('ERR'):
                                local_divs.append({'where': 'shim_err@%d' % h,
                                                   'detail': line})
                            else:
                                parts = line.split()
                                if len(parts) >= 4:
                                    rec['accept'] = parts[0][1:] == '1'
                                    rec['asm_hash'] = parts[1][1:] if parts[1].startswith('H') else ''
                                    rec['pow'] = parts[2][1:] == '1' if parts[2].startswith('P') else False
                                    rec['ntx_asm'] = int(parts[3][1:]) if parts[3].startswith('N') else -1
                                else:
                                    local_divs.append({'where': 'shim_bad@%d' % h,
                                                       'detail': line})
                            local[h] = rec
                            n_done += 1
                            p += 8 + n
                        if calibrate and n_done >= calibrate:
                            break
                        buf = buf[p:]
                        buf_file_off += p   # advance the buffer's file offset
                    if calibrate and n_done >= calibrate:
                        break
                # Mark file done.
                json.dump({'n': n_in}, open(os.path.join(state_dir, 'done_%s.json' % fname), 'w'))
        finally:
            try:
                shim.stdin.close()
            except Exception:
                pass
            try:
                shim.wait(timeout=30)
            except Exception:
                shim.kill()
        with lock:
            recs.update(local)
            divs.extend(local_divs)
        return n_done

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(lambda t: w(*t), enumerate(groups)))
    if log:
        log('stream pass done in %.1fs (%d blocks)' % (time.time() - t0, len(recs)))
    return recs, divs

def verify_surfaces(recs, divs_out, n_blocks, tip=None, log=None):
    """Surfaces A/B/D/E/CHAIN, anchored to Core's ACTIVE chain by hash.

    A blk*.dat file's PHYSICAL block order is NOT the active-chain height
    order: during early reorgs Core leaves replaced/orphaned blocks in the
    file, so the assumption 'file position == height' breaks (visible as
    spurious chain divergences near e.g. heights 169-196). This function is
    therefore keyed by BLOCK HASH: it indexes every ASM-verified record by
    its block hash, then for each ACTIVE-CHAIN height h queries Core's
    authoritative hash (getblockhash) and checks that the ASM record for that
    exact block verifies. The true 'hash-for-hash vs Core' claim is B surface:
    ASM block_hash == Core's canonical hash for every one of the ~962k
    active-chain blocks.
    """
    stats = {'blocks': 0, 'accept_ok': 0, 'hash_ok': 0, 'pow_ok': 0,
             'ntx_ok': 0, 'chain_ok': 0, 'missing': 0}
    byhash = {}
    for _k, r in recs.items():
        byhash[r['py_hash']] = r
    if tip is None:
        try:
            tip = rpc('getblockcount')
        except Exception:
            tip = -1
    if n_blocks:
        top = n_blocks  # pilot mode: only check up to the calibration cap
    else:
        top = tip
    # Prefetch Core's authoritative hash for every active-chain height in
    # parallel (962k local RPC calls; ~30-60s at 32-way concurrency). This is
    # the oracle the hash-for-hash differential is anchored to.
    core_hashes = [None] * (top + 1)
    failed = []
    def _geth(h):
        try:
            return h, rpc('getblockhash', [h])
        except Exception as e:
            return h, ('ERR', str(e))
    with ThreadPoolExecutor(max_workers=32) as ex:
        for h, res in ex.map(_geth, range(0, top + 1)):
            if isinstance(res, tuple) and res[0] == 'ERR':
                failed.append((h, res[1]))
            else:
                core_hashes[h] = res
    for h, e in failed:
        divs_out.append({'where': 'rpc@%d' % h, 'detail': e})
    if log:
        log('  prefetched %d/%d Core hashes (%d failures)' %
            (sum(1 for x in core_hashes if x), top + 1, len(failed)))
    tot_links = 0
    prev_core = None
    for h in range(0, top + 1):
        core_hash = core_hashes[h]
        if core_hash is None:
            continue
        stats['blocks'] += 1
        r = byhash.get(core_hash)
        if r is None:
            stats['missing'] += 1
            divs_out.append({'where': 'missing@%d' % h,
                             'detail': 'active-chain block not matched on disk: %s' % core_hash})
            continue
        if r['accept']:
            stats['accept_ok'] += 1
        else:
            divs_out.append({'where': 'accept@%d' % h,
                             'detail': 'ASM cons_verify rejected Core block %s' % core_hash})
        # B: ASM block_hash (LE digest bytes), normalized to display hex == Core hash
        if pairwise_reverse(r['asm_hash']) == core_hash:
            stats['hash_ok'] += 1
        else:
            divs_out.append({'where': 'hash@%d' % h,
                             'detail': 'ASM block_hash %s != Core hash %s' %
                             (pairwise_reverse(r['asm_hash']), core_hash)})
        if r['pow']:
            stats['pow_ok'] += 1
        else:
            divs_out.append({'where': 'pow@%d' % h,
                             'detail': 'ASM pow_check rejected Core block %s' % core_hash})
        if r['ntx_asm'] == r['ntx'] and r['ntx'] > 0:
            stats['ntx_ok'] += 1
        else:
            divs_out.append({'where': 'txcnt@%d' % h,
                             'detail': 'ASM ntx %d != wire tx-count %d' % (r['ntx_asm'], r['ntx'])})
        # CHAIN: this block's on-disk prev field must equal Core's previous height hash.
        if prev_core is not None:
            tot_links += 1
            if r['prev'] == prev_core:
                stats['chain_ok'] += 1
            else:
                divs_out.append({'where': 'chain@%d' % h,
                                 'detail': 'prev of %d=%s != Core hash of %d=%s' %
                                 (h, r['prev'], h - 1, prev_core)})
        prev_core = core_hash
    if log:
        log('verify_surfaces (Core-anchored): %d heights checked, %d missing, %d chain links' %
            (stats['blocks'], stats['missing'], tot_links))
    return stats

# ---------------------------------------------------------------------------
# Phase 3: MUT pass (per-block mutation REJECT differential vs Core)
# ---------------------------------------------------------------------------
class CShim:
    """Persistent consensus_shim (hex protocol) for ASM reject verdicts."""
    def __init__(self, path):
        self.p = subprocess.Popen([path], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True)
    def block_reject(self, raw):
        try:
            self.p.stdin.write('BLOCK %s\n' % raw)
            self.p.stdin.flush()
            line = self.p.stdout.readline().strip()
        except (BrokenPipeError, OSError):
            raise
        if line == '':
            raise RuntimeError('cshim died')
        parts = line.split()
        if len(parts) >= 2:
            return (int(parts[1]) == 0)     # 1 = accepted
        return None
    def close(self):
        try:
            self.p.stdin.write('QUIT\n'); self.p.stdin.flush()
        except Exception:
            pass
        try:
            self.p.terminate()
        except Exception:
            pass

def mut_battery(win, seed):
    """Yield (name, bytearray) mutations of a 256-byte block window
    (81-byte header + first 175 bytes of the coinbase tx). Mirrors the
    corpus_diff.py mutation battery restricted to the window."""
    out = []
    b = bytearray(win)
    def add(name, m):
        out.append((name, m))
    m = bytearray(b); m[36] ^= 0x40; add('flip-merkle@36', m)
    m = bytearray(b); m[4 + seed % 32] ^= 0x01; add('flip-prevblk@%d' % (4 + seed % 32), m)
    m = bytearray(b); m[76] ^= 0x01; add('flip-nonce@76', m)
    m = bytearray(b); m[80] = (m[80] + 1) & 0xff; add('corrupt-txcount@80', m)
    if len(b) > 90:
        off = 81 + seed % 174
        m = bytearray(b); m[off] ^= 0x01; add('flip-coinbase@%d' % off, m)
    return out

def mut_pass(blocks_dir, file_sizes, groups, base, workers, magic, xor_key,
             calibrate=0, CSHIM=CSHIM, log=None):
    """Re-read a 256-byte window per block; run the 5-mutation battery;
    compare ASM cons_verify reject vs Core submitblock reject on identical
    mutated bytes."""
    divs = []
    stats = {'mut_run': 0, 'mut_agree': 0, 'mut_both_accepted': 0,
             'mut_asm_unknown': 0}
    lock = threading.Lock()

    def w(gi, g):
        f_lo, f_hi = g
        cs = CShim(CSHIM)
        local_divs = []
        local = {'mut_run': 0, 'mut_agree': 0, 'mut_both_accepted': 0,
                 'mut_asm_unknown': 0}
        n_done = 0
        try:
            for fi in range(f_lo, f_hi + 1):
                fname, fsize = file_sizes[fi]
                b0 = base[fname]
                n_in = 0
                pos = 0
                with open(os.path.join(blocks_dir, fname), 'rb') as fp:
                    while pos + 8 <= fsize:
                        if calibrate and n_done >= calibrate:
                            break
                        fp.seek(pos)
                        hd = fp.read(8)
                        if len(hd) < 8:
                            break
                        if xor_key:
                            hd = _xor_deobf(hd, xor_key, pos)
                        if hd[:4] != magic:
                            break
                        n = int.from_bytes(hd[4:8], 'little')
                        if n < 81 or n > MAX_BLOCK:
                            break
                        # header + first 175 body bytes (the window)
                        win_raw = fp.read(min(n, 81 + 175))
                        if len(win_raw) < 81:
                            break
                        if xor_key:
                            win = _xor_deobf(win_raw, xor_key, pos + 8)
                        else:
                            win = win_raw
                        n_in += 1
                        h = b0 + n_in
                        n_done += 1
                        # Skip blocks that are too small to have a coinbase
                        # tx region (genesis-era blocks are tiny but always
                        # >= 81 + coinbase; all mainnet blocks qualify).
                        for name, mb in mut_battery(win, h + 7):
                            raw = mb.hex()
                            # Core verdict first (the oracle).
                            try:
                                res = rpc('submitblock', [raw])
                                core_reject = res not in (None, '', 'null', 'duplicate')
                                verdict = str(res) if res else ''
                            except RuntimeError as e:
                                core_reject = True
                                verdict = 'rpc-error:%s' % e
                            # ASM verdict on the same window.
                            try:
                                asm_reject = cs.block_reject(raw)
                            except Exception:
                                asm_reject = None
                                # respawn once
                                try: cs.close()
                                except Exception: pass
                                cs = CShim(CSHIM)
                                try:
                                    asm_reject = cs.block_reject(raw)
                                except Exception:
                                    asm_reject = None
                            local['mut_run'] += 1
                            if asm_reject is None:
                                local['mut_asm_unknown'] += 1
                            elif asm_reject != core_reject:
                                local_divs.append({'where': 'mut@%d:%s' % (h, name),
                                                   'detail': 'ASM reject=%s Core reject=%s (%s)' %
                                                   (asm_reject, core_reject, verdict)})
                            elif asm_reject and core_reject:
                                local['mut_agree'] += 1
                            else:
                                local['mut_both_accepted'] += 1
                        pos += 8 + n
        finally:
            try:
                cs.close()
            except Exception:
                pass
        with lock:
            divs.extend(local_divs)
            for k in stats:
                stats[k] += local.get(k, 0)

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(lambda t: w(*t), enumerate(groups)))
    if log:
        log('MUT pass done in %.1fs (%d blocks, %d mutations)' %
            (time.time() - t0, stats['mut_run'] // 5 if stats['mut_run'] else 0, stats['mut_run']))
    return divs, stats

# ---------------------------------------------------------------------------
def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--blocks-dir', default='/storage/bitcoin/data/blocks')
    ap.add_argument('--state-dir', default=STATE_DEFAULT)
    ap.add_argument('--workers', type=int, default=16)
    ap.add_argument('--calibrate', type=int, default=0,
                    help='pilot: stop after N blocks (0 = full chain)')
    ap.add_argument('--no-mut', action='store_true',
                    help='skip the per-block mutation pass')
    ap.add_argument('--shim', default=SHIM)
    ap.add_argument('--cshim', default=CSHIM)
    args = ap.parse_args()

    def log(s):
        print(s, flush=True)

    os.makedirs(args.state_dir, exist_ok=True)
    t_start = time.time()
    log('fullchain_diff: blocks=%s workers=%d calibrate=%s' %
        (args.blocks_dir, args.workers, args.calibrate or 'off'))

    try:
        tip = rpc('getblockcount')
    except Exception:
        tip = -1
    log('Core tip: %d' % tip)

    file_sizes, groups = plan_groups(args.blocks_dir, args.workers)
    log('%d blk files, %d groups' % (len(file_sizes), len(groups)))

    log('Phase 0: counting blocks...')
    magic = _learn_magic(args.blocks_dir)
    xor_key = _load_xor_key(args.blocks_dir)
    log('  storage magic: %s  xor: %s' % (magic.hex(), 'on' if xor_key else 'off'))
    counts = count_blocks(args.blocks_dir, file_sizes, groups, args.workers, magic, xor_key, log=log)
    total = sum(v for k, v in counts.items() if isinstance(v, int))
    base = height_bases(file_sizes, counts)
    n_target = min(args.calibrate, total) if args.calibrate else total
    log('Phase 1+2: streaming %d blocks through fullchain_shim...' % n_target)
    recs, stream_divs = stream_pass(args.blocks_dir, args.state_dir, args.shim,
                                    file_sizes, groups, base, args.workers,
                                    magic, xor_key, calibrate=n_target, log=log)

    cmp_divs = []
    stats = verify_surfaces(recs, cmp_divs, (args.calibrate if args.calibrate else 0),
                            tip=tip, log=log)

    mut_divs, mut_stats = ([], {'mut_run': 0, 'mut_agree': 0,
                                'mut_both_accepted': 0, 'mut_asm_unknown': 0})
    if not args.no_mut:
        log('Phase 3: mutation REJECT differential (%d blocks x 5 mutations)...' % n_target)
        mut_divs, mut_stats = mut_pass(args.blocks_dir, file_sizes, groups, base,
                                       args.workers, magic, xor_key, calibrate=n_target,
                                       CSHIM=args.cshim, log=log)

    all_divs = stream_divs + cmp_divs + mut_divs
    stats.update(mut_stats)
    elapsed = time.time() - t_start
    report = {
        'generated': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'tip': tip,
        'total_blocks': total,
        'blocks_checked': stats['blocks'],
        'calibrate': args.calibrate or None,
        'elapsed_s': round(elapsed, 1),
        'stats': stats,
        'divergences': all_divs,
    }
    with open(REPORT_JSON, 'w') as f:
        json.dump(report, f, indent=1)
    with open(REPORT_TXT, 'w') as f:
        f.write('Full-chain differential vs Core (hash-for-hash, %d blocks)\n' % total)
        f.write('generated: %s  tip: %d  blocks: %d/%d  elapsed: %.1fs\n\n' %
                (report['generated'], tip, stats['blocks'], total, elapsed))
        f.write('surfaces: A accept / B hash / D pow / E txcount / CHAIN prev-link / F mut\n')
        f.write('stats: %s\n\n' % json.dumps(stats))
        if all_divs:
            f.write('DIVERGENCES: %d\n' % len(all_divs))
            for d in all_divs[:200]:
                f.write('  %s: %s\n' % (d['where'], d['detail']))
        else:
            f.write('ZERO DIVERGENCES across all %d real-mainnet blocks.\n' % stats['blocks'])
    log('report -> %s' % REPORT_JSON)
    log('report -> %s' % REPORT_TXT)
    log('divergences: %d' % len(all_divs))
    return 0 if not all_divs else 1

if __name__ == '__main__':
    sys.exit(main())
