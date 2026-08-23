#!/usr/bin/env python3
"""fetch_taproot_arena.py -- generate tests/taproot_arena_vec.h.

PERF_SCOPE.md section 14.7 names the fixture this produces:

    "The block that a wrong shared arena would break first is one where two
     transactions with DIFFERENT input counts verify concurrently; a fixture
     with that shape specifically, not just 'a busy block'."

Taproot inputs are now verified across the worker pool, reading one per-BLOCK
arena of BIP341 aggregate-sighash data with a per-transaction descriptor
(offsets + nin). Every way of getting that wrong -- a stale descriptor index,
a shared cursor, a worker rebuilding into the arena, an off-by-one in the
packed scriptPubKey array -- shows up as one transaction hashing another
transaction's `nin` or bytes. Transactions that all have the SAME input count
hide most of those: the arrays are the same size, so a wrong base offset can
still land on a plausibly-shaped record. Different input counts do not.

So this picks REAL taproot-bearing transactions from one real mainnet block
above height 800,000, deliberately spanning as many distinct input counts as
the block offers, and emits them with their real prevouts. The test
(tests/test_taproot_parallel_arena.c) interleaves them largest-against-
smallest, replicates the set until there is enough work to occupy the whole
pool, and requires every copy to verify.

Everything comes from the scratch Core oracle at /storage/core-oracle -- the
transactions are ones Core accepted into its chain, so ACCEPT is Core's
verdict for every one of them. The archive is not used: it is
witness-stripped above height 481,824 and would carry no signatures.

Usage:
    python3 validation/fetch_taproot_arena.py > tests/taproot_arena_vec.h
"""
import json, subprocess, sys

CLI = ("/storage/bitcoin-core-source/build/bin/bitcoin-cli"
       " -conf=/storage/core-oracle/bitcoin.conf"
       " -datadir=/storage/core-oracle").split()

HEIGHT = 825000
# How many transactions to keep per distinct input count. More than one keeps
# the fixture from being a single lucky transaction per shape.
PER_SHAPE = 2
MAX_NIN = 40          # keep the header small; the shape variety is the point


def rpc(*a):
    r = subprocess.run(CLI + list(a), capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("rpc failed: %s: %s" % (a, r.stderr.strip()))
    return r.stdout.strip()


def sat(v):
    return int(round(float(v) * 1e8))


# ------------------------------------------------------------- tx byte walking
def rd_cs(b, i):
    v = b[i]; i += 1
    if v < 0xfd:  return v, i
    if v == 0xfd: return int.from_bytes(b[i:i+2], 'little'), i+2
    if v == 0xfe: return int.from_bytes(b[i:i+4], 'little'), i+4
    return int.from_bytes(b[i:i+8], 'little'), i+8


def walk(b):
    """-> (nin, [[(off,len)] per input]) for a raw tx."""
    i = 4
    wit = b[i] == 0x00 and b[i+1] == 0x01
    if wit: i += 2
    nin, i = rd_cs(b, i)
    for _ in range(nin):
        i += 36
        sl, i = rd_cs(b, i); i += sl + 4
    nout, i = rd_cs(b, i)
    for _ in range(nout):
        i += 8
        sl, i = rd_cs(b, i); i += sl
    stacks = [[] for _ in range(nin)]
    if wit:
        for k in range(nin):
            ni, i = rd_cs(b, i)
            for _ in range(ni):
                il, i = rd_cs(b, i)
                stacks[k].append((i, il))
                i += il
    return nin, stacks


def corrupt_offset(b, stack):
    """Byte offset inside the tx whose flip is an unconditional reject:
    key-path -> the Schnorr signature; script-path -> the control block's
    internal pubkey (breaks the BIP341 Merkle commitment, which every
    script-path spend must satisfy regardless of leaf version or script)."""
    if not stack: return None
    annex = len(stack) >= 2 and stack[-1][1] >= 1 and b[stack[-1][0]] == 0x50
    eff = len(stack) - (1 if annex else 0)
    if eff == 1:
        return stack[0][0] if stack[0][1] >= 1 else None
    ci = eff - 1
    return stack[ci][0] + 1 if stack[ci][1] >= 33 else None


bh = rpc("getblockhash", str(HEIGHT))
blk = json.loads(rpc("getblock", bh, "3"))
raw = bytes.fromhex(rpc("getblock", bh, "0"))
header_hex = raw[:80].hex()

coinbase_hex = blk['tx'][0]['hex']

by_shape = {}
prevs = {}
for tx in blk['tx'][1:]:
    nin = len(tx['vin'])
    if nin > MAX_NIN:
        continue
    ntap = sum(1 for v in tx['vin']
               if v['prevout']['scriptPubKey'].get('type') == 'witness_v1_taproot')
    if ntap == 0:
        continue
    if len(by_shape.get(nin, [])) >= PER_SHAPE:
        continue
    b = bytes.fromhex(tx['hex'])
    n2, stacks = walk(b)
    assert n2 == nin, (n2, nin)
    # corrupt the FIRST taproot input
    ti = next(i for i, v in enumerate(tx['vin'])
              if v['prevout']['scriptPubKey'].get('type') == 'witness_v1_taproot')
    co = corrupt_offset(b, stacks[ti])
    if co is None:
        continue
    by_shape.setdefault(nin, []).append((tx, b, ntap, co))
    for v in tx['vin']:
        po = v['prevout']
        prevs[(v['txid'], v['vout'])] = (sat(po['value']), po['scriptPubKey']['hex'])

# One transaction with a WITNESSLESS input, kept deliberately. The test uses it
# to reach tapagg_build's ">= 0xfd prevout script" refusal: BIP341's aggregate
# scriptPubKey array has a one-byte length field, so any input's prevout script
# of 253 bytes or more makes the whole transaction unrepresentable. Growing a
# WITNESSED input's script instead would trip Phase 1's "unexpected witness on a
# non-witness script" first and never reach the arena. Block 825,000 has exactly
# one such transaction (2 inputs: one taproot, one P2PKH with no witness).
mixed = None
for tx in blk['tx'][1:]:
    nin = len(tx['vin'])
    if nin < 2 or nin > MAX_NIN:
        continue
    if not any(v['prevout']['scriptPubKey'].get('type') == 'witness_v1_taproot'
               for v in tx['vin']):
        continue
    wl = [i for i, v in enumerate(tx['vin']) if not v.get('txinwitness')]
    if not wl:
        continue
    b = bytes.fromhex(tx['hex'])
    n2, stacks = walk(b)
    ti = next(i for i, v in enumerate(tx['vin'])
              if v['prevout']['scriptPubKey'].get('type') == 'witness_v1_taproot')
    co = corrupt_offset(b, stacks[ti])
    if co is None:
        continue
    mixed = (tx, b, sum(1 for v in tx['vin']
                        if v['prevout']['scriptPubKey'].get('type') == 'witness_v1_taproot'),
             co, wl[0])
    for v in tx['vin']:
        po = v['prevout']
        prevs[(v['txid'], v['vout'])] = (sat(po['value']), po['scriptPubKey']['hex'])
    break
assert mixed is not None, "no taproot transaction with a witnessless input in block %d" % HEIGHT

shapes = sorted(by_shape)
chosen = [e for n in shapes for e in by_shape[n]]
assert len(shapes) >= 8, "too few distinct input counts: %r" % shapes
# de-dup: it may already have been picked up by the per-shape scan
mixed_ix = next((i for i, e in enumerate(chosen) if e[0]['txid'] == mixed[0]['txid']), None)
if mixed_ix is None:
    chosen.append(mixed[:4])
    mixed_ix = len(chosen) - 1

w = sys.stdout.write
w("/* taproot_arena_vec.h -- GENERATED by validation/fetch_taproot_arena.py.\n"
  " * Do not edit by hand; regenerate against the scratch Core oracle.\n"
  " *\n"
  " * Real taproot-bearing transactions from mainnet block %d, chosen to\n"
  " * span %d DISTINCT input counts %r -- the shape a wrong shared\n"
  " * per-block taproot arena breaks first (PERF_SCOPE.md section 14.7).\n"
  " * Core accepted every one of them, so ACCEPT is Core's verdict.\n"
  " */\n" % (HEIGHT, len(shapes), shapes))
w("#define TAV_HEIGHT %d\n" % HEIGHT)
w("#define TAV_NSHAPE %d\n" % len(shapes))
w("static const char TAV_BLOCK_HASH[] = \"%s\";\n" % bh)
w("static const char TAV_HEADER_HEX[] = \"%s\";\n" % header_hex)
w("static const char TAV_COINBASE_HEX[] =\n  \"%s\";\n" % coinbase_hex)
w("\n/* nin: total inputs. ntap: how many of them are taproot. corrupt_off: a\n"
  " * byte offset inside tx_hex whose flip is an unconditional reject. */\n")
w("typedef struct { const char* tx_hex; unsigned nin, ntap, corrupt_off; } tav_tx_t;\n")
w("static const tav_tx_t TAV_TX[] = {\n")
for tx, b, ntap, co in chosen:
    w("  { /* %s nin=%d ntap=%d */\n    \"%s\", %d, %d, %d },\n"
      % (tx['txid'][:16], len(tx['vin']), ntap, b.hex(), len(tx['vin']), ntap, co))
w("};\n#define TAV_NTX (sizeof TAV_TX / sizeof TAV_TX[0])\n")
w("/* A transaction with one taproot input and one WITNESSLESS input, and that\n"
  " * input's 0-based position. Growing its prevout script past 252 bytes is how\n"
  " * the test reaches the aggregate array's one-byte length limit without\n"
  " * tripping Phase 1's unexpected-witness check first. */\n")
w("#define TAV_MIXED_TX %d\n#define TAV_MIXED_IN %d\n\n" % (mixed_ix, mixed[4]))
w("typedef struct { const char* txid_hex; unsigned index; unsigned long long value; const char* spk_hex; } tav_prev_t;\n")
w("static const tav_prev_t TAV_PREV[] = {\n")
for (txid, idx), (val, spk) in sorted(prevs.items()):
    w("  { \"%s\", %d, %dULL, \"%s\" },\n" % (txid, idx, val, spk))
w("};\n#define TAV_NPREV (sizeof TAV_PREV / sizeof TAV_PREV[0])\n")

sys.stderr.write("block %d: %d tx over %d distinct input counts %r, %d prevouts\n"
                 % (HEIGHT, len(chosen), len(shapes), shapes, len(prevs)))
