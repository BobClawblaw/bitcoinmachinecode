#!/usr/bin/env python3
"""fetch_tapscript_scale.py -- inscription-SCALE tapscript coverage fixtures.

CHAIN_AHEAD_CENSUS.md left exactly one row open after incident #16:

    | ">10 KB tapscript / real inscription" untested at scale | **Still open.**
      No inscription-scale fixture yet ... The single biggest remaining
      untested risk, unchanged. |
    | `tap_leaf_hash` 4 MB leaf cap | Still open ... |

This closes both with REAL mainnet transactions, located by scanning raw
blocks (getblock <hash> 0, parsed here -- verbosity 2 on an inscription block
is hundreds of MB of JSON) for P2TR script-path spends and taking the maxima.

Two output channels, because one fixture is 3.9 MB:

  * INLINE (default output, tests/tapscript_scale_vec.h): every fixture whose
    raw tx is <= TS_INLINE_MAX bytes. Checked in, always runs, no oracle.
  * BLOB (--big <dir>): the two multi-hundred-KB/multi-MB fixtures, written
    as a gitignored text blob. tests/test_tapscript_scale.c runs them when the
    blob is present and prints a loud SKIP (exit 0) when it is not, so the
    checked-in test never fails merely because the oracle is offline.

Also emits reference TapLeaf hashes (computed here, in Python, from BIP341
directly -- an independent implementation, not our asm) for a size sweep
across tap_leaf_hash's real capacity boundary, so the 4 MB cap is measured
rather than assumed.

Usage:
  python3 validation/fetch_tapscript_scale.py > tests/tapscript_scale_vec.h
  python3 validation/fetch_tapscript_scale.py --big tests/fixtures
"""
import hashlib, json, struct, subprocess, sys, os

CLI = ("/storage/bitcoin-core-source/build/bin/bitcoin-cli "
       "-rpcport=8335 -datadir=/storage/core-oracle").split()

TS_INLINE_MAX = 64 * 1024      # raw tx bytes; 42 KB inscription fits, 372 KB does not


def rpc(*a):
    r = subprocess.run(CLI + list(a), capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("rpc failed: %s: %s" % (a, r.stderr.strip()))
    return r.stdout.strip()


# ---------------------------------------------------------------- raw parsing
class R:
    def __init__(self, b): self.b = b; self.i = 0
    def take(self, n):
        v = self.b[self.i:self.i + n]; self.i += n
        if len(v) != n: raise EOFError
        return v
    def u8(self): return self.take(1)[0]
    def u32(self): return struct.unpack('<I', self.take(4))[0]
    def varint(self):
        n = self.u8()
        if n < 0xfd: return n
        if n == 0xfd: return struct.unpack('<H', self.take(2))[0]
        if n == 0xfe: return struct.unpack('<I', self.take(4))[0]
        return struct.unpack('<Q', self.take(8))[0]
    def vbytes(self):
        n = self.varint(); off = self.i; return off, self.take(n)


def parse_tx(raw, base=0):
    """Parse one tx from raw[base:]. Returns (dict, end_offset). Witness item
    offsets are absolute within `raw`, which is what the corruption tests need."""
    r = R(raw); r.i = base
    start = r.i
    r.u32()                                        # version
    segwit = False
    nin = r.varint()
    if nin == 0:
        assert r.u8() == 1
        segwit = True
        nin = r.varint()
    vin = []
    for _ in range(nin):
        ph = r.take(32); pi = r.u32(); _o, ss = r.vbytes(); seq = r.u32()
        vin.append(dict(prev=ph[::-1].hex(), vout=pi, ss=ss, seq=seq, wit=[]))
    nout = r.varint()
    for _ in range(nout):
        r.take(8); r.vbytes()
    if segwit:
        for k in range(nin):
            nw = r.varint()
            vin[k]['wit'] = [r.vbytes() for _ in range(nw)]   # list of (off, bytes)
    r.u32()                                        # locktime
    end = r.i
    return dict(vin=vin, raw=raw[start:end], start=start), end


def txid_of(txraw):
    r = R(txraw)
    ver = r.take(4)
    nin = r.varint(); segwit = False
    if nin == 0:
        r.u8(); segwit = True; nin = r.varint()
    body = r.i
    for _ in range(nin):
        r.take(32); r.u32(); r.vbytes(); r.u32()
    nout = r.varint()
    for _ in range(nout):
        r.take(8); r.vbytes()
    body_end = r.i
    if segwit:
        for _ in range(nin):
            for _ in range(r.varint()): r.vbytes()
    lock = r.take(4)
    def wv(n):
        if n < 0xfd: return bytes([n])
        if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
        if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
        return b'\xff' + struct.pack('<Q', n)
    ser = ver + wv(nin) + txraw[body:body_end] + lock
    return hashlib.sha256(hashlib.sha256(ser).digest()).digest()[::-1].hex()


def block_txs(height):
    raw = bytes.fromhex(rpc("getblock", rpc("getblockhash", str(height)), "0"))
    r = R(raw); r.take(80); n = r.varint()
    out = []; off = r.i
    for _ in range(n):
        t, off = parse_tx(raw, off)
        out.append(t)
    return out


def scriptpath(v):
    """(leaf_off, leaf, ctrl, depth, n_initial) for a P2TR script-path input, else None."""
    if v['ss'] or len(v['wit']) < 2: return None
    items = v['wit']
    if len(items) >= 2 and items[-1][1][:1] == b'\x50':
        items = items[:-1]
        if len(items) < 2: return None
    ctrl = items[-1][1]
    if len(ctrl) < 33 or (len(ctrl) - 33) % 32: return None
    loff, leaf = items[-2]
    return loff, leaf, ctrl, (len(ctrl) - 33) // 32, len(items) - 2


def find_by_txid(height, want):
    for t in block_txs(height):
        if txid_of(t['raw']) == want:
            return t
    raise RuntimeError("txid %s not found in block %d" % (want, height))


def prevouts_of(t):
    out = []
    for v in t['vin']:
        pv = json.loads(rpc("getrawtransaction", v['prev'], "true"))['vout'][v['vout']]
        out.append((v['prev'], v['vout'], int(round(pv['value'] * 1e8)),
                    pv['scriptPubKey']['hex']))
    return out


# --------------------------------------------------------------- the fixtures
# Every txid below was DERIVED by scanning raw blocks for the maximum
# script-path leaf / control-block / witness-item size in its region; each is
# re-derived from block data here (find_by_txid re-hashes the block's txs), so
# a wrong or stale txid is a hard error, never a silently-skipped fixture.
FIXTURES = [
    # name, height, txid, target input, what it proves
    ("tap_leaf_3938182", 774628,
     "0301e0480b374b32851a9462db29dc19fe830a7f7d7a88b81612b9d42099c0ae", 0,
     "3,938,182-byte tapscript leaf (largest single-leaf inscription on mainnet; "
     "94% of a whole block's weight in one input)"),
    ("tap_leaf_371967", 779500,
     "e822e5eb8ef5332de472c9deb9d453fdf8167c9c0397315ab0376aa6a9124266", 0,
     "371,967-byte tapscript leaf -- the exact CHAIN_AHEAD_CENSUS.md maximum"),
    ("tap_leaf_42594", 775000,
     "4cc72b13218183d4a6b13e79ef3e0a73c7987688dd0334866a8398b03e514057", 0,
     "42,594-byte tapscript leaf (the census's own ~775000 evidence txid, "
     "full txid resolved from the block)"),
    ("tap_depth21", 850000,
     "b10c0000004da5a9d1d9b4ae32e09f0b3e62d21a5cce5428d4ad714fb444eb5d", 9,
     "705-byte control block = 21-node merkle path (deepest seen on mainnet), "
     "in a 10-input tx that is also legacy + P2SH + P2WPKH + P2WSH + P2TR key-path"),
    ("tap_12items", 860500,
     "ee8de7f69b6fa8766f8a607c67d674dcbc3e2656f3e5ddbac531860986d7a6dd", 0,
     "12-item script-path witness (10 initial stack items + leaf + control block)"),
]

# tap_leaf_hash capacity sweep. The asm bounds slen at TAP_PREIMG_CAP-70 =
# 4194234 and returns 0 (clean fail, nothing written) above it. MAX_BLOCK_WEIGHT
# is 4,000,000, so a real leaf can never exceed ~3,999,000 -- the last two sizes
# are unreachable-on-chain boundary probes, not chain data.
LEAF_SIZES = [0, 1, 252, 253, 65535, 65536, 371967, 3938182, 3999000, 4194234, 4194235]
LEAF_CAP = 4 * 1024 * 1024 - 70


def filler(n):
    """Deterministic, reproducible in C: b[i] = (uint8_t)(i*167 + 13)."""
    return bytes(((i * 167 + 13) & 0xff) for i in range(n))


def cs(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)


def tagged(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def tapleaf_ref(ver, script):
    return tagged("TapLeaf", bytes([ver]) + cs(len(script)) + script)


def collect():
    got = []
    for name, h, txid, tgt, note in FIXTURES:
        t = find_by_txid(h, txid)
        sp = scriptpath(t['vin'][tgt])
        if sp is None:
            raise RuntimeError("%s: input %d is not a P2TR script-path spend" % (name, tgt))
        loff, leaf, ctrl, depth, ninit = sp
        got.append(dict(name=name, height=h, txid=txid, target=tgt, note=note,
                        raw=t['raw'], leaf_off=loff - t['start'], leaf_len=len(leaf),
                        ctrl_len=len(ctrl), depth=depth, nwit=len(t['vin'][tgt]['wit']),
                        ninit=ninit, prev=prevouts_of(t)))
    return got


def emit_header(got, out):
    w = out.write
    w("/* GENERATED by validation/fetch_tapscript_scale.py from the Core oracle -- do not hand-edit. */\n")
    w("/* Inscription-SCALE tapscript coverage: real mainnet P2TR script-path spends whose\n"
      " * leaf script / control block / witness stack are the largest the chain has ever\n"
      " * carried. Closes the last two open rows of CHAIN_AHEAD_CENSUS.md's Outcome table. */\n")
    w("typedef struct { const char* txid_hex; unsigned index; unsigned long long value; const char* spk_hex; } ts_prevout_t;\n")
    w("typedef struct { const char* name; long height; const char* txid; const char* tx_hex;\n"
      "                 unsigned n_in; const ts_prevout_t* prev; unsigned target;\n"
      "                 unsigned long leaf_off; unsigned long leaf_len; unsigned long ctrl_len;\n"
      "                 unsigned depth; unsigned nwit; unsigned ninit; const char* note; } ts_fixture_t;\n")
    idx = 0
    ents = []
    for f in got:
        if len(f['raw']) > TS_INLINE_MAX:
            continue
        w("static const ts_prevout_t ts_prev_%d[%d] = {\n" % (idx, len(f['prev'])))
        for p in f['prev']:
            w('  { "%s", %d, %dULL, "%s" },\n' % p)
        w("};\n")
        ents.append('  { "%s", %d, "%s", "%s", %d, ts_prev_%d, %d, %luUL, %luUL, %luUL, %u, %u, %u, "%s" },'
                    % (f['name'], f['height'], f['txid'], f['raw'].hex(), len(f['prev']), idx,
                       f['target'], f['leaf_off'], f['leaf_len'], f['ctrl_len'],
                       f['depth'], f['nwit'], f['ninit'], f['note']))
        idx += 1
    w("static const ts_fixture_t TS_FIXTURES[%d] = {\n" % len(ents))
    for e in ents:
        w(e + "\n")
    w("};\n#define TS_N %d\n" % len(ents))
    w("/* Fixtures too large to inline (raw tx > %d B) -- fetched to the gitignored\n"
      " * blob by `fetch_tapscript_scale.py --big tests/fixtures`: */\n" % TS_INLINE_MAX)
    for f in got:
        if len(f['raw']) > TS_INLINE_MAX:
            w("/*   %-18s h=%d leaf=%lu B tx=%d B */\n"
              % (f['name'], f['height'], f['leaf_len'], len(f['raw'])))
    w('#define TS_BIG_BLOB "tapscript_big.txt"\n')

    # ---- tap_leaf_hash capacity sweep ----
    w("\n/* tap_leaf_hash() capacity sweep. script[i] = (uint8_t)(i*167+13); expected\n"
      " * TapLeaf hash computed independently in Python (BIP341 tagged hash), NOT by\n"
      " * our asm. `ok` is what tap_leaf_hash must RETURN: the asm bounds slen at\n"
      " * TAP_PREIMG_CAP-70 = %d and fails cleanly above it. MAX_BLOCK_WEIGHT is\n"
      " * 4,000,000, so a real leaf can never exceed ~3,999,000 bytes -- the last two\n"
      " * rows are unreachable-on-chain boundary probes. */\n" % LEAF_CAP)
    w("typedef struct { unsigned long len; int ok; const char* hash_hex; } ts_leafsize_t;\n")
    w("static const ts_leafsize_t TS_LEAFSIZES[%d] = {\n" % len(LEAF_SIZES))
    for n in LEAF_SIZES:
        ok = 1 if n <= LEAF_CAP else 0
        h = tapleaf_ref(0xc0, filler(n)).hex() if ok else "00" * 32
        w('  { %luUL, %d, "%s" },\n' % (n, ok, h))
    w("};\n#define TS_LEAFSIZE_N %d\n" % len(LEAF_SIZES))


def emit_blob(got, path):
    with open(path, "w") as fh:
        for f in got:
            if len(f['raw']) <= TS_INLINE_MAX:
                continue
            fh.write("FIXTURE %s\n" % f['name'])
            fh.write("HEIGHT %d\n" % f['height'])
            fh.write("TXID %s\n" % f['txid'])
            fh.write("TARGET %d\n" % f['target'])
            fh.write("LEAF %lu %lu\n" % (f['leaf_off'], f['leaf_len']))
            fh.write("CTRL %lu %u\n" % (f['ctrl_len'], f['depth']))
            fh.write("NWIT %u %u\n" % (f['nwit'], f['ninit']))
            fh.write("NOTE %s\n" % f['note'])
            for p in f['prev']:
                fh.write("PREV %s %d %d %s\n" % p)
            fh.write("TX %s\n" % f['raw'].hex())
            fh.write("END\n")


if __name__ == "__main__":
    got = collect()
    for f in got:
        sys.stderr.write("%-18s h=%-7d leaf=%-8d ctrl=%-4d depth=%-3d nwit=%-3d tx=%d B  %s\n"
                         % (f['name'], f['height'], f['leaf_len'], f['ctrl_len'],
                            f['depth'], f['nwit'], len(f['raw']),
                            "INLINE" if len(f['raw']) <= TS_INLINE_MAX else "BLOB"))
    if len(sys.argv) > 2 and sys.argv[1] == "--big":
        os.makedirs(sys.argv[2], exist_ok=True)
        emit_blob(got, os.path.join(sys.argv[2], "tapscript_big.txt"))
        sys.stderr.write("wrote %s\n" % os.path.join(sys.argv[2], "tapscript_big.txt"))
    else:
        emit_header(got, sys.stdout)
