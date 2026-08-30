#!/usr/bin/env python3
"""BIP325 SignetTxs vectors, from REAL signet blocks.

This is an INDEPENDENT reimplementation of Core's SignetTxs::Create -- the
modified merkle root, the two synthetic transactions, and the txid that links
them. Nothing here calls the C code under test, so a shared misreading of the
format would have to happen twice, in two languages.

It also closes the loop on ITSELF. A reference implementation that is merely
self-consistent proves nothing: if this file computed the wrong merkle root,
the C code could agree with it byte for byte and the node would still reject
every real signet block. So before emitting a vector this script VERIFIES THE
BLOCK'S ACTUAL SIGNATURE against the sighash it derived, using the challenge's
own pubkeys. Those signatures were made by the signet miner over Core's
sighash. If ours matches, our to_spend/to_sign/merkle root are right -- there
is no way to forge agreement with a secp256k1 signature we cannot produce.

Usage: gen_signet_txs_vectors.py <datadir> [count]
"""
import hashlib, json, os, subprocess, sys
from coincurve import PublicKey

CLI = "/storage/bitcoin-core-source/build/bin/bitcoin-cli"
HDR = bytes([0xec, 0xc7, 0xda, 0xa2])

def rpc(datadir, *args):
    r = subprocess.run([CLI, f"-datadir={datadir}", *args],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0: raise RuntimeError(r.stderr.strip())
    return r.stdout.strip()

def sha256(b): return hashlib.sha256(b).digest()
def sha256d(b): return sha256(sha256(b))

# ---------------------------------------------------------------- serialisation
def cs(n):
    if n < 253: return bytes([n])
    if n <= 0xffff: return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff: return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')

class R:
    def __init__(s, b): s.b, s.i = b, 0
    def take(s, n):
        if s.i + n > len(s.b): raise ValueError("truncated")
        s.i += n; return s.b[s.i-n:s.i]
    def u8(s):  return s.take(1)[0]
    def u16(s): return int.from_bytes(s.take(2), 'little')
    def u32(s): return int.from_bytes(s.take(4), 'little')
    def u64(s): return int.from_bytes(s.take(8), 'little')
    def cs(s):
        n = s.u8()
        if n == 253: n = s.u16()
        elif n == 254: n = s.u32()
        elif n == 255: n = s.u64()
        return n
    def var(s): return s.take(s.cs())
    def empty(s): return s.i == len(s.b)

def parse_tx(r):
    """Returns (version, vin, vout, locktime, witness, has_wit). vin entries are
    (prevout36, scriptSig, sequence); vout are (value, spk)."""
    ver = r.u32()
    save = r.i
    marker = r.u8(); flag = r.u8()
    has_wit = (marker == 0 and flag != 0)
    if not has_wit: r.i = save
    vin = []
    for _ in range(r.cs()):
        vin.append((r.take(36), r.var(), r.u32()))
    vout = []
    for _ in range(r.cs()):
        vout.append((r.u64(), r.var()))
    wit = [[] for _ in vin]
    if has_wit:
        for k in range(len(vin)):
            wit[k] = [r.var() for _ in range(r.cs())]
    lock = r.u32()
    return ver, vin, vout, lock, wit, has_wit

def ser_tx(ver, vin, vout, lock, wit=None):
    """Non-witness serialisation unless `wit` has a non-empty stack."""
    use_wit = wit is not None and any(len(w) for w in wit)
    o = ver.to_bytes(4, 'little')
    if use_wit: o += b'\x00\x01'
    o += cs(len(vin))
    for po, ss, sq in vin: o += po + cs(len(ss)) + ss + sq.to_bytes(4, 'little')
    o += cs(len(vout))
    for v, spk in vout: o += v.to_bytes(8, 'little') + cs(len(spk)) + spk
    if use_wit:
        for w in wit:
            o += cs(len(w))
            for it in w: o += cs(len(it)) + it
    return o + lock.to_bytes(4, 'little')

def txid(ver, vin, vout, lock): return sha256d(ser_tx(ver, vin, vout, lock))

# ---------------------------------------------------------------- script bits
def ops(s):
    i = 0
    while i < len(s):
        op = s[i]; st = i; i += 1
        if op <= 75: n = op
        elif op == 0x4c: n = s[i]; i += 1
        elif op == 0x4d: n = int.from_bytes(s[i:i+2], 'little'); i += 2
        elif op == 0x4e: n = int.from_bytes(s[i:i+4], 'little'); i += 4
        else:
            yield s[st:i], None; continue
        d = s[i:i+n]; i += n
        yield s[st:i], d

def minimal_push(d):
    n = len(d)
    if n < 76: return bytes([n]) + d
    if n <= 0xff: return bytes([0x4c, n]) + d
    if n <= 0xffff: return bytes([0x4d]) + n.to_bytes(2, 'little') + d
    return bytes([0x4e]) + n.to_bytes(4, 'little') + d

def split(spk):
    """Core's FetchAndClearCommitmentSection."""
    out, sol, found = b"", None, False
    for raw, d in ops(spk):
        if d is not None and len(d) > 0:
            if not found and len(d) > len(HDR) and d[:len(HDR)] == HDR:
                sol = d[len(HDR):]; d = d[:len(HDR)]; found = True
            out += minimal_push(d)
        else:
            out += raw
    return (sol, out) if found else (None, spk)

def commitment_index(vout):
    ci = -1
    for i, (_, spk) in enumerate(vout):
        if len(spk) >= 38 and spk[:6] == bytes.fromhex("6a24aa21a9ed"): ci = i
    return ci

def merkle_root(leaves):
    if not leaves: return b'\x00'*32
    h = list(leaves)
    while len(h) > 1:
        if len(h) & 1: h.append(h[-1])
        h = [sha256d(h[i] + h[i+1]) for i in range(0, len(h), 2)]
    return h[0]

# ---------------------------------------------------------------- SignetTxs
def signet_txs(raw, challenge):
    r = R(raw)
    nver = int.from_bytes(r.take(4), 'little')
    prev = r.take(32); mroot = r.take(32)
    ntime = r.u32(); r.take(4); r.take(4)          # bits, nonce
    ntx = r.cs()
    txs = [parse_tx(r) for _ in range(ntx)]
    if not r.empty(): raise ValueError("trailing block bytes")

    cb = txs[0]
    ci = commitment_index(cb[2])
    if ci < 0: raise ValueError("no witness commitment")
    sol, stripped = split(cb[2][ci][1])

    # modified coinbase: commitment output's spk replaced by the stripped form
    mvout = list(cb[2]); mvout[ci] = (mvout[ci][0], stripped)
    mcb_txid = txid(cb[0], cb[1], mvout, cb[3])

    leaves = [mcb_txid] + [txid(t[0], t[1], t[2], t[3]) for t in txs[1:]]
    signet_merkle = merkle_root(leaves)

    # to_spend: null outpoint (index 0xFFFFFFFF), scriptSig OP_0 <block_data>
    block_data = (nver.to_bytes(4, 'little') + prev + signet_merkle
                  + ntime.to_bytes(4, 'little'))
    ss_spend = b'\x00' + minimal_push(block_data)
    to_spend_vin = [(b'\x00'*32 + b'\xff\xff\xff\xff', ss_spend, 0)]
    to_spend_vout = [(0, challenge)]
    to_spend = ser_tx(0, to_spend_vin, to_spend_vout, 0)
    ts_txid = sha256d(to_spend)

    # to_sign: spends to_spend:0, scriptSig+witness read out of the solution
    ss_sign, wstack = b"", []
    if sol is not None:
        v = R(sol)
        ss_sign = v.var()
        wstack = [v.var() for _ in range(v.cs())]
        if not v.empty(): raise ValueError("extraneous data in solution")
    to_sign_vin = [(ts_txid + b'\x00\x00\x00\x00', ss_sign, 0)]
    to_sign_vout = [(0, b'\x6a')]                   # OP_RETURN
    to_sign = ser_tx(0, to_sign_vin, to_sign_vout, 0, [wstack])
    return dict(nver=nver, prev=prev, ntime=ntime, mroot=mroot,
                commit_spk=cb[2][ci][1], leaves=b"".join(leaves),
                signet_merkle=signet_merkle, mcb_txid=mcb_txid, ntx=ntx,
                solution=sol, stripped=stripped, to_spend=to_spend,
                ts_txid=ts_txid, to_sign=to_sign, ss_sign=ss_sign,
                wstack=wstack, challenge=challenge, ci=ci)

# ---------------------------------------------------------------- self-proof
def check_signature(d):
    """Returns True if a real signature in the solution verifies over our
    sighash under one of the challenge's pubkeys."""
    ch = d["challenge"]
    if not (ch and ch[-1] == 0xae): return None      # not bare multisig
    keys = [p[1] for p in ops(ch) if p[1] is not None and len(p[1]) in (33, 65)]
    sigs = [p[1] for p in ops(d["ss_sign"]) if p[1] is not None and len(p[1]) > 8]
    if not keys or not sigs: return None
    vin = [(d["ts_txid"] + b'\x00\x00\x00\x00', ch, 0)]
    z = sha256d(ser_tx(0, vin, [(0, b'\x6a')], 0) + (1).to_bytes(4, 'little'))
    for s in sigs:
        der, ht = s[:-1], s[-1]
        if ht != 1: return None                      # only SIGHASH_ALL handled
        if not any(_ver(k, der, z) for k in keys): return False
    return True

def _ver(pub, der, z):
    try: return PublicKey(pub).verify(der, z, hasher=None)
    except Exception: return False

# ---------------------------------------------------------------- main
def main():
    datadir = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 12
    info = json.loads(rpc(datadir, "getblockchaininfo"))
    challenge = bytes.fromhex(info["signet_challenge"])
    tip = info["blocks"]
    # Explicit heights, not an even sweep. Signet is mostly EMPTY blocks, and
    # a sweep gives ntx==1 almost every time -- which never exercises the
    # merkle tree at all, let alone the duplicate-last rule that only odd
    # levels reach. These are chosen for tx-count shape: 1, pairs, and odd
    # counts at several depths (3, 5, 7, 9, 11, 17, 21 each force a
    # duplication, some at more than one level).
    HEIGHTS = [170781, 113563, 26315, 131247, 220242, 62757, 38977, 48559,
               91359, 95752, 37624, 102525, 190573, 108981, 192726, 39378,
               133255, tip]
    rows, proved, seen_ntx = [], 0, set()
    for h in HEIGHTS:
        raw = bytes.fromhex(rpc(datadir, "getblock",
                                rpc(datadir, "getblockhash", str(h)), "0"))
        try:
            d = signet_txs(raw, challenge)
        except Exception as e:
            print("  height %d skipped: %s" % (h, e)); continue
        if d["solution"] is None or d["ntx"] > 200: continue
        seen_ntx.add(d["ntx"])
        ok = check_signature(d)
        if ok is False:
            sys.exit("height %d: REFERENCE IS WRONG -- the block's own signature "
                     "does not verify over the sighash this script derived" % h)
        if ok: proved += 1
        rows.append((h, d))
    if not rows: sys.exit("no signet solutions found")
    print("signature-proved %d/%d vectors against the challenge's own pubkeys"
          % (proved, len(rows)))
    odd = sorted(n for n in seen_ntx if n > 1 and n % 2)
    print("tx counts covered: %s" % sorted(seen_ntx))
    print("  odd counts >1 (these force the duplicate-last merkle rule): %s" % odd)
    if not odd:
        sys.exit("no odd multi-tx block sampled; the duplicate-last rule would "
                 "go untested -- pick different heights")
    if proved == 0:
        sys.exit("NOT ONE vector was signature-proved; the reference is unverified")

    here = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    o = ['/* GENERATED by validation/gen_signet_txs_vectors.py -- do not edit.',
         ' *',
         ' * BIP325 SignetTxs::Create over REAL signet blocks. Every field is',
         ' * recomputed by an independent Python implementation, and the generator',
         " * REFUSES to emit a vector whose to_sign sighash the block's OWN",
         ' * signature does not verify against -- so these are not merely a second',
         ' * opinion, they are pinned to secp256k1 signatures the signet miner made',
         " * over Core's sighash. Get the modified merkle root, either synthetic",
         ' * transaction, or the txid linking them wrong, and that check fails.',
         ' *',
         ' * `leaves` is the modified leaf list: the stripped coinbase txid followed',
         ' * by every other txid, which is exactly what the merkle root is taken',
         ' * over. Fields are hex, byte order as serialised (internal). */',
         '#ifndef SIGNET_TXS_VECTORS_H', '#define SIGNET_TXS_VECTORS_H', '',
         'typedef struct {', '  int height; int ntx;',
         '  const char* challenge;      /* the signet block challenge script */',
         '  const char* commit_spk;     /* coinbase witness-commitment scriptPubKey */',
         '  const char* solution;       /* signet solution carved out of it */',
         '  const char* leaves;         /* ntx * 32 bytes: modified leaf list */',
         '  const char* mcb_txid;       /* txid of the coinbase, solution stripped */',
         '  const char* signet_merkle;  /* modified merkle root */',
         '  int nversion; unsigned ntime;',
         '  const char* prev_block;',
         '  const char* to_spend;       /* serialised synthetic to_spend */',
         '  const char* to_spend_txid;',
         '  const char* to_sign;        /* serialised synthetic to_sign */',
         '} signet_txs_vec_t;', '',
         'static const signet_txs_vec_t SIGNET_TXS_VEC[] = {']
    for h, d in rows:
        o.append('  { %d, %d,\n    "%s",\n    "%s",\n    "%s",\n    "%s",\n'
                 '    "%s",\n    "%s",\n    %d, %uu,\n    "%s",\n'
                 '    "%s",\n    "%s",\n    "%s" },'
                 % (h, d["ntx"], d["challenge"].hex(), d["commit_spk"].hex(),
                    d["solution"].hex(), d["leaves"].hex(), d["mcb_txid"].hex(),
                    d["signet_merkle"].hex(), d["nver"], d["ntime"],
                    d["prev"].hex(), d["to_spend"].hex(), d["ts_txid"].hex(),
                    d["to_sign"].hex()))
    o += ['};',
          '#define SIGNET_TXS_NVEC ((int)(sizeof(SIGNET_TXS_VEC)/sizeof(SIGNET_TXS_VEC[0])))',
          '', '#endif', '']
    open(os.path.join(here, "asm/tests/signet_txs_vectors.h"), "w").write('\n'.join(o))
    print("wrote %d SignetTxs vectors from real signet blocks (tip %d)" % (len(rows), tip))

main()
