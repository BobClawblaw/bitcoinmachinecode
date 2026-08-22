#!/usr/bin/env python3
"""gen_segwit_txout_vectors.py -- BIP143 sighash vectors that exercise
sw_ser_txout()'s CTxOut serialization, especially outputs whose
scriptPubKey is larger than the 600-byte stack buffer the old code used
(incident #21).

Three families, answering three different questions.

  REAL        -- ordinary mainnet transactions pulled from the Core oracle,
                 driven through segwit_v0_sighash with every hashtype.  These
                 are the EQUIVALENCE half of the proof: the bound fix must not
                 move a single one of these hashes.  Their output
                 scriptPubKeys are tiny, so none of them can trip the old
                 buffer -- which is exactly the point.

  MAINNETBIG  -- real mainnet segwit-v0 spends whose own transaction carries
                 an output scriptPubKey OVER the old 589-byte ceiling.  These
                 were not supposed to exist, and a sparse census says they
                 do not: sampling 481,824..950,000 every 5,000 blocks finds a
                 maximum output scriptPubKey of 105 bytes.  Sample densely and
                 they appear.  Census of exactly this shape (a segwit-v0 --
                 not taproot -- input in a transaction with a >589-byte
                 output):

                   481,824..900,000 step 1,000 (419 blocks)  --  0
                   900,000..946,400 step   100 (464 blocks)  --  1 (927,500)
                   940,000..963,000 step    25 (920 blocks)  --  7

                 Multi-hundred-byte OP_RETURN outputs turn up from ~927,500
                 and become routine past ~946,000, and validating the
                 transaction's P2WPKH input hashes every one of those outputs.
                 Against unmodified main each of these smashes the stack.
                 They are why this is a live bug and not a hardening exercise.

  SYNTH       -- constructed transactions whose outputs carry scriptPubKeys
                 of 0..4000 bytes, including a sweep across the old buffer's
                 exact failure point (589 fits, 590 does not).  Consensus
                 places NO limit on an output's scriptPubKey size -- only
                 relay standardness does -- so these pin the boundary
                 precisely and reach sizes the chain has not produced yet.

The EXPECTED sighash for every vector -- real and synthetic alike -- comes
from Bitcoin Core itself: validation/core_verify_oracle.cpp's BIP143 command
runs Core's own SignatureHash(..., SigVersion::WITNESS_V0).  Nothing here is
checked against our implementation or against a re-reading of the BIP, and
the oracle self-checks against BIP-0143's published worked example before it
is trusted.

Usage (from asm/):
  # build the oracle first -- see validation/diff_tapscript_stack.py's header
  python3 validation/gen_segwit_txout_vectors.py /tmp/core_verify_oracle \\
      > tests/segwit_txout_vec.h
"""
import json, os, subprocess, sys

ORACLE = sys.argv[1] if len(sys.argv) > 1 else "/tmp/core_verify_oracle"
CLI = ("/storage/bitcoin-core-source/build/bin/bitcoin-cli "
       "-conf=/storage/core-oracle/bitcoin.conf -datadir=/storage/core-oracle").split()

SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE = 1, 2, 3
ACP = 0x80


def rpc(*a):
    r = subprocess.run(CLI + list(a), capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("rpc failed: %s: %s" % (a, r.stderr.strip()))
    return r.stdout.strip()


# ---------------------------------------------------------------- tx builder
def cs(n):
    if n < 0xfd:        return bytes([n])
    if n <= 0xffff:     return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff: return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')


def pattern(n):
    """Deterministic scriptPubKey filler.  The C test rebuilds the huge
    vectors from this same rule rather than carrying megabytes of hex."""
    return bytes(((i * 7 + 3) & 0xff) for i in range(n))


def mk_tx(version, ins, outs, locktime, segwit=True):
    """ins: [(txid32_le, vout, scriptSig, sequence)]  outs: [(value, spk)]"""
    b = version.to_bytes(4, 'little')
    if segwit:
        b += b'\x00\x01'
    b += cs(len(ins))
    for (op, vo, ss, seq) in ins:
        b += op + vo.to_bytes(4, 'little') + cs(len(ss)) + ss + seq.to_bytes(4, 'little')
    b += cs(len(outs))
    for (v, spk) in outs:
        b += v.to_bytes(8, 'little') + cs(len(spk)) + spk
    if segwit:
        for _ in ins:
            # one non-empty item per input; the witness never enters BIP143
            b += cs(1) + cs(71) + bytes(71)
    b += locktime.to_bytes(4, 'little')
    return b


def outpoint(seed):
    return bytes(((seed * 31 + i * 13) & 0xff) for i in range(32))


# ------------------------------------------------------------- Core BIP143
def core_bip143(batch):
    """batch: [(tx_bytes, n_in, hashtype, amount, scriptcode_bytes)] -> [hex]"""
    if not os.path.exists(ORACLE):
        sys.exit("core_verify_oracle not built at %s -- see "
                 "validation/diff_tapscript_stack.py's header for the build line"
                 % ORACLE)
    lines = []
    for (tx, n_in, ht, amt, sc) in batch:
        lines.append("BIP143 %d %d %d %s %s"
                     % (n_in, ht, amt, tx.hex(), sc.hex() if sc else "-"))
    lines.append("QUIT")
    p = subprocess.run([ORACLE], input="\n".join(lines) + "\n",
                       capture_output=True, text=True)
    out = [l for l in p.stdout.strip().splitlines() if l.startswith(("OK ", "ERR "))]
    if len(out) != len(batch):
        sys.exit("oracle returned %d lines for %d vectors\nstderr: %s"
                 % (len(out), len(batch), p.stderr[-2000:]))
    res = []
    for l, v in zip(out, batch):
        if not l.startswith("OK "):
            sys.exit("oracle refused a vector: %s" % l)
        res.append(l.split()[1])
    return res


# The oracle must reproduce BIP-0143's own published worked example before any
# of its answers are used.  (Native P2WPKH, input 1, scriptCode
# 76a914...88ac, amount 6 BTC -> c37af311...8cb670.)
BIP143_DOC_TX = bytes.fromhex(
    "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"
    "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57"
    "b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85"
    "c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2"
    "f0167faa815988ac11000000")
BIP143_DOC_SC = bytes.fromhex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac")
BIP143_DOC_EXPECT = "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"

got = core_bip143([(BIP143_DOC_TX, 1, SIGHASH_ALL, 600000000, BIP143_DOC_SC)])[0]
if got != BIP143_DOC_EXPECT:
    sys.exit("oracle self-check FAILED: got %s want %s" % (got, BIP143_DOC_EXPECT))


# ------------------------------------------------------------ synthetic set
# A plausible witness-v0 scriptCode (the implied P2PKH of a P2WPKH spend).
SC = bytes.fromhex("76a914") + bytes(range(20)) + bytes.fromhex("88ac")
SEQ = 0xfffffffe
AMT = 123456789

SYN = []   # (name, tx, n_in, hashtype, amount, scriptcode, note)


def syn(name, tx, n_in, ht, note, amt=AMT, sc=SC):
    SYN.append((name, tx, n_in, ht, amt, sc, note))


IN1 = [(outpoint(1), 0, b'', SEQ)]
IN2 = [(outpoint(1), 0, b'', SEQ), (outpoint(2), 7, b'', 0xffffffff)]

# 1) the boundary sweep.  The old buffer was uint8_t tmp[600] and the record
#    is 8 (value) + compactsize(len) + len, so len 589 is the last that fits
#    (8+3+589 = 600) and 590 is the first that overruns.  Sweep either side of
#    that, plus either side of the 252/253 compactsize step.
for sl in (0, 1, 25, 34, 75, 251, 252, 253, 254, 587, 588, 589, 590, 591,
           592, 600, 700, 1000, 4000):
    syn("sweep_all_%d" % sl,
        mk_tx(2, IN1, [(546, pattern(sl))], 0),
        0, SIGHASH_ALL, "1-out, spk=%d, SIGHASH_ALL (hashOutputs loop)" % sl)

# 2) SIGHASH_SINGLE -- the other call site, which hashes ONE CTxOut directly.
for sl in (589, 590, 700, 4000):
    syn("single_out1_%d" % sl,
        mk_tx(2, IN2, [(1000, bytes.fromhex("0014") + bytes(20)),
                       (2000, pattern(sl))], 0),
        1, SIGHASH_SINGLE, "2-in/2-out, out[1] spk=%d, SIGHASH_SINGLE n_in=1" % sl)

# 3) SIGHASH_SINGLE with n_in >= nout: hashOutputs stays zero (Core does the
#    same for WITNESS_V0 -- the legacy uint256(1) bug is BASE-only).
syn("single_no_matching_out",
    mk_tx(2, IN2, [(1000, pattern(700))], 0),
    1, SIGHASH_SINGLE, "SIGHASH_SINGLE with n_in=1 >= nout=1 -> hashOutputs zero")

# 4) multi-output with several large scriptPubKeys interleaved
syn("multi_out_mixed",
    mk_tx(2, IN2, [(1, pattern(20)), (2, pattern(900)), (3, pattern(34)),
                   (4, pattern(2000)), (5, pattern(0)), (6, pattern(300))], 500),
    0, SIGHASH_ALL, "6 outputs, spk 20/900/34/2000/0/300")

# 5) ANYONECANPAY and NONE variants over a large output
syn("acp_all_700",
    mk_tx(2, IN2, [(1000, pattern(700)), (2000, pattern(30))], 0),
    0, SIGHASH_ALL | ACP, "SIGHASH_ALL|ACP, out[0] spk=700")
syn("acp_single_700",
    mk_tx(2, IN2, [(1000, pattern(30)), (2000, pattern(700))], 0),
    1, SIGHASH_SINGLE | ACP, "SIGHASH_SINGLE|ACP, out[1] spk=700")
syn("none_700",
    mk_tx(2, IN2, [(1000, pattern(700))], 0),
    0, SIGHASH_NONE, "SIGHASH_NONE (hashOutputs zero) with a 700-byte spk")
syn("none_acp_700",
    mk_tx(2, IN2, [(1000, pattern(700))], 0),
    0, SIGHASH_NONE | ACP, "SIGHASH_NONE|ACP with a 700-byte spk")

# 6) many outputs, all just over the boundary -- forces the hashOutputs
#    accumulator well past a single record.
syn("many_out_590",
    mk_tx(2, IN1, [(700 + i, pattern(590)) for i in range(40)], 0),
    0, SIGHASH_ALL, "40 outputs of spk=590 each (~24 KB of CTxOut)")

# 7) a large scriptCode alongside a large output (both length-driven paths)
syn("bigscriptcode_bigout",
    mk_tx(2, IN1, [(1000, pattern(1500))], 0),
    0, SIGHASH_ALL, "spk=1500 with a 3000-byte witnessScript scriptCode",
    sc=pattern(3000))

# ------------------------------------------------------ synthetic SCALE set
# Too big to carry as hex.  The C test rebuilds these from the same rule
# (pattern(n), single input outpoint(1)/vout 0/empty scriptSig/nSequence
# fffffffe, one 71-zero-byte witness item, locktime 0, version 2, value 546)
# and only the Core-computed expected hash is stored.
#
# Why these sizes: MAX_BLOCK_WEIGHT caps any real transaction near 3,999,000
# bytes, and SW_MIDSTATE_CAP is 4 MiB = 4,194,304 -- so the largest CTxOut set
# a valid block can contain still fits, and the fix cannot false-reject.  The
# 3,900,000-byte vector is within 2.5% of that ceiling.
SCALE = []
for sl in (100000, 1000000, 3900000):
    SCALE.append(("scale_all_%d" % sl, sl,
                  mk_tx(2, IN1, [(546, pattern(sl))], 0)))

# ----------------------------------------------------------------- real set
def pick_real():
    """Take real segwit transactions off the chain: a spread of heights, and
    from each block the txs with the most inputs and the most outputs, so the
    corpus covers both aggregate-hash loops at realistic scale."""
    out = []
    for h in (481824, 482000, 500000, 550000, 620000, 700000, 800000, 900000, 949000):
        bh = rpc("getblockhash", str(h))
        blk = json.loads(rpc("getblock", bh, "2"))
        txs = [t for t in blk["tx"][1:]
               if any("txinwitness" in v for v in t["vin"])]
        if not txs:
            continue
        by_in = sorted(txs, key=lambda t: -len(t["vin"]))
        by_out = sorted(txs, key=lambda t: -len(t["vout"]))
        cand = []
        for t in (by_in[0], by_out[0], txs[0]):
            if t["txid"] not in [c["txid"] for c in cand]:
                cand.append(t)
        for t in cand:
            hx = t["hex"]
            if len(hx) // 2 > 12000:      # keep the header a sane size
                continue
            out.append((h, t["txid"], hx, len(t["vin"]), len(t["vout"])))
    return out


# ------------------------------------------------- REAL, and over the bound
# These are the ones that matter most, and they were not supposed to exist.
# A sweep of 481,824..950,000 (step 5,000) finds a maximum output scriptPubKey
# of 105 bytes -- which is what made this look like a synthetic-only shape.
# It is not: past ~953,600 the chain carries segwit-v0 spends whose own
# transaction has a multi-hundred-byte OP_RETURN output, and verifying such an
# input hashes every one of those outputs through sw_ser_txout. Each entry is
# (height, txid, input index, note); the amount and the scriptCode are the
# input's REAL ones, pulled from the spent output, so the vector is the exact
# BIP143 sighash Core computes when it validates that block.
#
# Taproot spends with equally large outputs exist too and are deliberately NOT
# here: BIP341 hashes outputs through bitcoin_taproot_sighash.c, a different
# buffer that incident #13 already moved to the heap. Every entry below was
# checked to spend witness_v0_keyhash, so every one reaches sw_ser_txout.
REAL_BIG = [
    (927500, "98850f2b6eca4919ecb1ebf109e88686383c0ef07fc4e78a5323aadac914b4b1", 0,
     "EARLIEST located: 1-in/1-out P2WPKH spend, 2019-byte OP_RETURN output"),
    (946375, "eb1a83f3576b89cc026b94c2655f6bd3454feb8c6abfb75e984b46e33ff8c5c3", 0,
     "P2WPKH spend, 1007-byte OP_RETURN output"),
    (946700, "07fc513ee83967f6a038c45ba6f858d004b9c60d40fff0b530ff3a6d8fd94583", 0,
     "P2WPKH spend, 1017-byte output"),
    (952224, "49ffed77fea5a3072a6d51d870bc63d8ba7e0643cbb86ec4b826bbfb855c05b8", 0,
     "P2WPKH spend, 1198-byte OP_RETURN output"),
    (952325, "018be3b94aa7270eb4316da316fcdf38f38bb4390a967e610706a7db393c5aa2", 2,
     "4-input P2WPKH spend, 1694-byte output (n_in=2, not 0)"),
    (952975, "8230a8c84264e5e56207c4eeec0a6e64daacafe7891326eeb4560c9736ccde30", 0,
     "P2WPKH spend, 855-byte output"),
    (962625, "56ed5c8390e69df26cc07ec027927697a443429c9ed03c69b8e7b63691e63875", 0,
     "P2WPKH spend, 1647-byte output"),
]


def real_big():
    """Resolve REAL_BIG into vectors carrying the input's true amount and
    BIP143 scriptCode. P2WPKH's scriptCode is the IMPLIED P2PKH script
    (76a914<h160>88ac), not the 22-byte witness program -- incident #11; for
    P2WSH it is the witnessScript, i.e. the last witness item."""
    out = []
    for (h, txid, n_in, note) in REAL_BIG:
        bh = rpc("getblockhash", str(h))
        t = json.loads(rpc("getrawtransaction", txid, "true", bh))
        vin = t["vin"][n_in]
        pv = json.loads(rpc("getrawtransaction", vin["txid"], "true"))["vout"][vin["vout"]]
        spk = bytes.fromhex(pv["scriptPubKey"]["hex"])
        amt = int(round(pv["value"] * 1e8))
        wit = vin.get("txinwitness", [])
        if len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14:
            sc = bytes.fromhex("76a914") + spk[2:] + bytes.fromhex("88ac")
        elif len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20:
            sc = bytes.fromhex(wit[-1])
        else:
            sys.exit("%s input %d is not segwit v0 (spk %s)" % (txid, n_in, spk.hex()))
        biggest = max(len(bytes.fromhex(o["scriptPubKey"]["hex"])) for o in t["vout"])
        for (ht, htname) in ((SIGHASH_ALL, "all"), (SIGHASH_SINGLE, "single")):
            out.append(("mainnetbig_%d_%s_%s" % (h, txid[:8], htname),
                        bytes.fromhex(t["hex"]), n_in, ht, amt, sc,
                        "MAINNET %d %s: %s, max out spk %d B, hashtype 0x%02x"
                        % (h, txid[:16], note, biggest, ht)))
    return out


REAL = []      # (name, tx, n_in, hashtype, amount, scriptcode, note)
for (h, txid, hx, nin, nout) in pick_real():
    tx = bytes.fromhex(hx)
    for (ht, htname) in ((SIGHASH_ALL, "all"), (SIGHASH_NONE, "none"),
                         (SIGHASH_SINGLE, "single"), (SIGHASH_ALL | ACP, "all_acp"),
                         (SIGHASH_SINGLE | ACP, "single_acp")):
        REAL.append(("real_%d_%s_%s" % (h, txid[:8], htname), tx, 0, ht,
                     AMT, SC,
                     "mainnet %d %s (%d in / %d out), hashtype 0x%02x"
                     % (h, txid[:16], nin, nout, ht)))

REAL += real_big()

# ----------------------------------------------------------------- resolve
ALL = SYN + REAL
hashes = core_bip143([(t, n, ht, amt, sc) for (_, t, n, ht, amt, sc, _) in ALL])
scale_hashes = core_bip143([(t, 0, SIGHASH_ALL, AMT, SC) for (_, _, t) in SCALE])

# ----------------------------------------------------------------- emit
w = sys.stdout.write
w("/* GENERATED by validation/gen_segwit_txout_vectors.py -- do not hand-edit.\n"
  " * Expected sighashes come from Bitcoin Core's own SignatureHash(...,\n"
  " * SigVersion::WITNESS_V0) via validation/core_verify_oracle.cpp's BIP143\n"
  " * command, which self-checks against BIP-0143's published worked example.\n"
  " * %d vectors + %d scale vectors. */\n" % (len(ALL), len(SCALE)))
# Transactions are pooled and referenced by index: the real corpus runs each
# tx under five hashtypes, and repeating a 12 KB hex string five times would
# quintuple this file for nothing.
txpool, txidx = [], {}
for (_, tx, _, _, _, _, _) in ALL:
    if tx.hex() not in txidx:
        txidx[tx.hex()] = len(txpool)
        txpool.append(tx.hex())
w("static const char* const SWTO_TXS[] = {\n")
for hx in txpool:
    w('  "%s",\n' % hx)
w("};\n")
w("typedef struct { const char* name; int tx; int n_in;\n"
  "                 unsigned nhashtype; unsigned long long amount;\n"
  "                 const char* sc_hex; const char* sighash_hex;\n"
  "                 const char* note; } swto_vec_t;\n")
w("static const swto_vec_t SWTO_VECS[] = {\n")
for (name, tx, n_in, ht, amt, sc, note), hh in zip(ALL, hashes):
    w('  { "%s", %d, %d, 0x%02x, %dULL,\n    "%s",\n    "%s",\n    "%s" },\n'
      % (name, txidx[tx.hex()], n_in, ht, amt, sc.hex(), hh, note))
w("};\n")
w("#define SWTO_NVEC ((int)(sizeof(SWTO_VECS)/sizeof(SWTO_VECS[0])))\n\n")

w("/* Scale vectors: rebuilt in C from the documented rule rather than carried\n"
  " * as hex.  spk[i] = (i*7+3)&0xff, one input (outpoint pattern below), value\n"
  " * 546, version 2, nSequence fffffffe, locktime 0, one 71-zero-byte witness\n"
  " * item, SIGHASH_ALL, amount %d, scriptCode = the P2WPKH implied P2PKH. */\n"
  % AMT)
w("typedef struct { const char* name; unsigned long spklen;\n"
  "                 const char* sighash_hex; } swto_scale_t;\n")
w("static const swto_scale_t SWTO_SCALE[] = {\n")
for (name, sl, _), hh in zip(SCALE, scale_hashes):
    w('  { "%s", %dUL, "%s" },\n' % (name, sl, hh))
w("};\n")
w("#define SWTO_NSCALE ((int)(sizeof(SWTO_SCALE)/sizeof(SWTO_SCALE[0])))\n")
w('static const char* const SWTO_SCALE_OUTPOINT = "%s";\n' % outpoint(1).hex())
w('static const char* const SWTO_SCALE_SC = "%s";\n' % SC.hex())
w("#define SWTO_SCALE_AMOUNT %dULL\n" % AMT)
