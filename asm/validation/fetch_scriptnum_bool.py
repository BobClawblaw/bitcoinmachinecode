#!/usr/bin/env python3
"""fetch_scriptnum_bool.py -- fixtures for LOG.md incident #28: the numeric
opcodes' boolean results carried the OPERAND's upper bits.

WHAT BROKE. bitcoin_interp.asm's `.mono_common` / `.bin_common` computed every
boolean result with `SETcc r14b` (or `SETcc r15b`) while r14/r15 still held the
DECODED 64-BIT OPERAND. SETcc writes only the low 8 bits, so the operand's
upper 56 bits survived into what got pushed. For values 0..255 the answer came
out right by accident; the moment an operand reached 256 -- or went negative --
it did not.

Eleven opcodes were affected: OP_NOT, OP_0NOTEQUAL, OP_BOOLAND, OP_BOOLOR,
OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN, OP_GREATERTHAN,
OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL. (OP_WITHIN uses the same SETcc
shape but ANDs against a register that WAS zeroed first, which masks the
result back down to 0/1 -- correct, but only by construction; it is swept here
too so that stays pinned.)

Emitted fixtures (tests/scriptnum_bool_vec.h):

  1. THE REAL BLOCK. Mainnet block 792,980, transaction
     c85311c12c70351948bf15c76963c9e5ae54831733bfa267692888b780a70876 -- a
     P2WSH 1-of-7 built from CHECKSIG+OP_ADD rather than CHECKMULTISIG, whose
     tail is `OP_IF <400000> OP_CHECKLOCKTIMEVERIFY OP_0NOTEQUAL OP_ELSE OP_0
     OP_ENDIF OP_ADD OP_2 OP_EQUAL`. 400000 is 0x061A80; OP_0NOTEQUAL returned
     0x061A01 = 400129 instead of 1, so OP_ADD gave 400130 and the OP_2
     OP_EQUAL was false. The live replay stopped here with
     "REJECT h=792980 tx=2941: p2wsh script verification failed".
     Its prevout and its block's coinbase come along (the block-wide entry
     point requires txs[0] to be a coinbase), plus the byte offset of one
     signature byte so the test can also prove signature checking is really
     running rather than blanket-accepting.

  2. A SWEEP of pure-arithmetic P2WSH scripts across the 255/256 and 0/-1
     boundaries, EVERY ONE of them carrying Bitcoin Core's own verdict, taken
     here from Core's VerifyScript (validation/core_verify_oracle.cpp
     TAPVERIFY, i.e. the real consensus flag set at a modern height). The
     sweep runs in BOTH directions on purpose: roughly half of these are
     scripts Core ACCEPTS and this node rejected, and roughly half are scripts
     Core REJECTS and this node ACCEPTED -- e.g. `<256> OP_NOT` (Core pushes
     0/false; we pushed 256/true) and `<256> <512> OP_NUMEQUAL` (Core pushes
     0; we pushed 256). A fix that merely made block 792,980 pass would leave
     the false-accept half open, which is the worse half.

     Only the SCRIPT hex and Core's verdict are baked. The test builds the
     synthetic spending transaction itself, byte-for-byte the same way this
     file does -- see SYNTH_* below, which is emitted into the header so the
     two constructions cannot drift.

Usage:
  g++ -std=c++20 -I../src -I./src -I../src/univalue/include \\
      -o /tmp/core_verify_oracle validation/core_verify_oracle.cpp \\
      ./lib/libbitcoin_common.a ./lib/libbitcoin_consensus.a ./lib/libbitcoin_util.a \\
      ./lib/libbitcoin_crypto.a ./lib/libbitcoin_clientversion.a \\
      ./src/univalue/libunivalue.a ./src/secp256k1/lib/libsecp256k1.a \\
      -levent -levent_pthreads          # from /storage/bitcoin-core-source/build
  python3 validation/fetch_scriptnum_bool.py > tests/scriptnum_bool_vec.h
"""
import hashlib, os, subprocess, sys

CLI = ("/storage/bitcoin-core-source/build/bin/bitcoin-cli"
       " -conf=/storage/core-oracle/bitcoin.conf"
       " -datadir=/storage/core-oracle").split()
ORACLE = os.environ.get("CORE_VERIFY_ORACLE", "/tmp/core_verify_oracle")

HEIGHT = 792980
TXID = "c85311c12c70351948bf15c76963c9e5ae54831733bfa267692888b780a70876"

# --------------------------------------------------------------- synthetic tx
# A one-input, one-output v2 transaction spending a native P2WSH whose
# witnessScript is the vector under test and whose initial witness stack is
# EMPTY (every operand is pushed by the script itself). Kept deliberately
# boring: sequence 0xffffffff and nLockTime 0, so nothing but the arithmetic
# can decide the verdict.
SYNTH_PREV_TXID = bytes(range(32))            # wire order, fabricated
SYNTH_PREV_N = 0
SYNTH_VALUE = 100000
SYNTH_OUT_VALUE = 90000
SYNTH_OUT_SPK = bytes.fromhex("001484194b5254928d55a25222c8af38aa24fed5c415")
SYNTH_SEQ = 0xffffffff
SYNTH_LOCKTIME = 0


def rpc(*a):
    r = subprocess.run(CLI + list(a), capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("rpc failed: %s: %s" % (a, r.stderr.strip()))
    return r.stdout.strip()


_oracle = None
def oracle(line):
    global _oracle
    if _oracle is None:
        if not os.path.exists(ORACLE):
            sys.exit("core oracle not built at %s (see this file's header)" % ORACLE)
        _oracle = subprocess.Popen([ORACLE], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, text=True, bufsize=1)
    _oracle.stdin.write(line + "\n"); _oracle.stdin.flush()
    return _oracle.stdout.readline().split()


def core_verdict(txhex, prevs):
    """prevs = [(amount, spk_hex)]. TAPVERIFY runs Core's VerifyScript for
    input 0 with the real consensus flag set at a modern height."""
    args = " ".join("%d %s" % (a, s) for a, s in prevs)
    r = oracle("TAPVERIFY 0 %s %d %s" % (txhex, len(prevs), args))
    if r[0] != "OK":
        sys.exit("oracle: %s" % r)
    return int(r[1]), " ".join(r[3:])


# ------------------------------------------------------------ tx (de)coding
def rd_cs(b, i):
    v = b[i]; i += 1
    if v < 0xfd:  return v, i
    if v == 0xfd: return int.from_bytes(b[i:i+2], "little"), i + 2
    if v == 0xfe: return int.from_bytes(b[i:i+4], "little"), i + 4
    return int.from_bytes(b[i:i+8], "little"), i + 8


def wr_cs(v):
    if v < 0xfd:        return bytes([v])
    if v <= 0xffff:     return b"\xfd" + v.to_bytes(2, "little")
    if v <= 0xffffffff: return b"\xfe" + v.to_bytes(4, "little")
    return b"\xff" + v.to_bytes(8, "little")


def witness_item_offsets(txhex):
    """[(off,len)] of input 0's witness items, as byte offsets into the raw tx."""
    b = bytes.fromhex(txhex)
    if not (b[4] == 0x00 and b[5] == 0x01):
        return []
    i = 6
    nin, i = rd_cs(b, i)
    for _ in range(nin):
        i += 36
        sl, i = rd_cs(b, i)
        i += sl + 4
    nout, i = rd_cs(b, i)
    for _ in range(nout):
        i += 8
        sl, i = rd_cs(b, i)
        i += sl
    out = []
    n, i = rd_cs(b, i)
    for _ in range(n):
        il, i = rd_cs(b, i)
        out.append((i, il)); i += il
    return out


def synth_tx(script):
    """The vector's spending transaction. MUST match the C test's builder."""
    spk = b"\x00\x20" + hashlib.sha256(script).digest()
    t = b"\x02\x00\x00\x00" + b"\x00\x01"
    t += b"\x01" + SYNTH_PREV_TXID + SYNTH_PREV_N.to_bytes(4, "little")
    t += b"\x00" + SYNTH_SEQ.to_bytes(4, "little")
    t += b"\x01" + SYNTH_OUT_VALUE.to_bytes(8, "little")
    t += wr_cs(len(SYNTH_OUT_SPK)) + SYNTH_OUT_SPK
    t += b"\x01" + wr_cs(len(script)) + script          # one witness item
    t += SYNTH_LOCKTIME.to_bytes(4, "little")
    return t, spk


# ------------------------------------------------------------- script pieces
def snum(v):
    """Core CScriptNum::serialize."""
    if v == 0:
        return b""
    neg = v < 0
    a = -v if neg else v
    o = bytearray()
    while a:
        o.append(a & 0xff); a >>= 8
    if o[-1] & 0x80: o.append(0x80 if neg else 0x00)
    elif neg:        o[-1] |= 0x80
    return bytes(o)


def push(v):
    b = snum(v)
    if not b:                      return b"\x00"          # OP_0
    if len(b) == 1 and 1 <= b[0] <= 16: return bytes([0x50 + b[0]])
    if len(b) == 1 and b[0] == 0x81:    return b"\x4f"      # OP_1NEGATE
    return bytes([len(b)]) + b


OP_1, OP_0, OP_EQUAL = b"\x51", b"\x00", b"\x87"
UNARY = {"NOT": 0x91, "0NOTEQUAL": 0x92}
BINARY = {"BOOLAND": 0x9a, "BOOLOR": 0x9b, "NUMEQUAL": 0x9c, "NUMNOTEQUAL": 0x9e,
          "LESSTHAN": 0x9f, "GREATERTHAN": 0xa0, "LESSTHANOREQUAL": 0xa1,
          "GREATERTHANOREQUAL": 0xa2,
          # unaffected, swept so a fix here cannot quietly break them
          "ADD": 0x93, "SUB": 0x94, "MIN": 0xa3, "MAX": 0xa4}

# Values chosen around the two boundaries the bug actually straddles: 255/256
# (the first value with a bit above bit 7) and 0/-1 (sign extension).
V = [0, 1, 2, 16, 127, 128, 255, 256, 257, 1000, 65535, 65536, 400000,
     2147483647, -1, -2, -128, -255, -256, -1000, -2147483647]
W = [0, 1, 255, 256, -1, -256, 1000]

# Three tails. The bare tail asks only "is the pushed value truthy" -- which is
# what a real script's final position asks, and where the FALSE ACCEPTS live.
# `OP_1 OP_EQUAL` / `OP_0 OP_EQUAL` compare the pushed BYTES against Core's
# CScriptNum(1).getvch() == {0x01} and CScriptNum(0).getvch() == {}, which pins
# the exact value rather than merely its truthiness.
TAILS = [("bare", b""), ("==1", OP_1 + OP_EQUAL), ("==0", OP_0 + OP_EQUAL)]


def vectors():
    out = []
    for name, op in UNARY.items():
        for v in V:
            for tn, tail in TAILS:
                out.append(("%s %s %s" % (v, name, tn), push(v) + bytes([op]) + tail))
    for name, op in BINARY.items():
        for a in V:
            for b in W:
                for tn, tail in TAILS[:2]:
                    out.append(("%s %s %s %s" % (a, b, name, tn),
                                push(a) + push(b) + bytes([op]) + tail))
    # OP_NUMEQUALVERIFY consumes its result, so it needs something after it.
    # It is the arm where a wrong value is HARDEST to see (VERIFY only casts to
    # bool) and where the false accepts are worst: `<256> <512> NUMEQUALVERIFY`
    # left 256 on the stack, which VERIFY happily accepted.
    for a in V:
        for b in W:
            out.append(("%s %s NUMEQUALVERIFY" % (a, b),
                        push(a) + push(b) + b"\x9d" + OP_1))
    # OP_WITHIN: correct today only because its AND masks the SETcc down.
    for a in V:
        for b in W:
            for c in (0, 256, -256):
                for tn, tail in TAILS[:2]:
                    out.append(("%s %s %s WITHIN %s" % (a, b, c, tn),
                                push(a) + push(b) + push(c) + b"\xa5" + tail))
    seen, uniq = set(), []
    for label, s in out:
        if s in seen or len(s) > 40:
            continue
        seen.add(s); uniq.append((label, s))
    return uniq


def cesc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def main():
    bh = rpc("getblockhash", str(HEIGHT))
    import json
    blk = json.loads(rpc("getblock", bh, "3"))   # verbosity 3: with prevouts
    txs = blk["tx"]
    tx = next(t for t in txs if t["txid"] == TXID)
    idx = txs.index(tx)
    cb = txs[0]["hex"]
    assert len(tx["vin"]) == 1
    vin = tx["vin"][0]
    prev = vin["prevout"]
    amount = int(round(prev["value"] * 100000000))
    spk = prev["scriptPubKey"]["hex"]

    # Core's verdict on the real transaction, and on it with one signature byte
    # broken -- the second is what stops "accept everything" from passing.
    ok, why = core_verdict(tx["hex"], [(amount, spk)])
    if ok != 1:
        sys.exit("Core REJECTS the real mainnet transaction?! %s" % why)
    wits = witness_item_offsets(tx["hex"])
    sig_off, sig_len = wits[7]                    # the one real signature
    assert sig_len == 71, sig_len
    broken = bytearray(bytes.fromhex(tx["hex"]))
    broken[sig_off + 10] ^= 0x01
    bok, bwhy = core_verdict(bytes(broken).hex(), [(amount, spk)])
    if bok != 0:
        sys.exit("Core accepts a corrupted signature?! %s" % bwhy)

    vs = vectors()
    verdicts = []
    for label, s in vs:
        t, sspk = synth_tx(s)
        v, why = core_verdict(t.hex(), [(SYNTH_VALUE, sspk.hex())])
        verdicts.append((label, s, v))

    naccept = sum(1 for _, _, v in verdicts if v)
    w = sys.stdout.write
    w("/* GENERATED by validation/fetch_scriptnum_bool.py -- DO NOT EDIT.\n"
      " * LOG.md incident #28. Every verdict below is Bitcoin Core's own, taken\n"
      " * from Core's VerifyScript at the real consensus flag set (see that\n"
      " * script's header). %d sweep vectors: %d Core ACCEPTS, %d Core REJECTS.\n"
      " */\n" % (len(verdicts), naccept, len(verdicts) - naccept))
    w("#ifndef SCRIPTNUM_BOOL_VEC_H\n#define SCRIPTNUM_BOOL_VEC_H\n\n")

    w("/* ---- the real chain: mainnet block %d, tx index %d ---- */\n" % (HEIGHT, idx))
    w('#define SNB_HEIGHT        %dL\n' % HEIGHT)
    w('#define SNB_BLOCKHASH_RPC "%s"\n' % bh)
    w('#define SNB_TXID          "%s"\n' % TXID)
    w('#define SNB_TX_INDEX      %d\n' % idx)
    w('#define SNB_SIG_BYTE_OFF  %d   /* inside the 71-byte signature */\n' % (sig_off + 10))
    w('#define SNB_PREV_TXID     "%s"\n' % vin["txid"])
    w('#define SNB_PREV_N        %d\n' % vin["vout"])
    w('#define SNB_PREV_VALUE    %dULL\n' % amount)
    w('#define SNB_PREV_SPK      "%s"\n' % spk)
    w('#define SNB_TX_HEX        "%s"\n' % tx["hex"])
    w('#define SNB_COINBASE_HEX  "%s"\n\n' % cb)

    w("/* ---- the synthetic spending transaction the sweep vectors ride in.\n"
      " * The C test rebuilds this byte-for-byte; these constants exist so the\n"
      " * two builders cannot drift apart. ---- */\n")
    w('#define SNB_SYNTH_PREV_TXID_HEX "%s"\n' % SYNTH_PREV_TXID.hex())
    w('#define SNB_SYNTH_PREV_N        %d\n' % SYNTH_PREV_N)
    w('#define SNB_SYNTH_VALUE         %dULL\n' % SYNTH_VALUE)
    w('#define SNB_SYNTH_OUT_VALUE     %dULL\n' % SYNTH_OUT_VALUE)
    w('#define SNB_SYNTH_OUT_SPK_HEX   "%s"\n' % SYNTH_OUT_SPK.hex())
    w('#define SNB_SYNTH_SEQ           0x%08xU\n' % SYNTH_SEQ)
    w('#define SNB_SYNTH_LOCKTIME      %dU\n\n' % SYNTH_LOCKTIME)

    w("typedef struct { const char* label; const char* script_hex; int core_ok; }\n"
      "        snb_vec_t;\n")
    w("static const snb_vec_t SNB_VECS[] = {\n")
    for label, s, v in verdicts:
        w('    { "%s", "%s", %d },\n' % (cesc(label), s.hex(), v))
    w("};\n")
    w("#define SNB_NVEC ((int)(sizeof SNB_VECS / sizeof SNB_VECS[0]))\n\n")
    w("#endif\n")


if __name__ == "__main__":
    main()
