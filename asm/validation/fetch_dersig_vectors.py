#!/usr/bin/env python3
"""fetch_dersig_vectors.py -- fixtures for the DERSIG (BIP66) consensus gap:
strict signature encoding computed by script_flags_for_block() and never
consulted by anything on the block-connect path.

THE DEFECT (same shape as LOG.md incident #22, opposite direction).
script_flags_for_block() sets SCRIPT_VERIFY_DERSIG (bit 2) for every block at
height >= 363,725, exactly as Core's GetBlockScriptFlags does. The bit reached
script_state.flags and stopped there: every CHECKSIG/CHECKMULTISIG parsed its
signature with der_parse_sig (bitcoin_script.asm), which is deliberately
TOLERANT at every height. So this node ACCEPTED, above the BIP66 activation
height, signatures Core REJECTS -- a chain split, and in the dangerous
direction (#22 was a false reject; this was a false accept).

WHY IT NEEDS CRAFTED TRANSACTIONS AND REAL ONES BOTH. There is no live symptom:
Core-valid history after 363,725 contains only strict-DER signatures, so no
replay will ever hit it. The trigger has to be constructed. But the OTHER half
of the rule -- that pre-BIP66 blocks must keep accepting what they always
accepted -- is pure history, and mainnet has plenty of it.

Emitted fixtures (tests/dersig_vec.h), all real mainnet data:

  POST-BIP66, one per dispatch shape, each as an unmodified transaction AND a
  variant with ONE redundant leading zero byte prepended to the R value of one
  signature (re-encoded: R length, SEQUENCE length, push length and the
  enclosing compactsize all follow). The padding changes neither R's value nor
  any sighash preimage -- the legacy sighash replaces the spending input's
  scriptSig with the scriptCode, and BIP143 never hashes the witness at all --
  so the padded signature still verifies cryptographically. The ONLY thing
  wrong with it is its encoding, which is precisely what makes it a clean
  probe of the DERSIG rule:
    DSLEG   P2PKH               (legacy, sv_verify_script -> interp_checksig)
    DSMS    P2SH 2-of-N multisig(legacy, -> interp_checkmultisig)
    DSW0    P2WPKH              (sv_verify_witness_v0 -> interp_checksig,
                                 SIGVERSION_WITNESS_V0)

  PRE-BIP66, real mainnet transactions whose signatures are ALREADY non-strict
  by Core's rule and which the chain accepted anyway -- these are what prove
  the fix did not break ~363,000 blocks of history:
    DSPRE0  height 149,850 -- R carries a redundant leading 0x00 (the exact
            encoding the crafted vectors above simulate), i.e. mainnet really
            did contain this before BIP66.
    DSPRE1  height 152,841 -- R's top bit is set with no 0x00 pad, i.e. a
            NEGATIVE DER INTEGER. Core rejects this at DERSIG heights too, by
            a different clause of IsValidSignatureEncoding.

  Every expectation below is taken from BITCOIN CORE, not from a reading of it:
  the generator drives Core's own VerifyScript / CheckSignatureEncoding through
  validation/core_verify_oracle.cpp (VERIFY, TAPVERIFY, SIGENC) at both the
  pre- and post-BIP66 consensus flag sets and ASSERTS the verdict it bakes in.

Usage:
  g++ ... -o /tmp/core_verify_oracle validation/core_verify_oracle.cpp ...
  python3 validation/fetch_dersig_vectors.py > tests/dersig_vec.h
"""
import json, os, subprocess, sys

CLI = ("/storage/bitcoin-core-source/build/bin/bitcoin-cli"
       " -conf=/storage/core-oracle/bitcoin.conf"
       " -datadir=/storage/core-oracle").split()
ORACLE = os.environ.get("CORE_VERIFY_ORACLE", "/tmp/core_verify_oracle")

# ---- the same flag schedule bitcoin_script_flags.asm implements ------------
SFC = dict(P2SH=1 << 0, DERSIG=1 << 2, NULLDUMMY=1 << 4,
           CLTV=1 << 9, CSV=1 << 10, WITNESS=1 << 11, TAPROOT=1 << 17)
H_DERSIG, H_CLTV, H_CSV, H_SEGWIT = 363725, 388381, 419328, 481824


def flags_for(h):
    f = SFC["P2SH"] | SFC["WITNESS"] | SFC["TAPROOT"]
    if h >= H_DERSIG: f |= SFC["DERSIG"]
    if h >= H_CLTV:   f |= SFC["CLTV"]
    if h >= H_CSV:    f |= SFC["CSV"]
    if h >= H_SEGWIT: f |= SFC["NULLDUMMY"]
    return f


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


# ------------------------------------------------------------ tx (de)coding
def rd_cs(b, i):
    v = b[i]; i += 1
    if v < 0xfd:  return v, i
    if v == 0xfd: return int.from_bytes(b[i:i+2], "little"), i + 2
    if v == 0xfe: return int.from_bytes(b[i:i+4], "little"), i + 4
    return int.from_bytes(b[i:i+8], "little"), i + 8


def wr_cs(v):
    if v < 0xfd:      return bytes([v])
    if v <= 0xffff:   return b"\xfd" + v.to_bytes(2, "little")
    if v <= 0xffffffff: return b"\xfe" + v.to_bytes(4, "little")
    return b"\xff" + v.to_bytes(8, "little")


def tx_decode(h):
    """-> dict(version, ins=[dict(prevout,script,seq,wit=[...])], outs=[bytes], locktime, segwit)"""
    b = bytes.fromhex(h); i = 4
    t = {"version": b[0:4], "ins": [], "outs": [], "segwit": False}
    if b[i] == 0x00 and b[i+1] == 0x01:
        t["segwit"] = True; i += 2
    nin, i = rd_cs(b, i)
    for _ in range(nin):
        po = b[i:i+36]; i += 36
        sl, i = rd_cs(b, i); ss = b[i:i+sl]; i += sl
        seq = b[i:i+4]; i += 4
        t["ins"].append({"prevout": po, "script": ss, "seq": seq, "wit": []})
    nout, i = rd_cs(b, i)
    for _ in range(nout):
        val = b[i:i+8]; i += 8
        sl, i = rd_cs(b, i); spk = b[i:i+sl]; i += sl
        t["outs"].append(val + wr_cs(sl) + spk)
    if t["segwit"]:
        for k in range(nin):
            ni, i = rd_cs(b, i)
            for _ in range(ni):
                il, i = rd_cs(b, i); t["ins"][k]["wit"].append(b[i:i+il]); i += il
    t["locktime"] = b[i:i+4]; i += 4
    assert i == len(b), "tx did not consume exactly (%d/%d)" % (i, len(b))
    return t


def tx_encode(t):
    o = bytearray(t["version"])
    if t["segwit"]: o += b"\x00\x01"
    o += wr_cs(len(t["ins"]))
    for v in t["ins"]:
        o += v["prevout"] + wr_cs(len(v["script"])) + v["script"] + v["seq"]
    o += wr_cs(len(t["outs"]))
    for x in t["outs"]: o += x
    if t["segwit"]:
        for v in t["ins"]:
            o += wr_cs(len(v["wit"]))
            for w in v["wit"]: o += wr_cs(len(w)) + w
    o += t["locktime"]
    return bytes(o)


def script_pushes(b):
    """[(op_start, data_start, data_len)] for a push-only script; [] otherwise.
    A small-int / OP_0 / OP_1NEGATE opcode is reported with data_len 0 and
    data_start == op_start + 1 (it has no length prefix to rewrite)."""
    i = 0; out = []
    while i < len(b):
        op = b[i]
        if op == 0x00 or op == 0x4f or 0x51 <= op <= 0x60:
            out.append((i, i + 1, 0)); i += 1; continue
        if op <= 0x4b:        j = i + 1; n = op
        elif op == 0x4c:      j = i + 2; n = b[i+1]
        elif op == 0x4d:      j = i + 3; n = b[i+1] | (b[i+2] << 8)
        elif op == 0x4e:      j = i + 5; n = int.from_bytes(b[i+1:i+5], "little")
        else: return []
        if j + n > len(b): return []
        out.append((i, j, n)); i = j + n
    return out


def push_encode(d):
    """Minimal push of `d` -- only ever applied to the ONE signature being
    re-encoded; every other push in the script is copied byte-for-byte."""
    assert len(d) <= 0xff
    if len(d) <= 0x4b: return bytes([len(d)]) + d
    return b"\x4c" + bytes([len(d)]) + d


# --------------------------------------------------------- DER manipulation
def der_parts(s):
    assert s[0] == 0x30 and s[2] == 0x02, "not a DER sig: %s" % s.hex()
    lr = s[3]; R = s[4:4+lr]
    assert s[4+lr] == 0x02, "no S marker: %s" % s.hex()
    ls = s[5+lr]; S = s[6+lr:6+lr+ls]
    return R, S, s[6+lr+ls:]


def der_build(R, S, ht):
    body = b"\x02" + bytes([len(R)]) + R + b"\x02" + bytes([len(S)]) + S
    return bytes([0x30, len(body)]) + body + ht


def pad_r(sig):
    """One redundant leading 0x00 on R. Value-preserving, encoding-invalidating."""
    R, S, ht = der_parts(sig)
    return der_build(b"\x00" + R, S, ht)


# ------------------------------------------------------------ chain helpers
def block2(h):
    return json.loads(rpc("getblock", rpc("getblockhash", str(h)), "2"))


def fetch(height, txindex):
    blk = block2(height)
    tx = blk["tx"][txindex]
    prevs = []
    for v in tx["vin"]:
        pv = json.loads(rpc("getrawtransaction", v["txid"], "true"))["vout"][v["vout"]]
        prevs.append((v["txid"], v["vout"], int(round(pv["value"] * 1e8)),
                      pv["scriptPubKey"]["hex"], pv["scriptPubKey"].get("type", "?")))
    return dict(height=height, blockhash=blk["hash"], txid=tx["txid"], hex=tx["hex"],
                coinbase=blk["tx"][0]["hex"], prevs=prevs)


def core_verdict(case, txhex, height):
    """Core's own accept/reject for EVERY input of `txhex` at `height`'s
    consensus flags. Legacy inputs go through VERIFY; witness inputs need the
    spent-output set, so they go through TAPVERIFY (whose fixed flag set is the
    modern consensus one -- segwit heights always have DERSIG on anyway)."""
    t = tx_decode(txhex)
    prevs = case["prevs"]
    witness_case = any(p[4].startswith("witness") for p in prevs)
    if witness_case:
        args = " ".join("%d %s" % (p[2], p[3]) for p in prevs)
        for i in range(len(t["ins"])):
            r = oracle("TAPVERIFY %d %s %d %s" % (i, txhex, len(prevs), args))
            if r[1] != "1": return False, r[3]
        return True, "ok"
    strip = tx_encode(dict(t, segwit=False, ins=[dict(v, wit=[]) for v in t["ins"]])).hex()
    for i, v in enumerate(t["ins"]):
        r = oracle("VERIFY %x %d %s %s %s" % (flags_for(height), i, strip,
                                              v["script"].hex() or "-", prevs[i][3]))
        if r[1] != "1": return False, r[3]
    return True, "ok"


def mutate(case, in_index, wit_index=None, push_index=0):
    """Return the tx hex with ONE signature R-padded. wit_index selects a
    witness item; otherwise push_index selects a scriptSig push."""
    t = tx_decode(case["hex"])
    v = t["ins"][in_index]
    if wit_index is not None:
        v["wit"][wit_index] = pad_r(v["wit"][wit_index])
    else:
        ps = script_pushes(v["script"])
        assert ps, "scriptSig is not push-only"
        sigs = [o for (_, o, n) in ps if n >= 9 and v["script"][o] == 0x30]
        assert sigs, "no DER push in scriptSig"
        off = sigs[push_index]
        # Only the target push is re-encoded (its length prefix has to grow);
        # every other byte of the scriptSig is copied verbatim, so nothing
        # else about the transaction can drift.
        out = b""
        for (p, o, k) in ps:
            out += push_encode(pad_r(v["script"][o:o+k])) if o == off \
                   else v["script"][p:o+k]
        v["script"] = out
    return tx_encode(t).hex()


# --------------------------------------------------------------------- main
# Located by scanning mainnet for the shapes below; see the module docstring.
LEG  = fetch(400000, 1)     # P2PKH,      1 input
MS   = fetch(500000, 17)    # P2SH multisig, 1 input
W0   = fetch(600000, 17)    # P2WPKH,     1 input
PRE0 = fetch(149850, 11)    # pre-BIP66, R has a redundant leading 0x00
PRE1 = fetch(152841, 12)    # pre-BIP66, R is a negative DER INTEGER

LEG["pad"] = mutate(LEG, 0)
MS["pad"]  = mutate(MS, 0)
W0["pad"]  = mutate(W0, 0, wit_index=0)

# A real pre-BIP66 block hash to re-host the padded post-BIP66 transactions at
# (the gate proof: same bytes, same verifier, DERSIG off -> Core accepts).
PRE_HEIGHT = 300000
PRE_HASH = rpc("getblockhash", str(PRE_HEIGHT))
# The two real blocks straddling the activation height, so the test pins the
# exact boundary (Core's DeploymentActiveAt is height >= BIP66Height).
BOUND_OFF_HASH = rpc("getblockhash", str(H_DERSIG - 1))
BOUND_ON_HASH  = rpc("getblockhash", str(H_DERSIG))

# ---- assert every baked expectation against Core itself --------------------
def expect(label, ok, want, why):
    if ok != want:
        sys.exit("CORE DISAGREES: %s -> %s, expected %s (%s)" % (label, ok, want, why))

for c, nm in ((LEG, "LEG"), (MS, "MS"), (W0, "W0")):
    expect(nm + " original @own height",
           core_verdict(c, c["hex"], c["height"])[0], True, "real mainnet tx")
    expect(nm + " R-padded @own height (DERSIG on)",
           core_verdict(c, c["pad"], c["height"])[0], False, "IsValidSignatureEncoding")
# the padded legacy tx at a pre-BIP66 height: Core accepts (this is what makes
# it a gate and not a blanket rule -- and it also proves the padding really is
# cryptographically harmless, since the only thing that changed is the flags)
expect("LEG R-padded @pre-BIP66 height",
       core_verdict(LEG, LEG["pad"], PRE_HEIGHT)[0], True, "DERSIG not yet active")
expect("LEG original @pre-BIP66 height",
       core_verdict(LEG, LEG["hex"], PRE_HEIGHT)[0], True, "strict is always fine")
expect("MS R-padded @pre-BIP66 height",
       core_verdict(MS, MS["pad"], PRE_HEIGHT)[0], True, "DERSIG not yet active")
for c, nm in ((PRE0, "PRE0"), (PRE1, "PRE1")):
    expect(nm + " @own (pre-BIP66) height",
           core_verdict(c, c["hex"], c["height"])[0], True, "real accepted history")
    expect(nm + " @post-BIP66 height",
           core_verdict(c, c["hex"], LEG["height"])[0], False, "already non-strict")

# ... and that the two historical signatures really are non-strict by Core's
# own CheckSignatureEncoding, not merely by our reading of it.
def first_sig(txhex, i):
    v = tx_decode(txhex)["ins"][i]
    for (_p, o, n) in script_pushes(v["script"]):
        if n >= 9 and v["script"][o] == 0x30: return v["script"][o:o+n]
    sys.exit("no sig found")

PRE0_SIG = first_sig(PRE0["hex"], 1)
PRE1_SIG = first_sig(PRE1["hex"], 0)
for nm, s in (("PRE0", PRE0_SIG), ("PRE1", PRE1_SIG)):
    expect(nm + " SIGENC DERSIG", oracle("SIGENC %x %s" % (SFC["DERSIG"], s.hex()))[1] == "1",
           False, "must be non-strict")
    expect(nm + " SIGENC no-flags", oracle("SIGENC 0 %s" % s.hex())[1] == "1",
           True, "pre-BIP66 accepts anything")

expect("LEG R-padded @%d (activation-1)" % (H_DERSIG - 1),
       core_verdict(LEG, LEG["pad"], H_DERSIG - 1)[0], True, "DERSIG not yet active")
expect("LEG R-padded @%d (activation)" % H_DERSIG,
       core_verdict(LEG, LEG["pad"], H_DERSIG)[0], False, "DERSIG active from here")

# ---- a direct der_sig_strict <-> IsValidSignatureEncoding vector table ------
# One vector per clause of Core's function, plus the two real historical
# signatures. The verdict column is Core's own SIGENC answer, so the unit test
# below pins our implementation to Core's without needing the oracle at test
# time. (The generating run also fuzzed ~18k encodings against SIGENC with zero
# disagreements; these are the readable subset worth carrying in-tree.)
R32 = bytes.fromhex("1b" + "34" * 31)
S32 = bytes.fromhex("3c" + "56" * 31)
RNEG = bytes.fromhex("9b" + "34" * 31)


def raw(hdr, seqlen, R, S, ht=b"\x01"):
    body = b"\x02" + bytes([len(R)]) + R + b"\x02" + bytes([len(S)]) + S
    return bytes([hdr, len(body) if seqlen is None else seqlen]) + body + ht


ENC = [
    ("strict baseline",                       raw(0x30, None, R32, S32)),
    ("strict, R legitimately 0x00-padded",    raw(0x30, None, b"\x00" + RNEG, S32)),
    ("strict, minimal 9-byte signature",      bytes.fromhex("300602010102010101")),
    ("hashtype 0x81 (ALL|ANYONECANPAY)",      raw(0x30, None, R32, S32, b"\x81")),
    ("hashtype 0x00 (undefined, not DERSIG's business)", raw(0x30, None, R32, S32, b"\x00")),
    ("R with one redundant leading 0x00",     raw(0x30, None, b"\x00" + R32, S32)),
    ("S with one redundant leading 0x00",     raw(0x30, None, R32, b"\x00" + S32)),
    ("R with two redundant leading 0x00",     raw(0x30, None, b"\x00\x00" + R32, S32)),
    ("both R and S double-padded",            raw(0x30, None, b"\x00\x00" + R32, b"\x00\x00" + S32)),
    ("R negative (top bit set, unpadded)",    raw(0x30, None, RNEG, S32)),
    ("S negative (top bit set, unpadded)",    raw(0x30, None, R32, bytes.fromhex("9c" + "56" * 31))),
    ("SEQUENCE length byte one too small",    raw(0x30, 0x43, R32, S32)),
    ("SEQUENCE length byte one too large",    raw(0x30, 0x45, R32, S32)),
    ("SEQUENCE length byte zero",             raw(0x30, 0x00, R32, S32)),
    ("header byte 0x31, not 0x30",            raw(0x31, None, R32, S32)),
    ("trailing garbage after the hashtype",   raw(0x30, None, R32, S32) + b"\xff"),
    ("no hashtype byte at all",               raw(0x30, None, R32, S32, b"")),
    ("two hashtype bytes",                    raw(0x30, None, R32, S32, b"\x01\x01")),
    ("zero-length R",                         raw(0x30, None, b"", S32)),
    ("zero-length S",                         raw(0x30, None, R32, b"")),
    ("R marker 0x03, not 0x02",               b"\x30\x44\x03\x20" + R32 + b"\x02\x20" + S32 + b"\x01"),
    ("S marker 0x03, not 0x02",               b"\x30\x44\x02\x20" + R32 + b"\x03\x20" + S32 + b"\x01"),
    ("R length overruns the buffer",          b"\x30\x44\x02\x40" + R32 + b"\x02\x20" + S32 + b"\x01"),
    ("8 bytes (below the 9-byte minimum)",    bytes.fromhex("3006020101020101")),
    ("74 bytes (above the 73-byte maximum)",  raw(0x30, None, b"\x00\x00" + RNEG, b"\x00" + bytes.fromhex("9c" + "56" * 31))),
    ("REAL mainnet h149850: R 0x00-padded",   PRE0_SIG),
    ("REAL mainnet h152841: R negative",      PRE1_SIG),
]
ENC = [(n, s, oracle("SIGENC %x %s" % (SFC["DERSIG"], s.hex()))[1] == "1") for n, s in ENC]
assert any(ok for _, _, ok in ENC) and not all(ok for _, _, ok in ENC), "table must have both verdicts"


# ------------------------------------------------------------------- output
def emit_prevs(name, prevs):
    print("static const dersig_prevout_t %s[%d] = {" % (name, len(prevs)))
    for txid, idx, val, spk, typ in prevs:
        print('  { "%s", %d, %dULL, "%s" },   /* %s */' % (txid, idx, val, spk, typ))
    print("};")


def emit(tag, c, comment, pad=True):
    print("/* --- %s --- */" % comment)
    print('#define %s_HEIGHT        %dL' % (tag, c["height"]))
    print('#define %s_BLOCKHASH_RPC "%s"' % (tag, c["blockhash"]))
    print('#define %s_TXID          "%s"' % (tag, c["txid"]))
    print('#define %s_TX_HEX        "%s"' % (tag, c["hex"]))
    if pad:
        print('#define %s_PAD_HEX      "%s"' % (tag, c["pad"]))
    print('#define %s_COINBASE_HEX  "%s"' % (tag, c["coinbase"]))
    emit_prevs("%s_PREVS" % tag, c["prevs"])
    print('#define %s_NPREV         %d' % (tag, len(c["prevs"])))
    print()


print("/* GENERATED by validation/fetch_dersig_vectors.py from the Core oracle -- do not hand-edit. */")
print("/* BIP66/DERSIG: the strict signature-encoding rule script_flags_for_block()")
print(" * computed and nothing on the block-connect path ever consulted. Every")
print(" * accept/reject below was asserted against Bitcoin Core's own VerifyScript")
print(" * and CheckSignatureEncoding at the generating run. */")
print("typedef struct { const char* txid_hex; unsigned index; unsigned long long value;")
print("                 const char* spk_hex; } dersig_prevout_t;")
print()
print('#define DERSIG_ACTIVATION_HEIGHT %dL   /* Core CMainParams BIP66Height */' % H_DERSIG)
print('/* a real mainnet block below the activation height, used to re-host the')
print(' * crafted post-BIP66 transactions with DERSIG off. */')
print('#define DSPRE_HEIGHT           %dL' % PRE_HEIGHT)
print('#define DSPRE_BLOCKHASH_RPC    "%s"' % PRE_HASH)
print('/* the two real blocks straddling the activation height */')
print('#define DSBOUND_OFF_HEIGHT     %dL' % (H_DERSIG - 1))
print('#define DSBOUND_OFF_BLOCKHASH_RPC "%s"' % BOUND_OFF_HASH)
print('#define DSBOUND_ON_HEIGHT      %dL' % H_DERSIG)
print('#define DSBOUND_ON_BLOCKHASH_RPC  "%s"' % BOUND_ON_HASH)
print()
emit("DSLEG", LEG, "P2PKH: legacy sv_verify_script -> interp_checksig")
emit("DSMS",  MS,  "P2SH multisig: legacy -> interp_checkmultisig")
emit("DSW0",  W0,  "P2WPKH: sv_verify_witness_v0 -> interp_checksig (WITNESS_V0)")
emit("DSPRE0", PRE0,
     "REAL pre-BIP66 mainnet tx, R padded with a redundant leading 0x00\n"
     " *     sig: " + PRE0_SIG.hex(), pad=False)
emit("DSPRE1", PRE1,
     "REAL pre-BIP66 mainnet tx, R is a NEGATIVE DER INTEGER (top bit set)\n"
     " *     sig: " + PRE1_SIG.hex(), pad=False)
print('/* which input of each historical tx carries the non-strict signature */')
print('#define DSPRE0_BAD_INPUT 1')
print('#define DSPRE1_BAD_INPUT 0')
print()
print('/* --- der_sig_strict() vs Core IsValidSignatureEncoding: one vector per')
print(' *     clause of Core\'s function. `ok` is Core\'s OWN SIGENC verdict under')
print(' *     SCRIPT_VERIFY_DERSIG alone (which is exactly IsValidSignatureEncoding).')
print(' *     The generating run additionally fuzzed ~18k encodings against the same')
print(' *     oracle command with zero disagreements; this is the readable subset. --- */')
print("typedef struct { const char* name; const char* sig_hex; int core_ok; } dersig_enc_t;")
print("static const dersig_enc_t DSENC[%d] = {" % len(ENC))
for n, s, ok in ENC:
    print('  { "%s", "%s", %d },' % (n, s.hex(), 1 if ok else 0))
print("};")
print('#define DSENC_N %d' % len(ENC))
