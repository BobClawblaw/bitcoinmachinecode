#!/usr/bin/env python3
"""Emit bitcoin_script_flags.asm's activation table from Core's own
kernel/chainparams.cpp (CMainParams) and script/interpreter.h (the
SCRIPT_VERIFY_* bit positions), for validation/gen_hashtype_vectors.py-style
reasons: PLAN_SCRIPT_VERIFY.md's Stage C requires heights read out of Core's
source, never from memory (defaults were misremembered twice in an earlier
session). The two script_flag_exceptions hashes are equally consensus-
critical and equally easy to mistranscribe by hand (64 hex chars each), so
they are generated too, never typed.

Re-run after a Core upgrade; anything unexpected in the extracted section
aborts rather than silently emitting a stale/wrong table.

Reference (read, not trusted from memory -- see Core's own
GetBlockScriptFlags in src/validation.cpp and DeploymentActiveAt in
src/deploymentstatus.h): P2SH|WITNESS|TAPROOT are active from height 0
UNCONDITIONALLY except for exactly two historical blocks (by hash, not
height) where Core overrides the flags down to something weaker; DERSIG/
CLTV/CSV/NULLDUMMY (NULLDUMMY activates with segwit, BIP147) are each
"buried" (active at height >= a fixed threshold, height.DeploymentHeight()).
"""
import re, sys, os

SRC = "/storage/bitcoin-core-source/src/kernel/chainparams.cpp"
IFACE = "/storage/bitcoin-core-source/src/script/interpreter.h"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "asm", "script_flags_consts.inc")
# The same numbers are needed by C (rpc_chain.c's getdeploymentinfo reports
# the heights this node actually enforces). Hand-copying them into a .c would
# reintroduce exactly the drift this generator exists to prevent, so a C
# header is emitted from the same parse.
OUT_H = os.path.join(HERE, "..", "asm", "script_flags_consts.h")

# ---- 1. bit positions, from Core's script_verify_flag_name enum (implicit
#      sequential numbering; script_verify_flags.h shifts 1<<position) ----
body = open(IFACE).read()
m = re.search(r"enum class script_verify_flag_name[^{]*\{(.*?)\};", body, re.S)
if not m: sys.exit("could not find script_verify_flag_name enum in " + IFACE)
names = re.findall(r"SCRIPT_VERIFY_[A-Z0-9_]+", m.group(1))
bitpos = {name: i for i, name in enumerate(names)}
NEEDED = ["SCRIPT_VERIFY_P2SH", "SCRIPT_VERIFY_DERSIG", "SCRIPT_VERIFY_NULLDUMMY",
          "SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY", "SCRIPT_VERIFY_CHECKSEQUENCEVERIFY",
          "SCRIPT_VERIFY_WITNESS", "SCRIPT_VERIFY_TAPROOT"]
for n in NEEDED:
    if n not in bitpos:
        sys.exit("expected flag %s not found in %s" % (n, IFACE))
print("bit positions:", {n: bitpos[n] for n in NEEDED})

# ---- 2. CMainParams class body only (not testnet/regtest) ----
src = open(SRC).read()
cm = re.search(r"class CMainParams : public CChainParams \{.*?\n\};", src, re.S)
if not cm: sys.exit("could not find CMainParams class body in " + SRC)
main = cm.group(0)

def height(field):
    m = re.search(r"consensus\.%s\s*=\s*(\d+)" % field, main)
    if not m: sys.exit("could not find consensus.%s in CMainParams" % field)
    return int(m.group(1))

BIP34 = height("BIP34Height")   # coinbase height-in-scriptSig
BIP65 = height("BIP65Height")   # CLTV
BIP66 = height("BIP66Height")   # DERSIG
CSV   = height("CSVHeight")
SEGWIT = height("SegwitHeight") # WITNESS + NULLDUMMY (BIP147, simultaneous)
print("heights: BIP34=%d BIP66(DERSIG)=%d BIP65(CLTV)=%d CSV=%d Segwit(WITNESS+NULLDUMMY)=%d"
      % (BIP34, BIP66, BIP65, CSV, SEGWIT))

# ---- 2b. CRegTestParams heights (regtest chain selection). Same fields, same
#      discipline: read from Core's source, never remembered. Regtest's two
#      mainnet exception hashes cannot occur (different genesis), so only the
#      buried heights are chain-dependent. ----
crt = re.search(r"class CRegTestParams : public CChainParams\s*\{.*?\n\};", src, re.S)
if not crt: sys.exit("could not find CRegTestParams class body in " + SRC)
rmain = crt.group(0)
def rheight(field):
    m = re.search(r"consensus\.%s\s*=\s*(\d+)" % field, rmain)
    if not m: sys.exit("could not find consensus.%s in CRegTestParams" % field)
    return int(m.group(1))
R_BIP34 = rheight("BIP34Height")
R_BIP65 = rheight("BIP65Height")
R_BIP66 = rheight("BIP66Height")
R_CSV   = rheight("CSVHeight")
R_SEGWIT = rheight("SegwitHeight")
print("regtest heights: BIP34=%d BIP66=%d BIP65=%d CSV=%d Segwit=%d"
      % (R_BIP34, R_BIP66, R_BIP65, R_CSV, R_SEGWIT))

# ---- 2c. CTestNet4Params heights (testnet4 chain selection). ----
ct4 = re.search(r"class CTestNet4Params : public CChainParams\s*\{.*?\n\};", src, re.S)
if not ct4: sys.exit("could not find CTestNet4Params class body in " + SRC)
t4 = ct4.group(0)
def theight(field):
    m = re.search(r"consensus\.%s\s*=\s*(\d+)" % field, t4)
    if not m: sys.exit("could not find consensus.%s in CTestNet4Params" % field)
    return int(m.group(1))
T_BIP34 = theight("BIP34Height")
T_BIP65 = theight("BIP65Height")
T_BIP66 = theight("BIP66Height")
T_CSV   = theight("CSVHeight")
T_SEGWIT = theight("SegwitHeight")
print("testnet4 heights: BIP34=%d BIP66=%d BIP65=%d CSV=%d Segwit=%d"
      % (T_BIP34, T_BIP66, T_BIP65, T_CSV, T_SEGWIT))

exc = re.findall(
    r"script_flag_exceptions\.emplace\(\s*//\s*(\w+) exception\s*\n\s*uint256\{\"([0-9a-f]{64})\"\},\s*([A-Z0-9_| ]+)\);",
    main)
if len(exc) != 2:
    sys.exit("expected exactly 2 script_flag_exceptions in CMainParams, found %d -- "
              "Core's exception list changed shape, update this generator" % len(exc))

def flags_expr_to_bits(expr):
    if expr.strip() == "SCRIPT_VERIFY_NONE":
        return 0
    bits = 0
    for tok in expr.split("|"):
        tok = tok.strip()
        if tok not in bitpos:
            sys.exit("exception flag %r not a known SCRIPT_VERIFY_* name" % tok)
        bits |= 1 << bitpos[tok]
    return bits

exceptions = []
for label, hexhash, flagsexpr in exc:
    bits = flags_expr_to_bits(flagsexpr)
    rawbytes = bytes.fromhex(hexhash)[::-1]  # display hex -> this codebase's
                                              # raw block_hash byte order
                                              # (verified empirically against
                                              # the real genesis hash before
                                              # writing this generator)
    exceptions.append((label, hexhash, rawbytes, bits))
    print("exception %-8s hash(display)=%s -> flags=0x%x" % (label, hexhash, bits))

# ---- 3. emit the generated .inc, self-checking by re-parsing it ----
lines = []
lines.append("; GENERATED by validation/gen_script_flags.py -- DO NOT EDIT.")
lines.append("; Bitcoin Core CMainParams (kernel/chainparams.cpp) + script_verify_flag_name")
lines.append("; (script/interpreter.h). Re-run after a Core upgrade.")
lines.append("")
lines.append("%%define SFC_BIT_P2SH   %d" % bitpos["SCRIPT_VERIFY_P2SH"])
lines.append("%%define SFC_BIT_DERSIG %d" % bitpos["SCRIPT_VERIFY_DERSIG"])
lines.append("%%define SFC_BIT_NULLDUMMY %d" % bitpos["SCRIPT_VERIFY_NULLDUMMY"])
lines.append("%%define SFC_BIT_CLTV %d" % bitpos["SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY"])
lines.append("%%define SFC_BIT_CSV %d" % bitpos["SCRIPT_VERIFY_CHECKSEQUENCEVERIFY"])
lines.append("%%define SFC_BIT_WITNESS %d" % bitpos["SCRIPT_VERIFY_WITNESS"])
lines.append("%%define SFC_BIT_TAPROOT %d" % bitpos["SCRIPT_VERIFY_TAPROOT"])
lines.append("")
lines.append("; NOTE: no manual column-padding here -- a self-check regex tuned to")
lines.append("; single-space output silently failed to re-parse padded output once")
lines.append("; already in this project (gen_script_error_defines.py's own note, and")
lines.append("; ENGINEERING_RULES.md rule 1) -- simplest fix is to not pad at all.")
lines.append("%%define SFC_HEIGHT_DERSIG %d ; BIP66Height" % BIP66)
lines.append("%%define SFC_HEIGHT_CLTV %d ; BIP65Height" % BIP65)
lines.append("%%define SFC_HEIGHT_CSV %d ; CSVHeight" % CSV)
lines.append("%%define SFC_HEIGHT_SEGWIT %d ; SegwitHeight (WITNESS+NULLDUMMY)" % SEGWIT)
lines.append("")
lines.append("; regtest (CRegTestParams) -- selected at runtime via sfc_chain")
lines.append("%%define SFC_R_HEIGHT_DERSIG %d ; regtest BIP66Height" % R_BIP66)
lines.append("%%define SFC_R_HEIGHT_CLTV %d ; regtest BIP65Height" % R_BIP65)
lines.append("%%define SFC_R_HEIGHT_CSV %d ; regtest CSVHeight" % R_CSV)
lines.append("%%define SFC_R_HEIGHT_SEGWIT %d ; regtest SegwitHeight" % R_SEGWIT)
lines.append("")
lines.append("; testnet4 (CTestNet4Params) -- selected at runtime via sfc_chain")
lines.append("%%define SFC_T_HEIGHT_DERSIG %d ; testnet4 BIP66Height" % T_BIP66)
lines.append("%%define SFC_T_HEIGHT_CLTV %d ; testnet4 BIP65Height" % T_BIP65)
lines.append("%%define SFC_T_HEIGHT_CSV %d ; testnet4 CSVHeight" % T_CSV)
lines.append("%%define SFC_T_HEIGHT_SEGWIT %d ; testnet4 SegwitHeight" % T_SEGWIT)
lines.append("")
lines.append("section .rodata")
for label, hexhash, rawbytes, bits in exceptions:
    lines.append("; %s exception: display hash %s -> flags 0x%x" % (label, hexhash, bits))
    lines.append("SFC_EXC_%s_HASH: db %s" % (label.upper(), ", ".join("0x%02x" % b for b in rawbytes)))
    lines.append("%%define SFC_EXC_%s_FLAGS %d" % (label.upper(), bits))
lines.append("section .text")
lines.append("")

open(OUT, "w").write("\n".join(lines))
print("wrote", OUT)

# ---- 3b. the C mirror. Same numbers, same parse, no second source. ----
hdr = [
    "/* GENERATED by validation/gen_script_flags.py -- DO NOT EDIT.",
    " * C mirror of script_flags_consts.inc: the buried-deployment heights this",
    " * node ENFORCES, read out of Core's kernel/chainparams.cpp (CMainParams).",
    " * getdeploymentinfo reports these, so what the RPC says and what the",
    " * script-flag path does cannot drift apart. Re-run after a Core upgrade.",
    " */",
    "#ifndef SCRIPT_FLAGS_CONSTS_H",
    "#define SCRIPT_FLAGS_CONSTS_H",
    "",
    "#define SFC_HEIGHT_BIP34  %d" % BIP34,
    "#define SFC_HEIGHT_DERSIG %d   /* BIP66 */" % BIP66,
    "#define SFC_HEIGHT_CLTV   %d   /* BIP65 */" % BIP65,
    "#define SFC_HEIGHT_CSV    %d" % CSV,
    "#define SFC_HEIGHT_SEGWIT %d   /* WITNESS + NULLDUMMY (BIP147) */" % SEGWIT,
    "",
    "/* regtest (CRegTestParams) */",
    "#define SFC_R_HEIGHT_BIP34  %d" % R_BIP34,
    "#define SFC_R_HEIGHT_DERSIG %d   /* BIP66 */" % R_BIP66,
    "#define SFC_R_HEIGHT_CLTV   %d   /* BIP65 */" % R_BIP65,
    "#define SFC_R_HEIGHT_CSV    %d" % R_CSV,
    "#define SFC_R_HEIGHT_SEGWIT %d" % R_SEGWIT,
    "",
    "/* testnet4 (CTestNet4Params) */",
    "#define SFC_T_HEIGHT_BIP34  %d" % T_BIP34,
    "#define SFC_T_HEIGHT_DERSIG %d   /* BIP66 */" % T_BIP66,
    "#define SFC_T_HEIGHT_CLTV   %d   /* BIP65 */" % T_BIP65,
    "#define SFC_T_HEIGHT_CSV    %d" % T_CSV,
    "#define SFC_T_HEIGHT_SEGWIT %d" % T_SEGWIT,
    "",
    "#endif",
    "",
]
open(OUT_H, "w").write("\n".join(hdr))
print("wrote", OUT_H)

# ---- self-check: re-read and re-derive, refuse to trust a generator that
#      cannot read its own output (ENGINEERING_RULES.md rule 3) ----
again = open(OUT).read()
h1 = re.findall(r"%define SFC_HEIGHT_DERSIG\s+(\d+)", again)
h2 = re.findall(r"%define SFC_HEIGHT_CLTV\s+(\d+)", again)
h3 = re.findall(r"%define SFC_HEIGHT_CSV\s+(\d+)", again)
h4 = re.findall(r"%define SFC_HEIGHT_SEGWIT\s+(\d+)", again)
exc_lines = re.findall(r"SFC_EXC_(\w+)_HASH: db ((?:0x[0-9a-f]{2}(?:, )?)+)", again)
if not (h1 and h2 and h3 and h4 and len(exc_lines) == 2):
    sys.exit("SELF-CHECK FAILED: could not re-parse the generated .inc")
if (int(h1[0]), int(h2[0]), int(h3[0]), int(h4[0])) != (BIP66, BIP65, CSV, SEGWIT):
    sys.exit("SELF-CHECK FAILED: re-parsed heights do not match what was written")
r1 = re.findall(r"%define SFC_R_HEIGHT_DERSIG\s+(\d+)", again)
r2 = re.findall(r"%define SFC_R_HEIGHT_CLTV\s+(\d+)", again)
r3 = re.findall(r"%define SFC_R_HEIGHT_CSV\s+(\d+)", again)
r4 = re.findall(r"%define SFC_R_HEIGHT_SEGWIT\s+(\d+)", again)
if not (r1 and r2 and r3 and r4):
    sys.exit("SELF-CHECK FAILED: could not re-parse the regtest heights")
if (int(r1[0]), int(r2[0]), int(r3[0]), int(r4[0])) != (R_BIP66, R_BIP65, R_CSV, R_SEGWIT):
    sys.exit("SELF-CHECK FAILED: re-parsed regtest heights do not match")
t1 = re.findall(r"%define SFC_T_HEIGHT_DERSIG\s+(\d+)", again)
t2 = re.findall(r"%define SFC_T_HEIGHT_CLTV\s+(\d+)", again)
t3 = re.findall(r"%define SFC_T_HEIGHT_CSV\s+(\d+)", again)
t4x = re.findall(r"%define SFC_T_HEIGHT_SEGWIT\s+(\d+)", again)
if not (t1 and t2 and t3 and t4x):
    sys.exit("SELF-CHECK FAILED: could not re-parse the testnet4 heights")
if (int(t1[0]), int(t2[0]), int(t3[0]), int(t4x[0])) != (T_BIP66, T_BIP65, T_CSV, T_SEGWIT):
    sys.exit("SELF-CHECK FAILED: re-parsed testnet4 heights do not match")
for label, hexbytes in exc_lines:
    got = bytes(int(x, 16) for x in hexbytes.split(", "))
    want = next(rb for lb, hh, rb, fl in exceptions if lb.upper() == label)
    if got != want:
        sys.exit("SELF-CHECK FAILED: re-parsed exception hash %s does not match" % label)
# the C mirror must re-parse to the SAME numbers; a header that drifted from
# the .inc would be worse than no header, since both would look authoritative
again_h = open(OUT_H).read()
def cdef(name):
    m = re.search(r"#define %s\s+(\d+)" % name, again_h)
    if not m: sys.exit("SELF-CHECK FAILED: %s missing from the generated .h" % name)
    return int(m.group(1))
if (cdef("SFC_HEIGHT_BIP34"), cdef("SFC_HEIGHT_DERSIG"), cdef("SFC_HEIGHT_CLTV"),
    cdef("SFC_HEIGHT_CSV"), cdef("SFC_HEIGHT_SEGWIT")) != (BIP34, BIP66, BIP65, CSV, SEGWIT):
    sys.exit("SELF-CHECK FAILED: the C header does not match the .inc heights")
if (cdef("SFC_R_HEIGHT_BIP34"), cdef("SFC_R_HEIGHT_DERSIG"), cdef("SFC_R_HEIGHT_CLTV"),
    cdef("SFC_R_HEIGHT_CSV"), cdef("SFC_R_HEIGHT_SEGWIT")) != (R_BIP34, R_BIP66, R_BIP65, R_CSV, R_SEGWIT):
    sys.exit("SELF-CHECK FAILED: the C header does not match the regtest heights")
if (cdef("SFC_T_HEIGHT_BIP34"), cdef("SFC_T_HEIGHT_DERSIG"), cdef("SFC_T_HEIGHT_CLTV"),
    cdef("SFC_T_HEIGHT_CSV"), cdef("SFC_T_HEIGHT_SEGWIT")) != (T_BIP34, T_BIP66, T_BIP65, T_CSV, T_SEGWIT):
    sys.exit("SELF-CHECK FAILED: the C header does not match the testnet4 heights")
print("self-check ok: %d heights + %d exception hashes re-parse correctly, "
      "and the C mirror agrees" % (4, len(exc_lines)))
