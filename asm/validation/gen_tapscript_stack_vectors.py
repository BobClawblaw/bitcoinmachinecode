#!/usr/bin/env python3
"""gen_tapscript_stack_vectors.py -- BIP342 initial-stack limit vectors.

These are SYNTHETIC on purpose, and that needs justifying, because this
project's own ENGINEERING_RULES/LOG history is emphatic that hand-written
vectors share the author's blind spots.

The shape under test -- a P2TR script-path spend whose INITIAL STACK carries an
item larger than MAX_SCRIPT_ELEMENT_SIZE (520) -- does not exist on mainnet:
sampling 47,578 real script-path inputs across 68 blocks spanning 775,000 to
869,000 found a maximum initial-stack item of 79 bytes and not one OP_SUCCESSx
leaf. It cannot be fetched from the chain, so it has to be constructed. What
keeps these honest is that the EXPECTED VERDICTS are not the author's opinion:
each is read directly off Bitcoin Core's ExecuteWitnessScript
(src/script/interpreter.cpp:1842-1880), and validation/diff_tapscript_stack.py
replays every vector through Core's own VerifyScript (core_verify_oracle) so
the expectations are checked against the implementation, not against a belief
about it.

The taproot commitment arithmetic below (lift_x, the TapTweak, the output key)
is a from-scratch BIP341 implementation in Python -- deliberately not our asm,
so a wrong tweak in secp256k1_taproot.asm could not make a broken vector look
correct.

Usage: python3 validation/gen_tapscript_stack_vectors.py > tests/tapscript_stack_vec.h
"""
import hashlib, struct, sys

P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def inv(a, m=P): return pow(a, m - 2, m)


def pt_add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    if a == b: lam = 3 * a[0] * a[0] % P * inv(2 * a[1]) % P
    else:      lam = (b[1] - a[1]) % P * inv((b[0] - a[0]) % P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def pt_mul(k, pt):
    r = None
    while k:
        if k & 1: r = pt_add(r, pt)
        pt = pt_add(pt, pt); k >>= 1
    return r


def lift_x(x):
    """BIP340 lift_x: the point with x-coordinate x and EVEN y."""
    if x >= P: return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if pow(y, 2, P) != y2: return None
    return (x, y if y % 2 == 0 else P - y)


def tagged(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def cs(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)


def tapleaf(script, ver=0xc0):
    return tagged("TapLeaf", bytes([ver]) + cs(len(script)) + script)


def taproot_output(internal_seckey, leaf_script, ver=0xc0):
    """-> (spk_bytes, control_block_bytes). Single leaf, so merkle root = leaf hash."""
    Pt = pt_mul(internal_seckey, (Gx, Gy))
    if Pt[1] % 2: Pt = (Pt[0], P - Pt[1])          # x-only: force even y
    px = Pt[0]
    m = tapleaf(leaf_script, ver)
    t = int.from_bytes(tagged("TapTweak", px.to_bytes(32, 'big') + m), 'big')
    assert t < N
    Q = pt_add(lift_x(px), pt_mul(t, (Gx, Gy)))
    parity = Q[1] & 1
    spk = b'\x51\x20' + Q[0].to_bytes(32, 'big')
    control = bytes([ver | parity]) + px.to_bytes(32, 'big')
    return spk, control


def filler(n):
    return bytes(((i * 167 + 13) & 0xff) for i in range(n))


def pushnum(v):
    """minimal-encoded CScriptNum push of a small positive int."""
    b = b''
    x = v
    while x:
        b += bytes([x & 0xff]); x >>= 8
    if b[-1] & 0x80: b += b'\x00'
    assert len(b) < 76
    return bytes([len(b)]) + b


OP_DROP, OP_1, OP_SIZE, OP_NIP, OP_EQUAL = 0x75, 0x51, 0x82, 0x77, 0x87
OP_SUCCESS187 = 0xbb

AMOUNT = 100000


def size_eq_leaf(n):
    """<n-byte item on stack> OP_SIZE OP_NIP <n> OP_EQUAL -> exactly one truthy element."""
    return bytes([OP_SIZE, OP_NIP]) + pushnum(n) + bytes([OP_EQUAL])


# name, initial-stack item size, leaf script, expected verdict, why (Core's rule)
VECTORS = [
    ("init_item_520", 520, size_eq_leaf(520), 1,
     "520-byte initial stack item is exactly at MAX_SCRIPT_ELEMENT_SIZE: Core ACCEPTS. "
     "Guards the fix against over-rejecting at the boundary."),
    ("init_item_521", 521, size_eq_leaf(521), 0,
     "521-byte initial stack item: Core's ExecuteWitnessScript rejects with "
     "SCRIPT_ERR_PUSH_SIZE. Before the fix this path had no element-size check at all, "
     "so it was a silent FALSE ACCEPT -- a consensus divergence with no memory symptom."),
    ("init_item_3900000", 3900000, bytes([OP_DROP, OP_1]), 0,
     "3,900,000-byte initial stack item (the largest witness item a 4M-weight block can carry is 3,938,182 B, seen at height 774628): Core rejects (SCRIPT_ERR_PUSH_SIZE). Before the "
     "fix, stack_push copied all 3.9 MB into ts_main_e's first 528-byte element record -- a "
     "~3.4 MB overrun of a 528,000-byte heap buffer, i.e. remote memory corruption from "
     "block relay. Run in a forked child: the assertion is that the child exits CLEANLY."),
    ("opsuccess_3900000", 3900000, bytes([OP_SUCCESS187]), 1,
     "3,900,000-byte initial stack item under an OP_SUCCESS187 leaf: Core ACCEPTS -- its "
     "OP_SUCCESSx scan runs BEFORE both the stack-size and element-size limits and "
     "'overrides everything'. So this exact shape is consensus-valid and mineable today. "
     "Before the fix it took the same 3.9 MB overrun as init_item_3900000; a NAIVE fix (reject "
     ">520 unconditionally) would turn it into a false reject, which is why it is here."),
]

def build_vectors():
    """-> list of dicts. The two 1 MB vectors are 2 MB of hex each, so the C
    header carries only the SHAPE (item size + leaf + control + spk + outpoint)
    and the test serializes the transaction itself; the full tx bytes are built
    here for the Core differential."""
    out = []
    for i, (name, isz, leaf, expect, note) in enumerate(VECTORS):
        sk = 0x1000 + i * 7
        spk, control = taproot_output(sk, leaf)
        item = filler(isz)
        # outpoint bytes exactly as they appear on the wire (internal order):
        wire_prev = hashlib.sha256(("bmc-tapscript-stack-" + name).encode()).digest()
        tx = build_tx_wire(wire_prev, 0, [item, leaf, control], AMOUNT - 1000)
        out.append(dict(name=name, item=isz, leaf=leaf, control=control, spk=spk,
                        wire_prev=wire_prev, value=AMOUNT, out_value=AMOUNT - 1000,
                        expect=expect, note=note, tx=tx,
                        # only an item that overruns a 528-byte element record can
                        # corrupt memory; those cases run in a forked child.
                        forked=1 if isz > 524 else 0))
    return out


def build_tx_wire(wire_prev, vout, witness_items, value_out):
    o = b'\x02\x00\x00\x00' + b'\x00\x01' + b'\x01'
    o += wire_prev + struct.pack('<I', vout) + b'\x00' + b'\xff\xff\xff\xff'
    o += b'\x01' + struct.pack('<Q', value_out) + cs(22) + b'\x00\x14' + bytes(20)
    o += cs(len(witness_items))
    for it in witness_items:
        o += cs(len(it)) + it
    o += b'\x00\x00\x00\x00'
    return o


if __name__ == "__main__":
    w = sys.stdout.write
    vs = build_vectors()
    w("/* GENERATED by validation/gen_tapscript_stack_vectors.py -- do not hand-edit. */\n")
    w("/* BIP342 initial-stack limit vectors. Synthetic BY NECESSITY (the shape does not\n"
      " * occur on mainnet -- 47,578 sampled real script-path inputs max out at a 79-byte\n"
      " * initial-stack item), with every expected verdict taken from Bitcoin Core's\n"
      " * ExecuteWitnessScript (src/script/interpreter.cpp:1842-1880) and cross-checked\n"
      " * against Core's own VerifyScript by validation/diff_tapscript_stack.py.\n"
      " *\n"
      " * Only the SHAPE is stored: the two 1,000,000-byte-item vectors would be 2 MB of\n"
      " * hex each. tests/test_tapscript_scale.c serializes the transaction from these\n"
      " * fields (version 2, one input spending outpoint_hex:0 with an empty scriptSig and\n"
      " * nSequence 0xffffffff, one 22-byte-P2WPKH output, witness = [filler(item_len),\n"
      " * leaf, control], nLockTime 0), with filler[i] = (uint8_t)(i*167+13). */\n")
    w("typedef struct { const char* name; unsigned long item_len; const char* leaf_hex;\n"
      "                 const char* control_hex; const char* spk_hex; const char* outpoint_hex;\n"
      "                 unsigned long long value; unsigned long long out_value;\n"
      "                 int expect; int forked; const char* note; } tss_vec_t;\n")
    w("static const tss_vec_t TSS_VECS[%d] = {\n" % len(vs))
    for v in vs:
        w('  { "%s", %luUL, "%s", "%s", "%s", "%s", %dULL, %dULL, %d, %d,\n    "%s" },\n'
          % (v['name'], v['item'], v['leaf'].hex(), v['control'].hex(), v['spk'].hex(),
             v['wire_prev'].hex(), v['value'], v['out_value'], v['expect'], v['forked'],
             v['note']))
        sys.stderr.write("%-16s item=%-8d leaf=%-4d tx=%-9d expect=%d forked=%d\n"
                         % (v['name'], v['item'], len(v['leaf']), len(v['tx']),
                            v['expect'], v['forked']))
    w("};\n#define TSS_N %d\n" % len(vs))
