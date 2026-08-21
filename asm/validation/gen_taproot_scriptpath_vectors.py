#!/usr/bin/env python3
"""Supplementary BIP341/BIP342 script-path spend vectors for
taproot_verify_input (bitcoin_taproot_sighash.c), independent of and
complementing tests/taproot_spend.h's existing scriptpath_checksig/
scriptpath_checksigadd entries (which only cover a single-leaf tree).

Adds: a real 2-leaf tree (exercises tap_merkle_root's branch-hash
combination, not just the trivial single-leaf passthrough), an unknown
leaf version (must verify TRUE without executing anything, per BIP341's
future-softfork rule), a BIP342 validation-weight-budget violation (must
verify FALSE), an annex present on a script-path spend, and negative
(tampered) variants of a straightforward single-leaf case.

Reuses the exact math from gen_taproot_vectors.py (copied, not imported --
keeps this script self-contained and avoids coupling to that file's CLI
side effects).
"""
import hashlib, struct
from ecdsa import SECP256k1, ellipticcurve
from ecdsa.ellipticcurve import Point, INFINITY

P = SECP256k1.curve.p()
N = SECP256k1.order
G = SECP256k1.generator
A = SECP256k1.curve.a()
B = SECP256k1.curve.b()

def sha256(b): return hashlib.sha256(b).digest()
def tagged_hash(tag, msg):
    t = sha256(tag.encode())
    return sha256(t + t + msg)
def ser_xonly(p):
    if p == INFINITY: raise ValueError("inf")
    return p.x().to_bytes(32, 'big')
def lift_x(b):
    x = int.from_bytes(b, 'big')
    if x >= P: raise ValueError("x>=p")
    c = (pow(x, 3, P) + B) % P
    y = pow(c, (P + 1) // 4, P)
    if (y * y) % P != c: raise ValueError("not a QR")
    return Point(SECP256k1.curve, x, y if (y % 2) == 0 else P - y, N)
def point_add(p, q):
    if p == INFINITY: return q
    if q == INFINITY: return p
    if p.x() == q.x() and (p.y() + q.y()) % P == 0: return INFINITY
    if p == q:
        lam = (3 * p.x() * p.x() + A) * pow(2 * p.y(), P - 2, P) % P
    else:
        lam = (q.y() - p.y()) * pow(q.x() - p.x(), P - 2, P) % P
    xr = (lam * lam - p.x() - q.x()) % P
    yr = (lam * (p.x() - xr) - p.y()) % P
    return Point(SECP256k1.curve, xr, yr, N)
def point_mul(p, k):
    r = INFINITY
    while k:
        if k & 1: r = point_add(r, p)
        p = point_add(p, p)
        k >>= 1
    return r
def has_even_y(p): return (p.y() % 2) == 0
def schnorr_sign(msg, sk, aux=b''):
    d = sk % N
    P_ = point_mul(G, d)
    d_ = d if has_even_y(P_) else N - d
    t = int.from_bytes(tagged_hash("BIP0340/aux", aux if aux else bytes(32)), 'big') ^ d_
    seed = int.to_bytes(t, 32, 'big') + ser_xonly(P_) + msg
    k0 = int.from_bytes(tagged_hash("BIP0340/nonce", seed), 'big') % N
    R = point_mul(G, k0)
    k = k0 if has_even_y(R) else N - k0
    e = int.from_bytes(tagged_hash("BIP0340/challenge", ser_xonly(R) + ser_xonly(P_) + msg), 'big') % N
    return ser_xonly(R) + int.to_bytes((k + e * d_) % N, 32, 'big')
def taproot_tweak_seckey(seckey0, h):
    """BIP341 key-path signing key: d = d0 (negated if P0 has odd y) + t, mod n.
    A key-path spend MUST be signed with this, not the raw seckey -- signing
    with the untweaked key produces a signature that verifies against the
    UNTWEAKED pubkey, not the actual (tweaked) taproot output key."""
    P0 = point_mul(G, seckey0)
    if not has_even_y(P0): seckey0 = N - seckey0
    t = int.from_bytes(tagged_hash("TapTweak", ser_xonly(P0) + (h or b'')), 'big')
    return (seckey0 + t) % N

def taproot_tweak_pubkey(pubkey, h):
    t = int.from_bytes(tagged_hash("TapTweak", pubkey + (h or b'')), 'big')
    if t >= N: return None
    P_ = lift_x(pubkey)
    Q = point_add(P_, point_mul(G, t))
    if Q == INFINITY: return None
    return ser_xonly(Q)
def tap_leaf_hash(leaf_version, script):
    return tagged_hash("TapLeaf", bytes([leaf_version]) + ser_compact_len(len(script)) + script)
def tap_branch_hash(a, b):
    if int.from_bytes(a, 'big') > int.from_bytes(b, 'big'):
        a, b = b, a
    return tagged_hash("TapBranch", a + b)
def ser_compact_len(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)
def write_varint(n): return ser_compact_len(n)

# ---------- SigMsg / sighash (script-path, ext_flag=1) ----------
def compute_sighash(tx, in_index, hash_type, amount, spent_scriptpubkeys, leaf_hash, annex=None):
    epoch = bytes([0])
    ht = bytes([hash_type])
    ver = struct.pack('<i', tx['version'])
    lt = struct.pack('<I', tx['locktime'])
    prevouts = b''.join(i['outpoint'] for i in tx['inputs'])
    amounts = b''.join(struct.pack('<Q', a) for a in tx['amounts'])
    spks = b''.join(ser_compact_len(len(s)) + s for s in spent_scriptpubkeys)
    seqs = b''.join(struct.pack('<I', i['sequence']) for i in tx['inputs'])
    sha_prevouts = sha256(prevouts)
    sha_amounts = sha256(amounts)
    sha_spks = sha256(spks)
    sha_sequences = sha256(seqs)
    outs = b''
    for o in tx['outputs']:
        outs += struct.pack('<Q', o['value']) + ser_compact_len(len(o['script'])) + o['script']
    sha_outputs = sha256(outs)
    annex_present = annex is not None
    spend_type = bytes([2 * 1 + (1 if annex_present else 0)])  # ext_flag=1 (script-path)
    input_index = struct.pack('<I', in_index)
    pre = epoch + ht + ver + lt + sha_prevouts + sha_amounts + sha_spks + sha_sequences + sha_outputs + spend_type + input_index
    if annex_present:
        pre += sha256(ser_compact_len(len(annex)) + annex)
    pre += leaf_hash + bytes([0x00]) + struct.pack('<I', 0xffffffff)  # key_version=0, codesep_pos=none
    return tagged_hash("TapSighash", pre)

def ser_tx(tx):
    b = struct.pack('<i', tx['version'])
    b += write_varint(len(tx['inputs']))
    for i in tx['inputs']:
        b += i['outpoint'] + b'\x00' + struct.pack('<I', i['sequence'])  # empty scriptSig
    b += write_varint(len(tx['outputs']))
    for o in tx['outputs']:
        b += struct.pack('<Q', o['value']) + ser_compact_len(len(o['script'])) + o['script']
    b += struct.pack('<I', tx['locktime'])
    return b

def carr(b):
    if not b: return '{}'
    return '{ ' + ','.join('0x%02x' % x for x in b) + ' }'

def mk_tx(numin=1, outval=90000, outspk=None):
    if outspk is None: outspk = bytes.fromhex('5120' + '55' * 32)
    ins = [{'outpoint': bytes(range(32)) + struct.pack('<I', i), 'sequence': 0xfffffffe} for i in range(numin)]
    return {'version': 2, 'locktime': 0, 'inputs': ins, 'outputs': [{'value': outval, 'script': outspk}],
            'amounts': [100000]*numin}

vectors = []

def add(name, tx, index, amount, spks, control, witness_items, spk, expect):
    """witness_items: list of bytes, in order (script/control appended by caller
    already at the end -- this is the FULL witness stack as broadcast)."""
    vectors.append({'name': name, 'tx': tx, 'index': index, 'amount': amount, 'spks': spks,
                    'witness': witness_items, 'spk': spk, 'expect': expect, 'control': control})
    # self-check: for script-path vectors (>=2 non-annex witness items), recompute
    # the commitment independently from the control block + script actually placed
    # in witness_items, and confirm it matches spk -- catches a generator bug before
    # it ever reaches the C side.
    w = witness_items
    annexp = len(w) >= 2 and len(w[-1]) >= 1 and w[-1][0] == 0x50
    eff = w[:-1] if annexp else w
    if expect and len(eff) >= 2:
        ctrl = eff[-1]; scr = eff[-2]
        if len(ctrl) >= 33:
            lv = ctrl[0] & 0xfe
            ih = ctrl[1:33]
            lh_ = tap_leaf_hash(lv, scr)
            node = lh_
            nsib = (len(ctrl) - 33) // 32
            for si in range(nsib):
                sib = ctrl[33+si*32:33+si*32+32]
                node = tap_branch_hash(node, sib)
            recomputed = taproot_tweak_pubkey(ih, node)
            if recomputed != spk[2:]:
                raise AssertionError(f"{name}: self-check FAILED -- recomputed commitment "
                                     f"{recomputed.hex() if recomputed else None} != spk {spk[2:].hex()}")

# ---- vector 1: 2-leaf tree, checksig in leaf A, sibling leaf B unrelated ----
sk = 0x1122334455667788990011223344556677889900112233445566778899aabb
Pk = ser_xonly(point_mul(G, sk))
leaf_a = bytes([0x20]) + Pk + bytes([0xac])          # <pk> CHECKSIG
leaf_b = bytes([0x51])                                # OP_1 (unrelated sibling script)
lh_a = tap_leaf_hash(0xc0, leaf_a)
lh_b = tap_leaf_hash(0xc0, leaf_b)
branch = tap_branch_hash(lh_a, lh_b)
isk = 0x0102030405060708091011121314151617181920212223242526272829303a
IP = point_mul(G, isk)
if not has_even_y(IP): isk = N - isk; IP = point_mul(G, isk)
internal_x = ser_xonly(IP)
output_x = taproot_tweak_pubkey(internal_x, branch)
tx1 = mk_tx()
spk1 = bytes([0x51, 0x20]) + output_x
dh1 = compute_sighash(tx1, 0, 0x01, 100000, [spk1], lh_a)
sig1 = schnorr_sign(dh1, sk) + bytes([0x01])
control1 = bytes([0xc0]) + internal_x + lh_b   # leaf_version|parity(0) , internal key, ONE sibling
add('scriptpath_2leaf', tx1, 0, 100000, [spk1], control1, [sig1, leaf_a, control1], spk1, 1)

# tampered variants of the 2-leaf case (all must FAIL)
sig1_bad = bytearray(sig1); sig1_bad[10] ^= 0xff
add('scriptpath_2leaf_badsig', tx1, 0, 100000, [spk1], control1, [bytes(sig1_bad), leaf_a, control1], spk1, 0)

leaf_a_bad = bytes([0x20]) + Pk + bytes([0xad])  # CHECKSIGVERIFY instead of CHECKSIG -> different leaf hash -> commitment mismatch
add('scriptpath_2leaf_badscript', tx1, 0, 100000, [spk1], control1,
    [sig1, leaf_a_bad, control1], spk1, 0)

control1_bad = bytes([0xc0]) + bytes([internal_x[0] ^ 0xff]) + internal_x[1:] + lh_b
add('scriptpath_2leaf_badcontrol', tx1, 0, 100000, [spk1], control1_bad,
    [sig1, leaf_a, control1_bad], spk1, 0)

# ---- vector 2: unknown leaf version (0xc2) -- must verify TRUE without execution ----
# script is deliberately garbage/invalid (would fail if ever executed) to prove it's
# genuinely skipped, not accidentally executed-and-passed.
garbage_script = bytes([0x00, 0x00, 0x00])  # three OP_0 pushes -> ends falsy if ever run
lh_unknown = tap_leaf_hash(0xc2, garbage_script)
output_x_unk = taproot_tweak_pubkey(internal_x, lh_unknown)
tx2 = mk_tx()
spk2 = bytes([0x51, 0x20]) + output_x_unk
control2 = bytes([0xc2]) + internal_x
add('scriptpath_unknown_leafver', tx2, 0, 100000, [spk2], control2,
    [garbage_script, control2], spk2, 1)

# ---- vector 3: BIP342 validation-weight budget exceeded ----
# many CHECKSIG calls (all with the SAME real signature, so each individually
# succeeds cryptographically) against a tiny witness -> weight_left goes
# negative before the script can finish -> must verify FALSE.
sk3 = 0x33445566778899aabbccddeeff001122334455667788990011223344556677
Pk3 = ser_xonly(point_mul(G, sk3))
NCHECKS = 40  # ser_size(witness) is tiny (~2 items), budget = tiny+50, each check costs 50
script3 = b''
for _ in range(NCHECKS):
    script3 += bytes([0x20]) + Pk3 + bytes([0xac, 0x75])  # <pk> CHECKSIG DROP  (drop the bool, keep looping)
script3 += bytes([0x51])  # OP_1 at the very end so it WOULD succeed if the budget didn't stop it first
lh3 = tap_leaf_hash(0xc0, script3)
output_x3 = taproot_tweak_pubkey(internal_x, lh3)
tx3 = mk_tx()
spk3 = bytes([0x51, 0x20]) + output_x3
dh3 = compute_sighash(tx3, 0, 0x01, 100000, [spk3], lh3)
sig3 = schnorr_sign(dh3, sk3) + bytes([0x01])
control3 = bytes([0xc0]) + internal_x
add('scriptpath_weight_exceeded', tx3, 0, 100000, [spk3], control3,
    [sig3, script3, control3], spk3, 0)

# ---- vector 4: annex present on a script-path spend (must still verify TRUE) ----
annex = bytes([0x50, 0xaa, 0xbb, 0xcc])  # 0x50 tag + arbitrary payload
sk4 = 0x445566778899aabbccddeeff0011223344556677889900112233445566778a
Pk4 = ser_xonly(point_mul(G, sk4))
leaf4 = bytes([0x20]) + Pk4 + bytes([0xac])
lh4 = tap_leaf_hash(0xc0, leaf4)
output_x4 = taproot_tweak_pubkey(internal_x, lh4)
tx4 = mk_tx()
spk4 = bytes([0x51, 0x20]) + output_x4
dh4 = compute_sighash(tx4, 0, 0x01, 100000, [spk4], lh4, annex=annex)
sig4 = schnorr_sign(dh4, sk4) + bytes([0x01])
control4 = bytes([0xc0]) + internal_x
add('scriptpath_with_annex', tx4, 0, 100000, [spk4], control4,
    [sig4, leaf4, control4, annex], spk4, 1)

# ---- vector 5: key-path WITH annex (nwit==2 after adding annex: sig + annex) ----
kp_sk = 0x556677889900aabbccddeeff00112233445566778899001122334455667788
kp_output = taproot_tweak_pubkey(ser_xonly(point_mul(G, kp_sk)), None)
kp_output_sk = taproot_tweak_seckey(kp_sk, None)  # MUST sign with the tweaked key, not kp_sk itself
tx5 = mk_tx()
spk5 = bytes([0x51, 0x20]) + kp_output
# key-path sighash (ext_flag=0), with annex committed
def compute_sighash_keypath(tx, in_index, hash_type, amount, spent_scriptpubkeys, annex=None):
    epoch = bytes([0]); ht = bytes([hash_type]); ver = struct.pack('<i', tx['version']); lt = struct.pack('<I', tx['locktime'])
    prevouts = b''.join(i['outpoint'] for i in tx['inputs'])
    amounts = b''.join(struct.pack('<Q', a) for a in tx['amounts'])
    spks = b''.join(ser_compact_len(len(s)) + s for s in spent_scriptpubkeys)
    seqs = b''.join(struct.pack('<I', i['sequence']) for i in tx['inputs'])
    outs = b''
    for o in tx['outputs']: outs += struct.pack('<Q', o['value']) + ser_compact_len(len(o['script'])) + o['script']
    annex_present = annex is not None
    spend_type = bytes([0 + (1 if annex_present else 0)])
    pre = epoch+ht+ver+lt+sha256(prevouts)+sha256(amounts)+sha256(spks)+sha256(seqs)+sha256(outs)+spend_type+struct.pack('<I', in_index)
    if annex_present: pre += sha256(ser_compact_len(len(annex))+annex)
    return tagged_hash("TapSighash", pre)
annex5 = bytes([0x50, 0x01, 0x02])
dh5 = compute_sighash_keypath(tx5, 0, 0x01, 100000, [spk5], annex=annex5)
sig5 = schnorr_sign(dh5, kp_output_sk) + bytes([0x01])
add('keypath_with_annex', tx5, 0, 100000, [spk5], b'', [sig5, annex5], spk5, 1)

# ---- vector 6: CHECKSIGADD 2-of-2 (mirrors taproot_spend.h's
# scriptpath_checksigadd shape but with the internal pubkey/control block
# this test actually needs, which that header doesn't export) ----
def sk_with_clean_pubkey(seed):
    """Pick a seckey whose x-only pubkey contains no 0xab byte -- taproot_
    verify_input deliberately (and documentedly) refuses ANY tapscript
    containing a raw 0xab byte as a conservative stand-in for not tracking
    OP_CODESEPARATOR position (see its header comment); a coincidental 0xab
    inside a pubkey embedded as script PUSH DATA would trip that same guard
    and isn't what this vector is testing. ~12.5% chance per random key, so
    just probe forward from the seed."""
    sk = seed
    while 0xab in ser_xonly(point_mul(G, sk)):
        sk = (sk + 1) % N
    return sk
sk6a = sk_with_clean_pubkey(0x6677889900aabbccddeeff001122334455667788990011223344556677889b)
sk6b = sk_with_clean_pubkey(0x778899aabbccddeeff00112233445566778899001122334455667788990a1c)
Pk6a = ser_xonly(point_mul(G, sk6a)); Pk6b = ser_xonly(point_mul(G, sk6b))
# witness (bottom..top): [sig_b, sig_a]; script: <pka> CHECKSIGADD <pkb> CHECKSIGADD 2 EQUAL
# OP_CHECKSIGADD stack semantics (sig num pubkey -- num), Core interpreter.cpp:
# each call needs an accumulator ALREADY on the stack below the pubkey --
# OP_0 seeds it before the first check (a real signature is not a valid
# scriptnum, so omitting this fails at the very first CHECKSIGADD).
leaf6 = bytes([0x00]) + bytes([0x20]) + Pk6a + bytes([0xba]) + bytes([0x20]) + Pk6b + bytes([0xba, 0x52, 0x87])
lh6 = tap_leaf_hash(0xc0, leaf6)
output_x6 = taproot_tweak_pubkey(internal_x, lh6)
tx6 = mk_tx()
spk6 = bytes([0x51, 0x20]) + output_x6
dh6 = compute_sighash(tx6, 0, 0x01, 100000, [spk6], lh6)
sig6a = schnorr_sign(dh6, sk6a) + bytes([0x01])
sig6b = schnorr_sign(dh6, sk6b) + bytes([0x01])
control6 = bytes([0xc0]) + internal_x
add('scriptpath_checksigadd_2of2', tx6, 0, 100000, [spk6], control6,
    [sig6b, sig6a, leaf6, control6], spk6, 1)

# ---- emit C header ----
with open('tests/taproot_scriptpath_vec.h', 'w') as f:
    f.write('/* Auto-generated by validation/gen_taproot_scriptpath_vectors.py. */\n')
    f.write('#pragma once\n#include <stdint.h>\n')
    for i, v in enumerate(vectors):
        txb = ser_tx(v['tx'])
        po = b''.join(i2['outpoint'] for i2 in v['tx']['inputs'])
        am = b''.join(struct.pack('<Q', a) for a in v['tx']['amounts'])
        sp = b''.join(ser_compact_len(len(s)) + s for s in v['spks'])
        f.write(f'\n/* {v["name"]} */\n')
        f.write(f'static const uint8_t sp{i}_tx[] = {carr(txb)};\n')
        f.write(f'static const int sp{i}_txlen = {len(txb)};\n')
        f.write(f'static const uint8_t sp{i}_prevouts[] = {carr(po)};\n')
        f.write(f'static const uint8_t sp{i}_amounts[] = {carr(am)};\n')
        f.write(f'static const uint8_t sp{i}_spks[] = {carr(sp)};\n')
        f.write(f'static const int sp{i}_numin = {len(v["tx"]["inputs"])};\n')
        f.write(f'static const uint8_t sp{i}_spk[] = {carr(v["spk"])};\n')
        for j, w in enumerate(v['witness']):
            f.write(f'static const uint8_t sp{i}_w{j}[] = {carr(w)};\n')
        f.write(f'static const uint8_t* sp{i}_wit[] = {{ ' + ', '.join(f'sp{i}_w{j}' for j in range(len(v['witness']))) + ' };\n')
        f.write(f'static const uint32_t sp{i}_witlen[] = {{ ' + ', '.join(str(len(w)) for w in v['witness']) + ' };\n')
    f.write('\ntypedef struct {\n  const char* name;\n  const uint8_t* tx; int txlen;\n')
    f.write('  const uint8_t* prevouts; const uint8_t* amounts; const uint8_t* spks; int numin;\n')
    f.write('  const uint8_t* spk;\n  const uint8_t* const* wit; const uint32_t* witlen; uint32_t nwit;\n')
    f.write('  int expect;\n} sp_vec_t;\n')
    f.write('static const sp_vec_t sp_vectors[] = {\n')
    for i, v in enumerate(vectors):
        f.write(f'  {{ "{v["name"]}", sp{i}_tx, sp{i}_txlen, sp{i}_prevouts, sp{i}_amounts, sp{i}_spks, sp{i}_numin, '
                f'sp{i}_spk, sp{i}_wit, sp{i}_witlen, {len(v["witness"])}, {v["expect"]} }},\n')
    f.write('};\n')
    f.write(f'static const int sp_num_vectors = {len(vectors)};\n')

print("wrote tests/taproot_scriptpath_vec.h with", len(vectors), "vectors")
for v in vectors:
    print("  %-32s expect=%d" % (v['name'], v['expect']))
