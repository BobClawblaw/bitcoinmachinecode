#!/usr/bin/env python3
"""BIP341 Taproot sighash + spend vector oracle.

Implements the BIP341 SigMsg / sighash independently (following the BIP and the
bitcoin-core reference), and generates:
  (1) reference sighash vectors for taproot_sighash() ASM, and
  (2) a small set of signed P2TR key-path and script-path spends that the C
      harness validates end-to-end.

We use the `ecdsa` library for field/point arithmetic + Schnorr signing.
All serialization is done here independently so the ASM is cross-checked.
"""
import hashlib, json, struct
from ecdsa import SECP256k1, ellipticcurve
from ecdsa.ellipticcurve import Point, INFINITY

P = SECP256k1.curve.p()
N = SECP256k1.order
G = SECP256k1.generator
A = SECP256k1.curve.a()
B = SECP256k1.curve.b()

def sha256(b): return hashlib.sha256(b).digest()
def sha256d(b): return sha256(sha256(b))
def tagged_hash(tag, msg):
    t = sha256(tag.encode())
    return sha256(t + t + msg)

def ser_compact(p):
    """Serialize point to 33-byte compressed."""
    if p == INFINITY:
        raise ValueError("infinity")
    x = p.x(); y = p.y()
    return bytes([2 | (y & 1)]) + x.to_bytes(32, 'big')

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

def has_even_y(p):
    return (p.y() % 2) == 0

def schnorr_sign(msg, sk, aux=b''):
    d = sk % N
    if d == 0: raise ValueError("bad sk")
    P_ = point_mul(G, d)
    d_ = d if has_even_y(P_) else N - d
    # BIP340 canonical nonce (RFC6979-free): aux defaults to 32 zero bytes
    t = int.from_bytes(tagged_hash("BIP0340/aux", aux if aux else bytes(32)), 'big') ^ d_
    seed = int.to_bytes(t, 32, 'big') + ser_xonly(P_) + msg
    k0 = int.from_bytes(tagged_hash("BIP0340/nonce", seed), 'big') % N
    if k0 == 0: raise ValueError("zero nonce")
    R = point_mul(G, k0)
    k = k0 if has_even_y(R) else N - k0
    e = int.from_bytes(tagged_hash("BIP0340/challenge", ser_xonly(R) + ser_xonly(P_) + msg), 'big') % N
    sig = ser_xonly(R) + int.to_bytes((k + e * d_) % N, 32, 'big')
    return sig

def schnorr_verify(msg, pk, sig):
    if len(pk) != 32 or len(sig) != 64: return False
    try: P_ = lift_x(pk)
    except ValueError: return False
    r = int.from_bytes(sig[0:32], 'big'); s = int.from_bytes(sig[32:64], 'big')
    if r >= P or s >= N: return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge", sig[0:32] + pk + msg), 'big') % N
    R = point_add(point_mul(G, s), point_mul(P_, N - e))
    if R == INFINITY or not has_even_y(R): return False
    return ser_xonly(R) == sig[0:32]

# ---------- BIP341 sigmsg / sighash ----------
def taproot_tweak_pubkey(pubkey, h):
    t = int.from_bytes(tagged_hash("TapTweak", pubkey + (h or b'')), 'big')
    if t >= N: return None
    P_ = lift_x(pubkey)
    Q = point_add(P_, point_mul(G, t))
    if Q == INFINITY: return None
    return ser_xonly(Q)

def taproot_tweak_seckey(seckey0, h):
    P0 = point_mul(G, seckey0)
    if not has_even_y(P0): seckey0 = N - seckey0
    t = int.from_bytes(tagged_hash("TapTweak", ser_xonly(P0) + (h or b'')), 'big')
    if t >= N: return None
    return (seckey0 + t) % N, ser_xonly(point_mul(G, (seckey0 + t) % N))

def tap_leaf_hash(leaf_version, script):
    return tagged_hash("TapLeaf", bytes([leaf_version]) + ser_compact_len(len(script)) + script)

def tap_branch_hash(a, b):
    if int.from_bytes(a, 'big') > int.from_bytes(b, 'big'):
        a, b = b, a
    return tagged_hash("TapBranch", a + b)

def ser_compact_len(n):
    if n < 0xfd: return bytes([n])
    elif n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    else: return b'\xff' + struct.pack('<Q', n)

def write_varint(n):
    if n < 0xfd: return bytes([n])
    elif n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    else: return b'\xff' + struct.pack('<Q', n)

def compute_sighash(script, tx, in_index, hash_type, amount, spent_scriptpubkeys,
                    sigversion, spend_type, leaf_hash=None, annex=None,
                    codesep_pos=0xffffffff):
    """Return (Sighash, SigMsg-epoch-prefixed) for the taproot sighash (BIP341 + BIP342 ext).

    Returns the full final hash input = 0x00 || SigMsg(hash_type, ext_flag) || ext,
    plus the same bytes, so the harness can compare against the ASM preimage.
    tapleaf_hash: 32 bytes for script-path (BIP342 ext), None for key-path.
    """
    raw_ht = hash_type
    eff_ht = hash_type if hash_type != 0 else 1  # DEFAULT behaves like ALL for selection
    n_in = len(tx['inputs'])
    outpoint = tx['inputs'][in_index]['outpoint']
    spk = spent_scriptpubkeys[in_index]
    nSequence = struct.pack('<I', tx['inputs'][in_index]['sequence'])

    anyonecanpay = (eff_ht & 0x80) != 0
    is_single = (eff_ht & 0x03) == 3
    is_none = (eff_ht & 0x03) == 2

    ext_flag = 1 if leaf_hash is not None else 0
    annex_present = 0

    # ----- SigMsg (starts with hash_type) -----
    m = bytes([raw_ht]) + struct.pack('<i', tx['version']) + struct.pack('<I', tx['locktime'])
    if not anyonecanpay:
        m += sha256(b''.join(tx['inputs'][i]['outpoint'] for i in range(n_in)))
        m += sha256(b''.join(struct.pack('<Q', amt) for amt in tx['amounts']))
        m += sha256(b''.join(ser_compact_len(len(s)) + s for s in spent_scriptpubkeys))
        m += sha256(b''.join(struct.pack('<I', tx['inputs'][i]['sequence']) for i in range(n_in)))
    # sha_outputs when not NONE and not SINGLE
    if not is_none and not is_single:
        m += sha256(b''.join(ser_txout(o) for o in tx['outputs']))
    # spend_type
    m += bytes([ext_flag * 2 + annex_present])
    if anyonecanpay:
        m += outpoint
        m += struct.pack('<Q', amount)
        m += ser_compact_len(len(spk)) + spk
        m += nSequence
    else:
        m += struct.pack('<I', in_index)
    # annexx
    if annex_present:
        m += sha256(ser_compact_len(len(annex)) + annex)
    # single output
    if is_single:
        if in_index < len(tx['outputs']):
            m += sha256(ser_txout(tx['outputs'][in_index]))
        else:
            m += bytes(32)

    # ----- BIP342 ext (script-path only) -----
    ext = b''
    if leaf_hash is not None:
        ext += leaf_hash          # tapleaf_hash
        ext += b'\x00'            # key_version (0x00)
        ext += struct.pack('<I', codesep_pos)
    # ----- final hash = TaggedHash("TapSighash", 0x00 || SigMsg || ext) -----
    final_in = b'\x00' + m + ext
    return tagged_hash('TapSighash', final_in), final_in

def ser_txout(txout):
    return struct.pack('<Q', txout['value']) + ser_compact_len(len(txout['script'])) + txout['script']

# ---------------- build a signed key-path and script-path example ----------------

def build_contexts():
    """Return dicts with tx data for the C harness to feed the asm sighash."""
    contexts = []
    # One 2-in, 2-out tx (to stress sha_prevouts/amounts/spks over many inputs),
    # signing input index 1 -- exercises the multi-input code path.
    prevout_txid = bytes(range(32))
    prevout_txid2 = bytes(range(32, 64))
    spk_a = bytes.fromhex('76a914' + '11' * 20 + '88ac')  # P2PKH
    spk_b = bytes.fromhex('5120' + '22' * 32)  # P2TR

    tx = {
        'version': 2,
        'locktime': 0x15f900,
        'inputs': [
            {'outpoint': prevout_txid + struct.pack('<I', 0), 'sequence': 0xfffffffd},
            {'outpoint': prevout_txid2 + struct.pack('<I', 3), 'sequence': 0xfffffffe},
        ],
        'outputs': [
            {'value': 50000, 'script': bytes.fromhex('0014' + '33' * 20)},
            {'value': 60000, 'script': bytes.fromhex('5120' + '44' * 32)},
        ],
        'amounts': [100000, 200000],
    }
    spent_spks = [spk_a, spk_b]

    # key-path sighash vectors, both hash_types
    for ht in (0x00, 0x01):
        dh, pre = compute_sighash(spk_b, tx, 1, ht, 200000, spent_spks, 2, 0, leaf_hash=None)
        contexts.append({
            'name': f'keypath_in1_ht{ht:02x}',
            'tx': tx, 'index': 1, 'hash_type': ht, 'amount': 200000,
            'spks': spent_spks, 'spend_type': 0, 'leaf': None,
            'sighash': dh.hex(), 'pre': pre.hex(),
        })
    # key-path sighash for input 0
    dh, _ = compute_sighash(spk_a, tx, 0, 0x00, 100000, spent_spks, 2, 0, leaf_hash=None)
    contexts.append({'name': 'keypath_in0_ht00', 'tx': tx, 'index': 0, 'hash_type': 0,
                     'amount': 100000, 'spks': spent_spks, 'spend_type': 0, 'leaf': None,
                     'sighash': dh.hex(), 'pre': _.hex()})

    # ---- SIGNED key-path spend: 1-in P2TR, sign the key-path sighash ----
    kpsk = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    kpP = point_mul(G, kpsk)
    if not has_even_y(kpP): kpsk = N - kpsk
    kp_internal = ser_xonly(point_mul(G, kpsk))
    kp_output = taproot_tweak_pubkey(kp_internal, None)   # key-path, no script tree
    assert kp_output is not None
    kp_tx = {
        'version': 2, 'locktime': 0,
        'inputs': [{'outpoint': bytes(range(32)) + struct.pack('<I', 2), 'sequence': 0xfffffffd}],
        'outputs': [{'value': 99000, 'script': bytes.fromhex('5120' + '77' * 32)}],
        'amounts': [100000],
    }
    kp_spk = [bytes([0x51, 0x20]) + kp_output]
    kpdh, kppre = compute_sighash(kp_spk[0], kp_tx, 0, 0x01, 100000, kp_spk, 2, 0, leaf_hash=None)
    # BIP341 key-path: sign with the TWEAKED secret (output key), not internal
    tweaked_sk, _tweaked_pk = taproot_tweak_seckey(kpsk, b'')
    assert _tweaked_pk == kp_output
    kpsig = schnorr_sign(kpdh, tweaked_sk) + bytes([0x01])
    assert schnorr_verify(kpdh, kp_output, kpsig[:64])
    contexts.append({
        'name': 'keypath_signed', 'tx': kp_tx, 'index': 0, 'hash_type': 0x01,
        'amount': 100000, 'spks': kp_spk, 'spend_type': 0, 'leaf': None,
        'sighash': kpdh.hex(), 'pre': kppre.hex(),
        'output_x': kp_output.hex(), 'sig': kpsig.hex(), 'key': kp_output.hex(),
    })

    # script-path: single leaf script OP_CHECKSIG (0x20 <pk> 0xac) -> tapscript
    sk = 0x1a2b3c4d5e6f7081728394059607a8b9c0d1e2f3a4b5c6d7e8f900112233445566
    Pk = ser_xonly(point_mul(G, sk))
    leaf_script = bytes([0x20]) + Pk + bytes([0xac])   # <pk> CHECKSIG
    lv = 0xc0
    lh = tap_leaf_hash(lv, leaf_script)
    # internal key (some valid random point) -- even
    isk = 0x0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a
    IP = point_mul(G, isk)
    if not has_even_y(IP):
        isk = N - isk; IP = point_mul(G, isk)
    internal_x = ser_xonly(IP)
    output_x = taproot_tweak_pubkey(internal_x, lh)
    assert output_x is not None
    # sign the tapscript: schnorr over BIP341 script-path sighash, sig = schnorr||0x01
    sp_tx = {
        'version': 2, 'locktime': 0,
        'inputs': [{'outpoint': bytes(range(32)) + struct.pack('<I', 1), 'sequence': 0xfffffffe}],
        'outputs': [{'value': 90000, 'script': bytes.fromhex('5120' + '55' * 32)}],
        'amounts': [100000],
    }
    sspk = [bytes([0x51, 0x20]) + output_x]
    # need sighash using tapscript spk = the P2TR script
    dh, pre = compute_sighash(bytes([0x51, 0x20]) + output_x, sp_tx, 0, 0x01, 100000, sspk, 2, 1, leaf_hash=lh)
    sig = schnorr_sign(dh, sk) + bytes([0x01])  # SIGHASH_ALL
    assert schnorr_verify(dh, Pk, sig[:64])
    contexts.append({
        'name': 'scriptpath_checksig', 'tx': sp_tx, 'index': 0, 'hash_type': 0x01,
        'amount': 100000, 'spks': sspk, 'spend_type': 1, 'leaf': lh.hex(),
        'sighash': dh.hex(), 'pre': pre.hex(),
        'internal_x': internal_x.hex(), 'output_x': output_x.hex(),
        'leaf_script': leaf_script.hex(), 'leaf_version': lv, 'sig': sig.hex(),
        'key': Pk.hex(),
    })

    # CHECKSIGADD (multikey) tapscript: <pk1> CHECKSIGADD <pk2> CHECKSIGADD 1 EQUAL
    sk1 = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab
    sk2 = 0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc
    Pk1 = ser_xonly(point_mul(G, sk1)); Pk2 = ser_xonly(point_mul(G, sk2))
    # stack (witness): [sig2, sig1]; then script: <pk1> CHECKSIGADD <pk2> CHECKSIGADD 1 EQUAL
    #   -> after pk1 CHECKSIGADD: stack [sig1, 1]; after pk2 CHECKSIGADD: [1+1]; 1 EQUAL passes
    leaf_script2 = bytes([0x20]) + Pk1 + bytes([0xba]) + bytes([0x20]) + Pk2 + bytes([0xba, 0x51, 0x87])
    lh2 = tap_leaf_hash(0xc0, leaf_script2)
    output_x2 = taproot_tweak_pubkey(internal_x, lh2)
    assert output_x2 is not None
    sp2_tx = {
        'version': 2, 'locktime': 0,
        'inputs': [{'outpoint': bytes(range(32)) + struct.pack('<I', 1), 'sequence': 0xfffffffe}],
        'outputs': [{'value': 90000, 'script': bytes.fromhex('5120' + '66' * 32)}],
        'amounts': [100000],
    }
    sspk2 = [bytes([0x51, 0x20]) + output_x2]
    dh2, pre2 = compute_sighash(sspk2[0], sp2_tx, 0, 0x01, 100000, sspk2, 2, 1, leaf_hash=lh2)
    sig1 = schnorr_sign(dh2, sk1) + bytes([0x01])
    sig2 = schnorr_sign(dh2, sk2) + bytes([0x01])
    assert schnorr_verify(dh2, Pk1, sig1[:64]) and schnorr_verify(dh2, Pk2, sig2[:64])
    contexts.append({
        'name': 'scriptpath_checksigadd', 'tx': sp2_tx, 'index': 0, 'hash_type': 0x01,
        'amount': 100000, 'spks': sspk2, 'spend_type': 1, 'leaf': lh2.hex(),
        'sighash': dh2.hex(), 'pre': pre2.hex(),
        'internal_x': internal_x.hex(), 'output_x': output_x2.hex(),
        'leaf_script': leaf_script2.hex(), 'leaf_version': 0xc0,
        'sig1': sig1.hex(), 'sig2': sig2.hex(), 'key1': Pk1.hex(), 'key2': Pk2.hex(),
        'stack_init': [sig2.hex(), sig1.hex()],  # witness stack order
    })
    return contexts

if __name__ == '__main__':
    ctxs = build_contexts()
    with open('tests/taproot_vec.h', 'w') as f:
        f.write('/* Auto-generated by validation/gen_taproot_vectors.py */\n')
        f.write('#pragma once\n')
        f.write('#include <stdint.h>\n')
        for i, c in enumerate(ctxs):
            f.write(f'\n/* {c["name"]} */\n')
            f.write(f'static const uint8_t tv{i}_pre[] = {{ {",".join("0x%02x"%b for b in bytes.fromhex(c["pre"]))} }};\n')
            f.write(f'static const uint8_t tv{i}_sighash[32] = {{ {",".join("0x%02x"%b for b in bytes.fromhex(c["sighash"]))} }};\n')
            if c['leaf'] is not None:
                L = ','.join('0x%02x' % b for b in bytes.fromhex(c['leaf']))
                f.write('static const uint8_t tv%d_leaf[32] = { %s };\n' % (i, L))
        f.write('\n')
        # write a compact table
        f.write('typedef struct { const char* name; const uint8_t* pre; int prelen; ')
        f.write('const uint8_t* sighash; int index; int hash_type; uint64_t amount; int spend_type; ')
        f.write('const uint8_t* leaf; } tvec_t;\n')
        f.write('static const tvec_t taproot_vecs[] = {\n')
        for i, c in enumerate(ctxs):
            leaf_field = '(const uint8_t*)0' if c['leaf'] is None else f'tv{i}_leaf'
            f.write(f'  {{ "{c["name"]}", tv{i}_pre, sizeof(tv{i}_pre), tv{i}_sighash, {c["index"]}, {c["hash_type"]}, {c["amount"]}ull, {c["spend_type"]}, {leaf_field} }},\n')
        f.write('};\n')
        f.write('static const int taproot_num_vecs = %d;\n' % len(ctxs))
    # Also dump a JSON with the spend materials for the C harness
    def hexify(o):
        if isinstance(o, bytes): return o.hex()
        if isinstance(o, dict): return {k: hexify(v) for k, v in o.items()}
        if isinstance(o, list): return [hexify(x) for x in o]
        return o
    with open('tests/taproot_spend.json', 'w') as f:
        json.dump(hexify(ctxs), f, indent=1)

    # ---- taproot_spend.h: full signed-spend materials for the C harness ----
    def ser_tx(tx):
        b = struct.pack('<i', tx['version'])
        b += write_varint(len(tx['inputs']))
        for i in tx['inputs']:
            b += i['outpoint']
            b += b'\x00'  # no scriptSig
            b += struct.pack('<I', i['sequence'])
        b += write_varint(len(tx['outputs']))
        for o in tx['outputs']:
            b += struct.pack('<Q', o['value'])
            b += ser_compact_len(len(o['script'])) + o['script']
        b += struct.pack('<I', tx['locktime'])
        return b
    def prevouts_all(tx):
        return b''.join(i['outpoint'] for i in tx['inputs'])
    def amounts_all(tx):
        return b''.join(struct.pack('<Q', a) for a in tx['amounts'])
    def spks_all(spks):
        return b''.join(ser_compact_len(len(s)) + s for s in spks)
    def carr(b):
        if not b: return '{}'
        return '{ ' + ','.join('0x%02x' % x for x in b) + ' }'

    with open('tests/taproot_spend.h', 'w') as f:
        f.write('/* Auto-generated by validation/gen_taproot_vectors.py -- signed spend materials. */\n')
        f.write('#pragma once\n#include <stdint.h>\n')
        for i, c in enumerate(ctxs):
            txb = ser_tx(c['tx'])
            po = prevouts_all(c['tx'])
            am = amounts_all(c['tx'])
            sp = spks_all(c['spks'])
            f.write(f'\n/* {c["name"]} */\n')
            f.write(f'static const uint8_t ts{i}_tx[] = {carr(txb)};\n')
            f.write(f'static const uint8_t ts{i}_txlen = {len(txb)};\n')
            f.write(f'static const uint8_t ts{i}_prevouts[] = {carr(po)};\n')
            f.write(f'static const uint8_t ts{i}_amounts[] = {carr(am)};\n')
            f.write(f'static const uint8_t ts{i}_spks[] = {carr(sp)};\n')
            f.write(f'static const int ts{i}_numin = {len(c["tx"]["inputs"])};\n')
            f.write(f'static const uint8_t ts{i}_sighash[32] = {carr(bytes.fromhex(c["sighash"]))};\n')
            if 'output_x' in c:
                f.write(f'static const uint8_t ts{i}_output_key[32] = {carr(bytes.fromhex(c["output_x"]))};\n')
            if 'leaf_script' in c:
                f.write(f'static const uint8_t ts{i}_leaf_script[] = {carr(bytes.fromhex(c["leaf_script"]))};\n')
            if 'sig' in c:
                f.write(f'static const uint8_t ts{i}_sig[] = {carr(bytes.fromhex(c["sig"]))};\n')
                f.write(f'static const uint8_t ts{i}_key[32] = {carr(bytes.fromhex(c["key"]))};\n')
            if 'sig1' in c:
                f.write(f'static const uint8_t ts{i}_sig1[] = {carr(bytes.fromhex(c["sig1"]))};\n')
                f.write(f'static const uint8_t ts{i}_sig2[] = {carr(bytes.fromhex(c["sig2"]))};\n')
                f.write(f'static const uint8_t ts{i}_key1[32] = {carr(bytes.fromhex(c["key1"]))};\n')
                f.write(f'static const uint8_t ts{i}_key2[32] = {carr(bytes.fromhex(c["key2"]))};\n')
        f.write('\n')
        f.write('typedef struct {\n  const char* name;\n  const uint8_t* tx; uint32_t txlen;\n')
        f.write('  const uint8_t* prevouts; const uint8_t* amounts; const uint8_t* spks;\n')
        f.write('  int numin; int index; int hash_type; const uint8_t* expect_sighash;\n')
        f.write('  const uint8_t* output_key; const uint8_t* leaf_script; int leaf_len;\n')
        f.write('  const uint8_t* sig; int siglen; const uint8_t* key;\n')
        f.write('  const uint8_t* sig2; int sig2len; const uint8_t* key2;\n} tspend_t;\n')
        f.write('static const tspend_t taproot_spends[] = {\n')
        for i, c in enumerate(ctxs):
            ok = 'ts%d_output_key' % i if 'output_x' in c else '(const uint8_t*)0'
            ls = 'ts%d_leaf_script' % i if 'leaf_script' in c else '(const uint8_t*)0'
            lsl = len(bytes.fromhex(c.get('leaf_script',''))) if 'leaf_script' in c else 0
            sg, sgl = '', 0
            k1 = '(const uint8_t*)0'
            if 'sig' in c:
                sg = 'ts%d_sig' % i; sgl = len(bytes.fromhex(c['sig'])); k1 = 'ts%d_key' % i
            s2 = '(const uint8_t*)0'; s2l = 0; k2 = '(const uint8_t*)0'
            if 'sig1' in c:
                sg = 'ts%d_sig1' % i; sgl = len(bytes.fromhex(c['sig1'])); k1 = 'ts%d_key1' % i
                s2 = 'ts%d_sig2' % i; s2l = len(bytes.fromhex(c['sig2'])); k2 = 'ts%d_key2' % i
            f.write('  { "%s", ts%d_tx, sizeof(ts%d_tx), ts%d_prevouts, ts%d_amounts, ts%d_spks, '
                    'ts%d_numin, %d, %d, ts%d_sighash, %s, %s, %d, %s, %d, %s, %s, %d, %s },\n' % (
                c['name'], i,i,i,i,i, i, c['index'], c['hash_type'], i,
                ok, ls, lsl, sg or '(const uint8_t*)0', sgl, k1, s2 or '(const uint8_t*)0', s2l, k2))
        f.write('};\n')
        f.write('static const int taproot_num_spends = %d;\n' % len(ctxs))

    print("wrote tests/taproot_vec.h, tests/taproot_spend.h and tests/taproot_spend.json with", len(ctxs), "vectors")
    for c in ctxs:
        print("  %-28s sighash=%s" % (c['name'], c['sighash'][:16]))
