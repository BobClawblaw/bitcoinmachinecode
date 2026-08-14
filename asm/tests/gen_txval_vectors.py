#!/usr/bin/env python3
"""gen_txval_vectors.py -- generate signed whole-transaction vectors for
tests/test_txval.c.

Reuses the exact SIGHASH_ALL preimage layout implemented by
asm/bitcoin_sighash.asm so the embedded signatures are genuine spends that the
asm verify_p2pkh path accepts. Signs each input with a fresh SECP256K1 key
(fully self-contained pure-Python RFC6979 ECDSA, low-S, canonical DER), builds
scriptSig = <der||01> <pub>. The same maths is cross-checked by
ecdsa_pure.py (independent pure-Python verify).

Emits tests/txval_vec.h with hex constants consumed by test_txval.c.
"""
import hashlib
import hmac

# secp256k1 params
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def varint(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')


def _ecc_add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0: return None
    if p == q:
        lam = (3 * p[0] * p[0]) * pow(2 * p[1], P - 2, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], P - 2, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    y = (lam * (p[0] - x) - p[1]) % P
    return (x, y)


def _ecc_mul(k, pt):
    r = None
    while k:
        if k & 1: r = _ecc_add(r, pt)
        pt = _ecc_add(pt, pt)
        k >>= 1
    return r


def pubkey(priv):
    return _ecc_mul(priv, G)


def pubkey_data(priv):
    """Compressed 33-byte SEC1 pubkey (03/02 || x). Parity is the LOW bit of y."""
    Q = pubkey(priv)
    x, y = Q
    prefix = 2 if (y & 1) == 0 else 3
    return bytes([prefix]) + x.to_bytes(32, 'big')


def hash160(b):
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()


def p2pkh_script(pub):
    # OP_DUP OP_HASH160 <20> hash160(pub) OP_EQUALVERIFY OP_CHECKSIG
    h = hash160(pub)
    return bytes([0x76, 0xa9, 0x14]) + h + bytes([0x88, 0xac])


def _rfc6979_k(priv, z):
    x = priv.to_bytes(32, 'big')
    h1 = z.to_bytes(32, 'big')
    V = b'\x01' * 32
    K = b'\x00' * 32
    K = hmac.new(K, V + b'\x00' + x + h1, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b'\x01' + x + h1, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = int.from_bytes(V, 'big')
        if 1 <= k < N:
            return k
        K = hmac.new(K, V + b'\x00', hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def sign(priv, z):
    """ECDSA sign message z (the raw 32-byte digest) with private key priv."""
    k = _rfc6979_k(priv, z)
    R = _ecc_mul(k, G)
    r = R[0] % N
    if r == 0: raise RuntimeError('r=0')
    s = (pow(k, N - 2, N) * (z + r * priv)) % N
    if s == 0: raise RuntimeError('s=0')
    if s > N // 2:      # normalize to low-S
        s = N - s
    return r, s


def sign_der(priv, z):
    r, s = sign(priv, z)

    def enc_int(x):
        b = x.to_bytes(32, 'big').lstrip(b'\x00') or b'\x00'
        if b[0] & 0x80:
            b = b'\x00' + b
        return b'\x02' + bytes([len(b)]) + b
    body = enc_int(r) + enc_int(s)
    return b'\x30' + bytes([len(body)]) + body


def build_tx(version, inputs, outputs, locktime):
    """inputs: list of (txid32, index, script_sig) ; outputs: list of (value,script)"""
    out = version.to_bytes(4, 'little')
    out += varint(len(inputs))
    for txid, idx, ss in inputs:
        out += txid + idx.to_bytes(4, 'little')
        out += varint(len(ss)) + ss
        out += b'\xff\xff\xff\xff'  # sequence
    out += varint(len(outputs))
    for val, sc in outputs:
        out += val.to_bytes(8, 'little')
        out += varint(len(sc)) + sc
    out += locktime.to_bytes(4, 'little')
    return out


def sighash_all(tx, input_index, prevout_script):
    """Replicate asm bitcoin_sighash.asm preimage construction."""
    # parse
    pos = 0
    version = int.from_bytes(tx[0:4], 'little')
    pos = 4
    # n_in
    b0 = tx[pos]
    if b0 < 0xfd:
        n_in = b0; pos += 1
    elif b0 == 0xfd:
        n_in = int.from_bytes(tx[pos+1:pos+3], 'little'); pos += 3
    elif b0 == 0xfe:
        n_in = int.from_bytes(tx[pos+1:pos+5], 'little'); pos += 5
    else:
        n_in = int.from_bytes(tx[pos+1:pos+9], 'little'); pos += 9

    inputs_raw = []
    for _ in range(n_in):
        prevout = tx[pos:pos+32]; idx = int.from_bytes(tx[pos+32:pos+36], 'little'); pos += 36
        b0 = tx[pos]
        if b0 < 0xfd:
            sl = b0; pos += 1
        elif b0 == 0xfd:
            sl = int.from_bytes(tx[pos+1:pos+3], 'little'); pos += 3
        elif b0 == 0xfe:
            sl = int.from_bytes(tx[pos+1:pos+5], 'little'); pos += 5
        else:
            sl = int.from_bytes(tx[pos+1:pos+9], 'little'); pos += 9
        script = tx[pos:pos+sl]; pos += sl
        seq = tx[pos:pos+4]; pos += 4
        inputs_raw.append((prevout, idx, script, seq))
    tail = tx[pos:]  # n_out..locktime

    # build preimage
    pre = version.to_bytes(4, 'little')
    pre += varint(n_in)
    for j, (prevout, idx, _sc, seq) in enumerate(inputs_raw):
        pre += prevout + idx.to_bytes(4, 'little')
        if j == input_index:
            pre += varint(len(prevout_script)) + prevout_script
        else:
            pre += b'\x00'
        pre += seq
    pre += tail
    pre += b'\x01\x00\x00\x00'  # SIGHASH_ALL
    return dsha(pre)


# ---------------------------------------------------------------------------
# Vector 1: valid 2-input / 2-output tx (real per-input signatures).
# Inputs 0,1 fund 50000+40000 = 90000; outputs 40000 + 30000 = 70000 (fee 20000).
# ---------------------------------------------------------------------------
priv0 = 0x1111111111111111111111111111111111111111111111111111111111111111
priv1 = 0x2222222222222222222222222222222222222222222222222222222222222222
in0_txid = bytes(range(32))           # outpoint txid (opaque to validator)
in1_txid = bytes(range(32, 64))
in0_idx = 0
in1_idx = 1
pub0 = pubkey_data(priv0)
pub1 = pubkey_data(priv1)
sc0 = p2pkh_script(pub0)
sc1 = p2pkh_script(pub1)

# placeholder scriptSigs
tx_v1 = build_tx(1, [(in0_txid, in0_idx, b''), (in1_txid, in1_idx, b'')],
                 [(40000, sc0), (30000, sc1)], 0)
z0 = int.from_bytes(sighash_all(tx_v1, 0, sc0), 'big')
z1 = int.from_bytes(sighash_all(tx_v1, 1, sc1), 'big')
sig0 = sign_der(priv0, z0) + b'\x01'
sig1 = sign_der(priv1, z1) + b'\x01'
ss0 = bytes([len(sig0)]) + sig0 + bytes([len(pub0)]) + pub0
ss1 = bytes([len(sig1)]) + sig1 + bytes([len(pub1)]) + pub1
tx_v1 = build_tx(1, [(in0_txid, in0_idx, ss0), (in1_txid, in1_idx, ss1)],
                 [(40000, sc0), (30000, sc1)], 0)

# ---------------------------------------------------------------------------
# Vector 2: valid 1-input / 1-output tx. input 100000 -> output 90000 (fee 10000)
# ---------------------------------------------------------------------------
priv2 = 0x3333333333333333333333333333333333333333333333333333333333333333
in2_txid = bytes(range(64, 96))
in2_idx = 5
pub2 = pubkey_data(priv2)
sc2 = p2pkh_script(pub2)
tx_v2 = build_tx(2, [(in2_txid, in2_idx, b'')], [(90000, sc2)], 0)
z2 = int.from_bytes(sighash_all(tx_v2, 0, sc2), 'big')
sig2 = sign_der(priv2, z2) + b'\x01'
ss2 = bytes([len(sig2)]) + sig2 + bytes([len(pub2)]) + pub2
tx_v2 = build_tx(2, [(in2_txid, in2_idx, ss2)], [(90000, sc2)], 0)

# ---------------------------------------------------------------------------
# Vector 3: DOUBLE-SPEND. References an outpoint that is NOT in the UTXO set.
# (Same shape as v1 but input prevout is unknown to the store.)
# ---------------------------------------------------------------------------
tx_v3 = build_tx(1, [(bytes(range(96,128)), 0, b'\x00')],
                 [(10000, sc0)], 0)   # sig irrelevant; never reached

# ---------------------------------------------------------------------------
# Vector 4: FEE FAIL. 1 input of value 50000 -> output 60000 (spends more than
# it has). Uses a UTXO-funded input but asserts the invalid fee.
# ---------------------------------------------------------------------------
priv4 = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
in4_txid = bytes(range(128,160))
in4_idx = 7
pub4 = pubkey_data(priv4)
sc4 = p2pkh_script(pub4)
tx_v4 = build_tx(1, [(in4_txid, in4_idx, b'')], [(60000, sc4)], 0)
z4 = int.from_bytes(sighash_all(tx_v4, 0, sc4), 'big')
sig4 = sign_der(priv4, z4) + b'\x01'
ss4 = bytes([len(sig4)]) + sig4 + bytes([len(pub4)]) + pub4
tx_v4 = build_tx(1, [(in4_txid, in4_idx, ss4)], [(60000, sc4)], 0)

# ---------------------------------------------------------------------------
# Vector 5: SIG FAIL. Valid fee, input present in UTXO, but scriptSig is empty
# (no signature) -> verify_p2pkh returns 0.
# ---------------------------------------------------------------------------
priv5 = 0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
in5_txid = bytes(range(160,192))
in5_idx = 9
pub5 = pubkey_data(priv5)
sc5 = p2pkh_script(pub5)
tx_v5 = build_tx(1, [(in5_txid, in5_idx, b'')], [(50000, sc5)], 0)
# no signature at all

# ---------------------------------------------------------------------------
# Vector 6: SIG FAIL v2. Present + valid fee, but a genuine-looking signature
# that does NOT correspond to the correct key (wrong signer for this prevout).
# ---------------------------------------------------------------------------
priv_wrong = 0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
in6_txid = bytes(range(192,224))
in6_idx = 3
pub6 = pubkey_data(priv5)           # prevout is owned by priv5
sc6 = p2pkh_script(pub6)
tx_v6 = build_tx(1, [(in6_txid, in6_idx, b'')], [(50000, sc6)], 0)
z6 = int.from_bytes(sighash_all(tx_v6, 0, sc6), 'big')
sig6 = sign_der(priv_wrong, z6) + b'\x01'     # signed by WRONG key
ss6 = bytes([len(sig6)]) + sig6 + bytes([len(pub6)]) + pub6
tx_v6 = build_tx(1, [(in6_txid, in6_idx, ss6)], [(50000, sc6)], 0)

# ---------------------------------------------------------------------------
# Emit header
# ---------------------------------------------------------------------------
def chex(b):
    return ''.join('%02x' % x for x in b)

h = []
h.append('/* txval_vec.h -- generated by gen_txval_vectors.py. Do not edit. */')
h.append('#ifndef TXVAL_VEC_H')
h.append('#define TXVAL_VEC_H')
h.append('')
# UTXO preloads: (txid, index, value, prevout_script_hex)
utxos = [
    (in0_txid, in0_idx, 50000, sc0, 'v1_input0'),
    (in1_txid, in1_idx, 40000, sc1, 'v1_input1'),
    (in2_txid, in2_idx, 100000, sc2, 'v2_input0'),
    (in4_txid, in4_idx, 50000, sc4, 'v4_input0'),
    (in5_txid, in5_idx, 60000, sc5, 'v5_input0'),
    (in6_txid, in6_idx, 60000, sc6, 'v6_input0'),
]
for txid, idx, val, sc, nm in utxos:
    h.append('static const char U_%s_TXID[] = "%s";' % (nm, chex(txid)))
    h.append('static const unsigned long U_%s_IDX = %d;' % (nm, idx))
    h.append('static const unsigned long long U_%s_VAL = %dULL;' % (nm, val))
    h.append('static const char U_%s_SCRIPT[] = "%s";' % (nm, chex(sc)))
    h.append('')
h.append('static const char TX_V1[] = "%s";' % chex(tx_v1))
h.append('static const char TX_V2[] = "%s";' % chex(tx_v2))
h.append('static const char TX_V3[] = "%s";' % chex(tx_v3))
h.append('static const char TX_V4[] = "%s";' % chex(tx_v4))
h.append('static const char TX_V5[] = "%s";' % chex(tx_v5))
h.append('static const char TX_V6[] = "%s";' % chex(tx_v6))
h.append('')
h.append('#endif /* TXVAL_VEC_H */')
h.append('')

open('asm/tests/txval_vec.h', 'w').write('\n'.join(h) + '\n')
print('wrote asm/tests/txval_vec.h')

# sanity: print lengths
for nm, t in [('v1', tx_v1), ('v2', tx_v2), ('v3', tx_v3),
              ('v4', tx_v4), ('v5', tx_v5), ('v6', tx_v6)]:
    print(nm, len(t), 'bytes')
print('sighash v1 in0 =', chex(z0.to_bytes(32,'big'))[:16], '...')
print('pub0 =', chex(pub0))
print('sc0  =', chex(sc0))
print('sc1  =', chex(sc1))
print('sc2  =', chex(sc2))
print('sc4  =', chex(sc4))
print('sc5  =', chex(sc5))
print('sc6  =', chex(sc6))
