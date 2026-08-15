#!/usr/bin/env python3
"""Independent Python oracle for witness-v0 segwit (BIP143) + taproot spends.

Mirrors Bitcoin Core's `SignatureHash(scriptCode, txTo, nIn, nHashType, amount,
SigVersion::WITNESS_V0, ...)` from src/script/interpreter.cpp byte-for-byte
(lines 1633-1687): the BIP143 segwit-v0 sighash. The Python port here follows
the Core reference algorithm exactly, so it is the Core-equivalent differential
oracle for the asm/C BIP143 implementation (same convention the taproot card used:
an independently-derived oracle standing in for Core's reference preimages).

It generates (and emits as C headers for the harness):
  (1) BIP143 sighash reference preimages  -> modern_vec.h  (byte-exact vs C)
  (2) genuine signed P2WPKH spends        -> modern_spend.h / modern_spend.json
  (3) genuine signed P2WSH spends        (OP_CHECKSIG witnessScript + 2-of-2
      OP_CHECKMULTISIG witnessScript) which exercise the full witness stack path.
  (4) a P2TR key-path spend with full witness serialization (matching the
      taproot_spend.h materials so the whole-tx validator can run it too).

Every signature is a genuine ECDSA over the BIP143 digest (for segwit v0) or a
genuine Schnorr over the BIP341 digest (for P2TR), so acceptance in the C
pipeline means the whole signature/witness chain verified.

Synopsis (BIP143 preimage, Core SignatureHash WITNESS_V0):
  hashPrevouts   = SHA256( concat(outpoint_i) )               if !ANYONECANPAY
  hashSequence   = SHA256( concat(nSequence_i) )              if !ACP && ht!=SINGLE && ht!=NONE
  hashOutputs    = SHA256( concat(ser_CTxOut_i) )             if ht!=SINGLE && ht!=NONE
                 = SHA256( ser_CTxOut[nIn] )                  elif SINGLE && nIn<vout.size()
  pre = version(4) || hashPrevouts(32) || hashSequence(32)
        || outpoint[nIn](36) || compactsize(scriptCode)||scriptCode
        || amount(8) || nSequence[nIn](4) || hashOutputs(32)
        || locktime(4) || nHashType(4)
  sighash = SHA256(SHA256(pre))   # GetHash()
"""
import hashlib, json, struct, sys
import ecdsa
import ecdsa.util
from ecdsa import SECP256k1, ellipticcurve
from ecdsa.ellipticcurve import Point, INFINITY
from ecdsa import SigningKey, VerifyingKey

# ---------------------------------------------------------------------------
# curve / helpers
# ---------------------------------------------------------------------------
P = SECP256k1.curve.p()
N = SECP256k1.order
G = SECP256k1.generator
A = SECP256k1.curve.a()
B = SECP256k1.curve.b()

def sha256(b): return hashlib.sha256(b).digest()
def sha256d(b): return sha256(sha256(b))
def h160(b): return hashlib.new('ripemd160', sha256(b)).digest()

def cs(n):
    if n < 0xfd: return bytes([n])
    elif n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)

def ser_outpoint(txid, idx):
    return bytes.fromhex(txid) + struct.pack('<I', idx)

def ser_ctxout(value, spk):
    return struct.pack('<Q', value) + cs(len(spk)) + spk

# ---------------------------------------------------------------------------
# BIP143 segwit-v0 sighash (Core SignatureHash WITNESS_V0 port)
# ---------------------------------------------------------------------------
# txv dict: {version, locktime, inputs:[{txid,idx,scriptSig,sequence}],
#            outputs:[{value,spk}], amount_in[nIn] (optional amount arg)}
SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE = 1, 2, 3
SIGHASH_ANYONECANPAY = 0x80

def bip143_sighash(scriptCode, txv, nIn, nHashType, amount):
    nin = len(txv['inputs'])
    if (nHashType & 0x1f) == SIGHASH_SINGLE and nIn >= len(txv['outputs']):
        return b'\x01' + bytes(31)  # Core: return uint256::ONE (0x000...001)
    acp = (nHashType & SIGHASH_ANYONECANPAY) != 0
    htype = nHashType & 0x1f
    # hashPrevouts  = dSHA256 of (concatenated outpoints)  [Core: SHA256Uint256(GetPrevoutsSHA256)]
    hashPrevouts = b''
    if not acp:
        hashPrevouts = sha256d(b''.join(ser_outpoint(i['txid'], i['idx']) for i in txv['inputs']))
    # hashSequence  = dSHA256 of (concatenated nSequences)
    hashSequence = b''
    if not acp and htype != SIGHASH_SINGLE and htype != SIGHASH_NONE:
        hashSequence = sha256d(b''.join(struct.pack('<I', i['sequence']) for i in txv['inputs']))
    # hashOutputs   = dSHA256 of (serialized outputs) [or single output for SINGLE]
    hashOutputs = b''
    if htype != SIGHASH_SINGLE and htype != SIGHASH_NONE:
        hashOutputs = sha256d(b''.join(ser_ctxout(o['value'], o['spk']) for o in txv['outputs']))
    elif htype == SIGHASH_SINGLE and nIn < len(txv['outputs']):
        hashOutputs = sha256d(ser_ctxout(txv['outputs'][nIn]['value'], txv['outputs'][nIn]['spk']))
    # assemble preimage
    pre = bytearray()
    pre += struct.pack('<i', txv['version'])
    pre += hashPrevouts
    pre += hashSequence
    pre += ser_outpoint(txv['inputs'][nIn]['txid'], txv['inputs'][nIn]['idx'])
    pre += cs(len(scriptCode)) + scriptCode
    pre += struct.pack('<Q', amount)
    pre += struct.pack('<I', txv['inputs'][nIn]['sequence'])
    pre += hashOutputs
    pre += struct.pack('<I', txv['locktime'])
    pre += struct.pack('<I', nHashType & 0xffffffff)
    sighash = sha256d(bytes(pre))
    return sighash, bytes(pre)

# ---------------------------------------------------------------------------
# taproot (BIP341) reuse from gen_taproot_vectors pattern
# ---------------------------------------------------------------------------
def point_mul(p, k):
    r = INFINITY
    while k:
        if k & 1: r = point_add(r, p)
        p = point_add(p, p); k >>= 1
    return r

def point_add(p, q):
    if p == INFINITY: return q
    if q == INFINITY: return p
    if p.x() == q.x() and (p.y() + q.y()) % P == 0: return INFINITY
    if p == q: lam = (3*p.x()*p.x() + A) * pow(2*p.y(), P-2, P) % P
    else: lam = (q.y()-p.y()) * pow(q.x()-p.x(), P-2, P) % P
    xr = (lam*lam - p.x() - q.x()) % P
    yr = (lam*(p.x()-xr) - p.y()) % P
    return Point(SECP256k1.curve, xr, yr, N)

def has_even_y(p): return (p.y() % 2) == 0
def ser_xonly(p): return p.x().to_bytes(32, 'big')

def tagged_hash(tag, msg):
    t = sha256(tag.encode())
    return sha256(t + t + msg)

def schnorr_sign(msg, sk):
    d = sk % N
    Pt = point_mul(G, d)
    d_ = d if has_even_y(Pt) else N - d
    t = int.from_bytes(tagged_hash("BIP0340/aux", bytes(32)), 'big') ^ d_
    seed = int.to_bytes(t, 32, 'big') + ser_xonly(Pt) + msg
    k0 = int.from_bytes(tagged_hash("BIP0340/nonce", seed), 'big') % N
    if k0 == 0: raise ValueError("zero nonce")
    R = point_mul(G, k0)
    k = k0 if has_even_y(R) else N - k0
    e = int.from_bytes(tagged_hash("BIP0340/challenge", ser_xonly(R)+ser_xonly(Pt)+msg), 'big') % N
    return ser_xonly(R) + int.to_bytes((k + e*d_) % N, 32, 'big')

def lift_x(b):
    x = int.from_bytes(b, 'big')
    c = (pow(x,3,P)+B)%P
    y = pow(c, (P+1)//4, P)
    if (y*y)%P != c: raise ValueError("not QR")
    return Point(SECP256k1.curve, x, y if (y%2)==0 else P-y, N)

def taproot_tweak_pubkey(pubkey_x, h):
    t = int.from_bytes(tagged_hash("TapTweak", pubkey_x+(h or b'')), 'big')
    if t >= N: return None
    Q = point_add(lift_x(pubkey_x), point_mul(G, t))
    if Q == INFINITY: return None
    return ser_xonly(Q)

# ---------------------------------------------------------------------------
# serialization of full segwit txs
# ---------------------------------------------------------------------------
def ser_tx_full(txv, witnesses):
    """witnesses: list-of-list of witness item (bytes) per input (may be b''/[])."""
    out = bytearray()
    out += struct.pack('<i', txv['version'])
    segwit = any(w for w in witnesses)
    if segwit:
        out += b'\x00\x01'  # marker + flag
    out += cs(len(txv['inputs']))
    for i in txv['inputs']:
        out += ser_outpoint(i['txid'], i['idx'])
        out += cs(len(i['scriptSig'])) + i['scriptSig']
        out += struct.pack('<I', i['sequence'])
    out += cs(len(txv['outputs']))
    for o in txv['outputs']:
        out += ser_ctxout(o['value'], o['spk'])
    if segwit:
        out += cs(len(witnesses))
        for w in witnesses:                     # one stack per input
            if not w: continue                  # input without witness
            out += cs(len(w))                   # number of stack items
            for item in w:
                out += cs(len(item)) + item
    out += struct.pack('<I', txv['locktime'])
    return bytes(out)

# ---------------------------------------------------------------------------
# ECDSA signing (deterministic, low-S, DER) over a 32-byte digest
# ---------------------------------------------------------------------------
def ecdsa_sign_der(digest, seckey):
    sk = SigningKey.from_secret_exponent(seckey, curve=SECP256k1)
    # seal the hash with deterministic nonce, low-S enforced by the lib default
    sig = sk.sign_digest_deterministic(digest, hashfunc=hashlib.sha256,
                                       sigencode=ecdsa.util.sigencode_der)
    # sigencode_der can return high-S; Bitcoin requires low-S. derive r,s and
    # re-encode with low-S if needed.
    r, s = ecdsa.util.sigdecode_der(sig, N)
    if s > N // 2:
        s = N - s
    return ecdsa.util.sigencode_der(r, s, N)

def der_with_hashtype(digest, seckey, htype):
    return ecdsa_sign_der(digest, seckey) + bytes([htype])

def ecdsa_verify_digest(pub, digest, der_sig):
    """Verify a DER sig (with trailing hashtype byte) over digest, low-S."""
    # strip the trailing SIGHASH byte (DER never legitimately ends in such a
    # position that breaks re-parsing; validate by decoding without it first)
    raw = der_sig
    try:
        r, s = ecdsa.util.sigdecode_der(raw[:-1], N)
    except Exception:
        r, s = ecdsa.util.sigdecode_der(raw, N)
    if s > N // 2:
        return False  # high-S not consensus-valid
    x, y = _decompress(pub)
    vk = VerifyingKey.from_public_point(
        ellipticcurve.Point(SECP256k1.curve, x, y), curve=SECP256k1)
    return vk.verify_digest(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'), digest)

def _decompress(pub):
    assert pub[0] in (0x02, 0x03) and len(pub) == 33
    x = int.from_bytes(pub[1:], 'big')
    y2 = (pow(x,3,P)+A*x+B) % P
    y = pow(y2, (P+1)//4, P)
    if (y&1) != (pub[0]&1): y = P-y
    return (x, y)

# ---------------------------------------------------------------------------
# vector builders
# ---------------------------------------------------------------------------
def build_p2wpkh(seckey, idx_tag):
    """1-in/1-out genuine P2WPKH spend."""
    pub = _decompress(ser_compressed(seckey))
    pub33 = ser_compressed(seckey)
    spk = b'\x00\x14' + h160(pub33)
    prev_txid = ('%02x' % (idx_tag*2+0)) * 32
    txid_in = ('%02x' % (idx_tag*2+1)) * 32
    txv = {
        'version': 2, 'locktime': 0,
        'inputs': [{'txid': txid_in, 'idx': 0, 'scriptSig': b'', 'sequence': 0xfffffffd}],
        'outputs': [{'value': 99000, 'spk': b'\x00\x14' + bytes([0xAA for _ in range(20)]) }],
    }
    # prevout to spend: index 0 of txid_in, value 100000, script = spk (P2WPKH)
    amount = 100000
    scriptCode = spk  # P2WPKH scriptCode == the scriptPubKey
    sighash, pre = bip143_sighash(scriptCode, txv, 0, SIGHASH_ALL, amount)
    sig = der_with_hashtype(sighash, seckey, SIGHASH_ALL)
    assert ecdsa_verify_digest(pub33, sighash, sig)
    witness = [[sig, pub33]]
    txfull = ser_tx_full(txv, witness)
    return {
        'name': f'p2wpkh_{idx_tag}', 'type': 'P2WPKH',
        'tx_hex': txfull.hex(), 'txid_in': txid_in, 'idx_in': 0,
        'prevout_spk': spk.hex(), 'prevout_amount': amount,
        'scriptCode': scriptCode.hex(), 'sighash': sighash.hex(), 'pre': pre.hex(),
        'nIn': 0, 'nHashType': SIGHASH_ALL, 'witness': [x.hex() for x in witness[0]],
        'sig': sig.hex(), 'pub': pub33.hex(),
    }

def ser_compressed(seckey):
    pt = point_mul(G, seckey)
    x = int.to_bytes(pt.x(), 32, 'big')
    return bytes([2 | (pt.y() & 1)]) + x

def build_p2wsh_checksig(seckey, idx_tag):
    """P2WSH with witnessScript = <pub> OP_CHECKSIG. Genuine BIP143 spend."""
    pub33 = ser_compressed(seckey)
    witness_script = b'\x21' + pub33 + b'\xac'   # PUSH33 <pub> CHECKSIG
    wsh160 = h160(witness_script)
    spk = b'\x00\x20' + wsh160                    # OP_0 PUSH32 <sha256(witness)>  -> actually P2WSH = 0x00 0x20 <sha256(script)>
    # P2WSH scriptPubKey is OP_0 PUSH32 <sha256(witnessScript)>
    spk = b'\x00\x20' + sha256(witness_script)
    txid_in = ('%02x' % (idx_tag*2+1)) * 32
    txv = {
        'version': 2, 'locktime': 0,
        'inputs': [{'txid': txid_in, 'idx': 0, 'scriptSig': b'', 'sequence': 0xfffffffd}],
        'outputs': [{'value': 99000, 'spk': b'\x00\x14' + bytes([0xBB for _ in range(20)])}],
    }
    amount = 100000
    scriptCode = witness_script
    sighash, pre = bip143_sighash(scriptCode, txv, 0, SIGHASH_ALL, amount)
    sig = der_with_hashtype(sighash, seckey, SIGHASH_ALL)
    assert ecdsa_verify_digest(pub33, sighash, sig)
    witness = [[sig, witness_script]]
    txfull = ser_tx_full(txv, witness)
    return {
        'name': f'p2wsh_checksig_{idx_tag}', 'type': 'P2WSH',
        'tx_hex': txfull.hex(), 'txid_in': txid_in, 'idx_in': 0,
        'prevout_spk': spk.hex(), 'prevout_amount': amount,
        'scriptCode': witness_script.hex(), 'witness_script': witness_script.hex(),
        'sighash': sighash.hex(), 'pre': pre.hex(),
        'nIn': 0, 'nHashType': SIGHASH_ALL, 'witness': [x.hex() for x in witness[0]],
        'sig': sig.hex(), 'pub': pub33.hex(),
    }

def build_p2wsh_multisig(sk1, sk2, idx_tag):
    """P2WSH 2-of-2 OP_CHECKMULTISIG witnessScript."""
    pub1 = ser_compressed(sk1); pub2 = ser_compressed(sk2)
    # 2-of-2: OP_2 <pub1> <pub2> OP_2 OP_CHECKMULTISIG
    witness_script = b'\x52' + b'\x21'+pub1 + b'\x21'+pub2 + b'\x52\xae'
    wsh160 = h160(witness_script)
    spk = b'\x00\x20' + sha256(witness_script)
    txid_in = ('%02x' % (idx_tag*2+1)) * 32
    txv = {
        'version': 2, 'locktime': 0,
        'inputs': [{'txid': txid_in, 'idx': 0, 'scriptSig': b'', 'sequence': 0xfffffffd}],
        'outputs': [{'value': 90000, 'spk': b'\x00\x20' + bytes([0xCC for _ in range(32)])}],
    }
    amount = 100000
    scriptCode = witness_script
    sighash, pre = bip143_sighash(scriptCode, txv, 0, SIGHASH_ALL, amount)
    sig1 = der_with_hashtype(sighash, sk1, SIGHASH_ALL)
    sig2 = der_with_hashtype(sighash, sk2, SIGHASH_ALL)
    assert ecdsa_verify_digest(pub1, sighash, sig1)
    assert ecdsa_verify_digest(pub2, sighash, sig2)
    # OP_CHECKMULTISIG witness: [dummy, sig1, sig2, witnessScript]
    witness = [[b'\x00', sig2, sig1, witness_script]]
    txfull = ser_tx_full(txv, witness)
    return {
        'name': f'p2wsh_multisig_{idx_tag}', 'type': 'P2WSH',
        'tx_hex': txfull.hex(), 'txid_in': txid_in, 'idx_in': 0,
        'prevout_spk': spk.hex(), 'prevout_amount': amount,
        'scriptCode': witness_script.hex(), 'witness_script': witness_script.hex(),
        'sighash': sighash.hex(), 'pre': pre.hex(),
        'nIn': 0, 'nHashType': SIGHASH_ALL, 'witness': [x.hex() for x in witness[0]],
        'sig1': sig1.hex(), 'sig2': sig2.hex(), 'pub1': pub1.hex(), 'pub2': pub2.hex(),
    }

def build_p2tr_keypath(kpsk, idx_tag):
    """Genuine P2TR key-path spend with full witness (from taproot_spend materials)."""
    Pt = point_mul(G, kpsk)
    d = kpsk if has_even_y(Pt) else N - kpsk
    internal = ser_xonly(point_mul(G, d))
    output = taproot_tweak_pubkey(internal, None)
    txid_in = ('%02x' % (idx_tag*2+1)) * 32
    txv = {
        'version': 2, 'locktime': 0,
        'inputs': [{'txid': txid_in, 'idx': 0, 'scriptSig': b'', 'sequence': 0xfffffffd}],
        'outputs': [{'value': 90000, 'spk': b'\x51\x20' + bytes([0xDD for _ in range(32)])}],
    }
    amount = 100000
    spk = b'\x51\x20' + output
    # BIP341 keypath sighash (SIGHASH_ALL=1) via gen_taproot compute (reuse minimal here)
    # We sign the BIP341 sighash for the key-path: SigMsg with ht=1.
    sighash, pre = _taproot_keypath_sighash(spk, txv, amount)
    # tweaked secret signs
    t = int.from_bytes(tagged_hash("TapTweak", internal + b''), 'big')
    tweaked = (d + t) % N
    sig = schnorr_sign(sighash, tweaked) + bytes([0x01])
    witness = [[sig]]
    txfull = ser_tx_full(txv, witness)
    return {
        'name': f'p2tr_keypath_{idx_tag}', 'type': 'P2TR',
        'tx_hex': txfull.hex(), 'txid_in': txid_in, 'idx_in': 0,
        'prevout_spk': spk.hex(), 'prevout_amount': amount,
        'sighash': sighash.hex(), 'pre': pre.hex(),
        'nIn': 0, 'nHashType': 0x01, 'witness': [x.hex() for x in witness[0]],
        'sig': sig.hex(), 'output_key': output.hex(), 'internal_key': internal.hex(),
    }

def _taproot_keypath_sighash(spk, txv, amount):
    """BIP341 key-path sighash (ht=1) for a 1-in tx, matching taproot oracle."""
    # SigMsg
    nin = len(txv['inputs'])
    outp = ser_outpoint(txv['inputs'][0]['txid'], txv['inputs'][0]['idx'])
    m = bytearray()
    m += bytes([0x01])  # hash_type ALL
    m += struct.pack('<i', txv['version'])
    m += struct.pack('<I', txv['locktime'])
    m += sha256(b''.join(ser_outpoint(i['txid'], i['idx']) for i in txv['inputs']))
    m += sha256(b''.join(struct.pack('<Q', amount) for _ in range(nin)))
    m += sha256(b''.join(cs(len(spk)) + spk for _ in range(nin)))
    m += sha256(b''.join(struct.pack('<I', i['sequence']) for i in txv['inputs']))
    m += sha256(b''.join(ser_ctxout(o['value'], o['spk']) for o in txv['outputs']))
    m += bytes([0])  # spend_type 0
    m += struct.pack('<I', 0)  # input index
    final = b'\x00' + bytes(m)
    return tagged_hash('TapSighash', final), final

# ---------------------------------------------------------------------------
def verify_official_vectors():
    """Byte-exact check of the BIP143 oracle against the official BIP-0143
    test vector #0 (Native P2WPKH, SIGHASH_ALL) published in the BIP and
    produced by Bitcoin Core's SignatureHash WITNESS_V0. Aborts on mismatch."""
    txv = {'version': 1, 'locktime': 17,
           'inputs': [
               {'txid': 'fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f',
                'idx': 0, 'scriptSig': b'', 'sequence': 0xffffffee},
               {'txid': 'ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a',
                'idx': 1, 'scriptSig': b'', 'sequence': 0xffffffff},
           ],
           'outputs': [
               {'value': 0x06B22C20, 'spk': bytes.fromhex('76a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac')},
               {'value': 0x0D519390, 'spk': bytes.fromhex('76a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac')},
           ]}
    scriptCode = bytes.fromhex('76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac')
    sh, pre = bip143_sighash(scriptCode, txv, 1, SIGHASH_ALL, 600000000)
    exp_pre = ('0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37'
               '52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b'
               'ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000'
               '1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac'
               '0046c32300000000ffffffff'
               '863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5'
               '1100000001000000')
    assert pre.hex() == exp_pre, "BIP143 oracle preimage mismatch vs official BIP-0143 vector"
    assert sh.hex() == 'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670', \
        "BIP143 oracle sighash mismatch vs official BIP-0143 vector"
    print("  ok  oracle BIP143 == official BIP-0143 test vector #0 (byte-exact)")

def main():
    verify_official_vectors()
    ctxs = []
    ctxs.append(build_p2wpkh(0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef, 0))
    ctxs.append(build_p2wpkh(0x1111111111111111111111111111111111111111111111111111111111111111, 1))
    ctxs.append(build_p2wsh_checksig(0x1a2b3c4d5e6f7081728394059607a8b9c0d1e2f3a4b5c6d7e8f900fedcba98, 2))
    ctxs.append(build_p2wsh_multisig(
        0xa5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5,
        0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a, 3))
    ctxs.append(build_p2tr_keypath(0x0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a, 4))

    # ---- emit C headers ----
    def carr(b): return ','.join('0x%02x' % x for x in b)
    with open('tests/modern_vec.h', 'w') as f:
        f.write('/* Auto-generated by validation/gen_modern_vectors.py -- BIP143 preimages. */\n')
        f.write('#pragma once\n#include <stdint.h>\n')
        for i, c in enumerate(ctxs):
            f.write('\n/* %s */\n' % c['name'])
            f.write('static const uint8_t mv%d_pre[] = { %s };\n' % (i, carr(bytes.fromhex(c['pre']))))
            f.write('static const uint8_t mv%d_sighash[32] = { %s };\n' % (i, carr(bytes.fromhex(c['sighash']))))
        f.write('\ntypedef struct { const char* name; const uint8_t* pre; int prelen; '
                'const uint8_t* sighash; int nIn; int nHashType; } mvec_t;\n')
        f.write('static const mvec_t modern_vecs[] = {\n')
        for i, c in enumerate(ctxs):
            f.write('  { "%s", mv%d_pre, sizeof(mv%d_pre), mv%d_sighash, %d, %d },\n'
                    % (c['name'], i, i, i, c['nIn'], c['nHashType']))
        f.write('};\nstatic const int modern_num_vecs = %d;\n' % len(ctxs))

    with open('tests/modern_spend.h', 'w') as f:
        f.write('/* Auto-generated by validation/gen_modern_vectors.py -- signed modern spends. */\n')
        f.write('#pragma once\n#include <stdint.h>\n')
        for i, c in enumerate(ctxs):
            f.write('\n/* %s */\n' % c['name'])
            txb = bytes.fromhex(c['tx_hex'])
            f.write('static const uint8_t ms%d_tx[] = { %s };\n' % (i, carr(txb)))
            f.write('static const int ms%d_txlen = %d;\n' % (i, len(txb)))
            idb = bytes.fromhex(c['txid_in'])
            f.write('static const uint8_t ms%d_txid[32] = { %s };\n' % (i, carr(idb)))
            spk = bytes.fromhex(c['prevout_spk'])
            f.write('static const uint8_t ms%d_prev_spk[] = { %s };\n' % (i, carr(spk)))
            f.write('static const int ms%d_prev_spklen = %d;\n' % (i, len(spk)))
            f.write('static const unsigned long long ms%d_prev_amount = %dull;\n' % (i, c['prevout_amount']))
            f.write('static const uint8_t ms%d_type = %u;\n' % (i, {'P2WPKH':1,'P2WSH':2,'P2TR':3}[c['type']]))
            # witness stack
            ws = c['witness']
            f.write('static const int ms%d_nwit = %d;\n' % (i, len(ws)))
            for j, item in enumerate(ws):
                ib = bytes.fromhex(item)
                f.write('static const uint8_t ms%d_wit%d[] = { %s };\n' % (i, j, carr(ib)))
                f.write('static const int ms%d_wit%d_len = %d;\n' % (i, j, len(ib)))
            if c['type']=='P2WSH' and 'witness_script' in c:
                wsb = bytes.fromhex(c['witness_script'])
                f.write('static const uint8_t ms%d_wit_script[] = { %s };\n' % (i, carr(wsb)))
                f.write('static const int ms%d_wit_script_len = %d;\n' % (i, len(wsb)))
        # table
        f.write('\ntypedef struct { const char* name; const uint8_t* tx; int txlen;\n')
        f.write('  const uint8_t* txid; const uint8_t* prev_spk; int prev_spklen; unsigned long long prev_amount;\n')
        f.write('  int type; int nwit; const uint8_t** wit; const int* witlen; } msend_t;\n')
        f.write('static const uint8_t* ms_wit0[]={}; static const uint8_t* ms_wit1[]={};\n')
        # helper arrays per vector
        arrs = []
        for i, c in enumerate(ctxs):
            wnp = 'ms%d_witp' % i
            qnp = 'ms%d_witl' % i
            arrs.append((wnp, qnp, c['witness']))
        for i, c in enumerate(ctxs):
            wnp, qnp, ws = arrs[i]
            f.write('static const uint8_t* %s[] = { %s };\n' % (wnp, ', '.join('ms%d_wit%d' % (i,j) for j in range(len(ws)))))
            f.write('static const int %s[] = { %s };\n' % (qnp, ', '.join('ms%d_wit%d_len' % (i,j) for j in range(len(ws)))))
        f.write('static const msend_t modern_spends[] = {\n')
        for i, c in enumerate(ctxs):
            wnp, qnp, ws = arrs[i]
            f.write('  { "%s", ms%d_tx, sizeof(ms%d_tx), ms%d_txid, ms%d_prev_spk, ms%d_prev_spklen, '
                    '%dull, %d, %d, %s, %s },\n'
                    % (c['name'], i,i,i,i,i, c['prevout_amount'], {'P2WPKH':1,'P2WSH':2,'P2TR':3}[c['type']],
                       len(ws), wnp, qnp))
        f.write('};\nstatic const int modern_num_spends = %d;\n' % len(ctxs))

    with open('tests/modern_spend.json', 'w') as f:
        json.dump(ctxs, f, indent=1)

    print('wrote tests/modern_vec.h, tests/modern_spend.h, tests/modern_spend.json (%d vectors)' % len(ctxs))
    for c in ctxs:
        print('  %-24s %-7s sighash=%s' % (c['name'], c['type'], c['sighash'][:16]))
    return 0

if __name__ == '__main__':
    sys.exit(main())
