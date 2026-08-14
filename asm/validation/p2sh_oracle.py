#!/usr/bin/env python3
"""Independent Python oracle for P2SH / multisig (asm/bitcoin_multisig.asm).

Cross-checks three things that tests/test_multisig.c asserts:

  1. p2sh_hash  == RIPEMD160(SHA256(redeemScript))
        * a P2PKH-shaped redeem script  -> 4f2fc3e91d71d26a70637423e1e8935bafdc3215
        * the 2-of-2 multisig redeem    -> e3db5dfd1b951e336c4a9030726e69b30ba4376a
  2. legacy SIGHASH_ALL for the spend tx with the redeem script as the
     signing script equals 07bbe9a5ffd25684577b7b8b359ecc34c14a44a048194242986058f12df28e08
     (matches the C harness / asm sighash_all).
  3. multisig_verify: the DER signature (with SIGHASH_ALL) embedded in the
     scriptSig as [0x00][sig+0x01][pubkey] verifies against that sighash for
     the given pubkey, using the pure-python 'ecdsa' elliptic math (a fully
     independent implementation from the repo's NASM ECDSA).

Run:  python3 asm/validation/p2sh_oracle.py
"""
import hashlib
import struct
import ecdsa
from ecdsa.curves import SECP256k1


def h160(b):
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def parse_varint(data, off):
    v = data[off]
    if v < 0xfd:
        return v, off + 1
    if v == 0xfd:
        return struct.unpack('<H', data[off+1:off+3])[0], off + 3
    if v == 0xfe:
        return struct.unpack('<I', data[off+1:off+5])[0], off + 5
    return struct.unpack('<Q', data[off+1:off+9])[0], off + 9


def parse_tx(tx):
    off = 0
    version = tx[off:off+4]; off += 4
    n_in, off = parse_varint(tx, off)
    inputs = []
    for _ in range(n_in):
        prev = tx[off:off+36]; off += 36
        slen, off = parse_varint(tx, off)
        ss = tx[off:off+slen]; off += slen
        seq = tx[off:off+4]; off += 4
        inputs.append((prev, ss, seq))
    n_out, off = parse_varint(tx, off)
    outputs = []
    for _ in range(n_out):
        val = tx[off:off+8]; off += 8
        plen, off = parse_varint(tx, off)
        ps = tx[off:off+plen]; off += plen
        outputs.append((val, ps))
    locktime = tx[off:off+4]
    return version, inputs, outputs, locktime


def legacy_sighash_all(tx, input_index, script):
    version, inputs, outputs, locktime = parse_tx(tx)
    pre = bytearray()
    pre += version
    pre += bytes([len(inputs)])
    for i, (prev, ss, seq) in enumerate(inputs):
        pre += prev
        if i == input_index:
            pre += bytes([len(script)]) + script
        else:
            pre += b'\x00'
        pre += seq
    pre += bytes([len(outputs)])
    for val, ps in outputs:
        pre += val
        pre += bytes([len(ps)]) + ps
    pre += locktime
    pre += struct.pack('<I', 1)  # SIGHASH_ALL
    return sha256d(bytes(pre))


def der_to_rs(sig_der_plus_hashtype):
    der = sig_der_plus_hashtype[:-1]
    assert der[0] == 0x30
    body = der[2:]
    assert body[0] == 0x02
    rlen = body[1]
    r = int.from_bytes(body[2:2+rlen], 'big')
    body = body[2+rlen:]
    assert body[0] == 0x02
    slen = body[1]
    s = int.from_bytes(body[2:2+slen], 'big')
    return r, s, sig_der_plus_hashtype[-1]


def pubkey_point(pub):
    assert pub[0] in (0x02, 0x03) and len(pub) == 33, "need compressed pubkey"
    x = int.from_bytes(pub[1:], 'big')
    curve = SECP256k1.curve
    p = curve.p(); a = curve.a(); b = curve.b()
    y2 = (pow(x, 3, p) + a * x + b) % p
    y = pow(y2, (p + 1) // 4, p)
    if (y & 1) != (pub[0] & 1):
        y = p - y
    return (x, y)


def ecdsa_verify_digest(pub, digest, r, s):
    """Raw ECDSA verify over a 32-byte digest (Bitcoin 'ecdsa' package)."""
    point = pubkey_point(pub)
    vk = ecdsa.VerifyingKey.from_public_point(
        ecdsa.ellipticcurve.Point(SECP256k1.curve, point[0], point[1]),
        curve=SECP256k1)
    raw = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    return vk.verify_digest(raw, digest)


def main():
    nfail = 0

    def ck(label, cond):
        print(("ok  : " if cond else "FAIL: ") + label)
        if not cond:
            nfail += 1

    # ---- 1. p2sh_hash vectors ----
    redeem_p2pkh = bytes.fromhex(
        "76a9145b63f4d2c5d8e6aab2f0d3c4e5a6b7c8d9e0f1a288ac")
    ck("p2sh (P2PKH-shaped redeem) == 4f2f...3215",
       h160(redeem_p2pkh).hex() == "4f2fc3e91d71d26a70637423e1e8935bafdc3215")

    redeem_2of2 = bytes.fromhex(
        "5221027aa62d4e768712599405b00daa337c10f5d81471c4781e8a029507ed28a23281"
        "2102c0ef8f29629fbbd0dfc1532cd7bce2d048d509f421bad2b948dd290ba1566ebd52")
    ck("p2sh (2-of-2 redeem) == e3db...376a",
       h160(redeem_2of2).hex() == "e3db5dfd1b951e336c4a9030726e69b30ba4376a")

    # ---- 2. the spend tx + sighash ----
    tx = bytes.fromhex(
        "0100000001"
        "1111111111111111111111111111111111111111111111111111111111111111"
        "00000000"
        "6b"
        "00473044022013131873884588cb8966458b69e901e1467f417ac69e140061647975bb6b669c022005feb0c5af0f3724e5fb66c7aab2e640c783ce721edcea6e17389b551de0378001"
        "21027aa62d4e768712599405b00daa337c10f5d81471c4781e8a029507ed28a23281"
        "feffffff"
        "0150c300000000000014a67244ef26b38d31c475a4609a4758f9e0c66c2e"
        "00000000")
    sig = bytes.fromhex(
        "3044022013131873884588cb8966458b69e901e1467f417ac69e140061647975bb6b669c"
        "022005feb0c5af0f3724e5fb66c7aab2e640c783ce721edcea6e17389b551de0378001")
    pub = bytes.fromhex(
        "027aa62d4e768712599405b00daa337c10f5d81471c4781e8a029507ed28a23281")

    version, inputs, outputs, lt = parse_tx(tx)
    ck("parse tx (1 input, 1 output)", len(inputs) == 1 and len(outputs) == 1)
    z = legacy_sighash_all(tx, 0, redeem_2of2)
    ck("legacy SIGHASH_ALL == 07bbe9a5...8e08",
       z == bytes.fromhex("07bbe9a5ffd25684577b7b8b359ecc34c14a44a048194242986058f12df28e08"))

    # ---- 3. ECDSA verify (independent 'ecdsa' impl) ----
    r, s, htype = der_to_rs(sig)
    ck("hashtype == SIGHASH_ALL(1)", htype == 1)
    ck("sig verifies over z for pub", ecdsa_verify_digest(pub, z, r, s))

    # wrong-pubkey negative
    wrong = bytes.fromhex("02c0ef8f29629fbbd0dfc1532cd7bce2d048d509f421bad2b948dd290ba1566ebd")
    try:
        bad_ok = ecdsa_verify_digest(wrong, z, r, s)
    except Exception:
        bad_ok = False
    ck("sig does NOT verify for the other pubkey", not bad_ok)

    print("\n" + ("ALL ORACLE CHECKS PASSED" if nfail == 0 else "ORACLE FAILURES=%d" % nfail))
    return 1 if nfail else 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
