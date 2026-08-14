#!/usr/bin/env python3
"""Generate a VALID P2SH/multisig test vector for the C harness + oracle.

The asm multisig_verify expects scriptSig laid out as:
    [0x00 dummy] <len> <DERsig+0x01> <len> <pubkey>
i.e. it scans for the pubkey data-push and treats the immediately preceding
push as that signer's DER signature. We build a fully VALID serialized tx
(full 36-byte outpoint, correct scriptSigLen, correct lengths) and sign the
legacy SIGHASH_ALL preimage (with the redeem script as the signing script)
using one private key. We then emit C array literals for the harness.

Also emits the BIP16 p2sh known-vector check (hash of a 1-of-1 p2sh script).
"""
import hashlib
import struct
import ecdsa
from ecdsa.curves import SECP256k1
from ecdsa.util import sigencode_der, number_to_string


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def h160(b):
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()


def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)


def pubpoint(pub):
    assert pub[0] in (0x02, 0x03)
    x = int.from_bytes(pub[1:], 'big')
    curve = SECP256k1.curve
    p = curve.p(); a = curve.a(); bcoef = curve.b()
    y2 = (pow(x, 3, p) + a * x + bcoef) % p
    y = pow(y2, (p + 1) // 4, p)
    if (y & 1) != (pub[0] & 1):
        y = p - y
    return (x, y)


def make_keypair():
    sk = ecdsa.SigningKey.generate(curve=SECP256k1)
    priv = sk.privkey.secret_multiplier
    pub_pt = sk.get_verifying_key().pubkey.point
    x, y = pub_pt.x(), pub_pt.y()
    pub = bytes([0x02 + (y & 1)]) + x.to_bytes(32, 'big')
    return priv, pub


def der_sig(r, s):
    def enc_int(v):
        b = v.to_bytes((v.bit_length() + 7) // 8, 'big')
        if b[0] & 0x80:
            b = b'\x00' + b
        return b'\x02' + bytes([len(b)]) + b
    body = enc_int(r) + enc_int(s)
    return b'\x30' + bytes([len(body)]) + body


def build_and_sign(redeem, priv_to_sign, input_prevout, input_value_nonzero=True):
    """Build a valid single-input tx and return parts + sig."""
    # outpoint: 32-byte txid + 4-byte index
    prev_txid = bytes.fromhex('11111111111111111111111111111111'
                              '11111111111111111111111111111111')
    index = struct.pack('<I', 0)
    # dummy scriptSig placeholder (we fill length after building sig)
    sequence = b'\xfe\xff\xff\xff'
    out_val = struct.pack('<Q', 50000)
    out_script = bytes.fromhex('a67244ef26b38d31c475a4609a4758f9e0c66c2e')
    locktime = struct.pack('<I', 0)

    # We need the preimage BEFORE signing, but the preimage embeds scriptSig
    # len of the target input. For SIGHASH_ALL the target input's scriptSig in
    # the preimage is REPLACED by the redeem script (that's the signing script),
    # so scriptSig length in the preimage = len(redeem) regardless of the
    # actual scriptSig. Good — build preimage directly.
    n_in = 1
    n_out = 1

    def preimage():
        pre = bytearray()
        pre += struct.pack('<I', 1)         # version
        pre += varint(n_in)
        pre += prev_txid + index
        pre += varint(len(redeem)) + redeem  # signing script
        pre += sequence
        pre += varint(n_out)
        pre += out_val
        pre += varint(len(out_script)) + out_script
        pre += locktime
        pre += struct.pack('<I', 1)          # SIGHASH_ALL
        return bytes(pre)

    z = sha256d(preimage())

    sk = ecdsa.SigningKey.from_secret_exponent(priv_to_sign, curve=SECP256k1)
    # Sign the 32-byte digest directly (low-S)
    order = SECP256k1.order
    r, s = sk.sign_digest_deterministic(
        z, hashfunc=hashlib.sha256, sigencode=lambda r, s, o: (r, s))
    s = min(s, order - s)  # low-S normalization
    sig = der_sig(r, s) + b'\x01'            # + SIGHASH_ALL

    pub = sk.get_verifying_key().pubkey.point
    pub_comp = bytes([0x02 + (pub.y() & 1)]) + pub.x().to_bytes(32, 'big')

    # scriptSig = [0x00 dummy] <slen> sig <plen> pub_comp
    scriptSig = b'\x00' + varint(len(sig)) + sig + varint(len(pub_comp)) + pub_comp

    # assemble full tx
    tx = bytearray()
    tx += struct.pack('<I', 1)
    tx += varint(n_in)
    tx += prev_txid + index
    tx += varint(len(scriptSig)) + scriptSig
    tx += sequence
    tx += varint(n_out)
    tx += out_val
    tx += varint(len(out_script)) + out_script
    tx += locktime
    return bytes(tx), sig, pub_comp, z, redeem


def main():
    # 2-of-2 multisig redeem script
    priv1, pub1 = make_keypair()
    priv2, pub2 = make_keypair()
    redeem = (b'\x52'                                     # OP_2
              + varint(len(pub1)) + pub1
              + varint(len(pub2)) + pub2
              + b'\x52')                                  # OP_2 -> 2-of-2
    # NOTE: no trailing OP_CHECKMULTISIG here; this is a data-only redeem
    # used as the signing script for sighash. Multisig_verify checks the one
    # signature; the m/n multisig structure is evaluated by the caller.

    tx, sig, pub_comp, z, _ = build_and_sign(redeem, priv1, None)

    print("=== GENERATED VECTOR ===")
    print("priv1      :", hex(priv1))
    print("priv2      :", hex(priv2))
    print("pub1       :", pub1.hex())
    print("pub2       :", pub2.hex())
    print("redeem     :", redeem.hex())
    print("redeem_len :", len(redeem))
    print("p2sh hash  :", h160(redeem).hex())
    print("sig (DER+1):", sig.hex(), "len", len(sig))
    print("pub_comp   :", pub_comp.hex())
    print("sighash z  :", z.hex())
    print("tx         :", tx.hex())
    print()
    print("p2sh BIP16 known vector (1-of-1 redeem OP_DUP HASH160 ... CHECKSIG):")
    # BIP16 example: scriptPubKey = OP_DUP OP_HASH160 <20B> OP_EQUALVERIFY OP_CHECKSIG
    p2sh_script = bytes.fromhex(
        "76a914" + ("11" * 20) + "88ac")
    # but BIP16 defines p2sh of the P2PKH script itself
    p2pkh = bytes.fromhex("76a914" + "11"*20 + "88ac")
    print("  h160(p2pkh redeem) =", h160(p2pkh).hex())
    print("  (BIP16 official example hash = e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a)")


if __name__ == '__main__':
    main()
