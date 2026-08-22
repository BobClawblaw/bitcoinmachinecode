#!/usr/bin/env python3
"""gen_multi_p2wpkh.py -- regenerate tests/multi_p2wpkh_vec.h.

A genuinely-signed 10-input P2WPKH transaction (MPV_GOOD_TX_HEX), the same
transaction with input MPV_BAD_INDEX's signature corrupted (MPV_BAD_TX_HEX),
and the 10 prevouts tests/test_tx_verify_parallel.c seeds into its UTXO view.

Reuses gen_modern_vectors.py's own BIP143 + ECDSA helpers so this fixture can
never again disagree with the main vector generator (incident #11, 2026-08-22:
the original /tmp generator and the verifier shared the same wrong P2WPKH
scriptCode -- the witness program instead of the implied P2PKH script -- so
the fixture "passed" against a verifier that rejected the first real P2WPKH
spend in history).

Usage: python3 validation/gen_multi_p2wpkh.py > tests/multi_p2wpkh_vec.h
"""
import hashlib, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_modern_vectors import (bip143_sighash, der_with_hashtype, ser_compressed,
                                h160, ser_tx_full, ecdsa_verify_digest, SIGHASH_ALL, N)

N_IN, BAD = 10, 5
seckeys = [int.from_bytes(hashlib.sha256(b'bmc multi_p2wpkh %d' % i).digest(), 'big') % N for i in range(N_IN)]
pubs    = [ser_compressed(sk) for sk in seckeys]
spks    = [b'\x00\x14' + h160(pk) for pk in pubs]
prev    = [{'txid': ('%02x' % (i + 1)) * 32, 'idx': 0, 'value': 100000 + i, 'spk': spks[i]} for i in range(N_IN)]
txv = {'version': 2, 'locktime': 0,
       'inputs': [{'txid': p['txid'], 'idx': p['idx'], 'scriptSig': b'', 'sequence': 0xfffffffd} for p in prev],
       'outputs': [{'value': sum(p['value'] for p in prev) - 10000, 'spk': b'\x00\x14' + bytes([0xAA] * 20)}]}
wit = []
for i in range(N_IN):
    # BIP143: P2WPKH scriptCode is the implied P2PKH script, not the program
    sc = b'\x76\xa9\x14' + spks[i][2:22] + b'\x88\xac'
    sighash, _ = bip143_sighash(sc, txv, i, SIGHASH_ALL, prev[i]['value'])
    sig = der_with_hashtype(sighash, seckeys[i], SIGHASH_ALL)
    assert ecdsa_verify_digest(pubs[i], sighash, sig)
    wit.append([sig, pubs[i]])
good = ser_tx_full(txv, wit)
bad_sig = bytearray(wit[BAD][0]); bad_sig[6] ^= 0x01          # inside r: DER still parses, value wrong
bad_wit = [list(w) for w in wit]; bad_wit[BAD][0] = bytes(bad_sig)
bad = ser_tx_full(txv, bad_wit)
assert good != bad and len(good) == len(bad)
print("/* GENERATED -- do not hand-edit. See validation/gen_multi_p2wpkh.py. */")
print("#define MPV_N_INPUTS %d" % N_IN)
print('static const char* MPV_GOOD_TX_HEX = "%s";' % good.hex())
print('static const char* MPV_BAD_TX_HEX = "%s";' % bad.hex())
print("#define MPV_BAD_INDEX %d" % BAD)
print("typedef struct { const char* txid_hex; unsigned index; unsigned long long value; const char* spk_hex; } mpv_prevout_t;")
print("static const mpv_prevout_t MPV_PREVOUTS[%d] = {" % N_IN)
for p in prev:
    print('  { "%s", %d, %dULL, "%s" },' % (p['txid'], p['idx'], p['value'], p['spk'].hex()))
print("};")
