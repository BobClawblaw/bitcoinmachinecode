#!/usr/bin/env python3
"""gen_dscript_vecs.py -- differential vectors for bitcoin_script.

der_parse_sig: the valid-17-byte shape, long-form SEQUENCE (skipped
unchecked -- the length value can be anything), long-form INTEGER lengths
(1..3 significant bytes and the >= 4 rejection), any number of redundant
leading 0x00s in r/s (the height-124275 double-zero 34-byte case), 33-byte
overshoots, hashtype absent/0x01/0x02/0x81, truncations at every byte, and
random DER-ish garbage.  be_to_limbs: lengths 1..32 incl. all-FF and
single-byte edges.  verify_p2pkh: the pure-Python-verified P2PKH spend from
tests/test_p2pkh.c (mkfull.py), a flipped-signature negative, and structural
negatives (empty scriptSig, 76-byte and PUSHDATA1 pushes, missing pubkey,
short txs, bad idx).
"""
import struct, random, sys

out = bytearray()
u32 = lambda v: struct.pack('<I', v & 0xFFFFFFFF)
random.seed(0xDC5)

def der(r, s, ht=None, rpad=0, spad=0, seq_long=None, r_long=None, s_long=None):
    body = b''
    rb = r.to_bytes(32, 'big').lstrip(b'\x00') or b'\x00'
    sb = s.to_bytes(32, 'big').lstrip(b'\x00') or b'\x00'
    rb = b'\x00' * rpad + rb
    sb = b'\x00' * spad + sb
    def enc_int(b, longform):
        if longform is None:
            return b'\x02' + bytes([len(b)]) + b
        n = longform
        return b'\x02' + bytes([0x80 | n]) + n.to_bytes(n, 'big') + b
    body += enc_int(rb, r_long) + enc_int(sb, s_long)
    if seq_long is None:
        return b'\x30' + bytes([len(body)]) + body + (bytes([ht]) if ht is not None else b'')
    n = seq_long
    return b'\x30' + bytes([0x80 | n]) + n.to_bytes(n, 'big') + body + (bytes([ht]) if ht is not None else b'')

def rec_sig(b): out.append(0); out.extend(u32(len(b))); out.extend(b)
def rec_limbs(b): out.append(1); out.extend(u32(len(b))); out.extend(b)
def rec_v(tx, idx, pv):
    out.append(2); out.extend(u32(len(tx))); out.extend(tx)
    out.extend(u32(idx)); out.extend(u32(len(pv))); out.extend(pv)

R, S = 0x0401546f83a81708c6fe7c377c911bdfb08a60a797597531b37ac1ddc2132e68, \
       0x0a19109980a117e28405737402efb1d9422f776b0cdaaa036bc7c18e9bfe0fa6

# ---- der_parse_sig ----
rec_sig(der(R, S, 1))
rec_sig(der(R, S, None))
rec_sig(der(R, S, 2))
rec_sig(der(R, S, 0x81))
rec_sig(der(R, S, 1, rpad=1, spad=1))                    # one redundant zero each
rec_sig(der(R, S, 1, rpad=2, spad=3))                    # the 124275 shape
rec_sig(der(R, S, 1, rpad=10))
rec_sig(der(0, S, 1))                                    # zero r (all stripped)
rec_sig(der(R, 0, 1))
rec_sig(der(R, S, 1, seq_long=1))                        # long SEQUENCE, value len ok
rec_sig(der(R, S, 1, seq_long=3))                        # long SEQUENCE, value lies
rec_sig(der(R, S, 1, r_long=1))
rec_sig(der(R, S, 1, r_long=3))
bad = bytearray(der(R, S, 1, r_long=4)); rec_sig(bytes(bad))   # >= 4 length bytes
rec_sig(der(R, S, 1, s_long=1))
rec_sig(der(R, S, 1, s_long=4))
big_r = (1 << 256) - 1
rec_sig(der(big_r, S, 1))                                # 32-byte r, minimal
rec_sig(b'\x30\x25\x02\x21\x00' + b'\xff'*32 + b'\x02\x01\x01\x01')  # 33 significant r -> reject
full = der(R, S, 1)
for cut in range(1, len(full)):                          # every truncation
    rec_sig(full[:cut])
for _ in range(120):                                     # DER-ish garbage
    n = random.randrange(0, 80)
    b = bytearray(random.getrandbits(8) for _ in range(n))
    if n and random.random() < 0.5: b[0] = 0x30
    if n > 1 and random.random() < 0.5: b[1] = random.choice([len(b) - 2, 0x81, 0x82])
    rec_sig(bytes(b))

# ---- be_to_limbs ----
for n in range(1, 33):
    rec_limbs(bytes(random.getrandbits(8) for _ in range(n)))
rec_limbs(bytes([0xff]))
rec_limbs(bytes(32))
rec_limbs(b'\x00')
rec_limbs(bytes([0x01, 0x00] * 16))

# ---- verify_p2pkh ----
TX = ("0200000001111111111111111111111111111111111111111111111111111111111111111"
      "100000006a47304402200401546f83a81708c6fe7c377c911bdfb08a60a797597531b37ac1d"
      "dc2132e6802200a19109980a117e28405737402efb1d9422f776b0cdaaa036bc7c18e9bfe0"
      "fa6012103ba6f2e86a2b485e96242506b576251b7c8038255463401361d248973b654d445f"
      "efffffff0150c30000000000001976a9143333333333333333333333333333333333333333"
      "88ac00000000")
SCPK = "76a914444444444444444444444444444444444444444488ac"
tx = bytes.fromhex(TX)
pv = bytes.fromhex(SCPK)
rec_v(tx, 0, pv)                                         # valid -> 1
bad = bytearray(tx); bad[51] ^= 0xff
rec_v(bytes(bad), 0, pv)                                 # tampered sig -> 0
rec_v(tx, 1, pv)                                         # bad idx -> 0
rec_v(tx[:40], 0, pv)                                    # short tx -> 0
# oversized push (76) and PUSHDATA1 sig in the scriptSig
sig_full = bytes.fromhex("47304402200401546f83a81708c6fe7c377c911bdfb08a60a797"
                         "597531b37ac1ddc2132e6802200a19109980a117e28405737402"
                         "efb1d9422f776b0cdaaa036bc7c18e9bfe0fa601")
pub33 = bytes.fromhex("2103ba6f2e86a2b485e96242506b576251b7c8038255463401361d"
                      "248973b654d445")
def rebuild(ss):
    """tx with input 0's scriptSig replaced by ss (everything else equal)"""
    pre = tx[:4+1]                      # version + n_in
    inp = tx[5:5+36]                    # prevout
    rest = tx[5+36+1+106+4:]            # from n_out on
    return pre + inp + bytes([len(ss)]) + ss + b'\xfeffffff' + rest
rec_v(rebuild(bytes([76]) + b'\x30' * 20), 0, pv)   # header 76 -> refused
rec_v(rebuild(b'\x4c' + bytes([71]) + sig_full[1:72] + pub33[1:34]), 0, pv)  # PUSHDATA1 -> refused
rec_v(rebuild(sig_full), 0, pv)                     # missing pubkey push -> 0
rec_v(rebuild(b''), 0, pv)                          # empty scriptSig -> 0
rec_v(rebuild(b''), 0, pv)                          # empty scriptSig -> 0
for _ in range(40):                                        # random garbage txs
    n = random.randrange(10, 200)
    rec_v(bytes(random.getrandbits(8) for _ in range(n)), random.randrange(0, 3), pv)

sys.stdout.buffer.write(bytes(out))
