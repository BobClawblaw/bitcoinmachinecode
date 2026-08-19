#!/usr/bin/env python3
"""gen_hashtype_vectors.py -- prove Stage B's non-ALL legacy hashtypes are
wired correctly end-to-end, not just that the raw hash matches a fixture.

Builds genuine P2PK spends signed with SIGHASH_NONE, SIGHASH_SINGLE, and
ANYONECANPAY combinations, using this repo's own legacy_sighash Python
reference (gen_sighash_vectors' algorithm, already proven 500/500 against
Bitcoin Core's official sighash.json). For each hashtype, emits BOTH:
  - the genuine spend (must ACCEPT), and
  - a tampered variant that changes exactly the field that hashtype is
    supposed to ignore (must ALSO ACCEPT -- proving the field really is
    unbound), and
  - a tampered variant that changes a field the hashtype DOES bind (must
    REJECT -- proving it isn't just accepting everything).
Also one SIGHASH_SINGLE-out-of-range (nIn>=nOut) quirk case: the degenerate
uint256(1) hash, genuinely signed, so verification must ACCEPT it -- Core's
well-known consensus quirk, not a bug in this project's implementation.

Output: asm/tests/hashtype_vec.h consumed by tests/test_hashtype_e2e.c via
sv_verify_script directly (real ECDSA, real interpreter, no shortcuts).
"""
import sys, os, struct, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_p2sh_vectors import der_sign, pubkey, push, cs, Tx, sha256d

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

def strip_codesep(s):
    out = b''; i = 0; n = len(s)
    while i < n:
        op = s[i]
        if op < 0x4c: ln, hdr = op, 1
        elif op == 0x4c: ln, hdr = s[i+1], 2
        elif op == 0x4d: ln, hdr = s[i+1]|(s[i+2]<<8), 3
        elif op == 0x4e: ln, hdr = s[i+1]|(s[i+2]<<8)|(s[i+3]<<16)|(s[i+4]<<24), 5
        else: ln, hdr = 0, 1
        unit = hdr+ln
        if i+unit > n: out += s[i:]; return out
        if op != 0xab: out += s[i:i+unit]
        i += unit
    return out

def legacy_sighash(tx_bytes, script_hex_or_bytes, nIn, hashtype):
    sc = script_hex_or_bytes if isinstance(script_hex_or_bytes, bytes) else bytes.fromhex(script_hex_or_bytes)
    b = tx_bytes; p = 0
    version = struct.unpack_from('<i', b, p)[0]; p += 4
    def rd_cs():
        nonlocal p
        v = b[p]
        if v < 0xfd: p += 1; return v
        if v == 0xfd: r = struct.unpack_from('<H', b, p+1)[0]; p += 3; return r
        if v == 0xfe: r = struct.unpack_from('<I', b, p+1)[0]; p += 5; return r
        r = struct.unpack_from('<Q', b, p+1)[0]; p += 9; return r
    nin = rd_cs(); ins = []
    for _ in range(nin):
        prevout = b[p:p+36]; p += 36
        slen = rd_cs(); p += slen
        seq = struct.unpack_from('<I', b, p)[0]; p += 4
        ins.append((prevout, seq))
    nout = rd_cs(); outs = []
    for _ in range(nout):
        val = b[p:p+8]; p += 8
        slen = rd_cs(); spk = b[p:p+slen]; p += slen
        outs.append((val, spk))
    locktime = struct.unpack_from('<I', b, p)[0]; p += 4

    hb = hashtype & 0x1f
    fSingle = hb == 3; fNone = hb == 2; fACP = (hashtype & 0x80) != 0
    if fSingle and nIn >= len(outs):
        return b'\x01' + b'\x00'*31
    scF = strip_codesep(sc)
    pre = struct.pack('<i', version)
    nInputs = 1 if fACP else len(ins)
    pre += cs(nInputs)
    for i in range(nInputs):
        real_i = nIn if fACP else i
        prevout, seq = ins[real_i]
        pre += prevout
        pre += (cs(len(scF)) + scF) if real_i == nIn else b'\x00'
        pre += struct.pack('<i', 0) if (real_i != nIn and (fSingle or fNone)) else struct.pack('<I', seq)
    if fNone: nOutputs = 0
    elif fSingle: nOutputs = nIn+1
    else: nOutputs = len(outs)
    pre += cs(nOutputs)
    for i in range(nOutputs):
        if fSingle and i != nIn: pre += b'\xff'*8 + b'\x00'
        else:
            val, spk = outs[i]; pre += val + cs(len(spk)) + spk
    pre += struct.pack('<I', locktime)
    pre += struct.pack('<i', hashtype)
    return sha256d(pre)

def p2pk_spk(pub): return push(pub) + b'\xac'

def locate_fields(tx_bytes):
    """Parse a serialized tx and return (input_offsets, output_offsets) where
    each input_offsets[i] = offset of that input's 36-byte prevout, and each
    output_offsets[j] = offset of that output's 8-byte value. Avoids
    hand-computed byte arithmetic for the tamper cases below."""
    b = tx_bytes; p = 4
    def rd_cs():
        nonlocal p
        v = b[p]
        if v < 0xfd: p += 1; return v
        if v == 0xfd: r = struct.unpack_from('<H', b, p+1)[0]; p += 3; return r
        if v == 0xfe: r = struct.unpack_from('<I', b, p+1)[0]; p += 5; return r
        r = struct.unpack_from('<Q', b, p+1)[0]; p += 9; return r
    nin = rd_cs(); in_offs = []
    for _ in range(nin):
        in_offs.append(p)
        p += 36
        slen = rd_cs(); p += slen
        p += 4
    nout = rd_cs(); out_offs = []
    for _ in range(nout):
        out_offs.append(p)
        p += 8
        slen = rd_cs(); p += slen
    return in_offs, out_offs

def build_and_sign(fund_outs, spend_outs, nIn, hashtype, key, spk):
    fund = Tx(); fund.ins = [('00'*32, 0xffffffff, b'\x51', 0xffffffff)]
    fund.outs = fund_outs
    fund_bytes = fund.ser()
    previd = sha256d(fund_bytes)
    spend = Tx(); spend.locktime = 0
    spend.ins = [(previd.hex(), i, b'', 0xffffffff) for i in range(len(fund_outs))]
    spend.outs = spend_outs
    raw = spend.ser()
    d = legacy_sighash(raw, spk, nIn, hashtype)
    sig = der_sign(key, d) + bytes([hashtype & 0xff])
    ss = push(sig)   # P2PK scriptSig is JUST the signature -- the pubkey is
                      # already in scriptPubKey, unlike P2PKH.
    spend.ins[nIn] = (spend.ins[nIn][0], spend.ins[nIn][1], ss, 0xffffffff)
    return fund_bytes, spend.ser(), ss

CASES = []
def add(name, tx, ss, spk, nIn, expect_accept):
    CASES.append((name, tx, ss, spk, nIn, 1 if expect_accept else 0))

def main():
    k1 = 0xA11CE
    pub1 = pubkey(k1)
    spk = p2pk_spk(pub1)

    # ---- SIGHASH_NONE: outputs are unbound after signing ----
    fund, spend, ss = build_and_sign([(100000, spk)], [(90000, b'\x51')], 0, SIGHASH_NONE, k1, spk)
    add('none-genuine', spend, ss, spk, 0, True)
    _, out_offs = locate_fields(spend)
    spend_t = bytearray(spend)
    spend_t[out_offs[0]:out_offs[0]+8] = struct.pack('<Q', 12345)
    add('none-tampered-output-still-accepts', bytes(spend_t), ss, spk, 0, True)

    # control: same spend but SIGHASH_ALL -- tampering the output MUST now reject
    fundA, spendA, ssA = build_and_sign([(100000, spk)], [(90000, b'\x51')], 0, SIGHASH_ALL, k1, spk)
    add('all-genuine', spendA, ssA, spk, 0, True)
    _, out_offsA = locate_fields(spendA)
    spendA_t = bytearray(spendA)
    spendA_t[out_offsA[0]:out_offsA[0]+8] = struct.pack('<Q', 12345)
    add('all-tampered-output-rejects', bytes(spendA_t), ssA, spk, 0, False)

    # ---- SIGHASH_SINGLE: only the same-index output is bound ----
    fundS, spendS, ssS = build_and_sign([(100000, spk)], [(50000, b'\x51'), (40000, b'\x52')], 0, SIGHASH_SINGLE, k1, spk)
    add('single-genuine', spendS, ssS, spk, 0, True)
    _, out_offsS = locate_fields(spendS)
    spendS_other = bytearray(spendS)
    spendS_other[out_offsS[1]:out_offsS[1]+8] = struct.pack('<Q', 999)  # output[1]: unbound by SINGLE at nIn=0
    add('single-tampered-other-output-still-accepts', bytes(spendS_other), ssS, spk, 0, True)
    spendS_same = bytearray(spendS)
    spendS_same[out_offsS[0]:out_offsS[0]+8] = struct.pack('<Q', 999)  # output[0]: the bound one
    add('single-tampered-same-output-rejects', bytes(spendS_same), ssS, spk, 0, False)

    # ---- ANYONECANPAY: other inputs' prevouts are unbound ----
    fundP, spendP, ssP = build_and_sign(
        [(100000, spk), (50000, b'\x51')],
        [(140000, b'\x51')], 0, SIGHASH_ALL | SIGHASH_ANYONECANPAY, k1, spk)
    add('acp-genuine', spendP, ssP, spk, 0, True)
    in_offsP, _ = locate_fields(spendP)
    spendP_other = bytearray(spendP)
    spendP_other[in_offsP[1]:in_offsP[1]+4] = b'\xde\xad\xbe\xef'  # input[1]: unbound by ANYONECANPAY
    add('acp-tampered-other-input-still-accepts', bytes(spendP_other), ssP, spk, 0, True)
    spendP_same = bytearray(spendP)
    spendP_same[in_offsP[0]:in_offsP[0]+4] = b'\xde\xad\xbe\xef'  # input[0]: the signed one
    add('acp-tampered-signed-input-rejects', bytes(spendP_same), ssP, spk, 0, False)

    # ---- SIGHASH_SINGLE out-of-range quirk: nIn>=nOut -> degenerate hash,
    # genuinely signed, still verifies (Core's own well-known behavior). ----
    fundQ, spendQ, ssQ = build_and_sign([(100000, spk)], [], 0, SIGHASH_SINGLE, k1, spk)
    add('single-out-of-range-quirk-still-accepts', spendQ, ssQ, spk, 0, True)

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'asm', 'tests', 'hashtype_vec.h')
    with open(out_path, 'w') as f:
        f.write('/* AUTO-GENERATED by validation/gen_hashtype_vectors.py -- DO NOT EDIT. */\n')
        f.write('#ifndef HASHTYPE_VEC_H\n#define HASHTYPE_VEC_H\n\n')
        f.write('static const char* HT_NAME[] = {\n')
        for c in CASES: f.write('  "%s",\n' % c[0])
        f.write('};\n\nstatic const char* HT_TX[] = {\n')
        for c in CASES: f.write('  "%s",\n' % c[1].hex())
        f.write('};\n\nstatic const char* HT_SS[] = {\n')
        for c in CASES: f.write('  "%s",\n' % c[2].hex())
        f.write('};\n\nstatic const char* HT_SPK[] = {\n')
        for c in CASES: f.write('  "%s",\n' % c[3].hex())
        f.write('};\n\nstatic const unsigned HT_NIN[] = {\n  ')
        f.write(', '.join(str(c[4]) for c in CASES))
        f.write('\n};\n\nstatic const unsigned HT_EXPECT[] = {\n  ')
        f.write(', '.join(str(c[5]) for c in CASES))
        f.write('\n};\n\nstatic const unsigned HT_COUNT = %d;\n\n#endif\n' % len(CASES))
    print('wrote %d cases to %s' % (len(CASES), out_path))
    for c in CASES:
        print('  %-42s nIn=%d expect=%s' % (c[0], c[4], 'ACCEPT' if c[5] else 'REJECT'))

if __name__ == '__main__':
    main()
