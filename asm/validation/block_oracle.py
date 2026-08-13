#!/usr/bin/env python3
# Block-construction oracle for cons_verify (S4). Builds a VALID serialized
# block (2 txs: 1 coinbase + 1 normal) with correct PoW-satisfying nonce and a
# correct merkle root over the txids. Also emits deterministic INVALID variants.
import hashlib, struct

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def rev32(b): return b[::-1]
def cvarint(n):
    if n < 0xfd: return bytes([n])
    return b'\xfd'+struct.pack('<H', n)

def tx_coinbase(extra, n=1):
    v = struct.pack('<I',1)
    nin = b'\x01'                  # 1 input
    prevout = b'\x00'*32
    idx = struct.pack('<I',0xffffffff)
    scr = b'\x51' + extra + b'\x00'*4   # push op
    scl = cvarint(len(scr))
    seq = struct.pack('<I',0xffffffff)
    nout = b'\x00'                  # 0 outputs for test simplicity? use 1
    nout = b'\x01'
    val = struct.pack('<Q', 50*10**8)
    oscr = b'\x51\xa9'             # OP_TRUE OP_HASH160? keep minimal: OP_TRUE
    oscr = b'\x51'
    oscl = cvarint(len(oscr))
    lt = struct.pack('<I',0)
    return v+nin+prevout+idx+scl+scr+seq+nout+val+oscl+oscr+lt

def tx_normal(prev_txid, prev_index=0):
    v = struct.pack('<I',1)
    nin = b'\x01'
    prevout = prev_txid             # 32 bytes (the coinbase txid)
    idx = struct.pack('<I',prev_index)
    scr = b'\x51'                   # scriptSig: push 1
    scl = cvarint(len(scr))
    seq = struct.pack('<I',0xffffffff)
    nout = b'\x01'
    val = struct.pack('<Q', 49*10**8)
    oscr = b'\x51'
    oscl = cvarint(len(oscr))
    lt = struct.pack('<I',0)
    return v+nin+prevout+idx+scl+scr+seq+nout+val+oscl+oscr+lt

def merkle_root(ids):
    ids = list(ids)
    while len(ids) > 1:
        if len(ids) % 2: ids.append(ids[-1])
        nxt=[]
        for i in range(0,len(ids),2):
            nxt.append(sha256d(ids[i]+ids[i+1]))
        ids=nxt
    return ids[0]

BITS = 0x207fffff     # very easy target (near-maximum) so PoW needs no searching
# PoW target from bits (little-endian 32-byte target)
def target_from_bits(bits):
    exp = bits >> 24
    mant = bits & 0x00ffffff
    target = mant << (8*(exp-3))
    return target.to_bytes(32,'little')

def find_nonce(hdr, target):
    # with an easy target, nonce 0 already satisfies PoW
    h = bytearray(hdr)
    struct.pack_into('<I', h, 76, 0)
    hsh = sha256d(bytes(h))
    assert int.from_bytes(hsh,'little') <= int.from_bytes(target,'little'), 'nonce 0 should satisfy easy target'
    return 0

def build_block(extra=b'\x11'):
    cb = tx_coinbase(extra)
    cbid = sha256d(cb)
    # note: cbid is the internal/LE txid (== raw sha256d)
    n = tx_normal(cbid)
    txs = cb+n
    mr = merkle_root([sha256d(cb), sha256d(n)])
    # header: version, prevhash(zeros), merkle, time, bits, nonce
    prev = b'\x00'*32
    hdr = bytearray(struct.pack('<I',1) + prev + mr + struct.pack('<I', 1700000000) + struct.pack('<I', BITS) + struct.pack('<I',0))
    target = target_from_bits(BITS)
    nonce = find_nonce(hdr, target)
    assert nonce is not None
    struct.pack_into('<I', hdr, 76, nonce)
    blk = hdr + txs
    return blk, nonce, mr, [sha256d(cb), sha256d(n)], cb, n

if __name__=='__main__':
    blk, nonce, mr, ids, cb, n = build_block(b'\x11')
    print('block len:', len(blk))
    print('tx count: 2')
    print('merkle root:', mr.hex())
    print('nonce:', nonce)
    print('coinbase in_present n_out skip')
    print('block[0:4] version:', blk[:4].hex())
    print('header merkle field (block[36:68]):', blk[36:68].hex())
    # variants
    open('/tmp/cons_block.bin','wb').write(blk)
    # invalid: wrong merkle (flip it)
    bad = bytearray(blk); bad[36] ^= 0x01
    open('/tmp/cons_block_badmerkle.bin','wb').write(bytes(bad))
    # invalid: trailing garbage
    open('/tmp/cons_block_trailing.bin','wb').write(blk + b'\xff')
