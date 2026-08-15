#!/usr/bin/env python3
"""Parse a captured Core cmpctblock payload, reload the real block via RPC,
recompute short-tx-ids with the reference implementation, and verify that the
recomputed short IDs match the shorttxids Core actually put on the wire.

Also dumps the wire codecs (shorttxid list + prefilled txn) that the ASM
implementation must reproduce byte-for-byte.
"""
import struct, sys, hashlib, subprocess, json
sys.path.insert(0, '/storage/bitcoinmachinecode/validation')
from bip152_ref import shortid_for

RPC = ['/storage/bitcoin-core-source/build/bin/bitcoin-cli',
       '-datadir=/tmp/corecmpt','-rpcuser=u','-rpcpassword=p']

def cli(*args):
    args=[str(a) for a in args]
    return subprocess.run(RPC+list(args), capture_output=True, text=True).stdout

def varint(data, off):
    b=data[off]
    if b<0xfd: return b, off+1
    if b==0xfd: return struct.unpack('<H',data[off+1:off+3])[0], off+3
    if b==0xfe: return struct.unpack('<I',data[off+1:off+5])[0], off+5
    return struct.unpack('<Q',data[off+1:off+9])[0], off+9

def parse_cmpctblock(data):
    hdr80 = data[0:80]
    nonce = struct.unpack('<Q', data[80:88])[0]
    off=88
    nshort, off = varint(data, off)
    shortids=[]
    for i in range(nshort):
        shortids.append(int.from_bytes(data[off:off+6],'little'))
        off+=6
    nprefill, off = varint(data, off)
    return hdr80, nonce, shortids, nprefill, off

if __name__=='__main__':
    data=open('/tmp/corecmpt/captured_cmpctblock.bin','rb').read()
    hdr80, nonce, shortids, nprefill, off = parse_cmpctblock(data)
    print("header80[0:8]:", hdr80[:8].hex())
    print("nonce: %#x"%nonce)
    print("nshorttxids:", len(shortids), "nprefilled:", nprefill)
    print("prefilled txn region starts at offset", off, "(blockhash-hdr = %d bytes)"%len(data))
    # block hash from RPC: get the best block
    # block hash from the header: sha256d(header80) in wire order (reversed hex)
    hsh = hashlib.sha256(hashlib.sha256(hdr80).digest()).digest()  # internal order
    bh = hsh[::-1].hex()  # wire/display order
    blk = json.loads(cli('getblock', bh, 2))
    print("block:", bh, "ntx:", len(blk['tx']))
    # The cmpctblock has prefilledtxn for coinbase (index 0) and shorttxids for the rest.
    # Full tx count = nshorttxids + nprefilled.
    total = len(shortids) + nprefill
    print("expected txs in block:", total, "(block actual ntx:", len(blk['tx']), ")")
    # recompute short ids for each non-coinbase tx (index 1..end)
    # wtxid = 'hash' field (witness hash)
    recomputed=[]
    for tx in blk['tx'][1:]:  # skip coinbase (prefilled)
        wtxid = bytes.fromhex(tx['hash'])[::-1]  # wire order (LE)
        recomputed.append(shortid_for(hdr80, nonce, wtxid))
    match = (recomputed == shortids)
    print("shorttxids recomputed == on-wire:", "MATCH" if match else "MISMATCH")
    if not match:
        for i,(a,b) in enumerate(zip(shortids, recomputed)):
            if a!=b: print("  shortid[%d] wire=%#012x ref=%#012x"%(i,a,b))
    # dump wire vectors for the ASM test
    print("\n=== WIRE VECTORS ===")
    print("SIPHASH/HEADERS: hdr=%s nonce=%d"%(hdr80.hex(), nonce))
    for i,s in enumerate(shortids):
        print("SHORTID %d %#012x wtxidhex=%s"%(i, s, blk['tx'][i+1]['hash']))
    json.dump({'hdr80':hdr80.hex(),'nonce':nonce,'shortids':shortids,
               'blockhash':bh,'ntx':len(blk['tx'])},
              open('/tmp/corecmpt/cmpct_vectors.json','w'))
    print("saved vectors to /tmp/corecmpt/cmpct_vectors.json")
