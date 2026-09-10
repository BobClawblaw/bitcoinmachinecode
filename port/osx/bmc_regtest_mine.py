#!/usr/bin/env python3
"""bmc_regtest_mine.py -- mine regtest blocks into the native osx bmcbitcoind.

Uses the node's own getblocktemplate/submitblock: builds the segwit coinbase
(BIP34 height in scriptSig, witness reserved value), the witness commitment
output, assembles the header, scans the nonce (regtest difficulty is
trivial), and submits.  usage: bmc_regtest_mine.py <nblocks> [addr]
"""
import hashlib, http.client, json, sys, struct, time

RPC_HOST, RPC_PORT = '127.0.0.1', 18443

def rpc(method, params=None):
    cookie = open('/tmp/bmc_regtest/regtest/.cookie').read().strip()
    c = http.client.HTTPConnection(RPC_HOST, RPC_PORT, timeout=30)
    c.request('POST', '/', json.dumps({'jsonrpc':'2.0','id':1,'method':method,
                                       'params':params or []}),
              {'Authorization': 'Basic ' + __import__('base64').b64encode(cookie.encode()).decode(),
               'Content-Type': 'application/json'})
    r = json.loads(c.getresponse().read())
    c.close()
    if 'error' in r and r['error']: raise RuntimeError(r['error'])
    return r['result']

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def cs(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + n.to_bytes(2,'little')
    return b'\xfe' + n.to_bytes(4,'little')

BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
def bech32_decode(addr):
    """minimal BIP173 decoder: returns (witver, program bytes)"""
    pos = addr.rindex('1')
    hrp, data = addr[:pos].lower(), addr[pos+1:]
    vals = [BECH32_CHARSET.index(c) for c in data]
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + vals:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    if chk != 1: raise ValueError('bad bech32 checksum')
    witver = vals[0]
    body = vals[1:-6]                      # drop witver + 6 checksum chars
    acc, bits, prog = 0, 0, []
    for v in body:
        acc = (acc << 5) | v; bits += 5
        while bits >= 8:
            bits -= 8; prog.append((acc >> bits) & 0xff)
    return witver, bytes(prog)

def build_coinbase(height, value, spk, extranonce):
    # BIP34: scriptSig starts with the height, in Core's exact encoding:
    # heights 1..16 are the OP_N opcodes (0x50+h); larger heights are a
    # minimal push (len byte + LE bytes + sign byte when the top bit is set).
    if 1 <= height <= 16:
        height_part = bytes([0x50 + height])
    else:
        hb = b''
        vn = height
        while vn:
            hb += bytes([vn & 0xff]); vn >>= 8
        if hb[-1] & 0x80: hb += b'\x00'
        height_part = bytes([len(hb)]) + hb
    script_sig = height_part + cs(8) + extranonce.to_bytes(8, 'little')
    # input: null prevout, scriptSig, sequence 0xffffffff
    txin = b'\x00'*32 + b'\xff\xff\xff\xff' + cs(len(script_sig)) + script_sig + b'\xff\xff\xff\xff'
    # witness reserved value (32 zero bytes) as the ONLY witness item
    wit = cs(1) + cs(32) + b'\x00'*32   # 1 item: the 32-byte reserved value
    # outputs: (1) payout (2) witness commitment (6a24aa21a9ed<h32>)
    commit_h = sha256d(b'\x00'*32 + b'\x00'*32)   # empty witness root + reserved key
    commitment_out = b'\x00\x00\x00\x00\x00\x00\x00\x00' + cs(38) + b'\x6a\x24\xaa\x21\xa9\xed' + commit_h
    payout = value.to_bytes(8, 'little') + cs(len(spk)) + spk
    body = (b'\x01\x00\x00\x00'            # version
            + b'\x00'                       # marker (segwit)
            + b'\x01'                       # flag (segwit)
            + b'\x01'                       # n_in
            + txin
            + b'\x02'                       # n_out
            + payout + commitment_out
            + wit
            + b'\x00\x00\x00\x00')          # locktime
    return body

def merkle_with_coinbase(cb_txid_internal, other_txids):
    # cb_txid_internal = the txid in INTERNAL (little-endian) byte order --
    # the merkle tree hashes internal-order txids, NOT the display hex
    h = [cb_txid_internal] + [bytes.fromhex(t) for t in other_txids]
    while len(h) > 1:
        if len(h) % 2: h.append(h[-1])
        h = [sha256d(h[i] + h[i+1]) for i in range(0, len(h), 2)]
    return h[0]

def mine_one(tpl, spk, extranonce):
    prev = bytes.fromhex(tpl['previousblockhash'])[::-1]
    bits = int(tpl['bits'], 16)
    version = tpl['version'] | 0x20000000
    cb = build_coinbase(tpl['height'], tpl['coinbasevalue'], spk, extranonce)
    # coinbase txid = sha256d over the NO-WITNESS serialization:
    # version(4) + [n_in varint .. end of outputs) + locktime(4)
    # = drop marker/flag (2) and the witness (1 item-count + 1 len + 32 = 34)
    body = cb[:4] + cb[6:len(cb)-38] + cb[-4:]
    cb_txid_internal = sha256d(body)          # internal order for the merkle
    merk = merkle_with_coinbase(cb_txid_internal, [t['txid'] for t in tpl['transactions']])
    target = 0
    exp = bits & 0xffffff; shift = (bits >> 24) & 0xff
    target = exp * (1 << (8 * (shift - 3)))
    for nonce in range(0, 1 << 32):
        nt = int(time.time())
        hdr = (version.to_bytes(4,'little') + prev + merk + nt.to_bytes(4,'little')
               + bits.to_bytes(4,'little') + nonce.to_bytes(4,'little'))
        if int.from_bytes(sha256d(hdr), "little") <= target:
            block = hdr + struct.pack('<B', len(tpl['transactions']) + 1) + cb \
                    + b''.join(bytes.fromhex(t['data']) for t in tpl['transactions'])
            return block.hex()
    raise RuntimeError('nonce exhausted')

def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    addr = sys.argv[2] if len(sys.argv) > 2 else open('/tmp/bmc_addr').read().strip()
    witver, prog = bech32_decode(addr)
    spk = bytes([witver, len(prog)]) + prog if witver else b'\x00\x14' + prog
    for i in range(n):
        tpl = rpc('getblocktemplate', [{'mode':'template','rules':['segwit']}])
        blk = mine_one(tpl, spk, 0x5fadc0de + i)
        open('/tmp/try_block.bin','wb').write(bytes.fromhex(blk))
        r = rpc('submitblock', [blk])
        print(f"block {tpl['height']}: submit -> {r!r}")
        if r is not None and r != '': print('  (rejected)'); sys.exit(1)
    info = rpc('getblockchaininfo')
    print(f"tip height now {info['blocks']}, ibd={info['initialblockdownload']}")

if __name__ == '__main__':
    main()
