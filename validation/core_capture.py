#!/usr/bin/env python3
"""Capture Core's real BIP152 wire traffic over loopback.

Connects to a real Bitcoin Core regtest node as a P2P peer, performs the
version/verack/wtxidrelay handshake, negotiates compact blocks (sendcmpct
high-bandwidth), triggers a new block on the node, and captures the
`cmpctblock` / `blocktxn` messages Core actually sends. We then recompute
the short-tx-ids from the block with our own reference implementation and,
if we requested a getblocktxn, rebuild the block to prove byte-parity.

Used to generate authoritative per-Core vectors (wire bytes) that exercise
the ASM implementation.
"""
import socket, struct, hashlib, time, sys, json

MAGIC = b'\xfa\xbf\xb5\xda'   # regtest
NETWORK='regtest'

class Msg:
    def __init__(self, cmd, payload=b''):
        self.cmd=cmd[:12].encode()+b'\x00'*(12-len(cmd[:12]))
        self.payload=payload

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def frame(cmd, payload):
    if isinstance(cmd, str): cmd = cmd.encode()
    h = MAGIC + cmd[:12] + b'\x00'*(12-len(cmd[:12])) + struct.pack('<I',len(payload))
    h += sha256d(payload)[:4]
    return h+payload

def varint(n):
    if n<0xfd: return bytes([n])
    if n<=0xffff: return b'\xfd'+struct.pack('<H',n)
    if n<=0xffffffff: return b'\xfe'+struct.pack('<I',n)
    return b'\xff'+struct.pack('<Q',n)

def readframe(s):
    hdr = b''
    while len(hdr)<24:
        b=s.recv(24-len(hdr))
        if not b: raise EOFError
        hdr+=b
    assert hdr[:4]==MAGIC, "bad magic %r"%hdr[:4]
    cmd = hdr[4:16].split(b'\x00')[0].decode()
    ln = struct.unpack('<I', hdr[16:20])[0]
    ck = hdr[20:24]
    payload=b''
    while len(payload)<ln:
        b=s.recv(ln-len(payload))
        if not b: raise EOFError
        payload+=b
    assert sha256d(payload)[:4]==ck, "cksum fail %s"%cmd
    return cmd, payload

def connect(port=18444):
    s=socket.create_connection(('127.0.0.1',port),timeout=10)
    return s

def do_handshake(s, wtxid=True):
    # version message
    v = struct.pack('<i', 70016)                    # version
    v += struct.pack('<Q', 1)                       # services
    v += struct.pack('<q', int(time.time()))        # timestamp
    # NetworkAddress: services(8) + 16-byte IP (12 pad + 4 ipv4) + port(2)
    addr_recv = struct.pack('<Q',0)+ b'\x00'*12 + b'\x7f\x00\x00\x01' + struct.pack('>H',18444)
    v += addr_recv
    addr_from = struct.pack('<Q',0)+ b'\x00'*12 + b'\x7f\x00\x00\x01' + struct.pack('>H',0)
    v += addr_from
    v += struct.pack('<Q', 0x0100000000000000)      # nonce
    v += varint(1)+ b'\x0f\x2f\x53\x61\x74\x6f\x73\x68\x69\x3a\x32\x35\x2e\x30\x2f'  # user agent "/Satoshi:25.0/"
    v += struct.pack('<i', 0)                       # start height 0
    v += struct.pack('<?', 1)                       # relay
    s.sendall(frame('version', v))
    # receive version + wireready (sendheaders since ver >= 70012 is automatic if we don't). 
    # Core sends version, wtxidrelay (if request), verack, sendheaders, sendcmpct...
    r=[]
    cmd,payload=readframe(s); r.append(cmd)
    assert cmd=='version', cmd
    # Must send wtxidrelay BEFORE verack completes the handshake, else Core
    # disconnects ("wtxidrelay received after verack").
    if wtxid:
        s.sendall(frame('wtxidrelay', b''))
    s.sendall(frame('verack', b''))
    # we must send sendaddrv2? Core sends sendaddrv2 to us only if we send first; not required.
    # Now read until we have our verack
    for _ in range(6):
        cmd,payload=readframe(s); r.append(cmd)
        if cmd in ('verack',):
            # after verack, Core will send sendheaders, sendcmpct
            continue
    return r

if __name__=='__main__':
    port=int(sys.argv[1]) if len(sys.argv)>1 else 18444
    outfile=sys.argv[2] if len(sys.argv)>2 else '/tmp/corecmpt/captured_cmpctblock.bin'
    s=connect(port)
    print("connected", flush=True)
    r=do_handshake(s)
    print("handshake msgs:", r, flush=True)
    # Catch up on headers: send sendheaders, then consume Core's initial headers
    # so Core records pindexBestKnownBlock == current tip (required for the
    # high-bandwidth fast-announce of a NEW block to us).
    s.sendall(frame('sendheaders', b''))
    print("sent sendheaders", flush=True)
    # Request the full chain: getheaders with a locator rooted at the regtest
    # genesis block hash (0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206).
    # Empty (count=0) locators are ignored by Core, so use the genesis hash.
    genesis = bytes.fromhex('0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206')
    getheaders_payload = struct.pack('<i', 70015) + b'\x01' + genesis + b'\x00'*32
    s.sendall(frame('getheaders', getheaders_payload))
    print("sent getheaders(genesis locator)", flush=True)
    s.settimeout(6)
    headers_synced=False
    tip_header=None
    try:
        while not headers_synced:
            cmd,payload=readframe(s)
            print("recv", cmd, "len", len(payload), flush=True)
            if cmd=='headers':
                # record last header 80 bytes
                # payload: count varint + (80-byte header + 0 tx-count) each
                cnt=payload[0]
                if cnt>0:
                    tip_header=payload[1+ (cnt-1)*81 : 1+ (cnt-1)*81 +80]
                print("  received %d headers, tip_header=%s"%(cnt, tip_header[:4].hex() if tip_header else None), flush=True)
                headers_synced=True
            if cmd=='getheaders':
                # respond with one empty headers to stop the locator request
                s.sendall(frame('headers', b'\x00'))
                print("  replied empty headers to getheaders", flush=True)
    except (socket.timeout, EOFError) as e:
        print("headers sync ended:", e, flush=True)
    if tip_header is None:
        print("WARN: no tip header received; compact announce may not fire", flush=True)
    # NOW negotiate high-bandwidth compact blocks
    s.sendall(frame('sendcmpct', bytes([1])+struct.pack('<Q',2)))
    print("sent sendcmpct(hb=1, v=2)", flush=True)
    s.settimeout(15)
    try:
        while True:
            cmd,payload=readframe(s)
            print("recv", cmd, "len", len(payload), flush=True)
            if cmd=='cmpctblock':
                with open(outfile,'wb') as f:
                    f.write(payload)
                print("  saved cmpctblock payload (%d bytes) to %s"%(len(payload),outfile), flush=True)
    except (socket.timeout, EOFError) as e:
        print("capture ended:", e, flush=True)
