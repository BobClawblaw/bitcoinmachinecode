#!/usr/bin/env python3
"""Capture real Core sendheaders-announce + feefilter wire bytes over loopback.

Connects to a real Bitcoin Core regtest node as a P2P peer, does the
version/verack/wtxidrelay handshake, negotiates `sendheaders`, catches up on
the (single-genesis) chain, then mines a NEW block via RPC and captures what
Core announces to us:
  - because we negotiated sendheaders, Core must announce the new tip with a
    `headers` message (NOT an `inv`).
We also record any `feefilter` Core sends (min-relay-feerate as int64 LE).

Prints the exact wire frames so we can cross-check our ASM implementation.
"""
import socket, struct, hashlib, time, subprocess, sys

MAGIC = b'\xfa\xbf\xb5\xda'   # regtest
HOST, PORT = '127.0.0.1', 19444
RPC = ['/storage/bitcoin-core-source/build/bin/bitcoin-cli','-datadir=/tmp/ffsh','-rpcuser=u','-rpcpassword=p']

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def frame(cmd, payload):
    if isinstance(cmd,str): cmd=cmd.encode()
    h = MAGIC + cmd[:12] + b'\x00'*(12-len(cmd[:12])) + struct.pack('<I',len(payload))
    return h + sha256d(payload)[:4] + payload

def varint(n):
    if n<0xfd: return bytes([n])
    if n<=0xffff: return b'\xfd'+struct.pack('<H',n)
    return b'\xfe'+struct.pack('<I',n)

def readframe(s):
    hdr=b''
    while len(hdr)<24:
        b=s.recv(24-len(hdr))
        if not b: raise EOFError
        hdr+=b
    assert hdr[:4]==MAGIC,"bad magic"
    cmd=hdr[4:16].split(b'\x00')[0].decode()
    ln=struct.unpack('<I',hdr[16:20])[0]
    ck=hdr[20:24]; p=b''
    while len(p)<ln:
        b=s.recv(ln-len(p)); 
        if not b: raise EOFError
        p+=b
    assert sha256d(p)[:4]==ck,"cksum %s"%cmd
    return cmd,p

def main():
    s=socket.create_connection((HOST,PORT),timeout=15)
    s.settimeout(15)
    v=struct.pack('<i',70016)+struct.pack('<Q',1)+struct.pack('<q',int(time.time()))
    v+=struct.pack('<Q',0)+b'\x00'*12+b'\x7f\x00\x00\x01'+struct.pack('>H',PORT)
    v+=struct.pack('<Q',0)+b'\x00'*12+b'\x7f\x00\x00\x01'+struct.pack('>H',0)
    v+=struct.pack('<Q',0x0100000000000000)
    v+=varint(0)+struct.pack('<i',0)+struct.pack('<?',1)
    s.sendall(frame('version',v))
    recv=[]
    cmd,p=readframe(s); recv.append((cmd,p))
    assert cmd=='version'
    s.sendall(frame('wtxidrelay',b''))
    s.sendall(frame('verack',b''))
    s.settimeout(3)
    # Collect Core's post-handshake negotiation set (sendheaders/sendcmpct/
    # sendaddrv2/wtxidrelay/feefilter...) until a short quiet period.
    try:
        for _ in range(12):
            cmd,p=readframe(s); recv.append((cmd,p))
    except socket.timeout:
        pass
    print("post-handshake frames:",[(c,len(p)) for c,p in recv], flush=True)

    # negotiate sendheaders + catch up on the genesis chain
    s.sendall(frame('sendheaders',b''))
    genesis=bytes.fromhex('0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206')
    gh=struct.pack('<i',70015)+b'\x01'+genesis+b'\x00'*32
    s.sendall(frame('getheaders',gh))

    # drain until we've seen the initial headers page return (or timeout)
    frames=[]
    try:
        while True:
            cmd,p=readframe(s)
            frames.append((cmd,p))
            if cmd=='headers':
                # got initial catch-up headers; stop
                break
    except socket.timeout:
        pass
    print("catch-up:",[(c,len(p)) for c,p in frames], flush=True)

    # mine ONE new block via RPC -> Core should announce the new tip to us
    subprocess.run(RPC+['createwallet','w0'],capture_output=True,text=True)
    addr=subprocess.run(RPC+['getnewaddress'],capture_output=True,text=True).stdout.strip()
    r=subprocess.run(RPC+['generatetoaddress','1',addr],capture_output=True,text=True)
    print("mined:",r.stdout.strip(),r.stderr.strip(), flush=True)

    announced=[]
    try:
        while True:
            cmd,p=readframe(s)
            announced.append((cmd,p))
            if cmd in ('inv','headers') :
                # got the announcement; keep reading a moment for feefilter/others
                continue
    except socket.timeout:
        pass

    print("\n=== after mining new block, Core sent us: ===", flush=True)
    for cmd,p in announced:
        print(f"  {cmd} payload_len={len(p)}", flush=True)
        if cmd=='headers':
            # count varint + 81*count
            n=p[0]
            print(f"    count={n}  first-header-field bytes: {p[1:81].hex()}", flush=True)
            print(f"    tx-count byte after first header: {p[81]:#x}", flush=True)
        if cmd=='inv':
            n=p[0]
            print(f"    count={n} type={struct.unpack('<I',p[1:5])[0]} hash={p[5:37].hex()}", flush=True)
        if cmd=='feefilter':
            feerate=struct.unpack('<q',p[:8])[0]
            print(f"    min-relay-feerate (int64 LE) = {feerate} sat/kvB; bytes={p[:8].hex()}", flush=True)

    # Report whether the post-handshake set included a feefilter from Core
    print("\nfeefilter details:", flush=True)
    found_fee=False
    for c,p in recv:
        if c=='feefilter':
            found_fee=True
            print(f"  Core feefilter payload bytes: {p.hex()}  -> int64 LE = {struct.unpack('<q',p[:8])[0]} sat/kvB", flush=True)
    if not found_fee:
        print("  (no feefilter in handshake; Core v31.99 may not send one on regtest by default)", flush=True)
    ff2=[c for c,_ in frames if c=='feefilter']
    print("feefilter seen in catch-up frames:", ff2, flush=True)

if __name__=='__main__':
    main()
