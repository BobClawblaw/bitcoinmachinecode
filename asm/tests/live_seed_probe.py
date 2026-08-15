#!/usr/bin/env python3
"""Live Bitcoin P2P oracle v2 — probe whether a real seed serves block bodies.

Focus: test the node's current minimal services (1) vs a full-node services
against a live seed, and — critically — once we see the seed's `inv`
announcements, issue a `getdata` for an announced block hash and check whether
the seed actually serves the `block` body (the documented "seeds drop getdata
to minimal clients" gap).
"""
import socket, struct, time, hashlib, sys

MAGIC = b"\xf9\xbe\xb4\xd9"

def cmd(s):
    s = s.encode() if isinstance(s, str) else s
    return s.ljust(12, b"\x00")

def dsha(p):
    return hashlib.sha256(hashlib.sha256(p).digest()).digest()

def msg(name, payload=b""):
    hdr = MAGIC + cmd(name) + struct.pack("<I", len(payload)) + dsha(payload)[:4]
    return hdr + payload

def read_frame(s):
    hdr = b""
    while len(hdr) < 24:
        c = s.recv(24 - len(hdr))
        if not c:
            return None
        hdr += c
    if hdr[:4] != MAGIC:
        return None, None
    name = hdr[4:16].rstrip(b"\x00").decode()
    length = struct.unpack("<I", hdr[16:20])[0]
    payload = b""
    while len(payload) < length:
        c = s.recv(length - len(payload))
        if not c:
            return None, None
        payload += c
    return name, payload

def version_payload(services, start_height=0, relay=1):
    p = bytearray()
    p += struct.pack("<I", 70016)
    p += struct.pack("<Q", services)
    p += struct.pack("<q", int(time.time()))
    p += b"\x00" * 26
    p += b"\x00" * 26
    p += struct.pack("<Q", 0x1122334455667788)
    ua = b"/asm-node/"
    p += bytes([len(ua)]) + ua
    p += struct.pack("<i", start_height)
    p += bytes([relay])
    return bytes(p)

def getdata_block(h):
    return bytes([1]) + struct.pack("<I", 2) + h

def getheaders_payload(locator_hashes, stop=b"\x00"*32):
    p = struct.pack("<I", 70016)
    n = len(locator_hashes)
    if n < 253:
        p += bytes([n])
    elif n < 0x10000:
        p += b"\xfd" + struct.pack("<H", n)
    else:
        p += b"\xfe" + struct.pack("<I", n)
    for h in locator_hashes:
        p += h
    p += stop
    return p

GENESIS = bytes.fromhex(
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")

def trial(host, services, label, do_getdata_flow=False):
    print(f"--- PROFILE {label}: services={services} ---")
    try:
        s = socket.create_connection((host, 8333), timeout=15)
    except Exception as e:
        print("  connect fail:", e); return
    s.settimeout(12)
    s.sendall(msg("version", version_payload(services, start_height=900000)))
    got = {}
    got_inv = []
    inv_hashes = []
    verack_sent = False
    got_headers = None
    block_data = None
    requested = False
    sent_gh = False
    end = time.time() + 12
    while time.time() < end:
        try:
            fr = read_frame(s)
        except socket.timeout:
            # idle: try sending getheaders to solicit a headers response
            if do_getdata_flow and not sent_gh:
                s.sendall(msg("getheaders", getheaders_payload([GENESIS])))
                sent_gh = True
            continue
        if fr is None:
            break
        name, payload = fr
        got[name] = got.get(name, 0) + 1
        if name == "verack" and not verack_sent:
            s.sendall(msg("verack")); verack_sent = True
        if name == "ping":
            s.sendall(msg("pong", payload))
        if do_getdata_flow and name == "version" and not sent_gh:
            # solicit headers right after our version is acknowledged
            pass
        if do_getdata_flow and not sent_gh and verack_sent and name != "ping":
            s.sendall(msg("getheaders", getheaders_payload([GENESIS])))
            sent_gh = True
        if name == "headers":
            got_headers = payload
            # parse first header hash (32 bytes) if any
        if name == "block":
            block_data = payload
        # if we have headers and haven't requested a block yet, getdata the first
        if (do_getdata_flow and got_headers is not None and not requested and not block_data
                and len(got_headers) >= 81):
            # headers payload: count varint then 80-byte headers
            cnt = got_headers[0]
            if cnt >= 1:
                hdr = got_headers[1:81]
                # block hash = double-sha256 of the 80-byte header, reversed (display)
                import hashlib
                bh = hashlib.sha256(hashlib.sha256(hdr).digest()).digest()
                print(f"  got headers count={cnt}; getdata first block hash={bh.hex()[:16]}...")
                s.sendall(msg("getdata", getdata_block(bh)))
                requested = True
    if do_getdata_flow:
        if block_data:
            print(f"  RESULT [BLOCK FLOW]: seed SERVED a block body ({len(block_data)} bytes) !!!")
        elif got_headers:
            print(f"  RESULT [BLOCK FLOW]: seed sent headers (count={got_headers[0]}) but no block body served")
        else:
            print("  RESULT [BLOCK FLOW]: no headers/block response")
    else:
        if not trial.block_served:
            print(f"  RESULT: seed did NOT serve a requested block body in window (inv types={sorted(set(t for t,h in inv_hashes))})")
    s.close()

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "seed.bitcoin.sipa.be"
    trial.block_served = False
    trial(host, 3075, "B-fullnode", do_getdata_flow=True)

if __name__ == "__main__":
    main()
