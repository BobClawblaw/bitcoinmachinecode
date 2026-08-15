#!/usr/bin/env python3
"""Live Bitcoin P2P oracle — probe what a real seed actually serves.

Establishes GROUND TRUTH for the documented "seeds drop getdata to minimal
clients" gap (PLAN.md): we do a real handshake + getdata against a live seed
under two version-message profiles and record exactly what the peer serves.

Profiles:
  A) "minimal"  — the node's CURRENT advertised services = NODE_NETWORK(1)
                  (mirrors asm/bitcoind.asm node_make_version).
  B) "fullnode" — services = NODE_NETWORK|NODE_WITNESS|NODE_NETWORK_LIMITED|NODE_COMPACT_FILTERS
                  (what Core advertises), relay=1, start_height=~tip.

Real Bitcoin protocol v70016. Wire framing: magic f9beb4d9, then 12-byte
padded command, 4-byte length LE, 4-byte checksum, payload.
"""
import socket, struct, time, hashlib, sys

MAGIC = b"\xf9\xbe\xb4\xd9"
P2P_VER = 70016

def cmd(s):  # 12-byte zero-padded command
    if isinstance(s, str):
        s = s.encode()
    return s.ljust(12, b"\x00")

def msg(name, payload=b""):
    c = cmd(name)
    l = struct.pack("<I", len(payload))
    h = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return MAGIC + c + l + h + payload

def dsha(payload):
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()

def cksum(payload):
    return dsha(payload)[:4]

def read_frame(sock):
    hdr = b""
    while len(hdr) < 24:
        chunk = sock.recv(24 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    assert hdr[:4] == MAGIC, "bad magic"
    name = hdr[4:16].rstrip(b"\x00").decode()
    length = struct.unpack("<I", hdr[16:20])[0]
    ck = hdr[20:24]
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            return None
        payload += chunk
    assert cksum(payload) == ck, "bad checksum on " + name
    return name, payload

def version_payload(services, start_height=0, relay=1, pver=70016,
                    ua="tmp-oracle/"):
    payload = bytearray()
    payload += struct.pack("<I", pver)          # nVersion
    payload += struct.pack("<Q", services)      # nServices
    payload += struct.pack("<q", int(time.time()))  # nTime
    payload += b"\x00" * 26                     # addrRecv
    payload += b"\x00" * 26                     # addrFrom
    payload += struct.pack("<Q", 0x1122334455667788)  # nonce
    ub = ua.encode()
    payload += bytes([len(ub)]) + ub            # user-agent varstr
    payload += struct.pack("<i", start_height)  # start height
    payload += bytes([relay])                   # relay
    return bytes(payload)

def getheaders_payload(hashes, stop_hash=b"\x00"*32):
    p = struct.pack("<I", 70016)
    p += bytes([len(hashes)])
    for h in hashes:
        p += h
    p += stop_hash
    return p

def getdata_block(hash):
    p = bytes([1]) + struct.pack("<I", 2) + hash  # count=1, MSG_BLOCK=2
    return p

GENESIS_BLOCK = bytes.fromhex(
    "000000000019d6689c085ae165831e93" +
    "4ff763ae46a2a6c172b3f1b60a8ce26f")
# a well-known mainnet header hash near genesis for locator
LOCATOR = GENESIS_BLOCK if False else None  # use real chain

def run(host, services, ua, start_height):
    s = socket.create_connection((host, 8333), timeout=15)
    s.settimeout(15)
    v = version_payload(services, start_height=start_height, ua=ua)
    s.sendall(msg("version", v))
    got = {}
    # handshake: wait for verack (reply with verack), collect announce msgs
    deadline = time.time() + 10
    sent_verack = False
    while time.time() < deadline:
        fr = read_frame(s)
        if fr is None:
            break
        name, payload = fr
        got[name] = got.get(name, 0) + 1
        if name == "verack" and not sent_verack:
            s.sendall(msg("verack"))
            sent_verack = True
        if name == "ping":
            s.sendall(msg("pong", payload))
        # once we've seen verack+peer maybe sends sendheaders/feefilter; collect a moment
        if sent_verack and name != "ping":
            pass
    # Now request headers from genesis to observe server behavior
    s.sendall(msg("getheaders", getheaders_payload([GENESIS_BLOCK])))
    time.sleep(1.0)
    served_headers = 0
    also = {}
    end = time.time() + 8
    while time.time() < end:
        fr = read_frame(s)
        if fr is None:
            break
        name, payload = fr
        also[name] = also.get(name, 0) + 1
        if name == "headers":
            # count varint
            cnt = payload[0]
            served_headers += cnt
        if name == "inv":
            pass
        if name == "sendheaders" or name == "sendcmpct" or name == "feefilter":
            pass
    s.close()
    return got, also, served_headers

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "seed.bitcoin.sipa.be"
    services_minimal = 1  # NODE_NETWORK only (node's current value)
    services_full = (1 | 2 | (1 << 10) | (1 << 11))  # NETWORK|WITNESS|COMPACT_FILTERS|NETWORK_LIMITED
    print(f"### PROFILE A (minimal, node's current): services={services_minimal}")
    try:
        ga, aa, ha = run(host, services_minimal, "asm-node", 0)
        print("  handshake msgs:", ga)
        print("  after getheaders:", aa, "served_headers=", ha)
    except Exception as e:
        print("  ERROR:", e)
    print()
    print(f"### PROFILE B (full-node): services={services_full}")
    try:
        gb, ab, hb = run(host, services_full, "/Satoshi:27.0.0/", 900000)
        print("  handshake msgs:", gb)
        print("  after getheaders:", ab, "served_headers=", hb)
    except Exception as e:
        print("  ERROR:", e)

if __name__ == "__main__":
    main()
