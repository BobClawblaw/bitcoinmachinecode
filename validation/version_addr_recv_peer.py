#!/usr/bin/env python3
"""version_addr_recv_peer.py -- a v1 P2P peer that names a chosen addr_recv.

Connects to HOST:PORT, sends a `version` whose addr_recv is ADDR (an IPv4 or
IPv6 literal) and PORT_RECV, completes the handshake, then holds the
connection open for HOLD seconds so the far node's getpeerinfo can be read.
The far node must report addr_recv back as `addrlocal`, formatted as Core's
CService::ToStringAddrPort. Used by addrlocal_regtest_e2e.sh against Core
and this node alike, so both answer the same bytes.

  version_addr_recv_peer.py HOST PORT MAGIC_HEX ADDR PORT_RECV HOLD
"""
import hashlib, ipaddress, random, socket, struct, sys, time

host, port, magic, addr, port_recv, hold = sys.argv[1:7]
magic = bytes.fromhex(magic)

def msg(cmd, payload):
    ck = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return magic + cmd.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + ck + payload

ip = ipaddress.ip_address(addr)
ip16 = (b"\0" * 10 + b"\xff\xff" + ip.packed) if ip.version == 4 else ip.packed
payload = (struct.pack("<iQq", 70016, 0, int(time.time()))
           + struct.pack("<Q", 0) + ip16 + struct.pack(">H", int(port_recv))   # addr_recv
           + b"\0" * 26                                                        # addr_from
           + struct.pack("<Q", random.getrandbits(64))
           + b"\x0f/addrlocal-e2e/" + struct.pack("<i", 0) + b"\x00")
s = socket.create_connection((host, int(port)), timeout=10)
s.sendall(msg("version", payload))
buf, got_verack, t0 = b"", False, time.time()
while not got_verack and time.time() - t0 < 10:
    chunk = s.recv(65536)
    if not chunk:
        sys.exit("closed before verack")
    buf += chunk
    while len(buf) >= 24:
        cmd = buf[4:16].rstrip(b"\0").decode()
        n = struct.unpack("<I", buf[16:20])[0]
        if len(buf) < 24 + n:
            break
        buf = buf[24 + n:]
        if cmd == "version":
            s.sendall(msg("verack", b""))
        elif cmd == "verack":
            got_verack = True
if not got_verack:
    sys.exit("no verack")
print("handshake done", flush=True)
s.settimeout(1)
t_end = time.time() + float(hold)
while time.time() < t_end:
    try:
        if not s.recv(65536):
            break
    except socket.timeout:
        pass
