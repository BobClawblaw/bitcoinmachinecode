#!/usr/bin/env python3
"""p2p_inbound_probe.py -- ask a node every inbound P2P message we can, and
record what it answers.

WHY: this node's inbound serve path has only ever been exercised by our own
harnesses, and our own harnesses are exactly what missed a node that had
never served a block to anyone (2026-08-27, incident: index.dat keyed
backwards). The point of this probe is to be a STRANGER: it speaks the wire
protocol directly and reports what came back, with no knowledge of how the
node is implemented.

Run it against Bitcoin Core and against this node on the same chain, and diff
the two reports. A message Core answers and we ignore is a gap; a message we
answer differently is a divergence worth a look.

Usage: p2p_inbound_probe.py <host> <port> <magic-hex> [--json]
"""
import socket, struct, hashlib, sys, time, json

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

class Peer:
    def __init__(self, host, port, magic, timeout=6.0):
        self.magic = bytes.fromhex(magic)
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b''

    def send(self, cmd, payload=b''):
        c = cmd.encode() + b'\x00' * (12 - len(cmd))
        hdr = self.magic + c + struct.pack('<I', len(payload)) + sha256d(payload)[:4]
        self.s.sendall(hdr + payload)

    def recv_one(self, deadline):
        while True:
            if len(self.buf) >= 24:
                magic, cmd, ln, _chk = (self.buf[:4], self.buf[4:16],
                                        struct.unpack('<I', self.buf[16:20])[0], self.buf[20:24])
                if len(self.buf) >= 24 + ln:
                    payload = self.buf[24:24+ln]
                    self.buf = self.buf[24+ln:]
                    return cmd.rstrip(b'\x00').decode('latin1'), payload
            if time.time() > deadline:
                return None, None
            try:
                self.s.settimeout(max(0.2, deadline - time.time()))
                chunk = self.s.recv(65536)
            except (socket.timeout, TimeoutError):
                return None, None
            except OSError:
                return None, None
            if not chunk:
                return None, None
            self.buf += chunk

    def drain(self, secs=1.5):
        """collect everything that arrives within `secs`"""
        out, deadline = [], time.time() + secs
        while True:
            cmd, pl = self.recv_one(deadline)
            if cmd is None: return out
            out.append((cmd, pl))

def version_payload(magic):
    return (struct.pack('<iQq', 70016, 9, int(time.time()))
            + b'\x00'*26 + b'\x00'*26
            + struct.pack('<Q', 0x1234) + b'\x00'
            + struct.pack('<i', 0) + b'\x01')

def handshake(host, port, magic, pre_verack=()):
    """connect and complete the handshake; `pre_verack` messages are sent in
    the window Core requires for them (wtxidrelay/sendaddrv2 MUST precede
    verack -- sending them after is a protocol violation Core disconnects
    for, which is itself a thing worth probing separately)."""
    p = Peer(host, port, magic)
    p.send('version', version_payload(magic))
    got = p.drain(4.0)
    names = [c for c, _ in got]
    if 'verack' not in names:
        return None, names
    for cmd, pl in pre_verack:
        p.send(cmd, pl)
    p.send('verack')
    p.drain(1.0)
    return p, names

# Each probe gets its OWN connection. A node that disconnects on one message
# would otherwise silence every message after it, and the report would blame
# the wrong one.
ZERO32 = b'\x00' * 32

def build_probes(tip_hash_le, tip_height):
    """Probes that reference a REAL block. With a zero hash every node
    ignores getdata/getcfilters and the report reads as "not supported",
    which is a different and much more damning claim than the truth."""
    T = tip_hash_le
    return [
    ('ping',          'ping',         struct.pack('<Q', 0xfeedface), ()),
    ('getaddr',       'getaddr',      b'', ()),
    ('mempool',       'mempool',      b'', ()),
    ('getheaders',    'getheaders',   struct.pack('<i', 70016) + b'\x01' + T + ZERO32, ()),
    ('getblocks',     'getblocks',    struct.pack('<i', 70016) + b'\x01' + T + ZERO32, ()),
    ('getdata_blk',   'getdata',      b'\x01' + struct.pack('<I', 2) + T, ()),
    ('getdata_wblk',  'getdata',      b'\x01' + struct.pack('<I', 0x40000002) + T, ()),
    ('getdata_cmpct', 'getdata',      b'\x01' + struct.pack('<I', 4) + T, ()),
    ('getdata_tx',    'getdata',      b'\x01' + struct.pack('<I', 1) + ZERO32, ()),
    ('sendheaders',   'sendheaders',  b'', ()),
    ('sendcmpct',     'sendcmpct',    b'\x01' + struct.pack('<Q', 2), ()),
    ('feefilter',     'feefilter',    struct.pack('<q', 1000), ()),
    ('notfound',      'notfound',     b'\x01' + struct.pack('<I', 1) + ZERO32, ()),
    ('getcfilters',   'getcfilters',  struct.pack('<B', 0) + struct.pack('<I', max(0, tip_height-1)) + T, ()),
    ('getcfheaders',  'getcfheaders', struct.pack('<B', 0) + struct.pack('<I', max(0, tip_height-1)) + T, ()),
    ('getcfcheckpt',  'getcfcheckpt', struct.pack('<B', 0) + T, ()),
    ('filterload',    'filterload',   b'\x02\xff\xff' + struct.pack('<II', 1, 0) + b'\x00', ()),
    ('filterclear',   'filterclear',  b'', ()),
    ('sendtxrcncl',   'sendtxrcncl',  struct.pack('<IQ', 1, 0), ()),
    ('wtxidrelay',    None,           None, (('wtxidrelay', b''),)),
    ('sendaddrv2',    None,           None, (('sendaddrv2', b''),)),
]

def probe(host, port, magic, tip_hash_le=ZERO32, tip_height=0, wait=2.0):
    r = {"handshake": None, "handshake_ok": False, "messages": {}}
    p, names = handshake(host, port, magic)
    r["handshake"] = names
    if p is None:
        return r
    r["handshake_ok"] = True
    try: p.s.close()
    except OSError: pass

    for name, wire, pl, pre in build_probes(tip_hash_le, tip_height):
        try:
            p, hs = handshake(host, port, magic, pre)
            if p is None:
                r["messages"][name] = {"answered": ["<handshake refused>"]}
                continue
            if wire is None:
                # the probe IS the pre-verack negotiation: did it survive, and
                # did the peer echo the same offer back in its own handshake?
                r["messages"][name] = {"answered": ["accepted" if 'verack' in hs else "refused"],
                                       "peer_offered": name in hs}
            else:
                p.send(wire, pl)
                answers = p.drain(wait)
                r["messages"][name] = {"answered": [c for c, _ in answers],
                                       "sizes": [len(x) for _, x in answers]}
            try: p.s.close()
            except OSError: pass
        except OSError as e:
            r["messages"][name] = {"answered": ["<connection error>"], "err": str(e)}
    return r

if __name__ == '__main__':
    host, port, magic = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    # optional: a REAL block to ask about, as display hex + height
    tip = ZERO32; th = 0
    if len(sys.argv) > 5 and not sys.argv[4].startswith('--'):
        tip = bytes.fromhex(sys.argv[4])[::-1]; th = int(sys.argv[5])
    wait = 2.0
    for a in sys.argv:
        if a.startswith('--wait='): wait = float(a.split('=')[1])
    rep = probe(host, port, magic, tip, th, wait)
    if '--json' in sys.argv:
        print(json.dumps(rep, indent=1)); sys.exit(0)
    print("handshake: %s (ok=%s)" % (','.join(rep['handshake'] or []), rep.get('handshake_ok')))
    for k, v in rep["messages"].items():
        a = v["answered"]
        extra = ''
        if 'peer_offered' in v: extra = '   [peer offers it too: %s]' % v['peer_offered']
        print("  %-14s -> %s%s" % (k, ','.join(a) if a else '(silence)', extra))
