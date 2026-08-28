#!/usr/bin/env python3
"""peers_dat_port_audit.py -- audit (and optionally repair) the byte order of
the port field in this node's address book, data/peers.dat.

WHY. The book's 18-byte record is [ip 4][port 2][services 8][last_seen 4].
The contract is that the port sits BIG-ENDIAN on disk, exactly as it does on
the wire: the encoders that answer getaddr copy the two bytes verbatim. The
DNS-seed writers always honoured that (htons); the two gossip-ingest writers
(daemon/addr_ingest.c, daemon/addrgather.c) passed the host-order value until
2026-08-28, so every record THEY wrote holds the port byte-swapped. A book
written before that date is a mix, and once getaddr replies started working
(same day -- they never had before) the swapped entries would be served to
Core as e.g. 1.2.3.4:36128. Found by an adversarial review of that change.

HOW IT DECIDES. A swapped record for the default port reads, as a little-
endian u16, exactly 8333 (0x208d), whereas a correct record reads 36128
(0x8d20). 8333 is what essentially every Bitcoin peer listens on, so:
  - u16le == 8333  -> written host-order: swapped (repair = swap the bytes)
  - u16le == 36128 -> correct
  - anything else  -> ambiguous (a non-default port in either order); left
                      alone and counted, never touched
Repair is byte-for-byte in place with a backup copy, and is a no-op on a
book that is already consistent.

Usage: peers_dat_port_audit.py <peers.dat> [--fix]
"""
import os, shutil, struct, sys

def audit(path):
    data = open(path, 'rb').read()
    n = len(data) // 18
    swapped = correct = other = 0
    for i in range(n):
        p_le = struct.unpack('<H', data[i*18+4:i*18+6])[0]
        if p_le == 8333:    swapped += 1
        elif p_le == 36128: correct += 1
        else:               other += 1
    return n, swapped, correct, other

def fix(path):
    data = bytearray(open(path, 'rb').read())
    n = len(data) // 18
    fixed = 0
    for i in range(n):
        o = i*18+4
        if struct.unpack('<H', data[o:o+2])[0] == 8333:
            data[o], data[o+1] = data[o+1], data[o]
            fixed += 1
    if fixed:
        bak = path + '.pre-port-fix'
        if not os.path.exists(bak): shutil.copy2(path, bak)
        tmp = path + '.tmp'
        with open(tmp, 'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    return fixed

def selftest():
    import tempfile
    d = tempfile.mkdtemp(); p = os.path.join(d, 'peers.dat')
    rec = lambda port_bytes: b'\x05\x06\x07\x08' + port_bytes + struct.pack('<Q', 9) + struct.pack('<I', 1)
    open(p, 'wb').write(rec(b'\x8d\x20') + rec(b'\x20\x8d') + rec(b'\x00\x50'))   # swapped, correct, other(80)
    assert audit(p) == (3, 1, 1, 1), audit(p)
    assert fix(p) == 1
    assert audit(p) == (3, 0, 2, 1), audit(p)
    assert fix(p) == 0                      # idempotent
    assert open(p, 'rb').read()[4:6] == b'\x20\x8d'
    shutil.rmtree(d); return True

if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] == '--selftest':
        print("selftest ok" if selftest() else "selftest FAILED"); sys.exit(0)
    path = sys.argv[1]
    n, sw, ok, oth = audit(path)
    print("%s: %d records: %d port-swapped (u16le==8333), %d correct (bytes 20 8d), %d other/ambiguous"
          % (path, n, sw, ok, oth))
    if '--fix' in sys.argv:
        f = fix(path)
        n2, sw2, ok2, oth2 = audit(path)
        print("repaired %d record(s); now %d swapped, %d correct, %d other (backup: %s.pre-port-fix)"
              % (f, sw2, ok2, oth2, path))
