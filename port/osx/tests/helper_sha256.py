import struct, hashlib, sys
inp, outp = sys.argv[1], sys.argv[2]
d = open(inp, 'rb').read()
p = 0
o = []
while p < len(d):
    n = struct.unpack_from('<I', d, p)[0]
    p += 4
    o.append(hashlib.sha256(d[p:p+n]).digest())
    p += n
open(outp, 'wb').write(b''.join(o))
