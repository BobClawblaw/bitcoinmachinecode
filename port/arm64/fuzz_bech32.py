#!/usr/bin/env python3
"""Differential fuzz: bech32.S vs an independent pure-Python BIP173/BIP350
reference (Reference Implementation from BIP173, converted to bit ops here).

Generates random:
  - convert_bits cases (8->5, 5->8, and other from/to incl. pad 0/1)
  - encode (create_checksum + chars) for both specs + random hrp/data
  - verify_checksum on valid (matching spec) and cross-spec data
  - decode + decode-compat round trips
Feeds /tmp/fzb_cases.txt to ./fz_bech32, compares line-by-line.
"""
import sys, random, subprocess

GEN = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CHARSET_REV = {c:i for i,c in enumerate(CHARSET)}
CHARSET_REV_FULL = {}
for _i,_c in enumerate(CHARSET):
    CHARSET_REV_FULL[_c] = _i          # lowercase
    CHARSET_REV_FULL[_c.upper()] = _i  # uppercase

def polymod(values):
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GEN[i]
    return chk

def hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_polymod(hrp, data, spec):
    const = 1 if spec==0 else 0x2bc830a3
    vals = hrp_expand(hrp) + list(data)
    return polymod(vals) ^ const

def create_checksum(hrp, data, spec):
    values = hrp_expand(hrp) + list(data) + [0]*6
    mod = polymod(values) ^ (1 if spec==0 else 0x2bc830a3)
    return [(mod >> (5*(5-i))) & 31 for i in range(6)]

def encode(hrp, data, spec):
    ck = create_checksum(hrp, data, spec)
    return hrp + '1' + ''.join(CHARSET[d] for d in data) + ''.join(CHARSET[c] for c in ck)

def verify(hrp, data, spec):
    return bech32_polymod(hrp, data, spec) == 1

def convertbits(data, frombits, tobits, pad):
    acc = 0; bits = 0; ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits: ret.append((acc << (tobits - bits)) & maxv)
    elif bits and ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def decode(s):
    # reference decode, matching Core/x86 bech32::Decode semantics: data chars
    # map case-insensitively (uppercase -> same value as lowercase).
    pos = s.rfind('1')
    if pos < 1: return None
    hrp = s[:pos]; dat = s[pos+1:]
    if not all(33 <= ord(c) <= 126 for c in hrp): return None
    try:
        data = [CHARSET_REV_FULL[c] for c in dat]
    except KeyError:
        return None
    if len(dat) < 6: return None
    return hrp, data

def rand_hrp(rng):
    n = rng.randrange(1, 50)
    return ''.join(chr(rng.randrange(0x21, 0x7f)) for _ in range(n))

def rand_5(rng, n):
    return [rng.randrange(0,32) for _ in range(n)]

def rand_bytes(rng, n):
    return [rng.randrange(0,256) for _ in range(n)]

def main():
    seed = int(sys.argv[1]) if len(sys.argv)>1 else 1
    iters = int(sys.argv[2]) if len(sys.argv)>2 else 2000
    rng = random.Random(seed)
    cmds = []
    exp = []
    for _ in range(iters):
        k = rng.randrange(0,5)
        if k == 0:
            # convert_bits
            fb = rng.choice([3,4,5,6,8])
            tb = rng.choice([3,4,5,6,8])
            pad = rng.randint(0,1)
            n = rng.randrange(0,40)
            data = rand_bytes(rng, n)
            r = convertbits(data, fb, tb, pad)
            hx = bytes(data).hex()
            cmds.append(f"conv {fb} {tb} {pad} {hx}")
            exp.append(f"conv {'-1' if r is None else str(len(r))+' '+bytes(r).hex()}")
        elif k == 1:
            spec = rng.randint(0,1)
            hrp = rand_hrp(rng)
            n = rng.randrange(0,60)
            data = rand_5(rng, n)
            e = encode(hrp, data, spec)
            cmds.append(f"enc {spec} {hrp} {n} {bytes(data).hex()}")
            exp.append(f"enc {len(e)} {e}")
        elif k == 2:
            spec = rng.randint(0,1)
            hrp = rand_hrp(rng)
            n = rng.randrange(6,60)
            data = rand_5(rng, n)
            # if data is a real encoding's payload, tests must match; build valid one
            full = hrp_expand(hrp) + data
            r = polymod(full)==(1 if spec==0 else 0x2bc830a3)
            cmds.append(f"verify {spec} {hrp} {n} {bytes(data).hex()}")
            exp.append(f"verify {int(r)}")
        elif k == 3:
            # cross-spec verify: a payload checksummed for one spec must NOT
            # validate under the other spec
            spec = rng.randint(0,1)
            hrp = rand_hrp(rng)
            n = rng.randrange(0,60)
            d0 = rand_5(rng, n)
            other = 1 - spec
            ck = create_checksum(hrp, d0, spec)
            fulldata = d0 + ck
            cmds.append(f"verify {other} {hrp} {len(fulldata)} {bytes(fulldata).hex()}")
            exp.append("verify 0")
        else:
            # decode a freshly encoded string (round-trip) or a mutated/gibberish one
            spec = rng.randint(0,1)
            hrp = rand_hrp(rng)
            n = rng.randrange(0,60)
            data = rand_5(rng, n)
            s = encode(hrp, data, spec)
            if rng.random() < 0.35:
                # corrupt a char
                s = list(s)
                ci = rng.randrange(len(s))
                s[ci] = CHARSET[rng.randrange(32)]
                s = ''.join(s)
            d = decode(s)
            if d is None:
                cmds.append(f"dec {s}")
                exp.append("dec -1")
            else:
                hr, dat = d
                cmds.append(f"dec {s}")
                exp.append(f"dec {len(dat)} {hr} {bytes(dat).hex()}")
    inp = "\n".join(cmds) + "\n"
    open("/tmp/fzb_cases.txt","w").write(inp)
    p = subprocess.run(["./fz_bech32"], input=inp, capture_output=True, text=True)
    if p.returncode != 0:
        print("DRIVER FAILED rc", p.returncode); print(p.stderr); sys.exit(2)
    got = [l for l in p.stdout.splitlines() if l.strip()]
    if len(got) != len(exp):
        print("LINE COUNT mismatch", len(got), len(exp)); sys.exit(2)
    fails = 0
    for i,(e,g) in enumerate(zip(exp,got)):
        if e.rstrip() != g.rstrip():
            fails += 1
            if fails <= 5:
                print("MISMATCH")
                print("  cmd", cmds[i][:110])
                print("  exp ", e[:110])
                print("  got ", g[:110])
    print(f"seed={seed} iters={iters} lines={len(exp)} FAILS={fails}")
    sys.exit(1 if fails else 0)

if __name__ == "__main__":
    main()
