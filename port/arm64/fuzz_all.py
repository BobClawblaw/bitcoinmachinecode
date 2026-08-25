# Differential fuzz of all ported hashing modules vs Python hashlib.
import hashlib, ctypes, os, random, struct, sys

D = os.path.dirname(os.path.abspath(__file__))
def load(name, exports):
    lib = ctypes.CDLL(os.path.join(D, name))
    for f, at in exports.items():
        getattr(lib, f).argtypes = at
    return lib

def onepass(msg, fn, outlen):
    out = ctypes.create_string_buffer(outlen)
    buf = ctypes.create_string_buffer(msg)
    fn(out, buf, len(msg))
    return out.raw

fails = 0
random.seed(20260824)

# ---- sha256 / sha1 / sha512 / ripemd160
libs = {
 "sha256.so":    ("sha256_full", 32, lambda m: hashlib.sha256(m).digest()),
 "sha1.so":      ("sha1_full",   20, lambda m: hashlib.sha1(m).digest()),
 "sha512.so":    ("sha512_full", 64, lambda m: hashlib.sha512(m).digest()),
 "ripemd160.so": ("ripemd160",   20, lambda m: hashlib.new('ripemd160', m).digest()),
}

for so,(fnname,olen,pyfn) in libs.items():
    lib = ctypes.CDLL(os.path.join(D, so))
    fn = getattr(lib, fnname); fn.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_long]
    run = lambda m: onepass(m, fn, olen)
    # canonical vectors + boundaries
    cases = list(range(0,140)) + [200,255,256,257,511,512,513,1000,4096,65537]
    cases += [random.randint(0,3000) for _ in range(150)]
    for n in cases:
        m = bytes(random.getrandbits(8) for _ in range(n))
        if run(m) != pyfn(m):
            print(f"FAIL {so} len={n}"); fails += 1
    print(f"{so}: {len(cases)} msgs checked")

# ---- sha256d (double SHA-256)
bhash = load("bitcoin_hash.so", {"sha256d": [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_ulong]})
run = lambda m: onepass(m, bhash.sha256d, 32)
for n in [0,1,3,55,56,57,63,64,65,100,1000,4096]+[random.randint(0,3000) for _ in range(100)]:
    m = bytes(random.getrandbits(8) for _ in range(n))
    want = hashlib.sha256(hashlib.sha256(m).digest()).digest()
    if run(m) != want: print("FAIL sha256d len", n); fails += 1
print("bitcoin_hash.so sha256d checked")

print("TOTAL FAILS:", fails)
sys.exit(1 if fails else 0)
