# Differential fuzz: AArch64 asm SHA-256 vs Python hashlib
import hashlib, ctypes, os, random

lib = ctypes.CDLL(os.path.abspath("port/arm64/sha256.so"))
lib.sha256_full.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_ulong]
lib.sha256_init.argtypes = [ctypes.POINTER(ctypes.c_uint32)]
lib.sha256_block.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_char_p]

def asm_full(msg: bytes) -> bytes:
    out = ctypes.create_string_buffer(32)
    buf = ctypes.create_string_buffer(msg)
    lib.sha256_full(out, buf, len(msg))
    return out.raw

def asm_stream(chunks: list) -> bytes:
    # incremental via init + block over each full 64B chunk (partial chunk left)
    import struct
    data = b"".join(chunks)
    # emulate full: pad
    bitlen = len(data)*8
    data = data + b"\x80"
    while len(data) % 64 != 56:
        data += b"\x00"
    data += struct.pack(">Q", bitlen)
    st = (ctypes.c_uint32*8)()
    lib.sha256_init(st)
    for off in range(0, len(data), 64):
        blk = data[off:off+64]
        lib.sha256_block(st, blk)
    out = b""
    for i in range(8):
        out += struct.pack(">I", st[i])
    return out

fails = 0
cases = list(range(0, 130)) + [200, 255, 256, 257, 511, 512, 513, 1000, 1001, 4096, 65536+1]
random.seed(1234)
for _ in range(300):
    cases.append(random.randint(0, 2000))

for n in cases:
    for trial in range(2):
        msg = bytes(random.getrandbits(8) for _ in range(n))
        want = hashlib.sha256(msg).digest()
        got = asm_full(msg)
        if got != want:
            print(f"FAIL full len={n} trial={trial}")
            fails += 1
        got2 = asm_stream([msg[:len(msg)//2], msg[len(msg)//2:]])
        if got2 != want:
            print(f"FAIL stream len={n}")
            fails += 1

print(f"differential fuzz: {len(cases)*2} messages x (full+stream) checked, fails={fails}")
