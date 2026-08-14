#!/usr/bin/env python3
"""Standalone test: pure-python secp256k1 ECDSA sign + verify."""
import hashlib

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0: return None
    if p == q:
        lam = (3 * p[0] * p[0]) * pow(2 * p[1], P - 2, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], P - 2, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    y = (lam * (p[0] - x) - p[1]) % P
    return (x, y)

def mul(k, p):
    r = None
    while k:
        if k & 1: r = add(r, p)
        p = add(p, p); k >>= 1
    return r

def pubkey(priv):
    Q = mul(priv, G)
    return (Q[0], Q[1])

def rfc6979_k(priv, z):
    # simple deterministic nonce via RFC6979 (HMAC-SHA256)
    import hmac
    x = priv.to_bytes(32, 'big')
    h1 = z.to_bytes(32, 'big')
    V = b'\x01' * 32
    K = b'\x00' * 32
    K = hmac.new(K, V + b'\x00' + x + h1, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b'\x01' + x + h1, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = int.from_bytes(V, 'big')
        if 1 <= k < N:
            return k
        K = hmac.new(K, V + b'\x00', hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()

def sign(priv, z):
    k = rfc6979_k(priv, z)
    R = mul(k, G)
    r = R[0] % N
    if r == 0: raise RuntimeError('r=0')
    s = (pow(k, N - 2, N) * (z + r * priv)) % N
    if s == 0: raise RuntimeError('s=0')
    if s > N // 2:   # low-S
        s = N - s
    return r, s

def verify(z, r, s, Q):
    if not (1 <= r < N and 1 <= s < N): return False
    w = pow(s, N - 2, N)
    u1 = z * w % N; u2 = r * w % N
    R = add(mul(u1, G), mul(u2, Q))
    if R is None: return False
    return R[0] % N == r

def der(r, s):
    def enc_int(x):
        b = x.to_bytes(32, 'big')
        b = b.lstrip(b'\x00') or b'\x00'
        if b[0] & 0x80: b = b'\x00' + b
        return b'\x02' + bytes([len(b)]) + b
    body = enc_int(r) + enc_int(s)
    return b'\x30' + bytes([len(body)]) + body

if __name__ == '__main__':
    priv = 0x1111111111111111111111111111111111111111111111111111111111111111
    z = int.from_bytes(bytes.fromhex('d1e1a714a43c44c7287f20acbd78dab5c00b3d48afc2e6bb60755c8fe4dbab8d'), 'big')
    Q = pubkey(priv)
    r, s = sign(priv, z)
    print('Q = (%064x,\n     %064x)' % Q)
    print('r = %064x' % r)
    print('s = %064x' % s)
    print('low-S:', s <= N // 2)
    print('verify (pure py):', verify(z, r, s, Q))
    print('DER:', der(r, s).hex())
