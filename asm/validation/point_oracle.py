#!/usr/bin/env python3
P  = 2**256 - 2**32 - 977
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def inv(x): return pow(x, P-2, P)

def dbl(X1,Y1,Z1):
    A = X1*X1 % P; B = Y1*Y1 % P; C = B*B % P
    D = 2*((X1+B)*(X1+B) - A - C) % P
    E = 3*A % P; F = E*E % P
    X3 = (F - 2*D) % P
    Y3 = (E*(D-X3) - 8*C) % P
    Z3 = 2*Y1*Z1 % P
    return (X3,Y3,Z3)

def add(X1,Y1,Z1,X2,Y2,Z2):
    Z1Z1 = Z1*Z1 % P; Z2Z2 = Z2*Z2 % P
    U1 = X1*Z2Z2 % P; U2 = X2*Z1Z1 % P
    S1 = Y1*Z2*Z2Z2 % P; S2 = Y2*Z1*Z1Z1 % P
    if U1 == U2:
        if S1 != S2: return (0,1,0)
        return dbl(X1,Y1,Z1)
    H = (U2-U1) % P; R = (S2-S1) % P
    HH = H*H % P; HHH = H*HH % P; V = U1*HH % P
    X3 = (R*R - HHH - 2*V) % P
    Y3 = (R*(V - X3) - S1*HHH) % P
    Z3 = Z1*Z2*H % P
    return (X3,Y3,Z3)

def mul(k, X, Y, Z=1):
    bits = bin(k)[2:]
    res = (X, Y, Z)
    for b in bits[1:]:
        res = dbl(*res)
        if b == '1':
            res = add(res[0],res[1],res[2], X,Y,Z)
    return res

def to_aff(Pts):
    X,Y,Z = Pts
    if Z == 0:
        return None
    zi = inv(Z); zi2 = zi*zi % P
    return (X*zi2 % P, Y*zi2*zi % P)
