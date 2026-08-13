#!/usr/bin/env python3
from point_oracle import P, N, GX, GY, dbl, add, mul, to_aff
G = (GX, GY)

print('n*G ->', to_aff(mul(N, GX, GY)))
assert to_aff(mul(N, GX, GY)) is None
print('(n+1)G == G :', to_aff(mul(N+1, GX, GY)) == G)

two = to_aff(mul(2, GX, GY))
three = to_aff(mul(3, GX, GY))
print('2G x  :', '%064x' % two[0])
print('2G y  :', '%064x' % two[1])
print('3G x  :', '%064x' % three[0])
print('3G y  :', '%064x' % three[1])

s = to_aff(add(*mul(2, GX, GY), GX, GY, 1))
assert s == three
print('2G+G == 3G : OK')
assert to_aff(dbl(GX, GY, 1)) == two
print('dbl(G) == 2G : OK')

k = 0x1234567890abcdef1234567890abcdef
a = to_aff(mul(k, GX, GY))
print('k=%064x' % k)
print('kG x  :', '%064x' % a[0])
print('kG y  :', '%064x' % a[1])

ng = to_aff(mul(N-1, GX, GY))
assert ng == (GX, (-GY) % P)
print('(n-1)G == -G : OK')
print('ALL COORD CHECKS PASSED')
