import hashlib

script_hex = '522103ba6f2e86a2b485e96242506b576251b7c8038255463401361d248973b654d4452103775f5d3233b002e7e39e64862312c35c6099c51b35b1c8e3245b33d11f0772103ff7d17e4d06922442b01786c7e45e0e4140a1c81f049c1b0c8e418c64595353'
script = bytes.fromhex(script_hex)
sha = hashlib.sha256(script).digest()
rip = hashlib.new('ripemd160', sha).digest()
print('SHA256:', sha.hex())
print('RIPEMD160 (Python):', rip.hex())

# Also test with a simple case
rip_test = hashlib.new('ripemd160', b'abc').digest()
print('RIPEMD160("abc"):', rip_test.hex())
