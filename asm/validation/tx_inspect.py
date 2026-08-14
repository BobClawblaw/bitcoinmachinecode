tx_hex = '020000000111111111111111111111111111111111111111111111111111111111111000000006b483045022100d0de658467f2e3717c602e850e070152c402a94332a27c26b1407d367002203836f4f50d5e3c07c357c124557d5b9f0c26f222097b4c03064e7e0a012103ba6f2e86a2b485e96242506b576251b7c8038255463401361d248973b654d445feffffff0150c300000000000019a67244ef26b38d31c475a4609a4758f9e0c66c2e88ac00000000'
tx = bytes.fromhex(tx_hex)
print(f'Tx length: {len(tx)} bytes')
print(f'tx[4]: 0x{tx[4]:02x} = {tx[4]}')
print(f'tx[41]: 0x{tx[41]:02x} = {tx[41]}')

# ScriptSig bytes at offset 42, length tx[41]
sig_len = tx[41]
print(f'ScriptSig ({sig_len} bytes):')
sig_bytes = tx[42:42+sig_len]
print(''.join(f'{b:02x}' for b in sig_bytes))

# Parse scriptSig pushes
i = 0
while i < sig_len:
    plen = sig_bytes[i]
    push_data = sig_bytes[i+1:i+1+plen]
    print(f'  Push at {i}: len={plen}, data={"".join(f"{b:02x}" for b in push_data)}')
    i += 1 + plen
