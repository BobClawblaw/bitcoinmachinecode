#!/usr/bin/env python3
# Genesis block oracle v3
# Deterministically builds the serialized genesis coinbase tx around the
# authoritative 77-byte scriptSig PUSHDATA constant, then cross-checks the
# well-known published values (txid, merkle root, block hash).
# Trusted reference for the asm tx parser + hashing.
import hashlib, struct
def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def rev(b): return b[::-1]

# Authoritative genesis coinbase scriptSig (single 77-byte PUSHDATA)
SCRIPTSIG = bytes.fromhex(
    "04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368"
    "616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c"
    "6f757420666f722062616e6b73")
assert len(SCRIPTSIG) == 77, len(SCRIPTSIG)

# Authoritative 33-byte genesis pubkey
PUBKEY = bytes.fromhex(
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
    "b649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
assert len(PUBKEY) == 65, len(PUBKEY)  # 0x04-prefixed uncompressed SEC pubkey
SCRIPTPK = bytes([0x41]) + PUBKEY + bytes([0xac])   # PUSH33 <pubkey> OP_CHECKSIG (67B)
assert len(SCRIPTPK) == 67

def varint(n):
    assert n < 0xfd
    return bytes([n])

def vin(script):
    return b"\x00"*32 + struct.pack("<I", 0xffffffff) + varint(len(script)) + script + struct.pack("<I", 0xffffffff)
def vout(value, script):
    return struct.pack("<Q", value) + varint(len(script)) + script

# --- serialize coinbase tx ---
tx  = struct.pack("<I", 1)                 # version = 1
tx += varint(1)                            # 1 input
tx += vin(SCRIPTSIG)
tx += varint(1)                            # 1 output
tx += vout(50*10**8, SCRIPTPK)             # 50 BTC
tx += struct.pack("<I", 0)                # locktime = 0
print("serialized coinbase tx len =", len(tx))

# Known published facts to check against
txid_display_expected = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
merkle_root_display_expected = "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
block_hash_display_expected = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

txid_internal = sha256d(tx)
txid_display  = rev(txid_internal)
print("txid (internal) =", txid_internal.hex())
print("txid (display)  =", txid_display.hex())
assert txid_display.hex() == txid_display_expected, "txid mismatch!"

# --- 80-byte header ---
version, = struct.unpack("<I", struct.pack("<I", 1))
hdr  = struct.pack("<I", 1)                                    # version
hdr += b"\x00"*32                                              # prev hash
hdr += txid_internal                                           # merkle root (LE)
hdr += struct.pack("<I", 0x495fab29)                          # time
hdr += struct.pack("<I", 0x1d00ffff)                          # bits
hdr += struct.pack("<I", 0x7c2bac1d)                          # nonce
assert len(hdr) == 80
blockhash = sha256d(hdr)
# Byte-order notes (genesis quirk):
#  - The header stores the merkle root in RAW (internal) digest order == raw txid.
#  - Block explorers print the merkle root in raw order for genesis (3ba3edfd...)
#    but the txid/block-hash in display order. Both "3ba3edfd..." (raw root) and
#    "4a5e1e4b..." (display root/txid) are correct; they are byte-reverses.
raw_root  = txid_internal                     # == 3ba3edfd...
# verify the explorer-quoted RAW root matches
assert raw_root.hex() == merkle_root_display_expected, "raw merkle root mismatch"
# display root == display txid == reverse(raw root)
assert rev(raw_root).hex() == txid_display_expected
print("merkle root (raw/header)=", raw_root.hex())
print("block hash (display) =", rev(blockhash).hex())
assert rev(blockhash).hex() == block_hash_display_expected

print("--- asm test-harness reference values ---")
print("tx_hex = ", tx.hex())
print("tx_len =", len(tx))
print("txid_internal_hex =", txid_internal.hex())
print("value_sat =", 50*10**8)
print("script_sig_len =", len(SCRIPTSIG))
print("ALL GENESIS ORACLE CHECKS PASS")
