#!/usr/bin/env python3
"""fetch_taproot_exception.py -- fixtures for LOG.md incident #22, the ONE
mainnet block Core exempts from the taproot rules by HASH.

Core's kernel/chainparams.cpp carries a Taproot `script_flag_exception` for
block 692,261 (0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad):
GetBlockScriptFlags leaves P2SH|WITNESS|TAPROOT on for every block and then
overrides THAT ONE HASH down to P2SH|WITNESS. Transaction
b10c007c60e14f9d087e0291d4d0c7869697c6681d979c6639dbd960792b4d41 (index 193)
spends four real witness_v1_taproot outputs with NO witness at all -- invalid
under taproot, valid without it. Our script_flags_for_block() always computed
that correctly; the two P2TR dispatch sites in daemon/tx_verify.c ignored the
flags they had already computed, so the replay FALSE-REJECTED the block.

Emitted fixtures (tests/taproot_exception_vec.h):

  1. the exception transaction, its four prevouts, and its block's coinbase
     (tx_verify_block_connect_all requires txs[0] to be the coinbase);
  2. the hash of block 692,262 -- a real, non-exception mainnet block hash,
     used to drive the SAME transaction at the SAME height and require a
     REJECT.  That is the half that proves the gating, not merely acceptance;
  3. an ordinary post-activation P2TR key-path spend plus the byte offset of
     a Schnorr signature byte inside it, so the test can also show that the
     taproot rules are really ENFORCED at a non-exception block (the gate
     cannot be "accidentally always off").

The fixture is small, so it is baked into the header and the test never needs
the oracle.

Usage: python3 validation/fetch_taproot_exception.py > tests/taproot_exception_vec.h
"""
import json, subprocess, sys

CLI = ("/storage/bitcoin-core-source/build/bin/bitcoin-cli"
       " -conf=/storage/core-oracle/bitcoin.conf"
       " -datadir=/storage/core-oracle").split()

EXC_HEIGHT = 692261
EXC_HASH   = "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"
EXC_TXID   = "b10c007c60e14f9d087e0291d4d0c7869697c6681d979c6639dbd960792b4d41"
# Where to start looking for an ordinary key-path P2TR spend: comfortably
# after taproot activation at 709,632.
NORM_FROM  = 750000


def rpc(*a):
    r = subprocess.run(CLI + list(a), capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("rpc failed: %s: %s" % (a, r.stderr.strip()))
    return r.stdout.strip()


def getblock2(h):
    return json.loads(rpc("getblock", rpc("getblockhash", str(h)), "2"))


# ---------------------------------------------------------------- tx walking
def rd_cs(b, i):
    v = b[i]; i += 1
    if v < 0xfd:  return v, i
    if v == 0xfd: return int.from_bytes(b[i:i+2], "little"), i+2
    if v == 0xfe: return int.from_bytes(b[i:i+4], "little"), i+4
    return int.from_bytes(b[i:i+8], "little"), i+8


def witness_item_offsets(txhex):
    """[[(off,len), ...] per input] -- byte offsets into the RAW tx of each
    witness item's data. Used to pick a signature byte to corrupt."""
    b = bytes.fromhex(txhex); i = 4
    if b[4] == 0x00 and b[5] == 0x01:
        i = 6
    else:
        return []
    nin, i = rd_cs(b, i)
    for _ in range(nin):
        i += 36
        sl, i = rd_cs(b, i)
        i += sl + 4
    nout, i = rd_cs(b, i)
    for _ in range(nout):
        i += 8
        sl, i = rd_cs(b, i)
        i += sl
    out = []
    for _ in range(nin):
        ni, i = rd_cs(b, i)
        items = []
        for _ in range(ni):
            il, i = rd_cs(b, i)
            items.append((i, il)); i += il
        out.append(items)
    return out


def prevouts_of(txid, blockhash=None):
    t = json.loads(rpc(*(["getrawtransaction", txid, "true"] +
                         ([blockhash] if blockhash else []))))
    prevs = []
    for v in t["vin"]:
        pv = json.loads(rpc("getrawtransaction", v["txid"], "true"))["vout"][v["vout"]]
        prevs.append((v["txid"], v["vout"], int(round(pv["value"] * 1e8)),
                      pv["scriptPubKey"]["hex"], pv["scriptPubKey"].get("type", "?")))
    return t, prevs


def coinbase_hex(height):
    return getblock2(height)["tx"][0]["hex"]


def find_keypath_p2tr(start, rng=40):
    """First smallish tx after `start` all of whose inputs are P2TR key-path
    spends (empty scriptSig, exactly one 64/65-byte witness item)."""
    for h in range(start, start + rng):
        blk = getblock2(h)
        for tx in blk["tx"][1:]:
            vin = tx["vin"]
            if not (1 <= len(vin) <= 3):        continue
            if len(tx["hex"]) // 2 > 2000:      continue
            ok = True
            for v in vin:
                w = v.get("txinwitness", [])
                if v["scriptSig"]["hex"] != "" or len(w) != 1: ok = False; break
                if len(w[0]) // 2 not in (64, 65):             ok = False; break
            if not ok: continue
            # every prevout must really be witness_v1_taproot
            _, prevs = prevouts_of(tx["txid"], blk["hash"])
            if all(p[4] == "witness_v1_taproot" for p in prevs):
                return h, blk["hash"], tx, prevs
    sys.exit("no key-path P2TR spend found near %d" % start)


def emit_prevs(name, prevs):
    print("static const tapexc_prevout_t %s[%d] = {" % (name, len(prevs)))
    for txid, idx, val, spk, typ in prevs:
        print('  { "%s", %d, %dULL, "%s" },   /* %s */' % (txid, idx, val, spk, typ))
    print("};")


# --------------------------------------------------------------------- main
exc_tx, exc_prevs = prevouts_of(EXC_TXID, EXC_HASH)
assert rpc("getblockhash", str(EXC_HEIGHT)) == EXC_HASH, "oracle disagrees on the exception hash"
for _, _, _, _, typ in exc_prevs:
    assert typ == "witness_v1_taproot", "prevout is %s, expected witness_v1_taproot" % typ
for v in exc_tx["vin"]:
    assert not v.get("txinwitness"), "exception tx input unexpectedly HAS a witness"

nbr_hash = rpc("getblockhash", str(EXC_HEIGHT + 1))
nh, nhash, ntx, nprevs = find_keypath_p2tr(NORM_FROM)
sig_off, sig_len = witness_item_offsets(ntx["hex"])[0][0]
assert sig_len in (64, 65)

print("/* GENERATED by validation/fetch_taproot_exception.py from the Core oracle -- do not hand-edit. */")
print("/* LOG.md incident #22: Core's ONE Taproot script_flag_exception block, by HASH. */")
print("typedef struct { const char* txid_hex; unsigned index; unsigned long long value;")
print("                 const char* spk_hex; } tapexc_prevout_t;")
print()
print("/* --- the exception: height %d, the single mainnet block whose flags Core" % EXC_HEIGHT)
print(" *     overrides down to P2SH|WITNESS. Its tx %s..." % EXC_TXID[:16])
print(" *     spends %d witness_v1_taproot outputs with NO witness at all. --- */" % len(exc_prevs))
print('#define TAPEXC_HEIGHT           %dL' % EXC_HEIGHT)
print('#define TAPEXC_BLOCKHASH_RPC    "%s"' % EXC_HASH)
print('#define TAPEXC_TXID             "%s"' % EXC_TXID)
print('#define TAPEXC_TX_HEX           "%s"' % exc_tx["hex"])
print('#define TAPEXC_COINBASE_HEX     "%s"' % coinbase_hex(EXC_HEIGHT))
emit_prevs("TAPEXC_PREVS", exc_prevs)
print('#define TAPEXC_NPREV            %d' % len(exc_prevs))
print()
print("/* --- a REAL, non-exception mainnet block hash (height %d), used to drive" % (EXC_HEIGHT + 1))
print(" *     the very same transaction at the very same height and require a REJECT. --- */")
print('#define TAPEXC_OTHER_BLOCKHASH_RPC "%s"' % nbr_hash)
print()
print("/* --- an ordinary post-activation P2TR key-path spend (height %d), so the" % nh)
print(" *     test can also show taproot IS enforced where the exception does not")
print(" *     apply: unmodified accepts, one flipped Schnorr byte rejects. --- */")
print('#define TAPNORM_HEIGHT          %dL' % nh)
print('#define TAPNORM_BLOCKHASH_RPC   "%s"' % nhash)
print('#define TAPNORM_TXID            "%s"' % ntx["txid"])
print('#define TAPNORM_TX_HEX          "%s"' % ntx["hex"])
print('#define TAPNORM_COINBASE_HEX    "%s"' % coinbase_hex(nh))
print('#define TAPNORM_SIG_BYTE_OFF    %d   /* input 0 witness item 0, %d bytes */' % (sig_off, sig_len))
emit_prevs("TAPNORM_PREVS", nprevs)
print('#define TAPNORM_NPREV           %d' % len(nprevs))
