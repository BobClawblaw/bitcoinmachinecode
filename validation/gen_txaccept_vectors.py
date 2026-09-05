#!/usr/bin/env python3
"""gen_txaccept_vectors.py -- freeze REAL mined transactions, with their spent
prevouts, as a consensus-acceptance corpus.

WHAT THIS ASSERTS, AND WHAT IT DELIBERATELY DOES NOT
----------------------------------------------------
Every transaction here was MINED into the main chain, so it is
consensus-valid under the script flags active at its own height. That is the
claim the generated test makes: our verifier must accept each one at its
block's height. It is the full-archive replay in miniature -- the same
property, as a test that runs in milliseconds.

It does NOT assert mempool/standardness verdicts. A 2011 transaction is
routinely consensus-valid and non-standard today (bare multisig, uncompressed
keys, high-S signatures), and Core cannot be asked for a standardness verdict
on a transaction whose inputs are long spent. Conflating the two would produce
confident nonsense, so the corpus stays on the well-posed question.

SELECTION
---------
Chosen for the axis that actually changes verdicts -- script type x spend
shape x consensus-era flags -- and weighted towards transactions that broke
someone's assumption, not towards volume. A few dozen edge cases are worth
more than thousands of ordinary P2PKH spends, and keep the repo small
(BLD-10).

    python3 validation/gen_txaccept_vectors.py > asm/tests/txaccept_vec.h
"""
import json, subprocess, sys

CONF="/storage/core-oracle/bitcoin.conf"; DD="/storage/core-oracle"
CLI="/storage/bitcoin-core-source/build-zmq/bin/bitcoin-cli"

def cli(*a):
    r = subprocess.run([CLI, f"-conf={CONF}", f"-datadir={DD}", *a],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    return r.stdout.strip()

# (txid, why it is here). Ordered roughly by chain era.
WANTED = [
    ("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
     "h=170: the first ever P2PK->P2PK spend (Satoshi to Hal)"),
    ("6f7cf9580f1c2dfb3c4d5d043cdbb128c640e3f20161245aa7372e9666168516",
     "h=728: early P2PKH"),
    ("fb0a1d8d34fa5537e461ac384bac761125e1bfa7fec286fa72511240fa66864d",
     "h=124276: NON-MINIMAL DER -- 34-byte r AND s (two leading zero pad bytes "
     "each). The case bitcoin_script.asm's 2026-08-19 fix exists for; a parser "
     "that strips only ONE leading zero rejects this real, mined transaction"),
    ("315ac7d4c26d69668129cc352851d9389b4a6868f1509c6c8b66bead11e2619f",
     "the SIGHASH_SINGLE BUG: input index >= vout count, so the sighash is 1"),
    ("60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1",
     "FindAndDelete: a signature that appears inside its own scriptCode"),
    ("eb3b82c0884e3efa6d8b0be55b4915eb20be124c9766245bcc7f34fdac32bccb",
     "h=170060-ish: bare multisig (P2MS) output"),
    ("9c08a4d78931342b37fd5f72900fb9983087e6f46c4a097d8a1f52c74e28eaf6",
     "P2SH: an early pay-to-script-hash spend"),
    ("dfcec48bb8491856c353306ab5febeb7e99e4d783eedf3de98f3ee0812b92bad",
     "h=481824: the FIRST segwit (P2WPKH) spend, in the activation block"),
    ("f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd",
     "h=481824: native P2WPKH spend, in the segwit activation block"),
    ("8f907925d2ebe48765103e6845c06f1f2bb77c6adc1cc002865865eb5cfd5c1c",
     "h=481824: P2SH-wrapped P2WPKH -- scriptSig AND witness"),
    ("461e8a4aa0a0e75c06602c505bd7aa06e7116ba5cd98fd6e046e8cbeb00379d6",
     "h=481824: P2WSH output, activation block"),
    ("da917699942e4a96272401b534381a75512eeebe8403084500bd637bd47168b3",
     "h=481824: OP_RETURN (nulldata) output -- provably unspendable"),
    ("73965c0ab96fa518f47df4f3e7201e0a36f163c4857fc28150d277caa8589259",
     "h=550000: native P2WSH multisig spend, 4 witness items"),
    ("9cf007aa4ed2216c6ca42ba593558cb6ce4df9c5417677d7ca96a7b2be6d807b",
     "h=550000: P2SH-wrapped P2WSH, 4 witness items"),
    ("bdcb08cd977e229482f295345893405882a08132f1675beb844de8548007915f",
     "h=550000: BARE MULTISIG output (P2MS) -- consensus-valid, non-standard to relay"),
    ("4c9fe4ad5923fd41074da3f92da6359cbafbd96ecbb758481d6c1f106242703e",
     "h=750000: taproot KEY-path spend (BIP341), single witness item"),
    ("965f866bf8623bbf956c1b2aeec1efc1ad162fd428ab7fb89f128a0754ebbc32",
     "h=800000: taproot SCRIPT-path spend (BIP342) -- 33-byte control block"),
    ("b10c0000004da5a9d1d9b4ae32e09f0b3e62d21a5cce5428d4ad714fb444eb5d",
     "h=850000: ANCHOR output (P2A) -- Core v28's new output type"),
]

def prevouts_for(txj):
    out = []
    for vin in txj.get("vin", []):
        if "coinbase" in vin:
            return None                      # coinbases spend nothing
        praw = cli("getrawtransaction", vin["txid"], "1")
        if not praw: return None
        pj = json.loads(praw)
        vo = pj["vout"][vin["vout"]]
        h = pj.get("height")
        if h is None:
            bh = pj.get("blockhash")
            if not bh: return None
            h = json.loads(cli("getblock", bh, "1"))["height"]
        iscb = 1 if any("coinbase" in v for v in pj.get("vin", [])) else 0
        out.append({
            "spk":   vo["scriptPubKey"]["hex"],
            "value": int(round(vo["value"] * 100_000_000)),
            "height": h,
            "coinbase": iscb,
        })
    return out

def main():
    rows = []
    for txid, why in WANTED:
        raw = cli("getrawtransaction", txid, "1")
        if not raw:
            print(f"// SKIP {txid[:16]}: not retrievable ({why})", file=sys.stderr)
            continue
        txj = json.loads(raw)
        bh = txj.get("blockhash")
        if not bh:
            print(f"// SKIP {txid[:16]}: unconfirmed", file=sys.stderr); continue
        height = json.loads(cli("getblock", bh, "1"))["height"]
        pv = prevouts_for(txj)
        if pv is None:
            print(f"// SKIP {txid[:16]}: coinbase or unresolvable prevout", file=sys.stderr)
            continue
        rows.append((txid, why, height, txj["hex"], pv))
        print(f"  h={height:<8} {len(pv)} prevout(s)  {why}", file=sys.stderr)

    print("/* txaccept_vec.h -- GENERATED by validation/gen_txaccept_vectors.py.")
    print(" * Real MINED transactions with their spent prevouts, frozen from the")
    print(" * oracle. Every one is consensus-valid at its own height BY THE FACT")
    print(" * THAT IT WAS MINED -- that is the property the test asserts, and it is")
    print(" * the full-archive replay reduced to a millisecond unit test.")
    print(" *")
    print(" * NOT a standardness corpus: several of these are consensus-valid and")
    print(" * non-standard today, which is precisely why they are interesting.")
    print(" * Do not hand-edit; regenerate. */")
    print("typedef struct { const char* spk_hex; unsigned long long value;")
    print("                 long height; int coinbase; } txacc_prev_t;")
    print("typedef struct { const char* why; const char* txid; long height;")
    print("                 const char* tx_hex; int n_prev;")
    print("                 const txacc_prev_t* prev; } txacc_vec_t;")
    for i, (txid, why, height, hexs, pv) in enumerate(rows):
        print(f"static const txacc_prev_t TXACC_P{i}[] = {{")
        for p in pv:
            print(f'  {{ "{p["spk"]}", {p["value"]}ULL, {p["height"]}, {p["coinbase"]} }},')
        print("};")
    print("static const txacc_vec_t TXACC_VEC[] = {")
    for i, (txid, why, height, hexs, pv) in enumerate(rows):
        print(f'  {{ "{why}",\n    "{txid}", {height},')
        print(f'    "{hexs}",\n    {len(pv)}, TXACC_P{i} }},')
    print("};")
    print(f"#define TXACC_VEC_N {len(rows)}")

if __name__ == "__main__":
    main()
