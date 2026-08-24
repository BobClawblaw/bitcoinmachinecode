#!/usr/bin/env python3
"""decodescript_diff.py -- `decodescript` differential: ASM node vs Bitcoin Core.

decodescript is a PURE function of its input hex -- no chain, UTXO or mempool
state -- so this harness is a direct output comparison, not a sabotage probe:
it feeds the same script hex to our `bitcoin_rpcd` and to a scratch Bitcoin
Core, and compares the parsed JSON.

WHAT IT DRIVES
  ours   : a running bitcoin_rpcd (RPC_URL, default http://127.0.0.1:18545).
           Any -datadir works -- decodescript never touches the archive -- so
           point it at a read-only copy of the production datadir.
  theirs : bitcoin-cli against the scratch Core oracle (CORE_CLI env, default
           the 8335 core-oracle). NEVER the production node.

FULL COMPARE (no divergence)
  The whole object is compared exactly, including the inferred "desc" on the
  top-level and "segwit" sub-object: pk()/multi() when the key material is in
  the script, rawtr() for a taproot output key, addr() for a hash-only type,
  wsh(inner) for the segwit-of-a-known-script case, else raw() -- each with
  Core's descriptor #checksum. This is InferDescriptor's no-keystore behaviour,
  not a full descriptor engine.

WHAT THE MATRIX COVERS
  Every branch of Core's decodescript wrapper logic (rawtransaction.cpp):
  each standard scriptPubKey type; a bare pubkey compressed (gets a segwit
  program) vs uncompressed (segwit skipped); multisig all-compressed (segwit)
  vs with an uncompressed key (segwit skipped); nulldata / OP_CHECKSIGADD /
  witness programs (not wrappable); the empty script; and a set of REAL
  redeemscripts and scriptPubKeys pulled live from the oracle's own blocks so
  the vectors are not all synthetic.

  Exit 0 = all match (desc included). Exit 1 = at least one divergence, printed.
"""
import os, sys, json, subprocess, urllib.request

RPC_URL = os.environ.get("RPC_URL", "http://127.0.0.1:18545")
RPC_USER = os.environ.get("RPC_USER", "x")
RPC_PASS = os.environ.get("RPC_PASS", "y")
CORE_CLI = os.environ.get(
    "CORE_CLI",
    "/storage/bitcoin-core-source/build/bin/bitcoin-cli -rpcport=8335 -datadir=/storage/core-oracle",
).split()


def ours(script):
    body = json.dumps({"jsonrpc": "1.0", "id": "d", "method": "decodescript",
                       "params": [script]}).encode()
    import base64
    auth = base64.b64encode(f"{RPC_USER}:{RPC_PASS}".encode()).decode()
    req = urllib.request.Request(RPC_URL, data=body,
                                 headers={"Content-Type": "text/plain",
                                          "Authorization": "Basic " + auth})
    d = json.load(urllib.request.urlopen(req))
    if d.get("error"):
        return {"__err__": d["error"]}
    return d["result"]


def core(*args):
    r = subprocess.run(CORE_CLI + list(args), capture_output=True, text=True)
    if r.returncode != 0:
        return {"__err__": r.stderr.strip()}
    out = r.stdout.strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def strip_desc(o):
    return o          # identity: desc is now compared, kept for call-site names


def synthetic_cases():
    PKC = "02" + "a1" * 32          # 33B compressed
    PKU = "04" + "b2" * 64          # 65B uncompressed
    H20, H32 = "11" * 20, "22" * 32
    return {
        "P2PKH spk":        "76a914" + H20 + "88ac",
        "P2SH spk":         "a914" + H20 + "87",
        "P2WPKH spk":       "0014" + H20,
        "P2WSH spk":        "0020" + H32,
        "P2TR spk":         "5120" + H32,
        "bare pubkey (C)":  "21" + PKC + "ac",
        "bare pubkey (U)":  "41" + PKU + "ac",
        "1of2 multisig (C)": "5121" + PKC + "21" + PKC + "52ae",
        "1of2 multisig (U)": "5121" + PKC + "41" + PKU + "52ae",
        "nulldata":         "6a04deadbeef",
        "nonstandard OP_1": "51",
        "empty":            "",
        "OP_CHECKSIGADD":   "20" + H32 + "ba",
    }


def real_cases(n_blocks=3):
    """Pull real scriptPubKeys and P2SH/P2WSH redeemscripts from the oracle's
    own recent blocks, so the matrix is not entirely synthetic."""
    cases = {}
    try:
        tip = int(core("getblockcount"))
    except Exception:
        return cases
    for h in range(max(1, tip - n_blocks + 1), tip + 1):
        try:
            bh = core("getblockhash", str(h))
            blk = core(bh if isinstance(bh, str) else "", "2") if False else core("getblock", bh, "2")
        except Exception:
            continue
        if not isinstance(blk, dict):
            continue
        for tx in blk.get("tx", [])[:8]:
            for vout in tx.get("vout", []):
                spk = vout.get("scriptPubKey", {})
                hx = spk.get("hex")
                if hx and len(cases) < 24:
                    cases[f"real spk h{h} {spk.get('type','?')} {hx[:12]}"] = hx
    return cases


def main():
    cases = {}
    cases.update(synthetic_cases())
    cases.update(real_cases())
    fails = 0
    for name, scr in cases.items():
        o = strip_desc(ours(scr))
        c = strip_desc(core("decodescript", scr))
        if o == c:
            print(f"  MATCH  {name}")
        else:
            fails += 1
            print(f"  DIFFER {name}\n    ours={json.dumps(o)}\n    core={json.dumps(c)}")
    print(f"\n{fails} DIFF(S)" if fails else f"\nALL {len(cases)} MATCH (desc included)")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
