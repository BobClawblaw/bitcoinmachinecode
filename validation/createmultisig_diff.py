#!/usr/bin/env python3
"""createmultisig_diff.py -- `createmultisig` differential: ASM node vs Core.

createmultisig is a pure function of (nrequired, keys, address_type), so this
is a direct output comparison against a scratch Bitcoin Core.

WHAT IT DRIVES
  ours   : a running bitcoin_rpcd (RPC_URL, default http://127.0.0.1:18545);
           no chain state needed, so any -datadir works.
  theirs : bitcoin-cli against the scratch Core oracle (never production).

Valid on-curve pubkeys are generated here in pure Python (privkeys 1..N times
G) so the many-key, compressed-vs-uncompressed, and error branches can all be
exercised with keys Core's HexToPubKey/IsFullyValid accepts.

THE ONE DOCUMENTED DIVERGENCE
  Core returns an inferred output "descriptor" (sh(multi(...))#cksum etc.). We
  have no descriptor engine (see FEATURE_GAPS.md) and omit it; this harness
  strips "descriptor" from both sides before comparing. Everything else -- the
  address, the redeemScript, and the uncompressed-key "warnings" -- is
  compared exactly, and RPC error codes are compared for the error cases.

  Note: RPC errors come back over HTTP as 500 + a JSON error body (Bitcoin's
  own JSON-RPC convention); the client reads the body rather than treating 500
  as a transport failure.
"""
import os, sys, json, subprocess, urllib.request, urllib.error, base64

RPC_URL = os.environ.get("RPC_URL", "http://127.0.0.1:18545")
RPC_USER = os.environ.get("RPC_USER", "x")
RPC_PASS = os.environ.get("RPC_PASS", "y")
CORE_CLI = os.environ.get(
    "CORE_CLI",
    "/storage/bitcoin-core-source/build/bin/bitcoin-cli -rpcport=8335 -datadir=/storage/core-oracle",
).split()

# --- pure-python secp256k1: valid on-curve pubkeys from privkeys 1..N ---
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _inv(a): return pow(a, _P - 2, _P)


def _add(p, q):
    if p is None: return q
    if q is None: return p
    if p == q: m = (3 * p[0] * p[0]) * _inv(2 * p[1]) % _P
    else:       m = (q[1] - p[1]) * _inv(q[0] - p[0]) % _P
    x = (m * m - p[0] - q[0]) % _P
    return (x, (m * (p[0] - x) - p[1]) % _P)


def _mul(k):
    r, a = None, (_Gx, _Gy)
    while k:
        if k & 1: r = _add(r, a)
        a = _add(a, a); k >>= 1
    return r


def comp(d):
    x, y = _mul(d); return ("%02x" % (2 + (y & 1))) + "%064x" % x


def uncomp(d):
    x, y = _mul(d); return "04" + "%064x" % x + "%064x" % y


KC = [comp(d) for d in range(1, 22)]
KU = [uncomp(d) for d in range(1, 22)]


def ours(*p):
    body = json.dumps({"jsonrpc": "1.0", "id": "c", "method": "createmultisig",
                       "params": list(p)}).encode()
    auth = base64.b64encode(f"{RPC_USER}:{RPC_PASS}".encode()).decode()
    req = urllib.request.Request(RPC_URL, data=body,
                                 headers={"Content-Type": "text/plain",
                                          "Authorization": "Basic " + auth})
    try:
        d = json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:      # RPC errors -> HTTP 500 + JSON body
        d = json.load(e)
    return d["result"] if d.get("error") is None else {"__err__": d["error"]["code"]}


def core(*p):
    args = [str(p[0]), json.dumps(p[1])] + ([p[2]] if len(p) > 2 else [])
    r = subprocess.run(CORE_CLI + ["createmultisig"] + args, capture_output=True, text=True)
    if r.returncode != 0:
        import re
        m = re.search(r"error code:\s*(-?\d+)", r.stderr)
        return {"__err__": int(m.group(1)) if m else r.stderr.strip()}
    return json.loads(r.stdout)


def strip(o):
    return {k: v for k, v in o.items() if k != "descriptor"} if isinstance(o, dict) else o


CASES = [
    ("legacy 2of2",       (2, [KC[0], KC[1]])),
    ("legacy 1of1",       (1, [KC[0]])),
    ("legacy 3of3",       (3, KC[0:3])),
    ("bech32 2of2",       (2, [KC[0], KC[1]], "bech32")),
    ("p2sh-segwit 1of2",  (1, [KC[0], KC[1]], "p2sh-segwit")),
    ("legacy 15of15",     (15, KC[0:15])),
    ("legacy 16 keys (OP_16)", (1, KC[0:16])),
    ("legacy 17 keys (push count)", (1, KC[0:17])),
    ("bech32 + uncompressed -> forced legacy + warning", (1, [KC[0], KU[1]], "bech32")),
    ("legacy uncompressed 1of2", (1, [KC[0], KU[1]])),
    ("ERR required 0",    (0, [KC[0]])),
    ("ERR required>keys", (3, [KC[0], KC[1]])),
    ("ERR 21 keys",       (1, KC[0:21])),
    ("ERR bech32m",       (1, [KC[0]], "bech32m")),
    ("ERR unknown type",  (1, [KC[0]], "frobnicate")),
    ("ERR invalid key",   (1, ["deadbeef"])),
    ("ERR off-curve key", (1, ["02" + "00" * 32])),
]


def main():
    fails = 0
    for name, args in CASES:
        o, c = strip(ours(*args)), strip(core(*args))
        if o == c:
            print(f"  MATCH  {name}")
        else:
            fails += 1
            print(f"  DIFFER {name}\n    ours={json.dumps(o)}\n    core={json.dumps(c)}")
    print(f"\n{fails} DIFF(S)" if fails else f"\nALL {len(CASES)} MATCH (modulo descriptor)")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
