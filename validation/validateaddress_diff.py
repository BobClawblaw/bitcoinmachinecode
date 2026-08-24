#!/usr/bin/env python3
"""validateaddress_diff.py -- `validateaddress` differential: ASM node vs Core.

validateaddress is a pure function of the address string, so this is a direct
output comparison. It feeds each address to our bitcoin_rpcd and to a scratch
Bitcoin Core and compares the JSON.

WHAT IT DRIVES
  ours   : a running bitcoin_rpcd (RPC_URL, default http://127.0.0.1:18545).
           validateaddress needs no chain state; any -datadir works.
  theirs : bitcoin-cli against the scratch Core oracle (never production).

WHAT IT CAUGHT (2026-08-24) -- the reason this file exists
  The rpc_commands.c JSON builder had no field-level test, and three of its
  fields were wrong against Core: the P2WSH witness_program read the 20-byte
  h160 but copied 32 bytes (garbage tail), P2TR reported isscript=false (Core:
  true), and it emitted an "ischange" field validateaddress does not have.
  This differential is what surfaced all three.

COMPARISON RULE
  VALID address  -> full structural JSON compare (byte-for-byte fields).
  INVALID address -> compared on `isvalid==false` ONLY. Core's exact error
  string and bech32 error_locations are diagnostics we deliberately do not
  reproduce (see the RPC's own comment); a green run asserts the
  classification, not the error text.
"""
import os, sys, json, subprocess, urllib.request, base64

RPC_URL = os.environ.get("RPC_URL", "http://127.0.0.1:18545")
RPC_USER = os.environ.get("RPC_USER", "x")
RPC_PASS = os.environ.get("RPC_PASS", "y")
CORE_CLI = os.environ.get(
    "CORE_CLI",
    "/storage/bitcoin-core-source/build/bin/bitcoin-cli -rpcport=8335 -datadir=/storage/core-oracle",
).split()


def ours(a):
    body = json.dumps({"jsonrpc": "1.0", "id": "v", "method": "validateaddress",
                       "params": [a]}).encode()
    auth = base64.b64encode(f"{RPC_USER}:{RPC_PASS}".encode()).decode()
    req = urllib.request.Request(RPC_URL, data=body,
                                 headers={"Content-Type": "text/plain",
                                          "Authorization": "Basic " + auth})
    return json.load(urllib.request.urlopen(req))["result"]


def core(a):
    r = subprocess.run(CORE_CLI + ["validateaddress", a], capture_output=True, text=True)
    return json.loads(r.stdout) if r.returncode == 0 else {"__err__": r.stderr.strip()}


ADDRS = {
    "P2PKH":  "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
    "P2SH":   "3P14159f73E4gFr7JterCCQh9QjiTjiZrG",
    "P2WPKH": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    "P2WSH":  "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
    "P2TR":   "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    "P2WPKH upper (normalise)": "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
    "invalid word":       "notanaddress",
    "bad checksum P2PKH": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3",
    "empty":              "",
}


def main():
    fails = 0
    for name, a in ADDRS.items():
        o, c = ours(a), core(a)
        if o.get("isvalid"):
            match = (o == c)
        else:
            match = (o.get("isvalid") is False and c.get("isvalid") is False)
        print(("  MATCH  " if match else "  DIFFER ") + name
              + ("" if match else f"\n    ours={json.dumps(o)}\n    core={json.dumps(c)}"))
        fails += 0 if match else 1
    print(f"\n{fails} DIFF(S)" if fails else "\nALL MATCH (invalid compared on isvalid only)")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
