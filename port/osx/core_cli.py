#!/usr/bin/env python3
"""core_cli.py -- a bitcoin-cli stand-in for the local Bitcoin Core (Bitcoin-Qt)
on this Mac: JSON-RPC to 127.0.0.1:8332 with the rpcuser / rpcpassword from
~/Library/Application Support/Bitcoin/bitcoin.conf. The credentials are read
and sent, never printed. Output as bitcoin-cli prints it: a string result
raw, anything else as JSON; an RPC error to stderr, exit 1.

It exists so the x86 tree's fixture fetchers, which spawn bitcoin-cli, can run
here: CORE_CLI="python3 port/osx/core_cli.py" (see fetch_fixtures.sh). The
local Core has txindex, which `getblock <hash> 3` needs.

    python3 port/osx/core_cli.py getblockcount
    python3 port/osx/core_cli.py getblock <hash> 0
"""
import sys, json, base64, os, urllib.request

conf = os.path.expanduser("~/Library/Application Support/Bitcoin/bitcoin.conf")
kv = {}
for line in open(conf):
    line = line.strip()
    if "=" in line and not line.startswith("#"):
        k, v = line.split("=", 1)
        kv.setdefault(k.strip(), v.strip())

method, params = sys.argv[1], []
for a in sys.argv[2:]:
    try:
        params.append(json.loads(a))
    except Exception:
        params.append(a)

auth = base64.b64encode(f"{kv['rpcuser']}:{kv['rpcpassword']}".encode()).decode()
req = urllib.request.Request("http://127.0.0.1:8332/",
                             data=json.dumps({"id": 1, "method": method, "params": params}).encode(),
                             headers={"Authorization": "Basic " + auth})
try:
    r = json.loads(urllib.request.urlopen(req, timeout=600).read())
except urllib.error.HTTPError as e:
    r = json.loads(e.read())
if r.get("error"):
    sys.stderr.write(json.dumps(r["error"]) + "\n")
    sys.exit(1)
res = r["result"]
print(res if isinstance(res, str) else json.dumps(res))
