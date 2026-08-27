#!/usr/bin/env python3
"""Mining-polish differential: bmc (.wt-mining build, rpc 19446) vs the shared
Core regtest oracle (rpc 18460). Proves: exact per-tx sigops (P2SH redeem +
witness), CPFP present with parent-before-child on both, identical tx sets,
BIP23 proposal verdicts verbatim, and longpoll blocking until the tip moves."""
import json, subprocess, urllib.request, base64, time, threading, struct, hashlib, sys

CLI = ["/storage/bitcoin-core-source/build/bin/bitcoin-cli",
       "-datadir=/storage/core-regtest", "-rpcport=18460", "-rpcwallet=reg"]
BMC = "http://127.0.0.1:19446/"
AUTH = base64.b64encode(b"mbmc:mbmcpw").decode()
fails = 0
def ck(l, c):
    global fails
    print(("  ok  " if c else "  FAIL ") + l)
    if not c: fails += 1

def core(*a):
    r = subprocess.run(CLI+list(a), capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ("ERR:"+r.stderr.strip())

def bmc(method, params=None, timeout=90):
    req = urllib.request.Request(BMC, json.dumps(
        {"jsonrpc":"2.0","id":1,"method":method,"params":params or []}).encode(),
        {"Authorization":"Basic "+AUTH,"Content-Type":"application/json"})
    r = json.load(urllib.request.urlopen(req, timeout=timeout))
    return r

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

MINE = core("getnewaddress")

# ---- 1. build interesting spends ------------------------------------------
# Signature-free scripts with REAL accurate-sigop counts (a descriptor wallet
# cannot sign ad-hoc multisig): P2SH redeem `0-of-1 CHECKMULTISIG` (accurate
# sigops 1 -> BIP141 cost 4) and P2WSH witnessScript `0-of-2 CHECKMULTISIG`
# (witness sigops 2 -> cost 2). Zero required signatures = consensus-valid,
# standard (P2SH sigop cap 15), and hand-buildable.
def hash160(b): return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58check(payload):
    d = payload + sha256d(payload)[:4]
    n = int.from_bytes(d, "big"); out = ""
    while n: n, r = divmod(n, 58); out = B58[r] + out
    for c in d:
        if c == 0: out = "1" + out
        else: break
    return out
CS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech32_addr(hrp, prog):
    def polymod(v):
        GEN=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]; chk=1
        for x in v:
            b=chk>>25; chk=((chk&0x1ffffff)<<5)^x
            for i in range(5):
                chk ^= GEN[i] if ((b>>i)&1) else 0
        return chk
    def hrpx(h): return [ord(c)>>5 for c in h]+[0]+[ord(c)&31 for c in h]
    data=[0]
    acc=bits=0
    for byte in prog:
        acc=(acc<<8)|byte; bits+=8
        while bits>=5: bits-=5; data.append((acc>>bits)&31)
    if bits: data.append((acc<<(5-bits))&31)
    chk=polymod(hrpx(hrp)+data+[0]*6)^1
    return hrp+"1"+"".join(CS[d] for d in data)+"".join(CS[(chk>>5*(5-i))&31] for i in range(6))

DUMMY = bytes([2]) + b"\x11"*32
redeem  = bytes([0x00, 33]) + DUMMY + bytes([0x51, 0xae])            # 0-of-1 CMS
wscript = bytes([0x00, 33]) + DUMMY + bytes([33]) + DUMMY + bytes([0x52, 0xae])  # 0-of-2
p2sh_addr = b58check(b"\xc4" + hash160(redeem))
wsh_addr  = bech32_addr("bcrt", hashlib.sha256(wscript).digest())

t_p2sh = core("sendtoaddress", p2sh_addr, "1.0")
t_wsh  = core("sendtoaddress", wsh_addr, "1.0")
core("generatetoaddress", "1", MINE)
time.sleep(3)

def rawtx(txid):
    """wallet tx -> decoded; regtest oracle has no txindex"""
    gt = json.loads(core("gettransaction", txid))
    return json.loads(core("decoderawtransaction", gt["hex"]))

def find_vout(txid, addr):
    raw = rawtx(txid)
    return next(o["n"] for o in raw["vout"] if o["scriptPubKey"].get("address") == addr)

def outpoint(txid, n):
    return bytes.fromhex(txid)[::-1] + struct.pack("<I", n)

DEST_SPK = bytes.fromhex("0014" + "22"*20)
def spend_p2sh():
    n = find_vout(t_p2sh, p2sh_addr)
    ss = bytes([0x00, len(redeem)]) + redeem                          # OP_0 <redeem>
    tx = (struct.pack("<I",2) + b"\x01" + outpoint(t_p2sh, n)
          + bytes([len(ss)]) + ss + b"\xfd\xff\xff\xff"
          + b"\x01" + struct.pack("<q", 99900000) + bytes([len(DEST_SPK)]) + DEST_SPK
          + struct.pack("<I",0))
    return core("sendrawtransaction", tx.hex())
def spend_wsh():
    n = find_vout(t_wsh, wsh_addr)
    base = (b"\x01" + outpoint(t_wsh, n) + b"\x00" + b"\xfd\xff\xff\xff"
            + b"\x01" + struct.pack("<q", 99900000) + bytes([len(DEST_SPK)]) + DEST_SPK)
    wit = bytes([2, 0, len(wscript)]) + wscript                       # [empty, wscript]
    tx = struct.pack("<I",2) + b"\x00\x01" + base[:-0] + wit + struct.pack("<I",0)
    # base already lacks locktime; assemble: ver|mk|fl|in|out|wit|lock
    tx = (struct.pack("<I",2) + b"\x00\x01"
          + b"\x01" + outpoint(t_wsh, n) + b"\x00" + b"\xfd\xff\xff\xff"
          + b"\x01" + struct.pack("<q", 99900000) + bytes([len(DEST_SPK)]) + DEST_SPK
          + wit + struct.pack("<I",0))
    return core("sendrawtransaction", tx.hex())
sp_p2sh = spend_p2sh()
sp_wsh  = spend_wsh()
assert not sp_p2sh.startswith("ERR"), sp_p2sh
assert not sp_wsh.startswith("ERR"), sp_wsh

# CPFP pair: low-fee parent -> high-fee child (fee rates via settxfee)
core("settxfee", "0.00001")
parent = core("sendtoaddress", core("getnewaddress"), "2.0")
praw = rawtx(parent)
pv = next(o for o in praw["vout"] if abs(o["value"] - 2.0) < 1e-9)
child_dest = core("getnewaddress")
cr = core("createrawtransaction",
          json.dumps([{"txid":parent,"vout":pv["n"]}]),
          json.dumps([{child_dest: 1.99}]))          # 0.01 BTC fee: huge
sg = json.loads(core("signrawtransactionwithwallet", cr))
child = core("sendrawtransaction", sg["hex"])
core("settxfee", "0")
plain = core("sendtoaddress", core("getnewaddress"), "0.5")

pool = json.loads(core("getrawmempool"))
print("oracle mempool:", len(pool), "txs")

# ---- 2. hand the same txs to bmc ------------------------------------------
for t in pool:
    hexraw = core("getrawtransaction", t)     # mempool txs: fine w/o txindex
    r = bmc("sendrawtransaction", [hexraw])
    if r.get("error"): print("  note: bmc reject", t[:16], r["error"]["message"])
time.sleep(1)
bpool = bmc("getrawmempool")["result"]
ck("bmc holds the same tx set", sorted(bpool) == sorted(pool))

# ---- 3. template diff ------------------------------------------------------
ct = json.loads(core("getblocktemplate", '{"rules":["segwit"]}'))
bt = bmc("getblocktemplate", [{"rules":["segwit"]}])["result"]
cmap = {t["txid"]: t for t in ct["transactions"]}
bmap = {t["txid"]: t for t in bt["transactions"]}
ck("template tx sets identical", sorted(cmap) == sorted(bmap))
sig_ok = fee_ok = True
for txid in cmap:
    if txid in bmap:
        if int(cmap[txid]["sigops"]) != int(bmap[txid]["sigops"]):
            print("    sigops mismatch", txid[:16], "core", cmap[txid]["sigops"], "bmc", bmap[txid]["sigops"]); sig_ok = False
        if int(cmap[txid]["fee"]) != int(bmap[txid]["fee"]):
            print("    fee mismatch", txid[:16]); fee_ok = False
ck("per-tx sigops identical to Core (P2SH + witness spends included)", sig_ok)
ck("per-tx fees identical to Core", fee_ok)
def order_ok(tpl):
    ids = [t["txid"] for t in tpl]
    return parent in ids and child in ids and ids.index(parent) < ids.index(child)
ck("CPFP: parent precedes child in Core's template", order_ok(ct["transactions"]))
ck("CPFP: parent precedes child in bmc's template",  order_ok(bt["transactions"]))
ck("coinbasevalue equal", int(ct["coinbasevalue"]) == int(bt["coinbasevalue"]))
ck("longpollid present, prev-tip prefixed",
   bt.get("longpollid","").startswith(bt["previousblockhash"]))

# ---- 4. BIP23 proposal diff ------------------------------------------------
def build_block(tpl, txs_hex):
    prev = bytes.fromhex(tpl["previousblockhash"])[::-1]
    h = tpl["height"]; spk = bytes.fromhex("6a24aa21a9ed"+"00"*32)  # unused
    hb = h.to_bytes((h.bit_length()+8)//8, "little")
    ss = bytes([len(hb)])+hb+b"/prop/"
    dest = bytes.fromhex("0014"+"11"*20)
    cb = (struct.pack("<I",1)+b"\x01"+b"\x00"*32+b"\xff\xff\xff\xff"
          +bytes([len(ss)])+ss+b"\xff\xff\xff\xff"
          +b"\x01"+struct.pack("<q", 5000000000 >> (tpl["height"]//150))+bytes([len(dest)])+dest
          +struct.pack("<I",0))
    leaves = [sha256d(cb)]
    root = leaves[0]
    hdr = (struct.pack("<I",0x20000000)+prev+root
           +struct.pack("<III",tpl["curtime"],int(tpl["bits"],16),0))
    return hdr + b"\x01" + cb, hdr

tpl = bmc("getblocktemplate", [{"rules":["segwit"]}])["result"]
blk, hdr = build_block(tpl, [])
hexblk = blk.hex()
rb = bmc("getblocktemplate", [{"rules":["segwit"],"mode":"proposal","data":hexblk}])
rc = core("getblocktemplate", json.dumps({"rules":["segwit"],"mode":"proposal","data":hexblk}))
ck("valid proposal -> null on bmc",  rb.get("result") is None and not rb.get("error"))
ck("valid proposal -> null on Core", rc == "" or rc == "null")

bad = bytearray(blk); bad[40] ^= 0xff                       # merkle corrupt
rb = bmc("getblocktemplate", [{"rules":["segwit"],"mode":"proposal","data":bad.hex()}])
rc = core("getblocktemplate", json.dumps({"rules":["segwit"],"mode":"proposal","data":bad.hex()}))
ck("bad merkle -> 'bad-txnmrklroot' on bmc (Core: %r)" % rc,
   rb.get("result") == "bad-txnmrklroot" and rc == "bad-txnmrklroot")

bad = bytearray(blk); bad[8] ^= 0xff                        # prev corrupt
rb = bmc("getblocktemplate", [{"rules":["segwit"],"mode":"proposal","data":bad.hex()}])
rc = core("getblocktemplate", json.dumps({"rules":["segwit"],"mode":"proposal","data":bad.hex()}))
ck("bad prev -> 'inconclusive-not-best-prevblk' on both (Core: %r)" % rc,
   rb.get("result") == "inconclusive-not-best-prevblk" and rc == "inconclusive-not-best-prevblk")

# ---- 5. longpoll ----------------------------------------------------------
lp = tpl["longpollid"]
res = {}
def poll():
    t0 = time.time()
    r = bmc("getblocktemplate", [{"rules":["segwit"],"longpollid":lp}], timeout=90)
    res["dt"] = time.time() - t0
    res["height"] = r["result"]["height"]
th = threading.Thread(target=poll); th.start()
time.sleep(4)
ck("longpoll still pending after 4s", th.is_alive())
tip_before = int(core("getblockcount"))
core("generatetoaddress", "1", MINE)                        # tip moves
th.join(timeout=60)
ck("longpoll returned after the new block", not th.is_alive() and res.get("dt",0) >= 4)
ck("longpoll template is for the NEW tip (height %s)" % res.get("height"),
   res.get("height") == tip_before + 2)

print("\n%s (%d failures)" % ("ALL DIFFS PASS" if fails == 0 else "DIFFS FAILED", fails))
sys.exit(1 if fails else 0)
