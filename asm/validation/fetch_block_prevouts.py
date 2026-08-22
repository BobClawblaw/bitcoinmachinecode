#!/usr/bin/env python3
"""fetch_block_prevouts.py HEIGHT -- write tests/fixtures/blk_HEIGHT.bin (raw block,
read from the live archive's index.dat/blk files, read-only) and
tests/fixtures/blk_HEIGHT.prevouts (one line per non-coinbase input:
txid_hex index value_sat spk_hex, from the scratch Core oracle's txindex).
Gitignored; tests skip when absent. Used by test_block_481827_pool_stack."""
import sys, os, struct, json, subprocess
H=int(sys.argv[1]); D='/storage/bitcoinmachinecode/data'
CLI="/storage/bitcoin-core-source/build/bin/bitcoin-cli -conf=/storage/core-oracle/bitcoin.conf -datadir=/storage/core-oracle".split()
def rpc(*a): return subprocess.run(CLI+list(a),capture_output=True,text=True).stdout
with open(os.path.join(D,'index.dat'),'rb') as f:
    f.seek(H*48); r=f.read(48)
h=r[:32][::-1].hex(); fno,pos,size=struct.unpack('<IQI',r[32:48])
with open(os.path.join(D,'blk%05d.dat'%fno),'rb') as f:
    f.seek(pos+8); blk=f.read(size)
assert rpc("getblockhash",str(H)).strip()==h, "archive/oracle hash mismatch"
here=os.path.dirname(os.path.abspath(__file__)); fx=os.path.join(here,'..','tests','fixtures')
open(os.path.join(fx,'blk_%d.bin'%H),'wb').write(blk)
b=json.loads(rpc("getblock",h,"2")); cache={}; n=0
with open(os.path.join(fx,'blk_%d.prevouts'%H),'w') as out:
    for tx in b['tx'][1:]:
        for v in tx['vin']:
            t=v['txid']
            if t not in cache: cache[t]=json.loads(rpc("getrawtransaction",t,"true"))['vout']
            o=cache[t][v['vout']]
            out.write("%s %d %d %s\n"%(t,v['vout'],int(round(o['value']*1e8)),o['scriptPubKey']['hex'])); n+=1
print("block %d: %d bytes, %d prevouts, %d distinct prev txs"%(H,len(blk),n,len(cache)))
