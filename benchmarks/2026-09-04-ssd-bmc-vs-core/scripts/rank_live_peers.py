#!/usr/bin/env python3
# rank_live_peers.py -- from bmc's [dlc] worker lines, extract peers that are
# measurably FAST (>MIN_KBPS sustained median this run) and write a
# peers.good file for the next catch-up (dlc tries those FIRST, ranked).
import re, collections, sys
path = sys.argv[1] if len(sys.argv)>1 else '/mnt/2tbssd/bmc-bench/console.log'
min_kbps = float(sys.argv[2]) if len(sys.argv)>2 else 5.0
out_path = sys.argv[3] if len(sys.argv)>3 else '/mnt/2tbssd/peers.good'
PAT = re.compile(r'\[dlc\]\s+w\d+\s+([0-9.]+):\d+.*?\(\+\d+ blk/s, ([\d.]+)(KB/s|B/s|MB/s)\)')
vals = collections.defaultdict(list)
for line in open(path, errors='replace'):
    m = PAT.search(line)
    if not m: continue
    ip, v, u = m.group(1), float(m.group(2)), m.group(3)
    vals[ip].append(v * {'B/s':0.001,'KB/s':1,'MB/s':1000}[u])
good = []
for ip, vs in vals.items():
    if len(vs) < 10: continue
    vs.sort(); med = vs[len(vs)//2]
    if med >= min_kbps: good.append((med, ip))
good.sort(reverse=True)
with open(out_path,'w') as f:
    for med, ip in good: f.write(ip + '\n')
print(f"wrote {len(good)} peers >= {min_kbps} KB/s (median-of-ticks) to {out_path}")
for med, ip in good: print(f"  {ip:<18} {med:.1f} KB/s")
