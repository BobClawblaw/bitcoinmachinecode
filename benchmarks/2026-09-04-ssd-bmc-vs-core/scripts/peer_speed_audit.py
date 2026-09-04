#!/bin/bash
# peer_speed_audit.py -- parse bmc's [dlc] per-worker live lines and answer:
# how fast is each peer, how fast is each AS/region, and what does the peer
# pool selection actually look like?
#
# Peer selection today: dnsseed -> address book -> confirmed-live (TCP+verack)
# -> round-robin. There is NO speed history and NO ASN/geography awareness.
# Only reactive dead-weight drop at 32KB/s x30s. This script measures the
# result of that policy on the live run so the fix can be data-driven.
import re, sys, collections, ipaddress, json

path = sys.argv[1] if len(sys.argv) > 1 else '/mnt/2tbssd/bmc-bench/console.log'
# line shape: [dlc]   w8 192.69.53.35:8333  chunks=225  blocks=9000  (+16 blk/s, 13.6KB/s)
PAT = re.compile(r'\[dlc\]\s+w\d+\s+(\S+):\d+\s+chunks=(\d+)\s+blocks=(\d+)\s+\(\+(\d+) blk/s, ([\d.]+)(KB/s|B/s|MB/s)\)')
# [dlc w1] 8.156.79.36:8333 dead weight (last measured 367.4B/s ...
DROP = re.compile(r'\[dlc w\d+\] (\S+):\d+ dead weight \(last measured ([\d.]+)(KB/s|B/s|MB/s)')

def bps(v, unit):
    v = float(v)
    return v * {'B/s': 1, 'KB/s': 1e3, 'MB/s': 1e6}[unit]

samples = collections.defaultdict(list)   # peer -> [bps]
for line in open(path, errors='replace'):
    m = PAT.search(line)
    if m:
        samples[m.group(1)].append(bps(m.group(5), m.group(6)))
drops = collections.defaultdict(list)
for line in open(path, errors='replace'):
    m = DROP.search(line)
    if m:
        drops[m.group(1)].append(bps(m.group(2), m.group(3)))

rows = []
for peer, vals in samples.items():
    vals.sort()
    med = vals[len(vals)//2]
    rows.append((med, max(vals), len(vals), peer))
rows.sort(reverse=True)

def net_class(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return 'unknown'
    if a.is_private: return 'private'
    # cheap regional guess is out of scope offline; bucket by first octet block
    return 'ipv4'

print(f"{'peer':<22} {'median':>9} {'peak':>9} {'ticks':>6}  dropped-early")
for med, mx, n, peer in rows:
    ip = peer.split(':')[0]
    d = f"{len(drops[ip])} drop(s) last {drops[ip][-1]:.0f}B/s" if ip in drops else ''
    print(f"{peer:<22} {med/1000:>7.1f}KB {mx/1000:>8.1f}K {n:>6}  {d}")

meds = sorted(m for m, _, _, _ in rows)
if meds:
    print(f"\npeers sampled: {len(meds)}")
    print(f"median-of-medians: {meds[len(meds)//2]/1000:.1f} KB/s")
    print(f"p90: {meds[int(len(meds)*0.9)]/1000:.1f} KB/s   p10: {meds[int(len(meds)*0.1)]/1000:.1f} KB/s")
    print(f"peers below 32KB/s floor: {sum(1 for m in meds if m < 32768)}/{len(meds)}")
print(f"early-killed peers this run: {len(drops)} distinct")
hist = collections.Counter()
for peer, vals in samples.items():
    ip = peer.split(':')[0]
    # first-octet prefix as a cheap AS-ish proxy when no GeoIP db is loaded
    hist[ip.split('.')[0] + '.0.0/8'] += 1
print("pool /8 skew:", dict(hist.most_common(6)))
