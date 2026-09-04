#!/usr/bin/env python3
# peer_geo_audit.py -- enrich bmc's per-worker peers with country + reverse DNS
# to show what the round-robin pool actually looks like geographically.
import subprocess, json, sys, collections
PEERS = """192.69.53.35 204.12.245.4 162.229.22.126 47.144.177.117 18.191.31.215
184.144.159.30 47.144.29.121 96.227.114.56 62.210.124.104 80.89.69.65 94.130.20.235
187.125.157.191 95.31.188.110 84.203.235.176 218.148.208.55 176.126.75.34
198.176.55.2 8.156.79.36""".split()
MEDIAN_KB = {  # from peer_speed_audit.py, this run
 '192.69.53.35':11.5,'204.12.245.4':6.8,'162.229.22.126':6.6,'47.144.177.117':6.4,
 '18.191.31.215':6.4,'184.144.159.30':5.3,'47.144.29.121':5.3,'96.227.114.56':5.0,
 '62.210.124.104':2.9,'80.89.69.65':2.7,'94.130.20.235':2.7,'187.125.157.191':2.7,
 '95.31.188.110':2.5,'84.203.235.176':2.4,'218.148.208.55':2.4,'176.126.75.34':2.3,
 '198.176.55.2':1.7,'8.156.79.36':0.4}
rows=[]
for ip in PEERS:
    country='?'
    try:
        out=subprocess.run(['curl','-s','--max-time','6',f'https://get.geojs.io/v1/ip/country/{ip}.json'],
                           capture_output=True,text=True,timeout=10).stdout
        country=json.loads(out).get('country_3','?')
    except Exception as e:
        country='err'
    rows.append((MEDIAN_KB.get(ip,0), country, ip))
rows.sort(reverse=True)
print(f"{'peer':<18} {'median':>7}  country")
for med,c,ip in rows: print(f"{ip:<18} {med:>5.1f}KB  {c}")
cc=collections.Counter(c for _,c,_ in rows)
print("\ncountries in the worker pool:", dict(cc.most_common()))
