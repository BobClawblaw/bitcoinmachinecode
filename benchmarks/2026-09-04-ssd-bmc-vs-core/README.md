# bmc vs Bitcoin Core — fresh IBD + serve benchmark (2026-09-04, dedicated SSD)

Dedicated 1.8 TB SSD (/mnt/2tbssd, ext4), 32-core host, 60 GB RAM.
Chains synced from genesis; UTXO parity judged against a long-synced Core
v31.99 oracle via `gettxoutsetinfo muhash`.

| | bmc (this repo, fix/dlc-peer-floor-depth) | Bitcoin Core v31.1 |
|---|---|---|
| install | clone 8s + build 8s, 0 warnings | download 10s/87MB, sha256, extract 1s |
| boot | P2P bound ~5s, 416k headers ~129s | (starts when bmc finishes) |
| download | 10.9MB/s recv, 10.9MB/s write -- at 640547/965427 blocks, progressing | pending |
| UTXO / serve phases | stamped by monitor at first appearance | stamped by run_core_bench.sh |
| result | pending | pending |

Core progress: not started

## Headline (already measured)
The dl_catchup dead-peer byte floor was unreachable for the first ~150k
blocks (93fab72 AND-rule): fresh syncs crawled at 77 KB/s with 22/22
workers under the floor and zero evictions. The byte-floor-binds-at-every-
depth fix (this branch) restores 7-9 MB/s on the identical datadir and peer
pool. See analysis/PEER_ANALYSIS.md, logs/floorhunt.log, MEMORY.md.

Full history: logs/ (ticks, phases, bisect, floor-hunt). Scripts: scripts/.
