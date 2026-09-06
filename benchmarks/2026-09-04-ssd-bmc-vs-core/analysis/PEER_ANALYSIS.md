# bmc IBD peer-selection analysis — 2026-09-04

Live capture: `/mnt/2tbssd/bmc-bench/console.log`, fresh genesis sync,
commit f725cb7, 16 chunk-claiming workers, 126 confirmed-live peers.

## Measured state at ~13 min in

| metric | value |
|---|---|
| overall download rate | 75.9 KB/s recv (aggregate, 16 workers) |
| per-peer median (22 peers sampled) | 2.7 KB/s |
| best peer | 11.5 KB/s (192.69.53.35, USA) |
| peers below the 32 KB/s dead-weight floor | 22 / 22 |
| early-kills actually fired | 2 in 13 min |
| chain progress | 67k / 416k blocks, ETA ~3 days at this rate |

Geo audit (`/mnt/2tbssd/peer_geo_audit.py`): 7×USA, 3×DEU, and one each of
CAN/FRA/BRA/RUS/KOR/IRL/HKG/CHN. The host is in the US; the slowest peers
(1.7–2.7 KB/s) are HKG/CHN/KOR/RUS/BRA — exactly the round-robin tax of
dialing the *reachable* book rather than the *fast* book.

## Why every peer looks "slow" (two separate effects)

1. **Early-chain block size.** The 32 KB/s floor
   (`DLC_DEAD_WEIGHT_BPS`) was calibrated for ~1 MB blocks. Blocks 0–150k
   are a few hundred bytes, so a peer doing 50 blk/s delivers ~20 KB/s and
   is genuinely healthy in *block* terms. The min-blocks exemption
   (`DLC_DEAD_WEIGHT_MIN_BLOCKS=10/tick`) correctly keeps them alive — but
   it means the byte floor NEVER binds during the first ~150k blocks:
   22/22 peers sit under 32 KB/s and 0 get replaced. The "too many slow
   peers" state is un-enforced by design in that span.

2. **Selection has no speed history.** `dlc_probe_round` confirms TCP +
   verack only. `dlc_worker` picks `(slot+a) % nlive` — round-robin over
   reachability. A peer's measured bytes (the parent samples `/proc/<pid>/io`
   every 10 s!) are thrown away for selection: they only exist to write
   `last_bw_bps` for the drop message. Nothing ranks `live[]`, so a
   0.4 KB/s CHN peer holds a worker slot as long as a 12 KB/s USA peer —
   minus the ban, which fired once here because the floor is unreachable.

## The fix is cheap — the data already exists

- Rank `live[]` by EMA of measured KB/s **in block-equivalent units**
  (blocks/s, not bytes — size-aware, so no early-chain false-slow), refreshed
  from the `/proc` samples the parent already takes. Workers claim the
  *fastest unclaimed* peer, not the next round-robin index.
- Persist per-peer throughput to the address book (`peers2.dat` already
  round-trips) so a re-run starts with a pre-ranked pool; `dl_load_good_peers`
  already proves the hook exists.
- Optional (asmap is already linked): bias selection by RTT/ASN diversity so
  a single slow continent can't occupy more than N workers.
- Enforce *relative* dead-weight in the early-chain span: floor = max(
  absolute floor, α × pool median in blk/s ) so 2 blk/s gets replaced by
  50 blk/s on the same link even when bytes say both are "fine."

## Cost of the status quo (measured)

75.9 KB/s aggregate × 16 workers: replacing the bottom half of the pool with
top-half peers would raise the aggregate ≈35–40% at minimum (12 median
peers × ~3.3 KB/s of delta), and the ETA at 416k blocks is ~3 days — so the
peer-selection issue alone dominates the entire bmc IBD benchmark right now,
ahead of disk (0.4 GiB/s SSD, ~50 KB/s written = idle) and CPU (4.4%).

Scripts: `peer_speed_audit.py` (per-peer medians, floor coverage, drops),
`peer_geo_audit.py` (geo enrichment of the same).
