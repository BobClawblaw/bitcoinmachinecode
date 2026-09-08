# 2026-09-07 — The window anchor is rescanned by the parent on demand

The fresh-anchor rescan (#78) had a worker blocked at the window read `index.dat` itself, and those reads landed in its `/proc` io `rchar`, the counter every verdict is built from: per-worker rate, pool median, dead-weight floor, rotation bar. Run 12 printed an average of 263 MB/s on an 11 MB/s link and rotated on nearly every chunk.

A blocked worker now raises `DLC_CTL_WANT_ANCHOR`; the parent, whose counters judge nobody, rescans within 200 ms (its idle sleep is stepped) and publishes the first hole monotonically.

**Proof.** Fresh scratch node: **114,625 blocks at 5:53** (run 9 with no window: 86,266; the worker-rescan build: 101,591), average 476 KB/s and median 74 KB/s (sane), 213 rotations over 72 peers, 4 abandoned chunks all retried and below the connect line. Full gate 13,310 lines, 0 failures; 8 audits exit 0.

---

PR #79 (`batch/2026-09-07-anchor-in-parent`), merged 16:16Z as `b48e01f6`; tag `anchor-in-parent-2026-09-07`.
