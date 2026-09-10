# 2026-09-10 — The legs stay served through a reorg handoff

Inventory row 3 (long reorgs). Core stages a competing branch from its peers and connects it as one unit, serving every other peer meanwhile. Here a branch of more than 32 new blocks is not staged from the probing leg: the archive is rewound to the fork on the strength of the headers and the parallel downloader fetches the replacement. That part stays. What was wrong is what the legs saw during it: the parallel download ran inside the worker's loop and served no leg for its whole length, no pongs, no relay, no announcements, and the rotation came back to legs that had given up on us ("a rotation without legs after a handoff").

- **The legs' sweep is a function** (`legs_sweep_except`) and the parallel download's loop calls it once per connect pass, at most every ten seconds: buffered messages, pongs, the good mark, the ping schedule and block announcements all continue while a branch is fetched. The rotation's own use of it is unchanged.
- **Helpers bounded by the span.** A handoff of forty blocks forked 64 download helpers for one chunk; `dlc_workers_for` now takes the span and never starts more helpers than it has chunks. The boot line prints the span.

`test_dlc_rules` pins the bound (a 40-block span is one helper, 41 is two, 1,000 is 25, a full sync is still 64). The sweep inside the download is exercised on the next handoff on production or the next fresh run (the `[txrelay]` and ping lines keep coming during `[dlc]` output).
