# Parity attestation

The consensus oracle for this node is Bitcoin Core (the scratch build in
`/storage/core-oracle`, `txindex` + `coinstatsindex`). The attestation is
`gettxoutsetinfo muhash` on both nodes at the same height: the MuHash of the
entire UTXO set, plus the coin count. Identical means every coin created and
spent since genesis was tracked exactly as Core tracks it. It is produced
after every deploy and after every UTXO incident, and this file records the
latest ones (audit 2026-09-02, recommendation 8: publish the height).

| Date (UTC) | Height | Coins | muhash (prefix) | Occasion |
|---|---|---|---|---|
| 2026-09-30 06:50 | 969,273 | (not recorded) | `25640fa6c830242c` | run 31's capstone: a fresh IBD on main `49e26354` on the Core-matched defaults (5 h 28 m 11 s to its real tip), the per-height row equal to Core's and the live answer agreeing |
| 2026-09-28 11:48 | 968,987 | (not recorded) | `1b39ab301f79d471` | run 30's capstone: a fresh IBD on main `1370d041` (4 h 54 m 30 s on the repaired link), the per-height row equal to Core's and the live answer agreeing |
| 2026-09-28 00:53 | 968,910 | 165,238,604 | `c120bbaf14e37bdb` | production after #329 (the safegcd MuHash inverse): indexed row, no-height answer and Core all equal, 20,090,116.75 BTC |
| 2026-09-28 02:09 | 968,920 | (not recorded) | `20a98a1547ea0e51` | production after #331 (the AVX2 keystream under MuHash): indexed row equal to Core's |
| 2026-09-27 12:10 | 968,837 | (not recorded) | `b0982e65d4d5ed94` | production after #321: the no-height answer, the per-height row and Core all print this |
| 2026-09-27 09:3x | 968,821 | 165,210,914 | `ee7594826ad13e65` | production and the assumevalid=0 fresh sync, both equal to Core; rows 968,806–968,821 all equal |
| 2026-09-25 17:41 | 968,570 | 165,271,852 | `6cc459ddaa38e1ad` | bmc_osx (macOS/arm64) mainnet vs a local Core; muhash identical once printed in Core's byte order (c42cc03f) |
| 2026-09-02 07:04 | 965,135 | 165,632,732 | `4025abd64e518e80` | deploy ak (audit N3/N7) |

> BLD-5 (2026-09-05): THIS TABLE IS BEHIND THE NODE. The last attestation is
> 2026-09-02 at height 965,135; the node has since run past 965,500 across
> several deploys with no row added. The procedure above says an attestation
> follows every deploy -- that has not been happening, and the gap is recorded
> here rather than left for the next reader to infer from dates.

| 2026-09-02 06:41 | 965,134 | 165,633,295 | (exact, not recorded) | restart under the N5 sandbox |
| 2026-09-02 05:51 | 965,125 | 165,663,594 | `4358215250dc1fc1` | private broadcast enabled |
| 2026-09-02 05:45 | 965,124 | 165,662,711 | `aeed9ba506ff14a2` | deploy aj (private broadcast, wallet_store v3) |
| 2026-09-02 01:06 | 965,104 | (see incident) | identical | deploy ai, after the surgical repair |
| 2026-09-01 | 965,085 | (see incident) | identical | after deleting the 2,596 resurrected spends |

Procedure (`docs/OPERATIONS.md`, "tip procedure"): read our height, then ask
BOTH nodes for `gettxoutsetinfo muhash <height>` and compare muhash and
txouts. Pin the height on both sides: from 2026-09-25 to 2026-09-27 our
no-height answer printed the digest byte-reversed on any node with the
coinstats index (#321), and a live-vs-indexed comparison read an identical
set as divergent. A mismatch is an incident, never a note — but compare the
two hashes reversed before calling it one.
