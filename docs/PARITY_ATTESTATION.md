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
| 2026-09-02 07:04 | 965,135 | 165,632,732 | `4025abd64e518e80` | deploy ak (audit N3/N7) |
| 2026-09-02 06:41 | 965,134 | 165,633,295 | (exact, not recorded) | restart under the N5 sandbox |
| 2026-09-02 05:51 | 965,125 | 165,663,594 | `4358215250dc1fc1` | private broadcast enabled |
| 2026-09-02 05:45 | 965,124 | 165,662,711 | `aeed9ba506ff14a2` | deploy aj (private broadcast, wallet_store v3) |
| 2026-09-02 01:06 | 965,104 | (see incident) | identical | deploy ai, after the surgical repair |
| 2026-09-01 | 965,085 | (see incident) | identical | after deleting the 2,596 resurrected spends |

Procedure (`docs/OPERATIONS.md`, "tip procedure"): read our height from
`gettxoutsetinfo muhash`, ask the oracle for the same height, compare muhash
and txouts. A mismatch is an incident, never a note.
