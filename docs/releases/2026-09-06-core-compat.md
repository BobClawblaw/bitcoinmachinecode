# 2026-09-06 — Core behavioral compatibility: the work list resolved

`docs/CORE_BEHAVIORAL_COMPAT.md` listed ten items on 2026-09-06 morning.
By evening, every one is closed, decided, deferred with a reason, or
running — each closed item with a test watched to fail first and a stated
negative control, each landed as its own merge with a green gate.

| | item | outcome |
|---|---|---|
| CC-1 | tx relay to and from inbound peers | closed — a shared announce ring, Poisson-timed, feefilter-honouring; inbound-origin txs reach the outbound legs |
| CC-2 | BIP152 compact block receive | closed, low-bandwidth mode — reconstruction from the mempool in the asm download loop; high-bandwidth push is a follow-up |
| CC-3 | inbound eviction (`AttemptToEvictConnection`) | closed — and a full table no longer serves unrecorded peers (found while scoping) |
| CC-4 | block-relay-only legs + `anchors.dat` | closed — Core's file format byte for byte |
| CC-5 | low-work headers sync | closed, stage 1 — full pages below `-minimumchainwork` held, not stored |
| CC-6 | extra outbound on a stale tip | closed |
| CC-7 | `-peertimeout` (DMN-14) | closed — it was parsed and read by nothing |
| CC-8 | full-verification replay (`assumevalid=0`) | **running** from the Core oracle since 01:12Z; the wall-clock is the deliverable |
| CC-9 | BIP331 package relay wire | decided — Core does not ship it; opportunistic 1p1c already matches |
| CC-10 | completeness | coin selection (knapsack, SRD, waste) closed; `invalidateblock`/`reconsiderblock` closed; BIP389 was already there; taproot **script-path PSBT signing** deferred — it is absent for every key type and needs Core-generated fixtures |

Found and fixed on the way, none of them on the list: the CLI and the
daemon resolved configuration differently (`d0bc1c2`); the boot header fetch
tolerates ten minutes of silence from one peer; the downloader's byte-rate
rule misfires on early tiny blocks over loopback (`bmc.peerminbps` exists).

Register counts at close: see the table in `CORE_BEHAVIORAL_COMPAT.md`; the
remaining GAP rows are the deferred script-path PSBT work and the ban list
not persisting across restarts.
