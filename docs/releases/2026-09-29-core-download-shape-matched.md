# 2026-09-29 — The IBD download takes Core's shape

The operator asked for the two nodes' default network settings to match so
the IBD benchmark is a fair A/B. A line-by-line comparison of Core v31.1's
constants against this node's defaults found the connection budget already
equal and three download settings not, each in Core's favour. All three now
match, and run 31 is the first sync on the matched defaults.

## What was compared

| setting | Core v31.1 | this node before | this node now |
|---|---|---|---|
| `maxconnections` default | 200 (`DEFAULT_MAX_PEER_CONNECTIONS`) | 200 | same |
| outbound full-relay | 8 | 8 | same |
| block-relay-only | 2 | 2 | same |
| feeler | 1, every ~2 min | 1, every 120 s | same |
| inbound slots | `maxconnections` − the outbound classes | the same arithmetic (`CFG_INBOUND_LIMIT`) | same |
| connect / peer timeouts | 5,000 ms / 60 s | 5,000 ms / 60 s | same |
| **download peers in IBD** | **10**: every outbound peer that can serve blocks — full-relay 8 + block-relay-only 2 (`fPreferredDownload`, `net_processing.cpp`); inbound only when no preferred peer has anything in flight | 8 (`bmc.catchupworkers`, "Core's `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS`") | derived as `bmc.maxoutbound + bmc.blockrelayonly` = 10 unless the key is set |
| **download window** | 1,024 blocks above the connected tip (`BLOCK_DOWNLOAD_WINDOW`) | six times the claimed chunks, never under 4,096 | 1,024, never below what the workers claim at once |
| **connections beside the download** | none: the download peers are the outbound set | 4–8 idle legs beside the workers (run 30: "connected 4/8" + 8 workers = 12 outbound) | while the tip is older than `maxtipage` the idle legs are closed before the parallel download and re-dialled after it |
| blocks in flight per peer | 16, refilled as each lands | one 40-block chunk per `getdata` | unchanged (a shape, not a setting; `docs/CORE_BEHAVIORAL_COMPAT.md`) |

Both benchmark configs already set `maxconnections=48`, `dbcache=8192`,
`txindex`, `coinstatsindex`, `blockfilterindex`, `prune=0`, `listen=1` on
both sides.

## Why the register said 8

The 2026-09-10 note set the default to 8 as "the number Core uses" and the
divergences register pinned it there on 09-14. Both read
`MAX_OUTBOUND_FULL_RELAY_CONNECTIONS` and stopped; Core's block-relay-only
peers are outbound, serve blocks, and are preferred-download peers like the
rest. The 09-10 note carries a dated correction; the register's section is
rewritten with the citation.

## What run 30's status lines say about the margin

The change of window was not made on principle alone. Run 30's `[dlc] ==`
lines show the download's lag behind the applied tip pinned at 3,500–4,100
blocks from the eleventh minute to the end: the download sat at the
4,096-block window's edge, waiting on the apply, for the whole sync. On the
repaired link both nodes are apply-bound, and the flat 55–59% margin over
Core at every height through 850,000 is the apply rate. The window is now
Core's 1,024, so the next pair shares that constraint too.

## What changed in the tree

- `daemon/node_config.c` / `.h`: `catchup_workers` is derived at the end of
  the load from the two outbound classes unless `bmc.catchupworkers=`
  appears (`catchup_workers_explicit`); the compiled default is 10.
- `daemon/dlc_rules.h`: `dlc_window_blocks` returns Core's 1,024
  (`DLC_BLOCK_DOWNLOAD_WINDOW`), or the workers' claimed chunks when those
  exceed it; `DLC_WINDOW_MIN` and the six-times multiplier are gone.
- `daemon/main.c`: before an IBD-sized parallel download (the archive tip
  older than `maxtipage`, `dl_tip_is_ibd`) every idle leg is closed with a
  named reason (`ibd-download`) and its re-dial armed; a hole re-fetch or a
  handoff on a fresh tip keeps its legs.
- `config/bitcoin.sample.conf`, `validation/fresh_ibd_run.sh`: the harness
  no longer writes `bmc.catchupworkers=8`; `WORKERS=` still overrides.
- Docs: the divergences register section and row, the behavioural-compat
  rows, the benchmark fairness table, the run 30 report.

## Proof

- `tests/test_dlc_rules`: the window is 1,024 for 8 and 10 workers and
  2,560 for 64; revert-checked — the old rule fails all three.
- `tests/test_node_config`: the defaults give 10; `bmc.maxoutbound=12` +
  `bmc.blockrelayonly=3` without the key give 15; `bmc.catchupworkers=4`
  wins over the classes; revert-checked — the derivation disabled fails the
  second, the old compiled default fails all three.
- The leg-closing rule has no unit seam (it runs inside the serve loop
  around a download that takes hours); `tests/test_parallel_trigger`
  passes, and run 31's log is where it is verified: one
  `closed N idle leg(s) for the parallel download` line, then
  `Core's shape: 10 of M live peer(s) download at once`, then the top-up's
  re-dials after the download.

## Found on the way, not fixed here

- Production holds **9** full-relay legs against a target of 8 (four
  up-front, five background fills). Core's oracle holds exactly 8 + 2.
- Production holds **no** block-relay-only legs: every block-relay-only
  dial since the 22:44 restart timed out at connect (10 s), as did all 38
  feelers in two hours. The candidates come from the same pool the
  full-relay top-up draws from, which did land five of its dials. Peer
  selection for the extra classes is the open question, not the budget.
