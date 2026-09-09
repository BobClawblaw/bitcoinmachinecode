# Documentation index

The repository root holds one document, `README.md`, which describes the
node, its capabilities, how to build and run it, and how it differs from
Bitcoin Core. Everything else lives here.

## Operating the node

| | |
|---|---|
| [`OPERATIONS.md`](OPERATIONS.md) | installing, configuring, running as a service, upgrading, verifying, backing up, troubleshooting |
| [`../config/bitcoin.sample.conf`](../config/bitcoin.sample.conf) | the complete configuration reference: every key at its default, and every Bitcoin Core option the node accepts without effect, does not apply, or does not support |
| [`RPC_LIVE_NODE.md`](RPC_LIVE_NODE.md) | the embedded JSON-RPC server and its methods |
| [`MEMPOOL_SPACE.md`](MEMPOOL_SPACE.md) | running mempool.space against the node: the Esplora facade, the address history index, the backend configuration (2026-09-08) |
| [`FEATURE_GAPS.md`](FEATURE_GAPS.md) | what this node does and does not implement, against Bitcoin Core |
| [`CORE_BEHAVIORAL_COMPAT.md`](CORE_BEHAVIORAL_COMPAT.md) | every Core behavior in one table with DONE / PARTIAL / GAP / DECIDED / PROOF against the source, and the ordered work list |
| [`../validation/muhash_vs_core.sh`](../validation/muhash_vs_core.sh) | is this node's UTXO set byte-identical to Core's? Asks both nodes for `gettxoutsetinfo muhash` at the same height and compares muhash, txouts and total amount; an empty side is a failure. Re-runnable by anyone with an oracle |

## Contributing

| | |
|---|---|
| [`ENGINEERING_RULES.md`](ENGINEERING_RULES.md) | the rules this codebase is written under |
| [`ENGINEERING.md`](ENGINEERING.md) | how the pieces fit together: binaries, on-disk formats, validation gates |
| [`ABI_STACK_ALIGNMENT.md`](ABI_STACK_ALIGNMENT.md) | the SysV stack-alignment contract, and the audit that enforces it |
| [`PARITY_PLAN.md`](PARITY_PLAN.md) | how parity with Core is established and checked, method by method |

## Security

[`audits/`](audits/) holds each external audit and this project's written
response to it.

| | |
|---|---|
| [`audits/SECURITY_AUDIT_2026-08-29.md`](audits/SECURITY_AUDIT_2026-08-29.md) | independent audit, 11 findings |
| [`audits/AUDIT_RESPONSE_2026-08-30.md`](audits/AUDIT_RESPONSE_2026-08-30.md) | response: 8 findings resolved |
| [`audits/AUDIT_RESPONSE_2026-08-30_ADDENDUM.md`](audits/AUDIT_RESPONSE_2026-08-30_ADDENDUM.md) | follow-up: 2 more closed, 2 corrections |
| [`audits/SECURITY_AUDIT_2026-09-02.md`](audits/SECURITY_AUDIT_2026-09-02.md) | second independent audit: prior fixes re-verified, 11 new findings |
| [`audits/CODEBASE_AUDIT_2026-09-03.md`](audits/CODEBASE_AUDIT_2026-09-03.md) | full module-by-module code audit, 13 modules, 182 findings (5 CRITICAL, 32 HIGH); consolidated priority list and prior-audit re-verification |
| [`audits/AUDIT_2026-09-03_REMEDIATION.md`](audits/AUDIT_2026-09-03_REMEDIATION.md) | the remediation record for that audit: every finding dispositioned by id, including the ones declined and why |
| [`audits/INFO_REMEDIATION_2026-09-05.md`](audits/INFO_REMEDIATION_2026-09-05.md) | the INFO tier worked through: what was fixed, what was accepted as risk, and the reasoning for each closure |
| [`audits/BLD-3_CREDENTIAL_ROTATION_2026-09-05.md`](audits/BLD-3_CREDENTIAL_ROTATION_2026-09-05.md) | credential rotation record: what was rotated, how the old credential was proven dead, and the history caveat that stands |
| [`audits/NET-10_ADDRMAN_SCOPE.md`](audits/NET-10_ADDRMAN_SCOPE.md) | scope note for the address-manager finding |
| [`audits/IR-6_STACK_REPRESENTATION_SCOPE.md`](audits/IR-6_STACK_REPRESENTATION_SCOPE.md) | scope note for the interpreter review's one open finding: why OP_ROLL's cost is a representation change, and the order of work |
| [`audits/INTERP_REVIEW_2026-09-05.md`](audits/INTERP_REVIEW_2026-09-05.md) | in-session code review of the script interpreter slice: 17 findings (1 CRITICAL, 5 HIGH), two live consensus false-accepts and three valid-block DoS shapes; all OPEN and unreproduced, with the order and discipline for closing them |
| [`audits/DOCS_REVIEW_2026-09-05.md`](audits/DOCS_REVIEW_2026-09-05.md) | documentation consistency review of PR #11: 7 confirmed, all closed the same day; the reference systemd unit was publishing `LimitCORE=infinity` |
| [`audits/CORE_COMPAT_SCOPES_2026-09-06.md`](audits/CORE_COMPAT_SCOPES_2026-09-06.md) | scoping reports CC-1..CC-10 for every remaining Core-compatibility item: design against this architecture, files, tests with negative controls, risks, order |
| [`audits/UTXO_INLINE_CONNECT_SCOPE.md`](audits/UTXO_INLINE_CONNECT_SCOPE.md) | scope: building the UTXO set inline as blocks connect, Core's ConnectBlock model -- the tip is the connected tip, connect after every store, a failed connect is a rejection not a halt |
| [`audits/UTXO_INLINE_BUILD_PERF_SCOPE.md`](audits/UTXO_INLINE_BUILD_PERF_SCOPE.md) | the 3-hour gap to Core measured by the 2026-09-04 benchmark: connect runs after the download instead of inside it; the worker idles 19.5 h while its helpers download; interleaving connect into that loop is the fix, with the rate analysis, levers and the re-run as proof |
| [`audits/UTXO_CACHE_MODEL_SCOPE.md`](audits/UTXO_CACHE_MODEL_SCOPE.md) | scope: Core's in-RAM cache-and-flush model mapped onto our memtable/runs -- no WAL and size-triggered flushes in bulk mode only (readers need the WAL at the tip), tiered compaction, archive redo as recovery; additive to the interleave, decided by its instrumentation |

## Reports

[`reports/`](reports/) holds findings written to be read outside the
project, in Markdown, HTML and BBCode forms of the same text.

| | |
|---|---|
| [`reports/MINED_TX_CORPUS.md`](reports/MINED_TX_CORPUS.md) | the mined-transaction corpus: 17 real chain transactions replayed at their own heights as a consensus-acceptance test, the two controls that prove the corpus discriminates, and the gap those controls left named |

## Milestones

[`releases/`](releases/) holds one short note per landed batch -- the
paragraph behind each `git log --first-parent main` line. Milestones are
also annotated tags.

| | |
|---|---|
| [`releases/2026-09-05-interp-review.md`](releases/2026-09-05-interp-review.md) | interpreter review closed (14 of 17), MuHash re-verified and scripted, fresh clone builds, the mined-transaction corpus |
| [`releases/2026-09-05-net10-addrbook.md`](releases/2026-09-05-net10-addrbook.md) | NET-10 closed: the address book stores who told us about an address and whether we connected to it; the last open MEDIUM |
| [`releases/2026-09-05-audits-closed.md`](releases/2026-09-05-audits-closed.md) | the state of every audit by ID; one standing property not closable by a change, and the systemd unit closed by operator decision |
| [`releases/2026-09-06-core-compat.md`](releases/2026-09-06-core-compat.md) | the Core-compatibility work list resolved: CC-1..CC-7, CC-9, CC-10 closed or decided, CC-8 running, one item deferred with its reason |
| [`releases/2026-09-06-utxo-modules.md`](releases/2026-09-06-utxo-modules.md) | seven UTXO / MuHash / compact-block module branches landed: the MuHash fold leaves the connect path, IFMA modmul 3.3×, radix flush 5.9×, short-id table 6.9× |
| [`releases/2026-09-06-archive-genesis-seed.md`](releases/2026-09-06-archive-genesis-seed.md) | a fresh mainnet archive was shifted by one block for life; the false `bad-txns-BIP30` it caused, and why no test saw it |
| [`releases/2026-09-06-lowwork-hold-bound.md`](releases/2026-09-06-lowwork-hold-bound.md) | CC-5's four-page hold abandoned every honest header sync below ~880k; found on the replay, bounded by memory instead |
| [`releases/2026-09-06-utxo-interleave.md`](releases/2026-09-06-utxo-interleave.md) | the UTXO connect runs inside the parallel download instead of after it; the boot catch-up cannot interleave (`bmc.bootcatchup=0` for a fresh-clone benchmark) |
| [`releases/2026-09-07-chunk-stall-budget.md`](releases/2026-09-07-chunk-stall-budget.md) | the chunk budget is a stall clock, not a hidden ~470 KB/s bar |
| [`releases/2026-09-07-rename-bitcoinmcd.md`](releases/2026-09-07-rename-bitcoinmcd.md) | the daemon renamed (first pass) and the pid file follows it |
| [`releases/2026-09-07-bmc-prefix.md`](releases/2026-09-07-bmc-prefix.md) | everything we ship starts with `bmc`: `bmcbitcoind`, `bmc_rpcd`, the unit, the pid file |
| [`releases/2026-09-07-boundary-rotation-eta.md`](releases/2026-09-07-boundary-rotation-eta.md) | a slow peer rotated at the chunk boundary; the picker bar; ETA in DD:HH:MM:SS |
| [`releases/2026-09-07-keep-headers-ahead.md`](releases/2026-09-07-keep-headers-ahead.md) | headers ahead of the archive are kept across a restart |
| [`releases/2026-09-07-monotonic-download.md`](releases/2026-09-07-monotonic-download.md) | the download is monotonic like Core's: window, retry ring, the run-10 cascade; the 4096 window and 2 s help |
| [`releases/2026-09-08-rate-limits.md`](releases/2026-09-08-rate-limits.md) | `bmc.dialratelimit`, `bmc.downloadratelimit`, `bmc.uploadratelimit`: pacers shared across processes through one clock file; all default off |
| [`releases/2026-09-08-taproot-scriptpath-signing.md`](releases/2026-09-08-taproot-scriptpath-signing.md) | script-path signing verified by the consensus verifier on Core's own fixture |
| [`releases/2026-09-08-resume-deadlock.md`](releases/2026-09-08-resume-deadlock.md) | the apply-first backlog stops at the first hole: a resume no longer waits on a block that is not there |
| [`releases/2026-09-08-debuglog.md`](releases/2026-09-08-debuglog.md) | the daemon logs to `<chaindir>/debug.log` like Core; `printtoconsole=1` tees; `debuglogfile=0` turns the file off |
| [`releases/2026-09-08-cli-params.md`](releases/2026-09-08-cli-params.md) | `bmc_cli` converts arguments like bitcoin-cli and prints replies of any size; the config parser strips a trailing `#` comment |
| [`releases/2026-09-08-in-order-committer.md`](releases/2026-09-08-in-order-committer.md) | workers stage verified chunks; one committer appends the archive in height order, so the block files are laid out monotonically and the archive never has a hole |
| [`releases/2026-09-08-committer-sync-per-chunk.md`](releases/2026-09-08-committer-sync-per-chunk.md) | the committer fdatasyncs once per chunk: the early chain went from the SSD's commit rate to the link's 11 MB/s |
| [`releases/2026-09-08-undo-keep-all.md`](releases/2026-09-08-undo-keep-all.md) | undo data for every block in packed rev files, like Core; the 200-block window is gone |
| [`releases/2026-09-08-esplora-facade.md`](releases/2026-09-08-esplora-facade.md) | an Esplora-compatible listener for mempool.space, answered in process by the node's own RPC handlers (stage 1: blocks, transactions, mempool, outspends) |
| [`releases/2026-09-08-address-history.md`](releases/2026-09-08-address-history.md) | the address history index: every funding and spending event, native, ~200 GB; the facade's address routes on it |
| [`releases/2026-09-07-download-window.md`](releases/2026-09-07-download-window.md) | The download window is 4096 blocks with a fresh anchor and a 2 s help -- monotonic AND faster than run 9 |
| [`releases/2026-09-07-anchor-in-parent.md`](releases/2026-09-07-anchor-in-parent.md) | The window anchor is rescanned by the parent on demand -- a worker's own index reads were counted as network bytes |
| [`releases/2026-09-07-quiet-log.md`](releases/2026-09-07-quiet-log.md) | Per-event download lines become per-tick counts; the peer table prints once a minute |
| [`releases/2026-09-07-fail-backoff.md`](releases/2026-09-07-fail-backoff.md) | A failed fetch halves the peer's standing and backs off; the help chunk sits on the claim grid -- run 14's two-minute stall |
| [`releases/2026-09-07-inflight-label.md`](releases/2026-09-07-inflight-label.md) | The status line says 'in flight N of window W' and how old the oldest gap is, not 'holes' |
| [`releases/2026-09-07-index-holes-bmc-tools.md`](releases/2026-09-07-index-holes-bmc-tools.md) | Records above an index hole are kept when the header chain anchors them; every executable carries the bmc_ prefix |
| [`releases/2026-09-08-rpcthreads-default.md`](releases/2026-09-08-rpcthreads-default.md) | Rpcthreads defaults to Core's 4, not 16 |
| [`releases/2026-09-08-no-announce-in-ibd.md`](releases/2026-09-08-no-announce-in-ibd.md) | No tip announcements to the legs during initial block download, as Core |
| [`releases/2026-09-08-quieter-log.md`](releases/2026-09-08-quieter-log.md) | The catch-up tick is two lines, per-block lines silent in IBD, one line per compaction, peer table every five minutes |
| [`releases/2026-09-08-getpeerinfo-workers.md`](releases/2026-09-08-getpeerinfo-workers.md) | Getpeerinfo lists the parallel download's peers with their chunk in flight; getnettotals counts the download's bytes |
| [`releases/2026-09-08-cursor-help.md`](releases/2026-09-08-cursor-help.md) | The committer asks for its stalled cursor chunk once the pool has moved on |
| [`releases/2026-09-08-rawtx-v2-cap.md`](releases/2026-09-08-rawtx-v2-cap.md) | Getrawtransaction verbosity 2 keeps fee and prevouts past 1,024 inputs; the cursor help waits for a real stall |
| [`releases/2026-09-08-facade-locking.md`](releases/2026-09-08-facade-locking.md) | The Esplora facade locks per dispatch and never asks gettxout for a mempool prevout |
| [`releases/2026-09-08-stage-sweep.md`](releases/2026-09-08-stage-sweep.md) | Stale staged chunks are swept and the staged gauge is the directory's count |
| [`releases/2026-09-08-rawtx-prevouts.md`](releases/2026-09-08-rawtx-prevouts.md) | Getrawtransaction verbosity 2 attaches the RIGHT prevouts, by txid and by block hash |
| [`releases/2026-09-08-address-history-utxo-tail.md`](releases/2026-09-08-address-history-utxo-tail.md) | /address/:addr/utxo from funding events and the spender index; the tail journal adopts the history base |
| [`releases/2026-09-08-announce-cap.md`](releases/2026-09-08-announce-cap.md) | The far-behind trigger believes the second-highest announce, not one peer's claim |
| [`releases/2026-09-08-behind-peer.md`](releases/2026-09-08-behind-peer.md) | A header page that ends below our tip means the peer is behind us -- try another |
| [`releases/2026-09-08-address-mempool.md`](releases/2026-09-08-address-mempool.md) | The address routes include the mempool |
| [`releases/2026-09-08-core-rest.md`](releases/2026-09-08-core-rest.md) | Core's REST interface (`rest=1`), 82 route checks against Core's regtest REST; four RPC parity gaps it exposed |
| [`releases/2026-09-08-coinstats-hist.md`](releases/2026-09-08-coinstats-hist.md) | `gettxoutsetinfo` at any height the coinstats index covers: a row per applied block, Core's shape, 235 differential checks; the compact-block receive path found never to have completed |
| [`releases/2026-09-08-addrindex-boot-race.md`](releases/2026-09-08-addrindex-boot-race.md) | The address index boots after the UTXO engine and stops at its applied height |
| [`releases/2026-09-08-coinstats-self-heal.md`](releases/2026-09-08-coinstats-self-heal.md) | The coinstats history checks itself and rebuilds itself |
| [`releases/2026-09-08-undo-parity.md`](releases/2026-09-08-undo-parity.md) | getblockstats without undo errors like Core; the facade omits an unknown fee |
| [`releases/2026-09-09-addnode-dials.md`](releases/2026-09-09-addnode-dials.md) | `addnode` dials; the control channel waits for a whole worker rotation |
| [`releases/2026-09-09-announced-height.md`](releases/2026-09-09-announced-height.md) | The header phase refuses a chain far below what the pool announces |
| [`releases/2026-09-09-bip30-originals.md`](releases/2026-09-09-bip30-originals.md) | BIP30: the unspendable coinbases are the originals, as in Core |
| [`releases/2026-09-09-bip68-seq-cap.md`](releases/2026-09-09-bip68-seq-cap.md) | The BIP68 sequence cap is sized from the block weight limit |
| [`releases/2026-09-09-builder-keeps-inputs.md`](releases/2026-09-09-builder-keeps-inputs.md) | The coinstats builder keeps a pass's inputs until it completes |
| [`releases/2026-09-09-chain-selection.md`](releases/2026-09-09-chain-selection.md) | Chain selection like Core's: a handoff for long replacements, the header mirror as the best chain, a fork tree for every other branch |
| [`releases/2026-09-09-no-input-cap.md`](releases/2026-09-09-no-input-cap.md) | No per-transaction input cap in the single-transaction verifier; the connect path proven capless |
| [`releases/2026-09-09-no-seq-cap.md`](releases/2026-09-09-no-seq-cap.md) | No sequence cap: the BIP68 ledger is sized to the transaction, like Core's |
| [`releases/2026-09-09-one-record-per-key.md`](releases/2026-09-09-one-record-per-key.md) | One record per key per run: the UTXO defect behind bench run 18's rejected block |
| [`releases/2026-09-09-picker-dead-mark.md`](releases/2026-09-09-picker-dead-mark.md) | The download worker's picker: a dead-marked peer never clears the bar, not even a fresh sync's unknown bar |

## Development history

[`devlog/`](devlog/) and [`../worklog/`](../worklog/) are the working
record, written for the people building this rather than as a description
of the finished node. They hold the incident log, plans, measurements,
dead ends and the day-by-day action log, and are not tidied after the fact.

| | |
|---|---|
| [`devlog/LOG.md`](devlog/LOG.md) | incident log: every defect found, how it was found, what it cost |
| [`devlog/DEPLOYMENT_HISTORY.md`](devlog/DEPLOYMENT_HISTORY.md) | the deployment record: every production rollout, what it changed, what it proved |
| [`devlog/README_HISTORY.md`](devlog/README_HISTORY.md) | the previous, history-laden README, kept for its incident narratives |
| [`devlog/PLAN.md`](devlog/PLAN.md) | the build plan and its revisions |
| [`devlog/PLAN_SCRIPT_VERIFY.md`](devlog/PLAN_SCRIPT_VERIFY.md) | script/consensus verification plan |
| [`devlog/PERF_SCOPE.md`](devlog/PERF_SCOPE.md) | performance work, including the optimisations that were measured and rejected |
| [`devlog/BENCHMARKS.md`](devlog/BENCHMARKS.md) | benchmark results and methodology |
| [`devlog/ASSESSMENT.md`](devlog/ASSESSMENT.md) | periodic assessment of project state |
| [`devlog/CHAIN_AHEAD_CENSUS.md`](devlog/CHAIN_AHEAD_CENSUS.md) | survey of what the chain actually contains |
| [`../worklog/`](../worklog/) | one file per day: what was done, why, with evidence |

Source comments cite these documents by bare filename (`see LOG.md incident
#20`, `PERF_SCOPE.md 4.1`); each resolves to a file under `docs/`,
`docs/devlog/` or `docs/audits/`.
- [Incident 2026-09-01: boot header sync accepted a genesis-first answer](devlog/INCIDENT_2026-09-01_header_sync_genesis_answer.md) — root causes, damage assessment, fixes
- [Incident 2026-09-01: set-diff OOM took the box down; 2,596 spends resurrected by blind recoveries](devlog/INCIDENT_2026-09-01_oom_and_resurrected_spends.md) — host freeze root cause, the UTXO surplus traced to eight flush-time recoveries, repair options
