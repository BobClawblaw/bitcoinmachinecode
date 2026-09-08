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
