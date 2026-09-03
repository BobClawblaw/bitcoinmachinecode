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
