# Documentation index

The repository root holds one document — `README.md`. Everything else lives
here.

## Operating the node

| | |
|---|---|
| [`DEPLOYMENT.md`](DEPLOYMENT.md) | building, configuring, deploying, rolling back |
| [`RPC_LIVE_NODE.md`](RPC_LIVE_NODE.md) | the embedded JSON-RPC server and its methods |
| [`FEATURE_GAPS.md`](FEATURE_GAPS.md) | what this node does and does not implement, against Bitcoin Core |

## Contributing

| | |
|---|---|
| [`ENGINEERING_RULES.md`](ENGINEERING_RULES.md) | the rules this codebase is written under |
| [`ENGINEERING.md`](ENGINEERING.md) | how the pieces fit together |
| [`ABI_STACK_ALIGNMENT.md`](ABI_STACK_ALIGNMENT.md) | the SysV stack-alignment contract, and the audit that enforces it |
| [`PARITY_PLAN.md`](PARITY_PLAN.md) | how parity with Core is established and checked |

## Security

[`audits/`](audits/) holds each external audit and this project's written
response to it. Responses record what was fixed, what it was verified
*against*, and — deliberately — the mistakes made while fixing it.

| | |
|---|---|
| [`audits/SECURITY_AUDIT_2026-08-29.md`](audits/SECURITY_AUDIT_2026-08-29.md) | independent audit, 11 findings |
| [`audits/AUDIT_RESPONSE_2026-08-30.md`](audits/AUDIT_RESPONSE_2026-08-30.md) | response: 8 findings resolved |
| [`audits/AUDIT_RESPONSE_2026-08-30_ADDENDUM.md`](audits/AUDIT_RESPONSE_2026-08-30_ADDENDUM.md) | follow-up: 2 more closed, 2 corrections |

## Development log

[`devlog/`](devlog/) is the working record. It is written for the people
building this, not as a description of the finished thing — it is where the
mistakes, dead ends and measurements live, and it is deliberately not
tidied up after the fact.

| | |
|---|---|
| [`devlog/LOG.md`](devlog/LOG.md) | incident log: every defect found, how it was found, what it cost |
| [`devlog/PLAN.md`](devlog/PLAN.md) | the build plan and its revisions |
| [`devlog/PLAN_SCRIPT_VERIFY.md`](devlog/PLAN_SCRIPT_VERIFY.md) | script/consensus verification plan |
| [`devlog/PERF_SCOPE.md`](devlog/PERF_SCOPE.md) | performance work, including the optimisations that were measured and REJECTED |
| [`devlog/BENCHMARKS.md`](devlog/BENCHMARKS.md) | benchmark results and methodology |
| [`devlog/ASSESSMENT.md`](devlog/ASSESSMENT.md) | periodic honest assessment of project state |
| [`devlog/CHAIN_AHEAD_CENSUS.md`](devlog/CHAIN_AHEAD_CENSUS.md) | survey of what the chain actually contains |
| `devlog/KANBAN.md` | working task board (gitignored — local only) |

---

## A note on references

Source comments across the tree cite these documents by bare filename —
`see LOG.md incident #20`, `PERF_SCOPE.md 4.1` — rather than by path. There
are around 236 such references, most of them in consensus-critical assembly.

When these files moved out of the root on 2026-08-30 the references were
deliberately **left as bare names**: they still resolve by grep, and editing
236 comments inside consensus code for a cosmetic gain would have been a poor
trade. If you are looking for a document named in a comment, it is under
`docs/`, `docs/devlog/`, or `docs/audits/`.
