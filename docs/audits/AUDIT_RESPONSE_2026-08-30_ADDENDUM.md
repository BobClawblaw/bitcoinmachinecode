# AUDIT RESPONSE — ADDENDUM

Follow-up to `AUDIT_RESPONSE_2026-08-30.md`, closing four of the six items that
document left open, and correcting two statements in it that are no longer
true.

Everything below is on `main`, gated, and — where it changes runtime behaviour
— deployed.

---

## Corrections to the first response

**Incident 3 is closed.** The first response listed the peer-service-bits fix
as *"committed, effect not yet observed in production."* It has since been
observed: outbound BIP324 sessions are being established against real mainnet
peers.

```
2026-08-30 01:00:00 [dial] 12.244.119.30:8333  connected over v2
2026-08-30 01:02:30 [dial] 213.168.190.147:8333 connected over v2
2026-08-30 01:03:39 [dial] 47.133.222.86:8333   connected over v2
```

Five v2 sessions against 29 v1 at the time of writing, and the ratio should
keep climbing: the address book self-heals one peer per successful handshake,
so each contact makes the next dial more likely to qualify. The mechanism is
therefore confirmed end to end, not merely committed.

**Finding 4 understated Core's position.** The first response described
`rpcuser`/`rpcpassword` as Core's "legacy alternative". Checking the source,
Core is stronger than that: `InitRPCAuthentication()` generates a cookie
whenever `-rpcpassword` is empty, and when it is set it emits a `LogWarning`
calling plaintext credentials *"less secure, because credentials are
configured in plain text"* and recommending cookie or `rpcauth` instead.

Core does not tolerate their absence — it prefers it. Removing them put this
node on Core's default and recommended path, which is a better justification
for the change than the one originally given.

---

## FOLLOW-UP 1 — JSON parser recursion depth — RESOLVED

*(Audit recommendation 9 in the remediation plan: "add a parser
recursion-depth counter (defense-in-depth)".)*

**This was not defence in depth. It was a reachable crash.**

Every `[` or `{` recursed into `p_val` with no bound, so nesting depth was
attacker-controlled **stack** depth. Measured, not theorised: 200,000 levels
exhausted the stack and dumped core.

Worse, `rpc_json.c` carried a comment stating that recursion *"is bounded by
the parser's own nesting limit"*. **No such limit existed.** A comment
asserting a safety property that is absent is worse than no comment, because
it stops the next reader from checking. It has been corrected rather than
deleted, so the record of the claim survives.

**Fix.** Depth is counted on entry to a container and decremented on every
successful exit, capped at **512** — UniValue's `MAX_JSON_DEPTH` — so this
parser now accepts and rejects exactly the nesting Core does.

The decrement matters as much as the cap: without it the counter would measure
the *total number of containers* rather than nesting, silently turning the
limit into something else while still rejecting the hostile input. The test
pins that directly with 5,000 sibling arrays, which must parse.

**Reachability.** Any RPC request body. The listener is loopback-only and
authenticated, so this is not a remote crash — but "hard to reach" is not the
same as "bounded".

**Testing.** `tests/test_rpc_json_depth` checks 1 / 100 / 511 / **512** /
513 / 200,000 for both arrays and objects. The 512 case must still **parse** —
a bound that also refused ordinary requests would satisfy every "hostile input
is rejected" assertion while breaking the RPC interface.

Guard verified by removing the bound: the test then **dies with SIGSEGV**
rather than failing an assertion, which is its own unmistakable signal.

---

## FOLLOW-UP 2 — Misbehaviour scores now survive a fork — RESOLVED

*(Finding 7, the half the first response left open.)*

The first response said plainly that scores did not accumulate across
connections, because `g_misbehavior` was a process-local array and the serve
loop runs in a **forked child**. A peer could therefore misbehave once per
connection forever and never reach the 100-point threshold. Each individual
report was logged correctly, which is exactly why the gap was invisible: the
machinery looked like a defence and could not accumulate.

**Fix.** The table now lives in the pre-fork `MAP_SHARED` `node_status_t`
region — beside the ZMQ staging ring, which is there for precisely the same
reason: producers are forked children and the consumer is not.

A **cross-process spinlock** guards slot lookup and update. Without it two
children can allocate two slots for the same peer and each accumulate half the
evidence — the quiet version of the same bug, and one that would still have
logged every report correctly.

The process-local array survives as a fallback for binaries that link
`daemon/main.c` without mapping a status region, and a `_Static_assert` keeps
the two table sizes in step.

**Testing.** `tests/test_misbehavior_shared` does the one thing a
single-process test cannot: it scores the same peer from **separate forked
children** and asserts

- 5 children × 10 points = **50**, not 10;
- ten separate connections reach the ban threshold;
- 16 concurrent children leave the peer in **exactly one slot** with all 80
  points landed — the property the lock exists for.

**Closed 2026-08-30.** A second violation type is now wired, and choosing
which was decided by reading Core's 22 `Misbehaving()` sites rather than by
following the audit's list. Core scores **structural** violations — oversized
inv/getdata/headers, invalid proof of work, non-continuous headers, mutated
blocks. It does **not** score duplicate-inv spam or handshake failures, both of
which the audit suggested; scoring those risks banning honest peers with
quirky implementations, so they were deliberately left alone.

The one Core site that applies here — oversized `inv`/`getdata` — turned out to
sit on top of a parsing bug. The handler read the entry count as a **single
byte** and walked `count * 36` bytes without consulting the payload length:

1. any vector above 252 entries uses a multi-byte varint, which Core sends
   routinely, so `0xfd` was read as the count and every entry was offset by
   two — a silent misparse of **ordinary traffic**, not hostile input;
2. a short message with a large count byte walked past what the peer sent into
   whatever the previous, larger message left in the 8 MB receive buffer,
   letting a peer steer `getdata` at hashes assembled from earlier traffic.
   Not memory-unsafe — the buffer dwarfs 255×36 — but peer-influenced nonsense.

`serve_inv_bounds` (C, called from the assembly) now parses the varint,
enforces canonical `CompactSize` as Core's `ReadCompactSize` does, bounds the
vector by the bytes actually received, and rejects above `MAX_INV_SZ` (50,000).
Exceeding the cap is scored; short or malformed vectors are dropped **without**
a score, because a truncated read is not necessarily malice.

Two further defects were caught by testing rather than review: the test
asserted `255` was a single-byte count (`0xff` is the 8-byte varint *marker* —
single-byte counts stop at `0xfc`), which exposed that canonical encoding was
unchecked; and the assembly compared `RAX` against `-1` when SysV defines only
`EAX` for an `int` return, so the violation branch silently never matched. The
symptom was the test reporting *"dropped it WITHOUT reporting"* — a code path
that looked wired and was not.

---

## FOLLOW-UP 3 — Test wiring — RESOLVED, and worse than reported

*(Recorded but not triaged in the first response.)*

The first response noted the counts and deferred judgement. Triaging them
found the problem was **older and wider** than the two instances introduced
during this remediation.

**Seven tests were never run by `make test`, and all seven pass in seconds.**

| test | why it never ran |
|---|---|
| `test_ephemeral_dust` | built as a prerequisite, never invoked |
| `test_truc_policy` | built as a prerequisite, never invoked |
| `test_msg_sign` | had a rule, referenced nowhere |
| `test_net_policy` | had a rule, referenced nowhere |
| `test_wallet_txlog` | had a rule, referenced nowhere |
| `test_lsm_bloomsat` | had a rule, referenced nowhere |
| `test_interp_legacy_spend` | had a rule, referenced nowhere |

All are now gated.

**How they were classified.** By **building and running every candidate** in a
scratch worktree — not by reading header comments. That distinction produced
the result: several files whose comments suggested heavyweight integration
tests in fact complete in well under a second, and would have stayed excluded
on a reading of the prose alone.

**The remainder are declared manual, each with a reason a reader can
disagree with:** a live peer is required (`test_gh_real`, `test_addr_ingest`),
the run takes hours (`test_ibd_scale`), it is randomized stress with unbounded
runtime (`test_mpool_delete_stress`, `test_utxo_delete_stress`), or it needs a
prepared archive fixture (`test_truncate_guard_prim`). Helper binaries that
live in `tests/` and are invoked *by* other tests — `bip30_shim`,
`consensus_shim`, `run_batch`, `verify_p2sh_shim` — are listed separately,
confirmed by grepping for their call sites rather than assumed from their
names.

**One genuine defect surfaced:** `test_utxo_recover` **does not link**. It is
on the list marked `BROKEN: does not link. Tracked, not excused -- fix or
delete`, so it cannot pass as a deliberate exclusion.

**New gate stage: `runlist-check`**, running beside `prereq-check`.
`prereq-check` catches a rule that does not depend on what it links; this
catches a test that nothing runs, and a stale allowlist entry naming a test
that no longer exists.

Verified by deleting `test_msg_sign` from the run list — the checker names it
and fails. Its own **success path** then turned out to carry a `dict & set`
type error that the failing dry-run had never reached: testing one branch of a
checker tests half of it, which is the same shape as the RPC start-gate miss
recorded as Incident 2 in the first response.

---

## Why this class of bug kept recurring

Three of the four items above share one shape: **a thing that looked like it
worked, reported that it worked, and did not.**

- A comment asserting a nesting limit that did not exist.
- A misbehaviour system that logged every report correctly and could never
  accumulate them.
- A boot line reporting "8341 of 14825 known peers advertise v2" while dialling
  v1 to every peer, because it counted the address book rather than the peers
  actually dialled.
- Tests that were compiled, and never executed, inside a green gate.

None of these produce an error. Each produces a **reassuring signal** that is
measuring the wrong thing. The countermeasure applied throughout this round was
to verify the *negative* case as well as the positive one — remove the fix and
confirm the guard fails, pair every refusal with an input that must still be
accepted, and prefer a metric that counts the population actually acted upon.

---

## Open items after this addendum

1. **Finding 3** — hand-written consensus assembly. Structural; needs
   continuous oracle differential and property-based fuzzing, not a patch.
   **Not closeable by a change**: it is a standing property of the codebase,
   answered continuously by the differential harnesses and the gate rather
   than by a fix. As of 2026-09-05 every *defect* finding from every audit is
   closed, accepted or deferred with reasons; this row and the operator's
   declined systemd hardening (item 3) are what remain, and neither is a
   defect.
3. **Systemd hardening** — declined by the operator. `LimitCORE=0` remains
   worth revisiting: Incident 1 was a debugger reading wallet secrets from
   process memory, and a core dump is the same exposure.
4. ~~**`test_utxo_recover`** — does not link; fix or delete.~~ **Closed: it
   links.** Verified 2026-09-05 — `asm/Makefile:1016` builds it clean. It is
   deliberately *not* gated: it is a manual integration tool that takes a
   datadir (`./tests/test_utxo_recover <datadir>`, Makefile:1008) and exits 2
   with a usage message when run bare, like `test_addr_ingest`. The gated
   sibling is `test_utxo_recover_gate`, which `make test` does run
   (Makefile:3470). The 2026-08-30 complaint was that it would not link;
   that is fixed.

---

*Addendum prepared 2026-08-30. Follows `AUDIT_RESPONSE_2026-08-30.md`.
Gate: 265 test binaries, 1,365 assertions, zero failures.*
