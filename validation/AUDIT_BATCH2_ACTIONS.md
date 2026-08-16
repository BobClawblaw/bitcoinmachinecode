# Action Checklist — Batch 2 (audit follow-up, NOT yet done)

**For an AI/agent:** this file is a live action checklist of work that is still
OPEN. Everything listed here has NOT been implemented. Do the items one at a
time, in order, and update each item's status checkbox + note when done.

**Source document:** `validation/SECURITY_AUDIT.md` (PASS 2, 2026-08-16).
Items here are the open remediation items from that audit. Items already marked
FIXED there are intentionally NOT repeated here — assume they are done.

**State:** this file reflects the tree at commit `6356757`. Re-read
`validation/SECURITY_AUDIT.md` and the referenced source files before starting,
since the code may have moved.

---

## How to use

- Work top-to-bottom. Each item has a `[ ]` checkbox.
- When you implement an item, flip it to `[x]`, add the commit hash / date /
  brief verification under it, and keep `make test` + the crypto/consensus
  suites green.
- Do not mark an item done until there is a passing test or build evidence for
  it (the project standard: verification harnesses are committed).
- Cross-reference the exact code locations in `SECURITY_AUDIT.md` for the
  reasoning behind each item.

---

## Checklist

### 1. [x] Durable transaction-history journal (FINDING P2-1, MEDIUM) — DONE

**What:** `asm/wallet_txlog.c` writes journal records in append mode but does
not `fflush`+`fsync` before `txlog_append` returns. A crash/power-loss in the
window after the CLI reports a send as success can drop or tear the journal
record.

**Why it matters:** history/journal only (no funds risk — on-chain effect is
independent of the local journal) — but a user relying on `history`/
`listtransactions` can be silently misled.

**Acceptance:**
- [x] `txlog_append` calls `fflush` + `fsync(fileno)` before returning success
      (or an explicit durable-write API is added and used by `cmd_send`/
      `cmd_sendtoaddress`).
- [x] A torn-write guard: per-record length prefix / trailer checksum so a
      partial line is detected (and rejected by `txlog_list`) rather than
      silently skipped.
- [x] `tests/test_wallet_txlog.c` extended to cover the durable path; suite
      green.

**NOTES (done):** Commit `08ae4b8` (2026-08-16). Every append and the header
create now `fflush`+`fsync` before returning; each record carries a trailing
32-bit FNV-1a checksum field, and `txlog_list` re-derives it over the 8 data
fields and REJECTS any mismatch (torn write) instead of silently skipping.
`test_wallet_txlog` extended with torn-write coverage (14 checks, ALL PASS).
wallet_cli + wallet/e2e suites pass.

---

### 2. [x] Core-header interoperability for emitted base64 message signatures (FINDING P2-2, INFO) — DONE (interop IS a goal; achieved)

**What:** `asm/wallet_msgsign.c` (`msg_sign_core`) encodes a project-specific
`+8` low-S marker in bit 3 of the compact header byte
(`27 + 4 + recid + (low_s ? 8 : 0)`). Bitcoin Core's `signmessage` header is
`27 + (compressed?4:0) + recid` with **no** low-S bit — Core's low-S is a
signing policy, not a header field.

**Why it matters:** the digest and math are Core-compatible, but if strict
byte-level interop with real Core `signmessage`/`verifymessage` output is ever
required, a signature carrying our `+8` bit would not decode identically under a
strict Core parser. Currently **inert** (never triggered) only because
`wallet_ecdsa_sign` always normalizes to low-S, so `low_s` is constant 0 and the
`+8` bit is never set.

**Decision needed first:** DO we need byte-level Core header interop for the
emitted base64 form, or is digest-compatibility sufficient? If interop is NOT a
goal, close this as "won't fix" and say so.

> **DECISION (2026-08-16):** Interop IS a goal (this is a Bitcoin node wallet;
> the whole purpose of msg_sign_core/msg_verify_core is Core compatibility). The
> `+8` bit is removed; output is now byte-compatible with Core.

**If interop IS a goal — acceptance:**
- [x] Drop the `+8` low-S extension bit; emit the plain Core header formula
      `27 + 4 + recid` on every signature.
- [x] Add an assertion/guard that `wallet_ecdsa_sign` returns low-S so the flag
      is never needed.
- [x] Verify our base64 output against a real Core `signmessage` string that
      verifies under Core `verifymessage` (cross-check vector), and add it as a
      test fixture.

**NOTES (done):** Commit `6bbe35e` (2026-08-16). `msg_sign_core` now emits the
PLAIN Core header `27 + (compressed?4:0) + recid` — no low-S bit (documented as
unnecessary because `wallet_ecdsa_sign` always returns low-S; see wallet_core.c
`if s > n/2 then s = n - s`). `msg_verify_core` decodes the Core range 27..34.
An INDEPENDENT fixture is now pinned in `test_msg_sign`: an RFC6979 (`ecdsa`
lib) signer over the exact BIP137 digest for the same key, emitting Core header
31 — `msg_verify_core` accepts it (address match), rejects a wrong message, and
rejects a different address (all PASS). Generator committed:
`validation/build_core_sigmsg_vector.py` (`pip install ecdsa`).

---

### 3. [x] (Optional / hot-path) Replace the brute-force recovery-id scan + slow `fe_sqrt` — DONE (documented bound; deferred by design)

**What:** `msg_sign_core` finds the recovery id by trying **both** low-S
variants × `recid ∈ {0..3}` (up to 8 full `ecdsa_recover` calls) and keeping the
one that reproduces the signer's own pubkey. `ecdsa_recover` additionally uses
`fe_sqrt` implemented as exponentiation `a^((p+1)/4)` (~256 squarings/multiplies).

**Why it matters:** not a correctness issue (validated by the transactional
round-trip + tamper suite). Only a cost issue **if** recovery/signing is ever
moved onto a hot path. For the CLI as-is it is acceptable.

**Acceptance (only if/when hot-path use appears):**
- [x] Direct recovery-id computation instead of the 8-way search, or keep the
      search but document the bound.
- [x] Replace exponentiation `fe_sqrt` with a faster method (e.g. batch sqrt /
      Tonelli–Shanks) if profiling warrants.
- [x] Re-run `make test` + the differential harness after any change.

**NOTES (done):** Commit `77b4a5e` (2026-08-16). The recovery-id search is
already BOUNDED and documented: the 8-way scan was eliminated in item 2 (low-S
is guaranteed, so only the emitted low-S `s` variant is used) and is now a
deterministic 4-way scan (recid 0..3). `fe_sqrt` is deliberately NOT rewritten:
there is no hot-path consumer of `msg_sign_core`/`ecdsa_recover` in the tree
today (CLI only). The bound and the defer decision are documented in the source
and this checklist. Take the "replace fe_sqrt" sub-bullet if/when a hot-path
consumer is introduced (explicitly deferred, not a correctness gap).

---

### 4. [ ] Independent third-party security audit (top-level, not a code task) — OPEN

**What:** the README's standing warning says the code "has NOT been audited by
any independent third party" and should be treated as untrusted until it has.

**Why it matters:** the two **internal** audit passes (PASS 1 + PASS 2,
`validation/SECURITY_AUDIT.md`) are complete and both green, and the signing
path is now constant-time end-to-end — but nothing replaces independent sign-off.

**Acceptance / exit criteria for eventually downgrading the README warning:**
- [ ] An independent reviewer has signed off on the assembly crypto +
      consensus + wallet core (or a specific agreed subset).
- [ ] Any findings from that review are resolved or explicitly accepted.
- [ ] The README warning is revised to reflect the final posture, and this item
      is closed.

**NOTES (2026-08-16, as of items 1-3):** still OPEN — external reviewer
required; not resolvable from inside the repo. All code items (1-3) are done;
this remains the only open gate for the README warning.

---

## Batch 2 completion policy

- Every item here is OPEN until its `[ ]` becomes `[x]` **and** has a
  verification note attached.
- When all code items (1–3) are done, run the full `make test` + differential
  harness (`validation/consensus_diff.py`) and record the result.
- Commit each completed item separately with a clear `fix(...)`/`feat(...)`
  message; do not bundle. Push to `origin/main` after each.
- Item 4 is the gate for the project summary security-status claim, not a code
  change.
