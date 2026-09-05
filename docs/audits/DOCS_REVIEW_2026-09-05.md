# Documentation consistency review — 2026-09-05

**Source:** `/code-review` run by the operator against the merge of PR #11
(`327b1c0`), an 11-line prose change to
`docs/releases/2026-09-05-audits-closed.md` recording the systemd unit as
"closed by operator decision". Ten verifiers: **7 CONFIRMED, 3 REFUTED**.
The branch was even with `origin/main` and the tree clean, so the review
target was `git diff HEAD~1`.

**Status: 7 of 7 closed** in `667cb72` (PR #12), same day.

**Root cause, one sentence:** a decision was recorded in one document while
five others that state the same item's status were left saying the opposite.
This is the failure mode `audit-remediation-track-closure-by-id` exists to
prevent, and it happened in the same session that wrote that rule.

---

## Findings

Severity is by consequence to a reader who trusts the document, not by size
of edit.

### DR-1 (HIGH) — `docs/OPERATIONS.md:264` — the reference unit publishes an unhardened service

The copy-pasteable "Reference unit" for `bmc-bitcoind.service` ended with
`LimitCORE=infinity`, carried none of `NoNewPrivileges` / `ProtectSystem` /
`ProtectHome` / `PrivateTmp`, and its drop-in paragraph named only
`TimeoutStopSec=900` and `SupplementaryGroups=debian-tor`, never
`50-hardening.conf`.

**Failure scenario:** an operator standing up a second node follows "Running
as a service", pastes the block, runs the `systemctl enable --now` snippet,
and deploys a daemon holding the decrypted seed (`g_wallet_seed`,
`asm/daemon/main.c`) with unlimited core dumps and no sandbox — exactly
08-29 #11 / 09-02 N5 — while the release note tells the next reviewer not to
raise it.

**Closed:** the reference block carries `LimitCORE=0`, `NoNewPrivileges=yes`,
`ProtectSystem=full`, `ProtectHome=read-only`, `PrivateTmp=yes` inline with
the reason; the drop-in paragraph names `50-hardening.conf` and states that
the deployment's own unit is a local artifact by operator decision.

### DR-2 (MEDIUM) — `docs/releases/2026-09-05-audits-closed.md:12` — the lead-in miscounts its own list

"Two things are **not** closed, and neither is a defect:" introduced a bullet
opening "**closed by operator decision**". The item was also the only entry
not keyed to a finding ID in a note whose stated method is re-derivation by
ID.

**Closed:** lead-in now reads one item not closed, one closed by decision;
the systemd bullet is keyed `08-29 #11 / 09-02 N5 / 09-03 §3`.

### DR-3 (MEDIUM) — `docs/audits/AUDIT_RESPONSE_2026-08-30_ADDENDUM.md:238` — a live open-items list contradicts the closure

The addendum's "Open items after this addendum" list is live-maintained (items
1 and 4 had been edited the same day), and item 3 still read "Systemd
hardening — declined by the operator. `LimitCORE=0` remains worth
revisiting", contradicting both the decision and the verified `LimitCORE=0`.
The addendum has no supersession banner, so it reads as current.

**Closed:** item 3 struck through and replaced with applied / verified /
closed by decision, with the host evidence; item 1's cross-reference to it
corrected.

### DR-4 (MEDIUM) — `docs/audits/SECURITY_AUDIT_2026-09-02.md:17` and `AUDIT_RESPONSE_2026-08-30.md:17` — the supersession banners still say "cannot be verified from the tree"

Both banners (added in `1463718`, duplicated verbatim) named the systemd item
as one of two carry-overs "worth naming explicitly" and told the next auditor
to "treat it as an operator attestation, not a code fact" — the framing the
reviewed diff had just deleted — with no pointer to the decision.

**Closed:** both banners now state verified on the host 2026-09-05, unit
deliberately local by operator decision, closed, with a pointer to the
release note.

### DR-5 (LOW) — `docs/devlog/DEPLOYMENT_HISTORY.md:982` — the deploy-a entry calls the closed item "the real residual"

The same-day deploy-a entry cites the release note by name and concludes
"The unit remaining outside version control is the real residual
observation" — the residual the reviewed diff declared closed. Two documents
dated the same day, citing each other, disagreed.

**Closed:** the line now says the residual was noted and, later the same day,
resolved by operator decision; an earlier sentence in the same entry reworded
to past-tense narration so it does not read as a live claim.

### DR-6 (LOW) — `docs/README.md:64` — the index advertises two open items

The docs index summarised the release note as "the two items that are
deliberately not closed" when only one remained.

**Closed:** index line corrected.

### DR-7 (LOW) — `docs/FEATURE_GAPS.md:2252` — the accepted-risks register has no entry

An accepted-risk / won't-fix decision was recorded only inside a dated release
note, while the repository's canonical register for exactly this class
("Accepted risks, closed": CRY-8, SCR-11, BLD-6, BLD-10) had no entry. The
next audit re-derives open items from the audit files and this register, never
from dated release notes, so the "do not re-raise" directive had no reach.

**Closed:** register entry added, keyed `08-29 #11 / 09-02 N5`, ending "Do
not re-file."

---

## Refuted (3)

Recorded so the next reader does not re-verify them.

- **"Four drop-ins" inventory claim** — the reviewer questioned whether the
  deployment has four drop-ins. It does (`20-stop-timeout.conf`,
  `30-tor-control.conf`, `40-cjdns.conf`, `50-hardening.conf`, from
  `systemctl status`); the text was accurate.
- **Orphan-line formatting** — a suspected dangling line in the release note
  was a wrapped sentence, not a stray.
- **In-bullet restatement** — a suspected duplicate statement inside one
  bullet was the same fact stated once at the decision and once at the
  evidence; not a defect.

---

## Verification

```
grep -rnE 'cannot be verified from the tree|operator attestation that could|remains worth revisiting' docs/
```
returns nothing on `667cb72`. `grep -c 'LimitCORE=infinity' docs/OPERATIONS.md`
is 0.

## What to take from it

The fix that mattered was DR-1, and it was not a consistency nit: a document
that people copy from was actively wrong about a security setting. The
lesson is the one already in memory — when a status changes, re-derive every
document that states that status, by grep, before declaring it changed — and
the additional point that a "do not re-raise" directive is only as strong as
the register the next audit actually reads.
