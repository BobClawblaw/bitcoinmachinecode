# 2026-09-05 — every audit finding is closed, accepted or deferred with reasons

The state of the record after this day's work, re-derived by ID rather than
from narrative (`comm` over the finding lists and `git log`):

| Audit | Findings | State |
|---|---|---|
| `CODEBASE_AUDIT_2026-09-03.md` | 182 | **zero unaccounted.** No CRITICAL, HIGH or MEDIUM open; NET-10, the last MEDIUM, closed today |
| `INTERP_REVIEW_2026-09-05.md` | 17 | 14 closed with a test watched to fail first; IR-11 tracked in `ABI_STACK_ALIGNMENT.md`, IR-15 accepted, IR-16 deferred — each with its reasoning in §7 |
| `SECURITY_AUDIT_2026-08-29.md`, `AUDIT_RESPONSE_2026-08-30(_ADDENDUM).md`, `SECURITY_AUDIT_2026-09-02.md` | — | superseded: re-verified by the 09-03 audit §3, which folded anything still open into its own numbered findings |

Two things are **not** closed, and neither is a defect:

- **Hand-written consensus assembly** (08-30 Finding 3) is a standing property
  of the codebase, answered continuously by the C↔asm differentials and the
  gate, not by a patch.
- **`LimitCORE`/systemd hardening** — **closed by operator decision, 2026-09-05: the
  unit is a local deployment concern and is deliberately not vendored into this
  repository.** Do not re-raise it as a project gap. Verified on the host the
  same day
  during the deploy-a rollout: `systemctl show` gives `LimitCORE=0`,
  `NoNewPrivileges=yes`, `ProtectSystem=full`, `ProtectHome=read-only`,
  `PrivateTmp=yes` (the base unit's `LimitCORE=infinity` is overridden by the
  `50-hardening.conf` drop-in), and the running process shows
  `Max core file size 0`. The 09-03 audit's closure was correct. The unit lives
  only in `/etc/systemd/system/` and its four drop-ins, by choice.

Milestone tags: `audit-2026-09-03-all-closed`,
`interp-review-2026-09-05-complete`.
