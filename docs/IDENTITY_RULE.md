# Commit identity rule (hard, enforced)

Every commit pushed to any repository under this workstream — bitcoinmachinecode, the
benchmark repo, and any future branch — MUST be authored and committed as:

    BobClawblaw <BobClawblaw@users.noreply.github.com>

The following name fragments and any address containing them MUST NEVER appear
in any pushed commit's author, committer, message body, trailers, or diffs
(matched case-insensitively; the gate encodes them from character codes so
this file, the gate, and the test stay free of the literals they forbid):

  - a four-letter given-name fragment used as the service account/user name
  - a six-letter surname fragment
  - a nine-letter given-name variant
  - the three-letter mail-provider fragment

Enforcement (all three, every push):
1. git config user.name/user.email set globally and per-repo to the canonical identity.
2. Every push script commits via `git -c user.name=BobClawblaw -c user.email=...`.
3. A pre-push identity gate (scripts/identity_gate.sh) scans the range being pushed
   for author/committer identity, message-body leaks, and tracked-content leaks;
   on any match the push aborts. Regression-proven by scripts/test_identity_gate.sh.

Historical note: history was rewritten once (2026-09-04) to move the developer
identity to the GitHub noreply address and scrub personal references from file
contents; this rule is what keeps it that way.
