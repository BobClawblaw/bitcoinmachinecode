# 2026-09-05 — NET-10 closed: the address book resists a flood

- **NET-10** (`docs/audits/NET-10_ADDRMAN_SCOPE.md`): `peers2.dat` evicted by
  the smallest `last_seen`, a value the gossiping peer chooses, so a flood
  preferentially destroyed the once-connected set the dialer draws from.
  Format v3 stores the source netgroup and a tried flag; one source netgroup
  is capped at `AB2_MAX/16` live entries, a tried entry is never evicted, and
  eviction among untried entries prefers "terrible" over merely old. A v2 file
  upgrades in place with every record kept and its head marked tried.
  The negative control reproduces the finding.

With this, **every CRITICAL, HIGH and MEDIUM finding of the 2026-09-03 audit
is closed**, and the 2026-09-05 interpreter review is fully dispositioned
(14 of 17 closed, 2 accepted or tracked, 1 deferred).
