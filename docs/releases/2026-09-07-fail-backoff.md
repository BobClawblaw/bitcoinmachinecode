# 2026-09-07 — A failed fetch halves the peer's standing and backs off; the help chunk sits on the claim grid

Run 14 stalled for two minutes at 82,565: every worker reconnected to the same peer, one that accepted the handshake and dropped us ~100 ms later, because a failed fetch never lowered the peer's shared rate and the picker handed it straight back. 12 reconnects a second across the pool; 4,274 failed attempts in nine minutes.

- a failed fetch **halves the peer's shared rate** (a never-measured one becomes 1.0, tried);
- the worker **pauses 200 ms x attempts, capped at 2 s**, before the next attempt on that chunk (400 attempts take ~13 min, not 45 s);
- the **help chunk is computed on the claim grid** (`start + k*40`; the pass starts at 1 with genesis seeded, so the old multiples-of-40 help straddled two owners' chunks).

Six checks in `test_dialhelper`. Scratch proof: failed attempts 0-1 per tick, 0 abandons. Full gate 13,316 lines, 0 failures; 8 audits exit 0.

---

PR #81 (`batch/2026-09-07-fail-backoff`), merged 17:03Z as `6a65e0bc`; tag `fail-backoff-2026-09-07`.
