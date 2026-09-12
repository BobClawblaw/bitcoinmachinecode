# 2026-09-10 — The reorg probe runs before the pass, on an idle leg; no pass runs inline

Follow-up to the helper pass (#169-#171). Snapshot aa held three of nine legs: freshly installed legs, v1 and v2 alike, closed as "EOF on the first read" within seconds of their first pass, and four dial helpers were exhausted re-dialing them.

- **The reorg probe ran on a busy leg.** The rotation's fork probe was keyed on "the pass returned nothing" (`n<=0`), and since #169 the pass always returns nothing to the parent (the child reports later). So every rotation that started a pass helper also ran the parent's probe on the very socket the child was reading: two readers interleaving frames, the probe failing and tearing the leg down. Reproduced on regtest against a Core node with `-debug=net`: the leg died every 30-70 s, Core logged `Connection reset by peer` each time, and strace showed the probe's 60 s alarm armed in the parent within a millisecond of the child's fork. The probe now runs before the pass start, on an idle leg whose last report was empty (`g_pass_last_empty`).
- **No inline pass.** Four passes at once left the fifth of nine legs running inline and blocking the loop; one pass per leg now, and when no helper can start the leg waits for the next rotation.
- **Eight dial helpers** (was four): nine churning legs saturated four ("no dial helper free" every rotation).
- **One overlap line per block.** A pass child compared the compact-block counters against a static that held the parent's snapshot at fork, so every child reprinted the previous block's `[cmpct]` overlap line; the comparison is now against the counters at the pass's entry.

Verified: `validation/legchurn_regtest_e2e.sh` (new) holds one leg to a Core regtest node for 150-180 s through eight mined blocks with zero resets in Core's log and zero closes in ours; on the unfixed binary the same script showed four resets in 150 s. `test_dialhelper` covers DH_MAX 8.
