# Incident 2026-09-16 — getblock refused every block above a fixed height for the whole of IBD (two causes: a probe budget in a caller-saved register, and a fold that marked unwritten records as folded)

**Severity:** medium (no data loss, no corruption, production unaffected; every
syncing node's `getblock` unusable above a fixed height, which blocks BlockYard's
block rendering and anything else that resolves a block by hash during a sync).
**Detected:** 14:47 UTC, by `npm run check` from BlockYard against the freshly
launched run 24 bench node:

```
✗ getblock 3     getblock <tip> 3: Block not found -- the address index
                 follower cannot run
```

**Latent since:** unknown. The defect is in `asm/bitcoin_idx.asm`, which is old
code; it has been reachable on every node that opened its store mid-sync. It had
never been observed because production opens on a complete chain.

## Timeline (UTC)

| time | event |
|---|---|
| 14:42 | run 24 launched on `/mnt/2tbssd/bmc-run24`, build `0d5f4044`, full index set, `addrindex=1` from genesis. |
| 14:47 | BlockYard's `check.js` reports `getblock <tip> 3: Block not found`. Everything else about the node checks out, including the capability handshake. |
| 14:48 | Reproduced by hand at every verbosity (1, 2, 3), so not a verbosity-3 gap. `getblockhash` works at every height and agrees with `getbestblockhash`; only the hash→height lookup fails. |
| 14:49 | The same build **in production** serves the very hash the bench node rejects, at verbosity 1 and 3 → the code is fine, the state is not. |
| 14:50 | Bisected the boundary: heights 0…10,880 served, 10,881 and up refused. |
| 14:52 | Re-measured: cut unchanged while the tip advanced 159,440 → 193,360. Not lag. 16 sampled heights above the cut all fail → a clean prefix, not the out-of-order holes IBD would produce. |
| 15:05 | First hypothesis (`idx_sync` advancing `g_idx_tip` past unfolded heights) written up as a test. It **passes** — both in-process and cross-process. Hypothesis dead. |
| 15:28 | Instrumented `idx_sync`: it enters with `tip=67279, g_idx_tip=2720` and never returns from `idx_load_range`. Per-chunk tracing puts the hang inside `idx_put`, on the final chunk, with the table at capacity. |
| 15:35 | Read `memcmp_exact`: it writes `r8b`. `idx_put` and `idx_get` hold their probe budget in `r8` across the call to it. Root cause. |
| 15:50 | Fix written and dry-run assembled in scratch, then applied. |
| 16:05 | Deterministic pin added to `test_idx` (full-table case). Full gate: `MAKE_EXIT=0`, no failures. |
| 16:12 | run 24 stopped cleanly at height 393,520 via the `stop` RPC, binary swapped, relaunched on the same datadir. |
| 16:2x | Verified live: every height that previously failed now serves, and `getblock <tip> 3` works. Node resumed at 393,520 — no re-sync. |

> **UPDATED 2026-09-16 19:00Z.** The r8 fix below is real and stays, but it was
> not the cause of the clean prefix. Run 25's first launch, on the r8-fixed
> binary, cut at 4,240. The second cause is in `rpc_chain.c`'s fold and is
> written up in **"Root cause 2"** further down, with the trace line that found
> it and the prediction it made before the node failed.

## Root cause 1: the probe budget (real, and not the prefix)

`idx_put` and `idx_get` in `asm/bitcoin_idx.asm` held their linear-probe budget
in **r8** across `call memcmp_exact`:

```asm
    mov  r8,  [r12+8]        ; probe budget
    inc  r8
.probe:
    ...
    call memcmp_exact
    ...
.next:
    dec  r8
    jz   .full
```

and `memcmp_exact` writes `r8b` on every byte it compares:

```asm
    mov  r8b, byte [rdi+rcx]
```

`r8` is caller-saved under the SysV ABI, so this is `memcmp_exact`'s right and
the callers were wrong. On the first collision the budget's low byte is
overwritten by a byte of the stored hash, and it then counts down from a value
the data chose.

* **`idx_put`** — `dec / jz .full` may never reach zero: a full table spins
  forever instead of reporting full. It may also reach zero EARLY, reporting
  "full" on a table with room to spare.
* **`idx_get`** — `dec / jz .notfound` fires early: a key that IS in the table
  is reported absent. This is the `-5 Block not found` the operator sees.

Below capacity none of it shows, because a probe terminates on an empty slot
long before the budget matters.

## Why only a syncing node, and why a clean prefix

The by-hash table is sized from the tip **at open**:

```c
long tip = ST_TIP(g_st);
unsigned long slots = 1u << 16;
while (slots < (unsigned long)(tip + 1) * 4) slots <<= 1;
```

A node that opens its store mid-IBD sizes for the tip it had then and fills as
the sync runs past it. Production opens on a complete chain, so its table is
sized for the whole chain and never reaches the region where the budget matters.

The clean prefix — rather than scattered misses — follows from the premature
"full". `idx_sync` believes it, doubles the table and reloads from height 0, and
that reload stops at the same premature "full" because it re-inserts the same
keys in the same order. So the table ends up holding a PREFIX of the chain, and
every later refresh rebuilds exactly that prefix. Measured at 10,880 with the
node at 159,440, at 193,360, and still 10,880 at 356,682.

The doubling loop in `idx_sync` is not a bug and was not changed: it was
faithfully reacting to a lie from `idx_put`.

## Fix

The budget moves to the stack in both routines. Stack alignment at the calls is
unchanged (still ≡ 8 mod 16, as before). Landed on
`batch/2026-09-16-run24-getblock-freeze` (PR #237), commit `c0b1bf56`.

## The pin, and the thing that is NOT the pin

Every pre-existing case in `tests/test_idx.c` runs at a load factor where probes
end on an empty slot, so none of them walk the budget to exhaustion — which is
why a table-driven unit test with 5,000 inserts, heavy-collision coverage and a
clustering benchmark all passed against broken code for as long as it existed.
The new case fills a table to capacity and then asserts that `idx_put` reports
full and returns, that an absent key reports absent and returns, and that every
key that IS present is found. `SIGALRM` turns non-termination into a failure
rather than a hung suite. Against the unfixed assembly it fails; against the
fixed one it passes.

**`test_rpc_chain_growth` is not the pin.** It reproduced the hang at 70,000
blocks, which is how the bug was found — and then **passed with the fix
reverted**, because whether the corrupted budget loops forever depends on which
hash bytes land in `r8b`. It is kept as the regression guard that cross-process
archive growth never had, labelled for what it covers.

## Root cause 2: the fold marked records as folded before they existed

The downloader pre-extends `index.dat` with zero records up to the header
count, and the store's tip follows the file's extent. `idx_sync` folded
`(g_idx_tip, tip]`, skipped absent records, and set `g_idx_tip = tip`
unconditionally. The `[idx]` trace added to `rpc_chain.c` shows it in one line
from a throwaway node that opened at genesis and folded 36 seconds later:

    [idx] fold 1..967314: read=967314 present=13880 new=13880 dup=0 short=0 err=0 r=0

13,880 records existed; the fold inserted those and marked 967,314 heights as
folded. After that "tip > g_idx_tip" was never true again, so no fold ever ran
again, and every block stored later was "Block not found" by hash for the rest
of IBD. The cut is the number of records present at the first fold: 13,880
there, 4,240 on run 25's first launch, 10,880 on run 24.

The trace also predicted a failure before it happened. Run 25's second launch
logged `fold 199481..967314: present=31880`, i.e. records present to 231,360;
the node was then probed after the tip passed 232,600: 231,300 served,
231,361 and everything above refused. A pread error was handled the same way
(reported "ok", fold point advanced past what it failed to read).

**Fix (`8c2bddb6`):** `idx_load_range` reports the highest height up to which
every record was present, and `idx_sync` advances the fold point only that far.
Records above the first hole are still inserted when present but do not move
the fold point, so the hole is read again next time; the re-read is bounded by
the download window, which is what leaves holes. The trace stays.

**Pin:** `test_rpc_chain_growth` blanks a band of the writer's records BEFORE
the reader's first fold over them, folds, restores the band, and looks one up:
2 failures against the committed code, clean against the fix. An earlier draft
blanked AFTER the fold and passed against the unfixed code — the order is the
whole test, and the revert check is what caught it.

**Why the r8 fix looked sufficient for an hour:** the two defects have the same
symptom and the first one had a deterministic hang to pin, so its fix was
verified on the primitive, not on a syncing node. Run 25 was the first syncing
node to run the r8 fix, and it cut within a minute.

## Lessons

1. **A probe budget is loop state; it cannot live in a caller-saved register
   across a call.** `bitcoin_serve.asm:231` already carries a comment about
   holding a value in memory "so it survives the `idx_put` call" — the hazard
   was known in one place and not in the two that mattered.
2. **Load factor is a test parameter.** An open-addressing table behaves
   differently at capacity than at 30%, and every existing test sat below the
   threshold. "Heavy collision" coverage that still terminates on an empty slot
   does not exercise the budget.
3. **The reproduction that finds a bug is not automatically a test that catches
   it.** Reverting the fix and watching the test pass is what separated the two
   here, and it took three attempts to get an honest pin.
4. **A node's behaviour depends on what its chain looked like when it opened.**
   The whole class — anything sized from a boot-time tip — deserves a look.
5. **Fix one cause, then re-run the original symptom before calling it done.**
   Two defects shared one symptom. The unit pin for the first proved the first;
   only the live node could show there was a second.
6. **A fold point must follow what was actually read, never the target.**
   "Folded to the tip" was a claim about the file's extent, not about records.
7. **Instrument the live process when the fifth hypothesis dies.** Five
   hypotheses were argued from source and all were wrong; one trace line
   settled it, and then predicted the next failure to the block.

## Also found on the way (filed, not fixed here)

- `bitcoin.conf` reads Core's host-valued `connect=` and `addnode=` as numbers
  (`"not a usable number -- reading it as 0"`); Core takes an address. Register.
- `debug.log` carries NUL bytes, so GNU grep treats it as binary and `grep -c`
  prints nothing at all (rc=1). Read these logs with `grep -a` or `awk`. Two
  earlier log counts in this session were silently empty for this reason.

## Follow-ups

- [ ] Audit for the same shape: any other loop counter held across a call in the
      asm tree.
- [ ] `getblock`'s failure mode was indistinguishable from "the block is really
      not here". A lookup that exhausts its probe budget on a table it believes
      is full is a different condition from a miss, and could say so.
