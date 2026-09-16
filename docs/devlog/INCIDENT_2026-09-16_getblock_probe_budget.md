# Incident 2026-09-16 — getblock refused every block above height 10,880 for the whole of IBD (probe budget in a caller-saved register)

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

## Root cause

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

## Follow-ups

- [ ] Audit for the same shape: any other loop counter held across a call in the
      asm tree.
- [ ] `getblock`'s failure mode was indistinguishable from "the block is really
      not here". A lookup that exhausts its probe budget on a table it believes
      is full is a different condition from a miss, and could say so.
