# 2026-09-06 — UTXO / MuHash / compact-block modules: seven branches landed

The benchmark gap against Core (3 h on a full sync, `UTXO_INLINE_BUILD_PERF_SCOPE.md`)
decomposed into a set of independent levers; six were scoped as their own asm or
C modules and worked in parallel worktrees, each gated alone, then landed as one
merge. The MuHash fold — ~1.66 µs per coin on the bulk connect path, ~3 h over a
sync — is off that path entirely; the multiply under it is 3.3× faster where the
CPU has AVX-512 IFMA.

| module | landed | measured (one pinned core) |
|---|---|---|
| `bitcoin_muhash.asm` | BMI2/ADX and AVX-512 IFMA bodies for `num3072_mul` behind a leaf-7 dispatch; generic body is the fallback; each body diffed limb for limb against it | multiply 944 → 603 → 301 ns; per element 1640 → 1005 ns |
| `daemon/coinstats_index.c` | bulk catch-up folds nothing per coin; the index seeds once from a walk at caught-up. Steady state folds in a forked worker fed by a shared ring; `gettxoutsetinfo` waits on the fold watermark; a lapped ring invalidates the index rather than publish a wrong digest | the ~3 h fold leaves the connect path |
| `bitcoin_utxo_lsm.asm` | radix sort for the flush's descriptor sort; the run is byte-identical to the merge sort's (gated diff) | 541 → 91 ms at N=4M |
| `bitcoin_utxo.asm` | measured first: one probe is 1–2 DRAM misses, not a sequence; `utxo_prefetch` now warms the six lines a probe walks and nothing else changed | — |
| tiered compaction | measured on a growing set; `UTXO_CACHE_MODEL_SCOPE.md` §4.2 was stale (79d4c9c had already done it) and now says so; the ratio-4 behaviour is pinned by a test | — |
| `bitcoin_mempool.asm` | slot carries the wtxid (48 → 80 bytes); reconstruction no longer sha256d's the pool per compact block | — |
| `daemon/cmpct_recv.c` | short-id table generation-stamped and pool-sized — no 64 MiB memset per block; key derivation hoisted out of the loop | 10.03 → 1.45 ms per block |

Still open from the same scope: the download/connect interleave (the 4.5 h
of UTXO catch-up that runs after the 19.5 h download instead of under it) is
on its own branch; the ChaCha20 keystream is now the larger half of a MuHash
element and is the next lever there.
