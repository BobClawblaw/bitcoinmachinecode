# 2026-09-08 — gettxoutsetinfo at any height the coinstats index covers

Core's coinstatsindex persists a row per block, so `gettxoutsetinfo
<hash_type> <hash_or_height>` answers at any height. This node's index
kept one record, the running state at the applied tip, and refused a
height with Core's text. Now the fold process writes one 1 KB row per
applied block to `coinstats_hist.dat` (`daemon/coinstats_hist_fmt.h`): the
set's counters, both MuHash accumulators (the digest at that height is one
finalize away), and the cumulative per-block amounts Core's index keeps.

The RPC answers Core's shape: height, bestblock, txouts, bogosize, muhash
when asked, total_amount, total_unspendable_amount, and block_info with
prevout_spent, coinbase, new_outputs_ex_coinbase, unspendable and the four
unspendable categories. block_info is the difference between two
consecutive rows, as in Core; unclaimed_rewards is subsidy + prevout_spent
- new_outputs_ex_coinbase - coinbase - genesis - bip30 - scripts, Core's
formula per block; total_unspendable_amount is sum(subsidy 0..h) -
total_amount, an identity of Core's accounting verified on the oracle at
800,000 and 966,000. A height or a hash is accepted; hash_serialized_3 with
a block, use_index=false with a block, a negative height and one past the
tip get Core's texts.

Rows exist from the height the index was seeded at (a boot without a
valid persisted state seeds from a walk of the set); a query below that
is refused by name with the covered range. The history build that fills
rows from genesis is the next batch; until it lands `getindexinfo` keeps
reporting the index as it did, so mempool.space does not ask for heights
it cannot get.

## The differential

`validation/coinstats_regtest_diff.sh`: a regtest Core with
`-coinstatsindex=1` and this node with `coinstatsindex=1`, this node
connected first so its index folds every mined block live; then
`gettxoutsetinfo` at every height 1..116 in both hash types, json compared
as ordered documents: 235 checks, 0 failures.

Two things it found on the way. The index committed once per applied
batch, so a catch-up of 110 blocks wrote one row; a row is now written per
applied block (a new ring marker), the durability commit unchanged. And
the compact-block receive path had never completed a reconstruction that
needed a `getblocktxn` round trip -- a single-leg regtest node stalled at
the first such block; production's own counter read 14 needed, 0
reconstructed, 0 fallen back, its tip advancing through other legs' full
blocks. `bmc.cmpctrecv=0` (new, default 1) makes outbound legs request
full blocks; the registers now say OPEN; the defect is its own batch.

Also corrected: three documents said blockfilterindex and coinstatsindex
are on by default; both are opt-in, as in Core, since 2026-09-06.

Tests: `test_coinstats_hist` (17 checks), `test_node_config` +2. Tag
`coinstats-hist-2026-09-08`.
