# 2026-09-06 — a fresh mainnet archive was shifted by one block, for life

The archive index is addressed by height: slot `h` holds block `h`, so slot 0
holds genesis, and `store_read_at`, the locator build, catch-up, the
script-flag heights and the UTXO walk's skip-genesis-coinbase rule all rest
on it.

Boot seeded genesis on every chain **except mainnet**, because this machine's
mainnet archive already had genesis from a one-time injection. That was true
of that archive and of no other. On a fresh mainnet datadir the first block
stored decides slot 0: the parallel downloader starts its span at tip+1 = 0
and writes genesis itself — which is why every earlier benchmark, run with
the boot catch-up on, was fine — while the serial leg appends the first block
a *peer* sends, and no peer relays genesis. Block 1 landed in slot 0, reading
height `h` returned block `h+1`, and block `h+1`'s coins were filed under
height `h`.

It surfaced as a **false consensus rejection**: applying a height found its
own coinbase already unspent and refused a valid mainnet block with
`bad-txns-BIP30`. The oracle confirms those blocks are ordinary and their
coinbase outputs are unique and unspent to this day. The same day's
reject-not-halt change then marked the block failed, persisted the mark and
stopped all sixteen download helpers, so the datadir could never sync past
it — a worse outcome than the halt it replaced, on an input that was never
invalid.

Seeding is now keyed only on the archive being empty, in `daemon/archive_seed.c`
so a test can call it. Existing archives are untouched. `test_archive_seed`
was watched to fail first (7 of 9 checks) with the old condition restored,
and a real fresh mainnet sync on the fixed binary seeds genesis, maps slots
100/500/1000 to heights 100/500/1000, and rejects nothing.

**What this says about the test suite.** Nothing in the gate ever created a
fresh *mainnet* datadir; the sync tests use a fake peer on a non-mainnet
chain, which took the seeding branch that worked. The bug needed a real
fresh sync to appear, and that is now what the benchmark does.
