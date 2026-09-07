# 2026-09-07 — assumevalid resolves on the header chain

A perf profile of run 16's connect process at height 565,000 put about
70 percent of its CPU in ECDSA: `fe_mul`, `fe_sqr`, `point_double` and
`sc_inv` under `ecdsa_verify` and `sv_checksig`. The connect's own
breakdown agreed, verify at 35 to 43 percent of 31 ms per block. Mainnet's
assumed-valid block is 938,343, and Core skips script evaluation for every
block beneath it. This node's resolver looked the block up in `index.dat`,
that is among stored blocks, and in a headers-first sync the assumed-valid
block is one of the last stored, so the switch never turned off. Every
signature since genesis was being verified, for nothing.

The resolver now reads `headers.dat`, which is Core's rule: a block is
assumed valid when the assumed-valid block is its descendant on the
header chain, and that chain's work clears the minimum, which the header
phase's low-work hold already guarantees for anything in the mirror. The
index stays as a fallback for a datadir without a header mirror, and
while unresolved the lookup repeats every 1,000 blocks, because on a
fresh sync the headers arrive after the connect initialises.

`test_utxo_catchup_bounded` gains four checks and was watched to fail on
the index-only resolver with two failures.

## What else the profile said

- The box is nowhere near saturated: 6.4 of 32 cores busy, the 2.5 Gbit
  link at 4 percent, the sixteen download workers at 3 percent CPU
  combined. The download is bound by sixteen peers' individual rates,
  median about 600 KB/s.
- With this fix the connect drops to roughly 20 ms per block, about 50
  blocks per second, against a download of 17 per second on this stretch.
- The bench SSD writes about what the network delivers over an hour
  (amplification 1.0), with bursts during compaction.
- The obvious next lever is the worker count. `bmc.catchupworkers` is
  this node's own key, default 16; the pool held 114 live peers. That is
  an experiment for a run, not a code change.
