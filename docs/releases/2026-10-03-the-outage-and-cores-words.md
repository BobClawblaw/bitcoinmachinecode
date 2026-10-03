# 2026-10-03 — The outage, and Core's words

Production was down for 23 hours, from 2026-10-02 04:28Z to 2026-10-03
13:16Z. The fix for that is the first item below. Fixing it turned up four
more defects, each measured against Bitcoin Core v31.1 and closed on the same
day. The last batches make the node's rejection messages Core's, byte for
byte. Production runs `deploy-20261003g` (main `230074a4`).

## The crash (#373)

`deploy-20261002a` applied its first block correctly. It then segfaulted
three minutes later, and again about 40 s after every restart, once
mempool.space re-synced through the Esplora facade.

The facade's batch route, `POST /internal/mempool/txs` from #368, looked up
confirmed parents in the txid index without the RPC execution lock.
`irs_refresh` rewrites the index's run table in place: it zeroes each kept
run's mapping while the run's counts stay set. A lookup racing it read
through a NULL map.

All eleven crashes faulted at the same address, `0x6a61e3bd8`. That address
is exactly the run's sparse-index offset (48 + 1,425,612,630 × 20) plus the
first binary-search probe (16 × 2,784,399): a NULL base plus a data-derived
offset. The address named the bug before any debugger was attached.

The fix puts the lookup under the lock. `gettxspendingprevout` had the same
race since 09-30, in the lock-free mempool lane, and left that lane.

## Found while proving the fixes (#374)

A new end-to-end test, `validation/wtxid_relay_regtest_e2e.sh`, puts the node
between two v31.1 nodes: Core A ← bmc ← Core B, where B reaches the network
only through bmc. Its first runs failed for reasons nobody had looked for:

- **Inbound peers never saw a block past the node's boot height.** The serve
  process's store tip was read at boot and never moved. `getheaders`,
  `getblocks` and the new-block tip-watch were all capped by it. Production's
  serve process reported `tip=969479` at shutdown, nine hours and 49 blocks
  later. It now follows `index.dat` as it grows.
- **A v2 message that arrived with an earlier one waited for the peer's next
  packet.** That was up to two minutes for a ping. One `recv()` can carry
  several messages, and the serve loop polled the socket rather than the
  decrypted buffer.
- **wtxid relay:** the node sends `wtxidrelay` again and announces by
  `MSG_WTX` to a peer that negotiated it. Core drops `MSG_TX` announcements
  from such a peer, which is why it had been withheld since 10-01. Both
  getdata servers now answer `MSG_WTX`. Every production leg negotiates it.

## Core's words (#375, #377, #378)

`sendrawtransaction`, `testmempoolaccept` and `submitpackage` now give Core's
exact text:

- the reason plus Core's debug message (`min relay fee not met, 0 < 11`;
  `insufficient fee, rejecting replacement <txid>, less fees than conflicting
  txs; 0.00005 < 0.0001`; the TRUC, dust, belowout and premature-coinbase
  messages);
- script failures as `mempool-script-verify-flag-failed (<ScriptErrorString>),
  input N of <txid> (wtxid <w>), spending <p>:<n>`;
- Core's decode-failure messages;
- Core's stage order on the RPC paths: inputs, then fees/RBF/TRUC, then
  scripts. A transaction failing two stages is now named by the stage Core
  names.

`validation/reject_details_core_diff.sh` submits each case to both nodes:
26/26 byte-identical.

## Seeing the next crash (#376)

The unit keeps `LimitCORE=0`, deliberately: the process holds the decrypted
wallet seed, and a core file is that seed on disk. A fatal signal now writes
the crashing thread's stack to the log instead: the fault address, the
registers, a backtrace, and the stack's text-segment words only. Resolve them
with `addr2line`. On 10-02 the whole record was eleven kernel lines.

Also in #376: chainwork lookups past the end of `chainwork.dat` read only the
missing headers, not the chain from genesis. `getmininginfo` logs its
per-step timings when a call takes over a second. The 149.5 s RPC freeze seen
after one restart into catch-up is still unexplained; the timings will name
the step.

## Also

- `test_dlc_interleave`'s gate-lag bound is now relative to its control. It
  had failed a correct build under `-j8`.
- `docs/OPERATIONS.md` now spells out how to verify a deploy: a new block
  applied with the oracle's hash, then NRestarts=0 ten minutes in. It also has
  troubleshooting rows for a crash loop, `[crash]` lines and a slow
  `getmininginfo`.
