# bmc 2026-09 benchmark defects — resolution task ledger

Task branch: fix/bmc-2026-09-bench-defects (worktree /mnt/2tbssd/wt-fixes,
from origin/main). Source of truth: the /mnt/2tbssd bmc-vs-Core benchmark
(2026-09-04/05). Status codes: TODO / IN-FLIGHT(=another session owns it) /
DONE(=on main + test). Verification standard for every fix: a pinned test
corner + the live re-run of the exact benchmark gate that caught it.

## DONE (on main, this run's fixes)
- D1 byte floor unreachable early-chain -> `7f4adcf` (merged) — 7 corners in
  test_dialhelper; gate re-measure 77KB/s -> 11.1 MB/s
- D2 inbound probe broken tool (no pong / sentinel / relay flag / reversed
  magic) -> `1596697` — verified live report vs bmc
- D3 peers.good data loss via log_ts fprintf macro + EMA peer selection ->
  `5fb5102` — section-7 corners
- D4 the RPC-2 misdiagnosis -> withdrawn (see SC1 below for the real thing)

## IN-FLIGHT (audit session owns these files)
- RPC-1 handler wall-clock deadline. Audit ID RPC-14 (commit f4b1ac5
  describes the 72s socket-timeout misread = the same family). File:
  asm/rpc_server.c. Gate: gettxoutsetinfo under writer load returns a
  timeout error instead of hanging an RPC worker. Do NOT patch from this
  branch; coordinate via main.

## TODO on this branch (my lane — disjoint files)
- TXOQ-1: gettxout "not ready, retry shortly" persists on a quiesced store.
  Evidence: 2026-09-05 04:42-04:52, after clean restart + catch-up 100%,
  gettxout answered not-ready for 10+ min while heartbeats showed txouts
  live. Root cause (sketch rpc2-offline-open-no-exit + txoq1-*): the
  parent's 60s utxo_live_reload_parent_view() re-drains a huge WAL every
  cycle -> never settles. Correct end-state per main.c's own comments
  (line ~1516): answer gettxout IN THE WORKER on its service point (it has
  the live set). Files: asm/daemon/main.c (IPC), possibly utxo_live.c.
  Test: regtest — restart mid-WAL, gettxout answers within one service
  beat after catch-up. Benchmark gate: gettxout answers on quiesced store.
- SC1: inbound child accepted during shutdown-window forks into a dying
  parent -> child store_init race -> peer gets silence, child dies once.
  Fix: refuse accepts once g_shutdown_requested set; log errno in the
  store_init failure path. Files: asm/daemon/main.c accept site + child
  bootstrap (child is compiled into main.c; the sketch's "serve_child.c"
  correction note is wrong — no such file). Test: stop-while-connecting
  loop (python) -> no child deaths in log, connections refused, not died.
- CSI-1 (NEW today): gettxoutsetinfo ignores height/blockhash params and
  returns the TIP set silently. Fix is not "implement replay-to-height" —
  it is to be honest: reject params with the existing
  "coinstatsindex does not support querying at historical heights" error
  (message already exists in utxo_setinfo_rpc.c but the params path
  bypasses it). Test: RPC call with height param -> error, not tip data.
  This is a WRONG-ANSWER bug: highest correctness priority on this list.
- CSI-2 (NEW today): coinstats.dat stores ONE record (896 bytes, tip only)
  while getindexinfo claims synced=true — Core's index stores per-height
  digests (O(1) historical queries). Minimal fix: the index DOES store the
  per-height muhash it already computes incrementally — check the file
  format comment at coinstats_index.c:88 and either write per-height entries
  or narrow getindexinfo's meaning + add a comment. Decide with the audit
  session (their FEATURE_GAPS doc has the coinstats row).

## Explicitly NOT here
- probe tool (D2 fixed), the store-open exit(1) items — those live with
  whichever session owns reload_ro snapshot semantics (RPC-3 sketch filed)

## Order of attack
CSI-1 (correctness, tiny) -> TXOQ-1 (benchmark gate) -> SC1 (small, racy
test) -> CSI-2 (design decision, needs audit session).
