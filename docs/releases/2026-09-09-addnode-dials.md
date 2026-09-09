# 2026-09-09 — `addnode` dials; the control channel waits for a whole worker rotation

Found while trying to make production dial the Core oracle to read why remote peers hang up on our outbound legs: `addnode 127.0.0.1:8333 onetry` answered "the download worker did not answer the control request" twice, and when it would have answered, nothing would have dialed. The runtime addnode list (RPC `add`) was stored and never read; `onetry` set result 1 and did nothing. Both had answered "done" since the RPC was written.

- **A dial queue behind `addnode`** (`daemon/ctl_dial.c`): `add` queues a persistent entry that is dialed on the worker's next rotation and re-dialed with backoff (60 s doubling to 10 min) whenever its leg drops, for as long as it is listed; `onetry` is dialed exactly once; `remove` stops the retries; a host that is already a leg is not dialed twice; 32 entries. The worker's manual dial pass runs every rotation beside the top-up, whether or not the node wants more outbound (Core's manual peers are extra to the target). The leg is logged `[manual: addnode]`.
- **The control wait** was 3 s, shorter than one worker rotation (a 2.5 s poll plus the per-leg TCP_INFO pass), so a healthy worker "did not answer" a mutation. 10 s now.
- The coinstats history status file was written through the log-stamping `fprintf` and carried a timestamp into the RPC's refusal text; `fputs` now.

`test_ctl_dial`: onetry once; add dialed, backoff 60 then 120 s on failure, reset on connect, re-queued on a reported drop, remove stops it; the queue is bounded. The worker side is verified live: the manual leg on production against the oracle (next deploy). Gate `make -j8 test`: MAKE_EXIT 0, 0 failures (the expected test_rpc_signer segfault); audits exit 0. `getaddednodeinfo` still lists the config entries only (the runtime queue lives in the worker).

---

PR #127 (`batch/2026-09-09-addnode-dials`), merged 00:14Z as `1dac38ae`; tag `addnode-dials-2026-09-09`. Staged as `deploy-20260909a` and carried forward in snapshots b..e; the production restart is pending.
