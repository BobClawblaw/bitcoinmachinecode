# Incident 2026-10-07 — production RPC dead for 2 h 17 m: the getblock reader lane leaked three file descriptors per Esplora facade connection until accept() hit the 1,024 limit

**Severity:** high. Production's JSON-RPC and the Esplora facade answered nothing
for 2 h 17 m. The local mempool.space backend stalled at 970,365, 11 blocks behind
when the fix went live. No data loss and no consensus effect. P2P sync, block
validation, relay and the UTXO set were unaffected throughout, which is why
`systemctl is-active` and the tip looked healthy.
**Detected:** 18:22Z, by the operator ("why is production down?"). The node had
logged the cause once, at 16:26:22Z, and nothing watched for that line.
**Latent since:** `deploy-20261005a` (the RPC lanes, 6ed54746; the reader lane
itself is 3b807cc6, 2026-10-05). Every snapshot from `deploy-20261005a` through
`deploy-20261006d` carries the leak. The rate depends on how many facade
requests read a block, so the time to the limit varied from deploy to deploy.

## Timeline (UTC)

| time | event |
|---|---|
| 10-05 | The getblock reader lane lands (3b807cc6, PR #383) and is deployed in `deploy-20261005a`. It keeps a store handle and an 8 MB buffer in `__thread` storage, opened on a thread's first `getblock`. |
| 10-06 20:03 | `deploy-20261006d` (main b194dd01) starts. That is the process (pid 3144426) that ran out. |
| 10-07 16:26:22 | `[rpc] accept: out of file descriptors (Too many open files) -- backing off; the RPC listener is degraded`, printed once per process. From here accept() fails on both the RPC port and the facade. |
| 16:26 → 18:22 | The tip keeps advancing over P2P. mempool-backend, which reads the node through the facade, stops at 970,365. |
| 18:22 | Operator: "why is production down?" |
| 18:23:40 | Evidence captured (`/proc/3144426/fd`, `fdinfo`, `status`, `ss`, the log): **1,023 of 1,024** descriptors open, 12 threads. 314 handles on `index.dat`, opened RDWR at offset tip × 48, each paired with the current blk file RDWR and an older blk file RDONLY\|O_CLOEXEC. These are one triplet per thread that ever entered the lane. |
| 18:2x | Cause traced: the facade's `esp_conn_thread` (rpc_server.c) is one thread per connection (`Connection: close`). Its block routes call `getblock` in-process, so each facade block read created a lane on a thread that then exited, and nothing closed the lane. |
| 18:27:25 | Fix committed (d0527354): a pthread key whose destructor closes the lane and frees the buffer. `test_rpc_chain` pins it and was watched to FAIL on the unfixed code (14 → 206 descriptors over 64 threads). |
| 18:3x | The operator chooses "fix first, then deploy" over a restart on the leaking build. Full gate `MAKE_EXIT=0`. |
| 18:42:16 | PR #402 merged (main 54ffb790, which also carries #400). |
| 18:42:56 | `deploy-20261007a` started (built in a clean worktree at 54ffb790). |
| 18:43:46 | RPC answers again. |
| 18:51:36, 18:52:30 | New blocks 970,378 and 970,379 applied, with hashes identical to the Core v31.1 oracle's. The facade and mempool-backend were both at 970,378 by 18:52. |
| 18:52 → 18:56 | 12-minute watch: `NRestarts=0`, descriptors flat at 66–67 under facade traffic. |
| 20:42 | Still flat at 66 descriptors; tip 970,389 matches the oracle; facade and mempool at the tip. |

## Root cause

`rd_lane_enter` (asm/rpc_chain.c) gave each thread a private reader lane the first
time that thread called `getblock`: a store handle (`index.dat`, the current blk
file, the reader's fd cache) and an 8 MB block buffer, held in `__thread`
variables and never released. The design assumed the callers were the RPC worker
pool, a fixed set of threads (`-rpcthreads`), where 3 fds and 8 MB each is a fixed
cost. The Esplora facade is not a pool. It starts a thread per connection, and
mempool.space and the block explorer read blocks through it all day. Each of
those threads exited holding its lane.

Two things made this hard to see:

- **Nothing in the tests or benches used short-lived threads.** Every RPC test and
  load bench went through the fixed pool, so the cost really was fixed there.
- **Only new descriptors failed.** The RPC and facade listeners could not accept
  (new inbound P2P connections would have failed the same way; not checked).
  Outbound P2P legs, the download worker and the applier already held their
  descriptors. The node synced, relayed and validated normally,
  and every liveness check passed.

The 2026-09-03 codebase audit had described the same failure shape for a
different leak (CODEBASE_AUDIT_2026-09-03.md:1545: "at `RLIMIT_NOFILE` (1024
default) the RPC listener and the inbound P2P listener both stop accepting"). The service unit sets no `LimitNOFILE`, so 1,024
applies. The Core oracle's unit sets 65,536.

## What was damaged, and what was not

- **Not damaged:** the chain, the UTXO set, the indexes and the mempool. The node
  never stopped following the tip.
- **Unavailable for 2 h 17 m:** everything served over HTTP (JSON-RPC on 8331, the
  Esplora facade on 3005) and so the mempool.space instance built on it. The
  backend caught up within minutes of the deploy.
- **Leaked memory:** up to 8 MB of block buffer per leaked lane. Most of it was
  never touched, so RSS grew far less than 313 × 8 MB.

## Fix

PR #402 (d0527354, merged as 54ffb790): a `pthread_key_t` created once
(`pthread_once`) with destructor `rd_lane_release`, which closes the thread's lane
handle and frees its buffer. The key is set to a non-NULL value on the thread's
first lane entry, so the destructor runs when any thread that used the lane exits,
pool or not.

Test: `test_rpc_chain` creates and joins 64 threads one after another. Each calls
`getblock` on genesis once. The test checks that all 64 succeeded, that the lane
was entered 64 times, and that the process's descriptor count is unchanged.
Unfixed: 14 → 206. Fixed: 14 → 14.

Deployed as `deploy-20261007a` (see DEPLOYMENT_HISTORY.md).

## Lessons

- **Any `__thread` resource needs a thread-exit release, or its callers must be
  pool-only by construction.** A cost that is "per thread" is only bounded if the
  number of threads is.
- **"Up but RPC times out": count descriptors first.** Run
  `ls /proc/<pid>/fd | wc -l` and compare with `Max open files` in
  `/proc/<pid>/limits`, then grep for `accept: out of file descriptors`. This is
  now a check in OPERATIONS.md.
- **A deploy check must cover the shape of the traffic, not only its result.** The
  10-05 deploy was verified on new blocks and RPC answers, both true. The
  descriptor count staying flat across facade traffic is now a deploy criterion.
- **A degraded-listener line printed once is an alert nobody receives.** Watching
  for it is a follow-up below.

## Rollback guidance

`deploy-20261006d`, the only rollback target for `deploy-20261007a`, carries
this leak, and so does every snapshot back to `deploy-20261005a`. Nothing older
than 06d is safe at all: those builds predate B3's WAL retirement (see
OPERATIONS.md, *Upgrading and rollback*). If 07a has to be rolled back, 06d
serves as a bridge measured in hours. Watch the descriptor count.

## Follow-ups

- Decide on `LimitNOFILE` for the production unit (Core's oracle runs with 65,536).
  A higher limit only buys time against a leak like this one, but 1,024 is low for
  a node that serves HTTP.
- Alert on the `accept: out of file descriptors` line, or on the descriptor count
  passing a fraction of the limit.
- The facade's thread per connection is still the shape. A pool, or keep-alive
  for mempool-backend, would remove the churn that turned a fixed cost into a leak.
