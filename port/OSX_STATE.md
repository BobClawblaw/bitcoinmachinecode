# OSX PORT STATE — durable snapshot

Updated whenever status materially changes. Newest section top.
(Companion to `OSX_PORT.md` (branch model), `OSX_ROADMAP.md` (per-module
status) and `OSX_STRATEGY.md` (phased plan-of-record, PR #130).)

## 2026-10-06 (night, 2) — verbose `getrawmempool`'s tables sized by the live count, not the slot capacity (shared C)

The finding of the "later" section, fixed. `cmd_getrawmempool` sized `g_mpe_vs` and `g_mpe_inf` by `mp_slot_count` (mask + 1, 1,048,576 at `maxmempool=300MB`), and `g_mpe_inf`'s element is an ~8.3 KB `mp_entry_info`: ~8.7 GB asked of malloc per verbose call, under the lock, every 20 s. Now both start at the live count (`g_mph.count`) plus an eighth plus 64; the vsize table grows to capacity if the walk outruns it, and `pol_entry_info_all` is retried at capacity if it refuses the smaller buffer (it answers -1 when the registry has more nodes than `max` — stale nodes after a pool removal).
- **Measured** (`test_rpc_chunk_scale` now takes an optional slot count; `68000 1048576` is production's shape): snapshot hold 55.8 → 32.1 ms (best of 3), close to the 29.3 ms the same pool gets in a 262k-slot table; the rest is the walk of 1M slots. Peak RSS per call unchanged at ~+794 MB: it is the 8.3 KB record per registry node, which only a compact graph format would cut (not done).
- **Tests:** two new sections — a quarter of the entries dropped from the pool but kept in the registry (live 24,000: the retry must fire; snapshot hold 11.7 ms against 121.2, byte-identical), and a count hook under-reporting 4× (the buffer must grow; 12.4 against 131.4 ms, byte-identical). Without the retry or the grow, each falls to the per-entry path: **a ~45 s hold** on the test pool, which the checks catch.
- **Full suite:** 424 PASS, 11 SKIP, 14 N/A, 0 FAIL. Note item 24 and FEATURE_GAPS.md RPC-12 updated.

## 2026-10-06 (later) — verbose `getmempoolancestors` / `getmempooldescendants` render outside the pool lock too (shared C)

The bulk `getmempoolentry` paths. Without bulk tables each rendered member asked the registry per txid (its node, every ancestor's and descendant's for the size sums, every cluster member's for the chunk), and each `mpool_policy_entry_info` rebuilds the registry's children index, O(pool) — set × cluster × pool scans plus the JSON, all under `mpl()`. Now `mpe_snapshot_component` walks the transaction's connected component once under the lock (one entry_info per node; cap 256 nodes, the cluster limit being 64), copies each pool-present node's inputs into the per-call tables, and the render runs after `mpu()` in snapshot mode (`mpe_snapshot_index`, `mpe_tables_free`). Over the cap or on an allocation failure the old path answers. Non-verbose forms and single `getmempoolentry` unchanged.
- **Proof:** `test_rpc_chunk_scale`'s second new section — 12 calls (chain heads, middles, tails, a singleton; both directions; 10 non-empty) byte-identical to the old path, longest hold 85.3 → 1.6 ms, takes == releases. Mutations each fail it: the walk following parents only, the component's priority or arrival time not copied, the index pass skipped, the release dropped.
- **Found, not fixed:** `cmd_getrawmempool` sizes `g_mpe_inf` (and `g_mpe_vs`) by slot CAPACITY (`mp_slot_count` = mask + 1, 1,048,576 at `maxmempool=300MB`) × ~8.3 KB per `mp_entry_info` — ~8.7 GB of address space per verbose call, ~620 MB of it written by `pol_entry_info_all` at a 75k pool, under the lock, every 20 s under BlockYard's poll. Added to note item 24.
- **Full suite:** 424 PASS, 11 SKIP, 14 N/A, 0 FAIL.

## 2026-10-06 (late) — verbose `getrawmempool` holds the pool lock for the copy, not the build (shared C)

The fix for note item 24, on our side. `cmd_getrawmempool` (rpc_node.c) used to build every entry's JSON — the cluster linearizations and ~75k `rj_*` trees — inside `mpl()`, so each BlockYard poll held the cross-process pool lock 1.1–1.9 s with the worker's p2p accepts waiting behind it. Now the pass under the lock records per entry what the builder used to read from the pool and its hooks (slot-cache weight and BIP125, the wtxid's sha256d over the bytes, `time_of`, the `prioritisetransaction` delta, the pool order), takes the one-pass graph, allocates the chunk cache, reads `mempool_sequence`, and releases; the sort, cluster builds and JSON then run on the call's tables (`g_mpe_snap` makes `mpe_entry_obj` / `mpe_member_vsize` / `mpc_lookup_bulk` touch nothing shared). The per-call tables were already guarded by the mempool lane's own mutex, not by the pool lock. The wtxid is NOT cached across calls in the slot cache: that cache is keyed on txid + length, which a same-length witness replacement would defeat. A call whose tables did not build keeps the old under-the-lock path (it needs the per-txid lookups).
- **Proof:** `test_rpc_chunk_scale` (32,000-entry production-shaped pool, timed lock hooks, `time_of` / `sha256d` hooks, three priority deltas): hold 160.9 → 13.2 ms, wall unchanged, the answer byte-identical to the old path (`rpc_node_set_grm_snapshot(0)`, a new test knob), takes == releases. Mutations each fail it: no pri snapshot, no time snapshot, wtxid = txid, the pool order lost, the early release dropped (caught only by the takes/releases count — a timer-only lock reads a missed release as no hold).
- **Full suite:** 424 PASS, 11 SKIP, 14 N/A, 0 FAIL. Docs: FEATURE_GAPS.md RPC-12 "2026-10-06", note item 24 marked fixed on bmc_osx with what main should take.
- **Deployed and checked an hour on (`ed6f3455`, restarted 20:33Z; checked 21:34Z):** **zero** `[mempool] pool lock:` lines on mainnet or signet (the log threshold is the default 1,000 ms). The baseline poller was still at work: BlockYard's pool tier runs `getrawmempool(true)` per node every 20 s (~180 calls on `bmc-osx` in the hour; its `/api/nodes` shows the node online and synced, its mempool view 67,954 entries = the node's pool), with no `rpc-slow` warnings since the restart. Before the fix, the same poller against a ~75k pool produced four ≥1 s `getrawmempool` holds between 02:57 and 04:09Z on 10-02 (1.1–1.9 s, each with `tx_accept_validate_p2p` waiting 1.2–1.5 s). A verbose call by hand on the 68k pool now takes 0.42 s end to end and logs nothing. Heartbeats steady (mainnet 59 gaps, mean 60.3 s, max 62 s; signet mean 60.1, max 61); tips 970,235 / 325,250 = mempool.space; no crash/FATAL/REJECT/MUTATED. Caveat: the line only reports holds ≥ 1 s, so this shows the long holds are gone, not the new hold's size in production (13.2 ms on the 32k test pool).

## 2026-10-06 (night) — fe_add / fe_sub in line in the point formulas; `a2ccdea7` deployed

- **Deploy:** `a2ccdea7` (the native `glvj_ct`) on both nodes (snapshots `bmcbitcoind.pre-a2ccdea7`), restarted 18:07Z by stop.sh/start.sh; mainnet tip 970,211 and signet 325,225 = mempool.space, 10/10 peers each, no crash/FATAL/REJECT lines.
- **Inlining (`port/osx/secp256k1_fe_inline.h`, new):** `FE_ADD_INLINE` / `FE_SUB_INLINE` are `secp256k1_fe.S`'s `_fe_add` / `_fe_sub` instruction for instruction on the same x0/x1/x2 (bit-identical, alias-safe, x3..x13 only); the `FE3` macro of `secp256k1_point.S` and `secp256k1_point_ct.S` emits them in place of the call (`.ifc`), and the ct module's direct `bl _fe_sub` negations in the loops too. x86's counterpart is `5501c764`. Two one-off negations outside the loops stay calls.
- **Measured:** `point_double` 106 → 86 ns (1.23×, x86 saw 1.22×), `pointh_double` 91 → 89, `pointj_add_ge_ct` 122 → 122 (its time is its 12 multiplies), `glvj_ct` 22.9 → 20.5 µs, `glv_ct` unchanged at ~26. `fe_mul` is 5.2 ns, ~18 cycles for 16 mul + 16 umulh and the reduction — near what the multiplier allows; what is left is the store/load between steps, which only register-resident formulas (a rewrite of each formula, not a macro swap) would remove.
- **Full suite:** 424 PASS, 11 SKIP, 14 N/A, 0 FAIL (449 commands; `test_pointj_add_ge_ct` runs now).
- **Deploy:** `45fb3637` on both nodes (snapshots `bmcbitcoind.pre-45fb3637`), restarted 18:50Z; signet 325,232 and mainnet 970,215 = mempool.space, no crash/FATAL/REJECT/MUTATED lines, mainnet relay +276 accepted in its first tx window (64.6k pool).

## 2026-10-06 (evening) — `point_scalar_mul_glvj_ct` native (the Jacobian body and `pointj_add_ge_ct`)

The stand-in from the #366–#393 merge (a branch to `glv_ct`) is replaced by the port of x86's `dc63c274` in `secp256k1_point_ct.S`: libsecp256k1's `ecmult_const` — `(k + K)/2`, the λ-split, `v = s + 2^128`, 26 signed odd 5-bit digits, a 16-entry odd-multiples table of P on the isomorphic curve (`_point_double`, `_point_add_mixed_zr`, globalz) and its β twin, 125 Jacobian doubles + 51 `pointj_add_ge_ct` (gej_add_ge: the alternative λ and the a-infinity case by csel; Y3 halved in place). One csel scan (x86's AVX2/cmov probe has no counterpart). `test_pointj_add_ge_ct` is no longer N/A.
- **Proof:** `test_pointmul_ct_variants` 9,136 and `test_pointj_add_ge_ct` 14,002 checks PASS; the ECDH / BIP324 / v2 transport / ellswift tests and the point/scalar/schnorr/wallet tests that link the module PASS (14 commands). Six mutations (no alternative-λ select, no a-infinity csel, Y3 halving without the odd fixup, y never negated, no globalz scaling, `sc_half` without the n/2 add) each fail at least one of the two tests.
- **Speed:** 22.9 µs against `glv_ct`'s 25.9 (`win_ct` 35.8) — 11%, not x86's 36%. The pieces: `fe_mul` 5.6 ns, `fe_add` 1.4 ns, but the Jacobian `_point_double` costs 106 ns, more than the complete-formula `pointh_double` (91): its 13 add/sub calls each round-trip through memory. x86 inlined the field add/sub into its point formulas (`5501c764`, point_double 1.22×); the Mac's `secp256k1_point.S` has not. That inlining is the next speed step for this routine and for every Jacobian caller.

## 2026-10-06 (17:15Z) — main #366–#393 merged (`60370d45`); both nodes back after 4.5 days down

**The nodes had been down since 2026-10-02 04:28Z**: the Mac rebooted (23:28 local on 10-01) and nothing restarts them. Before that, `f0002ff7` on mainnet logged the Mac's first `[mempool] pool lock:` lines — 21 between 02:57Z and 04:25Z, single long holders, not x86's convoy: `getrawmempool` held 18,699 ms (a `tx_accept_validate_p2p` waited 16,970 ms behind it) and `tx_accept_validate_p2p` held 31,857 ms. Noted for the x86 side as item 24 (2026-10-06): the 1.1–1.9 s `getrawmempool` holds before 04:10 are the finding — verbose `getrawmempool` builds its whole JSON under `mpl()`, polled by BlockYard's monitor; the 18.7 s / 31.9 s holds after 04:10 were a host-wide stall (heartbeat gaps of 193 s and 169 s, Core on the same Mac answering RPC in 18–50 s), ending in the reboot.

Merge: 95 commits, two conflicts — `tx_relay.c` (main's `txr_v2_buffered` skip now wraps our wake-fd poll; both kept) and `.gitignore`. The link failed on main's new code; the port steps:
- **BIP339 (main 10-03, `9422df8b`)**: `bitcoind.S` sends `wtxidrelay` with `sendaddrv2` once the peer's version (≥ 70016) is in, in both roles, and sets `_g_peer_wtxidrelay` per handshake when the peer sends it (no echo); `bitcoin_serve.S` serves `getdata(MSG_WTX)` via `txann_txid_for_wtxid` → the pool, witness form. The Mac had never taken main's 10-01 withhold either: it sent `wtxidrelay` before the version exchange throughout, while announcing by txid — the shape Core drops. Every mainnet leg now logs `wtxid=1`.
- **`point_scalar_mul_glvj_ct`** (main's libsecp256k1 `ecmult_const` port, the ECDH's k·P since 10-02): on the Mac a branch to the native `glv_ct` — same contract (k < n, Jacobian, canonical infinity), old speed. `test_pointmul_ct_variants` checks it against the ladder; `test_pointj_add_ge_ct` is N/A (`run_tests.py` `NOT_PORTED`). (Ported natively the same evening; see above.)
- **New C in the link**: `crash_trace.c`, `index_worker.c` (plan B4), `benchlog.c`, `dlc_benchlog.c`. `crash_trace.c` needed Darwin branches (pc/sp/fp from `__ss`, `pthread_threadid_np`, `__text` bounds via `getsectiondata`) and **a real fix**: its stack scan read 2,048 words above the faulting sp; Darwin maps nothing above a thread's stack, so the read faulted inside the handler with SIGSEGV blocked and the thread spun forever (a crash would have become a hang). The scan now stops at `pthread_get_stackaddr_np`. `test_crash_trace` 8/8.
- **`test_dlc_header_probe`** (new, 4 fake peers on 127.0.0.1–4): SKIPs without the aliases via `loopback_alias.h`, and a failed peer start stops the peers already up — it had aborted and orphaned a listener that held the harness's pipe for 17 minutes.
- **Full suite:** 423 PASS, 11 SKIP, 15 N/A, **0 FAIL** (449 commands).
- **Deploy:** `60370d45` on both nodes (snapshots `bmcbitcoind.pre-60370d45`), started 16:55Z. Mainnet caught up 969,531 → 970,205 (`[ready]` at 970,054 in 179 s; `[ixw] index worker` started), tip = mempool.space's hash, 58k pool, `limitclustercount 64, optimal true`. Signet 325,084 → 325,220 = mempool.space, 11/11 peers. No FATAL/REJECT/crash/pool-lock lines in the first 15 minutes.
- **Restart at login (launchd):** `~/Library/LaunchAgents/com.bmc.{mainnet,signet}.plist` run each deploy home's `start.sh` at load (`RunAtLoad`, `AbandonProcessGroup` so the node survives `start.sh` exiting, no `KeepAlive` so `stop.sh` still stops it; output to `logs/launchd.log`). Loaded 17:20Z: both printed "already running" and left the nodes alone. They fire at login, not at boot; FileVault is on, so the boot unlock is the login and the nodes come up with it.

## 2026-10-01 (22:00Z) — main #362–#365 merged (`c07d8602`): the mempool follows Core v31.1; one Core oracle; MAIN_C_HDRS

Shared C and Python only; one conflict, `validation/fetch_taproot_blocks.py` (our `CORE_CLI` override kept, main's new default oracle path `/storage/bitcoin-core-v31.1/bin/bitcoin-cli` taken). **#363** is a policy change from BlockYard's differential (15 of 35 missing children refused by the 25-tx chain limit, 14 by the per-conflict RBF rule): cluster limits only (`limitclustercount` 64, `limitclustersize` 101,000; ancestor/descendant counts deprecated), v31.1 replacement rules (feerate-diagram check), optimal cluster linearization. **#362** `MAIN_C_HDRS` + `make header-check` (the Mac's `build_daemon.sh` already rebuilds on any newer header). **#364** is the x86 box's oracle move. **#365** their resume: their pool-lock log saw a convoy from the facade's per-tx batch after a restart and one `getrawmempool` hold of 1,071 ms; the 90 s stall has not recurred; run 32 (chunk 16) is running. They have not taken note 23 (the convoy count) yet.
- **Full suite:** 417 PASS, 10 SKIP, 14 N/A, **1 FAIL** — `test_mempool_lock_log` case E under suite load: the convoy threads waited long enough on each other to log lines of their own, which pushed the waiter's line out of the 4-slot ring before the test read it. Fixed in the test (`f0002ff7`: the ring is read while the lock is still held, when every convoy thread is blocked; six convoy threads and eight attempts for the fair-handoff case): 0 failures in 96 loaded runs across six lanes. The lock code is unchanged. The nine tests #363 touches PASS natively (`test_mempool_policy` 82, `test_mempool_cluster` 2,000, `test_mempool_core_parity` 14).
- **Deploy:** `f0002ff7` on both nodes (snapshots `bmcbitcoind.pre-f0002ff7`); signet 21:56Z, tip 324,552, `getmempoolinfo` → `limitclustercount 64, limitclustersize 101000, optimal true`; mainnet 21:57Z, tip 969,496 = mempool.space's hash, mempool.dat reload 78,341 of 78,372 in 3 m 10 s (10 refused by policy), relay gate opened at the first heartbeat. No `[mempool] pool lock:` line during the reload either — the convoy x86 saw at its reload did not show here (Darwin's pid-word lock hands off differently).

## 2026-10-01 (17:00Z) — main #361 merged (`246d3202`): the download chunk is a setting, default 16; cursor help fires again

Shared C only (`dlc_rules.h`, `main.c`, `node_config.*`, four tests, `validation/ab_dlcchunk.sh`), a clean merge, no port step. `bmc.dlcchunk` (4..64) defaults to 16 after two A/Bs to 300,000 in both orders (19.5% and 14.1% faster than 40); the committer's cursor help had been dead since the window became Core's 1,024 on 09-29 (its bar of 32 staged chunks could not be reached at 25 per window) and is a third of the window's chunks now. Tests run here: `test_dlc_rules`, `test_node_config`, `test_dialhelper`, `test_mempool_lock_log`, `test_rpc_responsive` PASS; `test_dlc_interleave` SKIP (Linux-only, as always). Nothing in the batch the Mac had not already gated apart from main's own gated code.
- **Deploy:** `246d3202` on both nodes (snapshots `bmcbitcoind.pre-246d3202`); signet 17:12Z, tip 324,523; mainnet 17:12Z, tip 969,467 = mempool.space's hash. At the tip the chunk size changes nothing until the next restart with a gap.
- **A deploy mistake, corrected:** the signet node was started from a shell command that the session later stopped, and the stop's signal took the node's process group with it — a clean shutdown at 17:00:23Z (`signal 15`, mempool saved), restarted at 17:12Z, 12 minutes off. Start a node from its own short command, never from one that waits on anything afterwards.
- Still no `[mempool] pool lock:` line on the Mac (≈100 blocks on the convoy-aware line).

## 2026-10-01 (00:00Z) — the pool-lock wait line tells a convoy from a holder (shared C, `530e6826`)

x86's resume asked for it: their first lines were waits of ~1.2 s let in by releases that had held 0–3 ms — a convoy of short holds the last-releaser line could not name. The lock's page now counts every take, each release made while anyone waits keeps the convoy's longest hold and its site (reset by the last waiter out), and the wait line adds `N other take(s) went by during the wait, the longest of them held M ms (site)`. `test_mempool_lock_log` case E (36 checks): three threads taking 3 ms holds back to back — `waited 374 ms; the holder was convoy_site (held 3 ms); 101 other take(s) went by during the wait, the longest of them held 3 ms`, no hold line from anyone. Note item 23 for the x86 side; OPERATIONS.md and FEATURE_GAPS.md RPC-12 updated.
- **Full suite:** 418 PASS, 10 SKIP, 14 N/A, 0 FAIL (442 commands).
- **Deploy:** `530e6826` on both nodes (snapshots `bmcbitcoind.pre-530e6826`); signet 00:01Z, tip 324,415; mainnet 00:03Z, tip 969,369 = mempool.space's hash, 69,811 mempool transactions carried across. Still no `[mempool] pool lock:` line on the Mac at any point today.

## 2026-09-30 (night) — main #357–#360 merged (`ba47f39f`): both of today's Mac fixes landed on main whole

Main took `f8611830` (the relay gate at the heartbeat) as #357 and `71f4369d` (the pool-lock log, the `getrawtransaction` yield) as #359, each re-gated on x86 (442 tests, the revert check reproduced at 1,700 ms) and deployed as `deploy-20260930e`; #360 is their resume with the first pool-lock lines: **a convoy, not a long holder** — during the mempool.dat reload two waiters saw ~1.2 s, but the releases that let them in held 0 and 3 ms and nobody logged a hold ≥ 1 s. The line names only the last releaser, so it cannot name a convoy's source; their suggestion is a take count per site over a window, or the longest hold seen during a wait. One conflict, `mempool_cfg.c`, ours-against-theirs on the Darwin pid-word lock's four `#ifdef __APPLE__` branches inside the new code: ours kept, the file now differs from main only by that section. One Mac-side change on the way in: `getrawtransaction`'s 404 KB per-thread copy buffer became heap TLS (`BMC_TLS_BUF`, the port's convention after the TLV fault of 09-11) instead of a `__thread` array — main keeps its array.
- **Tests run:** the seven that cover the changed handler (`test_rpc_responsive`, `test_rpc_chain`, `test_rpc_rawtx`, `test_rpc_core_fields`, `test_rest`, `test_rpc_esplora`, `test_mempool_lock_log`), all PASS; the merge brought no other code the Mac did not already have gated at 418/0 this evening.
- **Deploy:** `ba47f39f` on both nodes (snapshots `bmcbitcoind.pre-ba47f39f`); signet 23:34Z, tip 324,409; mainnet 23:36Z, tip 969,365 = mempool.space's hash, 69,986 mempool transactions saved across the restart, the relay gate flipped open at the first heartbeat. **Pool-lock lines on the Mac so far: none** in 25 blocks at a ~70k pool on `71f4369d` (block connect removed up to 6,153 transactions and held the lock under 1 s every time), and none during either reload — the convoy shape x86 saw at its reload did not show here.

## 2026-09-30 (evening) — the pool lock is timed and named; `getrawtransaction`'s consult of it left the execution lock (shared C)

The x86 resume's finding (their 09-30 resume, "the finding that sets the next step"): the exec-lock holders it had named were handlers WAITING on `mpl()`, the mempool's cross-process lock, held by the download worker for seconds at a new block — and nothing timed that lock. Items 1 and 2 of their list, done here and noted for them (note item 22):
- **`daemon/mempool_lock.h` (new) + `mempool_cfg.c`:** every take is `mp_lock_at(site)` (`__func__` at the ten C sites; the hooks' `mp_lock()` names the RPC thread by its method or facade route through a new `rpc_exec_current_label` export), every take and release is timed, and a wait or hold of `BMC_MEMPOOL_LOCK_LOG_MS` (default 1000 ms; 0 = off) is one `[mempool] pool lock:` line, after the release. `mp_lock_phase` names the holder's step: block connect reports `fest_begin`, `mark`, `remove_marked`, `rm/seq` … `rm/reindex`, `rejects_clear+note`, `fest_end`, `seq_C` with their ms. The lock's shared page is a struct now (mutex + holder pid/site + last release), so a waiter in the RPC process names the holder in the worker: `getrawtransaction (pid N) waited 3467 ms; the holder was tx_accept_block_connect_h/rm/reindex (pid M, held 3450 ms)`. On Darwin the pid-word lock sits in the page's first 128 bytes as before. `tests/test_mempool_lock_log`: 30 checks (both lines, the steps in order, a forked holder named across processes, quiet takes silent, 0 = off, the hook's label, a stray phase).
- **`rpc_chain.c`:** `getrawtransaction`'s mempool consult runs with the execution lock yielded (`rpc_exec_yield_begin`/`_end`, weak), a `__thread` copy buffer, the tip re-read after. `test_rpc_responsive` scenario F: the hooks' lock a mutex the test holds 2 s; the trivial methods and an exclusive `getchaintips` answer within 100 ms while the consult waits; the call completes after the release; the yield counter moved. Revert-checked: `getchaintips` waited 1,710 ms — and a synchronous probe DEADLOCKED the test (main thread holding the pool mutex, waiting on a call waiting on the exec lock held by the consult waiting on the pool mutex): the production stall from inside, so the probe has its own thread.
- **Docs:** OPERATIONS.md "Logging", FEATURE_GAPS.md RPC-12.
- **Full suite:** 418 PASS, 10 SKIP, 14 N/A, 0 FAIL (442 commands; `test_mempool_lock_log` is new).
- **Deploy:** `71f4369d` (not dirty) on both nodes, snapshots `bmcbitcoind.pre-71f4369d`. Signet restarted 19:15:25Z, tip 324,384, 10/10 peers; mainnet 19:17:05Z, tip 969,339 = mempool.space's hash, 71,430 mempool transactions saved across the restart. Now watching for the first `[mempool] pool lock:` line at a block connect.

## 2026-09-30 (afternoon) — after the #343–#355 deploy the tx relay was dead until the next block; fixed at the heartbeat

Both nodes accepted nothing for 20 minutes after the restart: #344's IBD gate (`g_dl_in_ibd`, evaluated once at boot in the parent and otherwise rewritten only when a new block connects) had stood at "in IBD" since boot. Found by the absence of `[tx_accept]` lines and a mempool frozen at the loaded count while the legs' inv bytes kept arriving unrequested. The heartbeat now refreshes the flag from the tip and prints `relay=off(ibd, N dropped)` while it is closed; the first heartbeat of the fixed build flipped it on both nodes and relay resumed (+214 accepted on mainnet in the next window). Note item 21 for the x86 side, which has the same code. The signet health gate in my deploy script was also too strict (it demanded an accepted-tx line inside the first minute, which a quiet signet mempool cannot promise) — the second deploy went on heartbeat + clean log, which is the real evidence.
- **Full suite:** 416 PASS, 10 SKIP, 14 N/A, 1 FAIL — `test_cmpct_recv`'s 3× timing ratio, measured while both nodes restarted under the suite; PASS three times alone.

## 2026-09-30 — main #343–#355 merged (`93a509e9`): the RPC lock work, Core's download shape, run 30/31 final

Shared C only (no new assembly exports), so no port step. Two conflicts, both ours-against-theirs on the same lines: `rpc_node.c`'s five submit-wait loops take main's test-settable bound (`g_srt_wait_us`) and keep the ARM64 acquire fence after the ack; `test_tx_relay.c` keeps both new sections (our case 20, the gettxout wake; main's IBD announcement drop). Built and linked first time; full suite 417 PASS, 10 SKIP, 14 N/A, 0 FAIL with main's new RPC tests in. Deployed to signet and mainnet; the mainnet node serves the same RPCs the batch moved off the execution lock.

## 2026-09-28 (night, 2) — the port's debug prints removed from the shared C

The x86 side's audit of `bmc_osx` against `main` (their 09-28 worklog, #341) took every shared fix and left "Darwin-guarded code, ARM64 fences and Mac-side debug printfs" behind. The printfs were the port's own debugging from the twin era, never meant to stay: `[ls-cs]` and `[wv0-cs]` env-gated hex dumps in `bitcoin_scriptverify.c` / `bitcoin_witness_v0.c`, an unconditional `[dbg-ctx]` dump of the script, prevouts and witness on every failed tapscript in `bitcoin_taproot_sighash.c`, and `ibd_pipeline.c` writing a failing block to `/tmp/ibd_bad_*.bin`. All four removed, with the includes that served only them; those files now differ from `main` only by the `BMC_TLS_BUF` thread-local shims (`ibd_pipeline.c` is identical). The covering tests (scriptverify, segwit, tapscript, taproot block diff, IBD pipeline) pass unchanged.
- **Full suite:** 416 PASS, 10 SKIP, 14 N/A, 1 FAIL — `test_net_timeouts`, a timing test on untouched code, PASS when rerun alone and in the three earlier full runs today: a load flake.

## 2026-09-28 (night) — the reorg probe's rejection memo (shared C)

The #304 cluster peer reappeared on the mainnet node at 19:23 and became the only leg with an empty pass, so the 30 s probe slot fell on it every time: 29 probes in 15 minutes, each fetching the 7,409-deep fork at 961,631 and rejecting it (correctly; the tip stayed at Core's). Now a leg whose probe rejected a candidate is not probed again for an hour (`probe_memo_*`, on a `host_memo_t` helper the #304 claim memo shares). `test_parallel_trigger` pins it. Note item 20 for the x86 side.
- **Full suite:** 417 PASS, 10 SKIP, 14 N/A, 0 FAIL. The peer is on the Bitcoin Knots BIP-110 split (nodes enforcing it stopped accepting the SHA256d chain's blocks on 2026-08-08; our fork point 961,631): eight SHA256d blocks 961,632–961,639, of which Core holds two as headers-only (bits 1702353d, version 0x200be010, 08-06/08), then BLAKE2b proof-of-work from block 961,640 on 08-30 (bitcoin-blake2b.org/faq) with a new header format. The ~974k it announces is that chain's height (its coinbase-maturity rule starts at 973,440); neither node can read those headers, which is why the probe sees only the 961,631 fork and rejects it on depth.

## 2026-09-28 (late) — the roadmap brought current; the wallet round-trip gate run

- `OSX_ROADMAP.md` had not been touched since the C-twin era: 42 entries still said "as a C TWIN", four boxes were open (bip341/342, the script VM modules, the wallet CLI gate, Phase 4 parity). A dated status section at its top now states what is true (every daemon-linked x86 module has a `.S`; the 13 shadow twins; the suite; the nodes; parity by vectors), and each open box is closed in place with what closed it.
- **The wallet round-trip against a running osx node** (the one gate that had never been run): on a throwaway regtest node from the Mac build, `bmc_wallet_cli init` → the daemon loads the store and serves the wallet RPCs (`private_keys_enabled=true`, `getnewaddress` → `bcrt1qe2kgnj…a0s3y`, `ismine`), and the CLI re-derives the same witness program from the mnemonic. `signmessage` over a bech32 address is refused as Core refuses it, so that leg is by design absent.
- Nothing new from the x86 side since #336; PR #337 (#294/#304) waits on their gate; both nodes clean since the deploy (no FATAL/REJECT/MUTATED, no parallel-downloader run, tips at Core's).

## 2026-09-28 (evening) — issues #294 and #304 fixed (shared C)

Two open issues from the BlockYard sync of 09-24/25, both in the daemon's C:
- **#294** — a restart mid-sync with a small gap, a just-under-threshold WAL and 17 runs of 42 GB took the 64 MB steady-state memtable and ground for 25 minutes in silence. A third sizing rule on the store's shape (`utxo_live_pick_bulk_shape`: runs ≥ the compaction threshold, or run bytes ≥ the 35%-of-RAM run budget), fed by a directory scan for `utxo_run_*.dat` before the load, and a "store shape" line either way so the silence has its reason. `test_utxo_sizing` pins it. On this Mac's mainnet node: 5 runs / 13 GB → steady-state, unchanged.
- **#304** — a cluster of Knots peers on a rejected fork passed the two-agreeing-peers gate and ran the full parallel downloader (60–130 s, 0 blocks) after every start and re-arm. Now a leg whose sync pass is failing does not vote, and a peer whose claim ran the downloader for nothing is remembered by host for 6 h across tips. `test_parallel_trigger` pins both.
- Note items 18 and 19 for the x86 side; the PR to main follows.
- **Full suite:** 417 PASS, 10 SKIP, 14 N/A, 0 FAIL.

## 2026-09-28 — main #327–#336 merged (`c891ce14`→): the comb, window and GLV multiplies, the SHA-1 second body, the chacha20/num3072 glue

The x86 session's benchmark day (`worklog/2026-09-28.md`: #329 MuHash safegcd in C, #330 ElligatorSwift comb/window, #331 ChaCha20 AVX2, #332 SHA-1 SHA-NI / SHA-512 / Base58, #334 GLV ECDH + the comb for every k·G caller + SHA-256 runs + the filter builder, #336 the three testnet4 fixes cherry-picked from this tree) merged cleanly, then failed to link: the shared C now calls x86 exports the Mac did not have. What the Mac got:

- **`secp256k1_point_ct.S`: `point_scalar_mul_gen_ct` (k·G over `g_comb_table_data`, 64 csel-scanned column reads, no doubling), `point_scalar_mul_win_ct` (w=4 window over a 16-entry table of P), `point_scalar_mul_glv_ct` (`sc_split_lambda`, the signs folded into the points by csel, 33 nibbles over two tables), `pointh_to_jac` (the ladder's tail as a function), `point_ct_force_scan` (x86's AVX2/csel scan knob: accepted, ignored — one scan here).** Same shape as x86: every table entry is read, the digit reaches only a `cmp`. Proof: main's `test_pointmul_ct_variants` (7,265 checks against the ladder and `point_scalar_mul`; edges 0, 1, n−1, n, n+1, 2²⁵⁶−1, every-nibble patterns, random bases incl. k = 1 and k = n−1). The first cut failed it: the scan/table macros used local label `1:` inside routines whose own loop was `1:`, so `b.pl 1b` re-entered the last scan; now `5:`/`6:`. **Timings:** ladder 56.2 µs → comb 9.5 µs, window 35.9 µs, GLV 25.7 µs (x86: 52 → 9 / 33 / 24.3). Every k·G caller (`bip340_sign`, `wallet_core`, `bip32_ckdpub`, `wallet_msgsign` via the shared C; `bitcoin_keys.S` by hand) is on the comb; the ECDH on the GLV routine (`test_ellswift_ecdh`, `test_bip324`, `test_v2transport` pass on it).
- **`sha1.S`: two bodies.** x86's `test_sha1` drives `sha1_block_scalar` and `sha1_block_shani` against each other and the FIPS vectors, with `sha1_force_path` / `sha1_cpu_has_sha`. The crypto-extension body is now `sha1_block_shani`; a plain FIPS 180-4 round loop is the scalar body (1.87 ns/B against the crypto body's 0.336); `sha1_block` dispatches after one `sysctlbyname("hw.optional.arm.FEAT_SHA1")` probe, `sha256.S`'s pattern.
- **`chacha20_paths_osx.c`**: `chacha20_cpu_has_avx2` = 0 and an unreachable `chacha20_xor_avx2`, so `crypto_chacha20.c` links and takes its C block; `chacha20_k0_force_path` is a no-op (the Mac's `bitcoin_muhash.S` has one keystream body). A NEON body is the counterpart if the v2 cipher ever shows in a Mac profile. `test_chacha20` / `test_muhash` report the vector body as not on this CPU, as x86 does without AVX2.
- **`build_daemon.sh`**: `daemon/num3072_inv.c` (Core's safegcd for the MuHash inverse, shared C) added to the explicit source list.
- **`bitcoin_keys.S`**: `point_scalar_mul_gen_ct` for k·G, as `bitcoin_keys.asm`.
- Everything else in the batch was C on both sides (`num3072_inv`, `fe_is_square_var`'s Jacobi, the filter builder, the sighash session) or x86-only assembly whose Mac counterpart already had the property (SHA-512, Base58: `test_addr` 321 PASS; SHA-256 multi-block runs: `test_sha256` PASS).
- **Full suite:** 417 PASS, 10 SKIP, 14 N/A, 0 FAIL (441 commands: main's `test_pointmul_ct_variants`, `test_sha1`, `test_num3072_inv` are in).

## 2026-09-28 (early) — main #324–#326 merged (`c891ce14`); the CLI's two x86 parities dropped with x86's

- **#325 (the mutated-block fix and the Darwin `legs_heard_within`) is on main** as `b022c0f9`/`f573b0ec`, with the x86 session's own addition `5c24fbc2` (`test_cmpct_fallback` links `block_witness.c` too — the Mac hunk covered only `test_cmpct_recv`'s rule; the Mac harness links every test against the daemon archive, so it never saw the gap).
- **#324 (store CLI + `multisig_verify`).** `bitcoin_cli.S` had kept, on purpose, the two x86 behaviours the twin documented — uppercase hex digits rejected, and per-command stack block buffers (0x180 / 0x800 / 0x4000) that made a real block "not found"; x86 fixed both, so the Mac follows: `HEXVAL` takes `'A'-'F'`, and the five block-reading commands share one static 4 MiB `Lblockbuf` (the old frames stay, their buffer bytes unused). `bitcoin_multisig.S` already refused a push that does not fit the scriptSig (its header says so: the C twin's rule, which is how the differential caught x86's over-read), so main's guard-page test passes unchanged. Main's `test_cli` (uppercase, a 20 KB block through every command) and `test_multisig` PASS.
- **`docs/PARITY_ATTESTATION.md`** merged by hand: x86's two 2026-09-27 rows above the Mac's 09-25 row.
- **Full suite:** 413 PASS, 10 SKIP, 15 N/A, 0 FAIL.

## 2026-09-27 (night) — safegcd inversion and the square-root chain in AArch64: `fe_inv_var`, `fe_pow_sqrt`, and `sc_inv_var` replaced

Main #319/#320 gave x86 an addition-chain square root for `pubkey_parse` and a Bernstein-Yang safegcd inverse mod p for the public inversions; the Mac assembly now exports both, and its `sc_inv_var` is the same safegcd body instantiated for n.

- **`port/osx/safegcd_var.h`** — the safegcd macro (`SAFEGCD_INV_VAR name, M62, MINV62, M4`), an assembly include the two .S files `#include` (the `.h` suffix is what `build_daemon.sh`'s staleness rule watches). Step for step the x86 `safegcd_var.inc`: 62 divsteps on the low words with the transition matrix in x22..x25, then the matrix applied to (d, e) mod m and to (f, g) over the live length, the top limb pair folded when both are 0/−1, d·sign(f) reduced into [0, m). Leaf; x19..x28 saved; a 160-byte frame. Variable-time: public inputs only, as on x86.
- **`secp256k1_fe.S`**: `fe_inv_var` (p's 5×62 limbs and p⁻¹ mod 2⁶² re-derived in Python) and `fe_pow_sqrt` (`fe_inv`'s chain to x223 with the (p+1)/4 tail: 253 squarings, 13 multiplies; the same frame and macros). **`secp256k1_scalar.S`**: `sc_inv_var` is the n instance. The binary extended GCD it replaces (u=a, v=n, halve mod n) took 1.4 µs and **looped forever on a ≥ n** — `test_fe_inv_var`'s non-canonical section would have hung on it; nothing in the daemon passes such a scalar (ecdsa_verify checks s < n first), so this was latent.
- **Users switched** (the same sites as x86): `schnorr_verify`'s Z⁻¹ for the even-Y test, `secp256k1_taproot.S`'s two affine conversions of the tweaked public point, `pubkey_parse`'s square root (the `Lexpqr` exponent constant is gone with `fe_pow`'s call; `fe_pow` itself stays exported for the test). `fe_inv` and `sc_inv` remain the constant-time paths for everything a signer computes.
- **Method.** A C prototype of exactly the x86 steps first, checked against `fe_inv`/`sc_inv` on 4×10⁵ inputs (9 outer iterations on average, 10 at most, as on x86); then the assembly against the prototype, `fe_inv`, `sc_inv` and `fe_pow` on 10⁶ inputs of every shape — canonical, ≥ m, up to 2²⁵⁶−1, short, aliased r == a, 0, p and n (return 0, r untouched): 0 mismatches. Then main's own `test_fe_inv_var` (3,020,828 checks, including the `sc_inv_var` ≥ n section) and `test_fe_pow_sqrt`, both un-gated in `run_tests.py`, plus the ECDSA/schnorr/taproot/musig/ellswift tests and both ABI checks: all PASS.
- **Timing on this Mac** (M-series, 2×10⁵ calls each): `fe_inv` 3.11 µs → `fe_inv_var` 0.84 µs; `sc_inv_var` 1.43 → 0.88 µs; `fe_pow` 5.79 µs → `fe_pow_sqrt` 3.19 µs per compressed-key parse.
- **Full suite:** 413 PASS, 10 SKIP, 15 N/A, 0 FAIL (`test_taproot_block_diff`: 36 mainnet blocks, 0 failures, on the safegcd inversion).

## 2026-09-27 (evening) — a mutated block is dropped and re-fetched, never marked invalid (mainnet 968824)

**The incident.** At 10:00 the mainnet node invalidated the real block 968,824 (its hash is Core's). A peer's compact block prefilled a coinbase WITHOUT its witness; the reconstruction passed the sync drain's `cons_verify` (PoW, txid merkle root — the witness is not in either), was stored, and the apply's witness-commitment phase refused it with `bad-witness-nonce-size`. The apply took that for a consensus rejection: `invalid.dat` got the hash, the archive was truncated, headers rolled back. The chain moved on only because the next peer's compact block, applied 10 s later on a path that never consults the mark, was the block as it really is. The wrong mark stayed in `invalid.dat` for ten hours, until `reconsiderblock` removed it by hand — any header re-sync through that height would have refused the real chain.

**Why it is wrong.** The block hash does not commit to witness data. Core (`IsBlockMutated`, `BLOCK_MUTATED`) never marks a header for a witness mismatch: the bytes are not the block, the block is fine; the peer misbehaved and the block is fetched again. `bad-witness-nonce-size`, `bad-witness-merkle-match` and `unexpected-witness` are all of that kind.

**The fix, shared C on both platforms:**
- `daemon/cmpct_recv.c`: every completed reconstruction is checked against the witness commitment before a caller sees it (Core's `FillBlock` → `CheckBlock`); a failure is a full `MSG_WITNESS_BLOCK` getdata, never a stored block. Both completion paths (mempool-only, and after `blocktxn`).
- `daemon/utxo_live.c`: a witness-commitment failure at apply is a new failure kind, MUTATED, not REJECT. A new hook (`utxo_live_set_mutated_fn`) drops the bytes: `reorg.c`'s `chain_drop_mutated_block` takes the archive back to h−1 through the reorg module's disconnect, with no mark and no headers rollback; `main.c`'s `dl_drop_mutated_block` stops the helpers first and scores the delivering peer when known. The same height mutated three times running is said out loud.
- Tests: `test_cmpct_recv` (a witness-stripped coinbase and a flipped nonce byte, on both completion paths → getdata, the real block → reconstructed) and `test_connect_reject` phase 5 (a mutated block at 151 is dropped: archive back to 150, headers.dat untouched, `invalid.dat` unchanged, then the real block at 151 connects).

**For the x86 side:** the same code, the same bug (note item 16).

**Main merged in the same evening (#316–#323, via the x86 session's `9e62e210`/`2087395d`):** `legs_heard_within` (#316) needed a Darwin branch (`tcp_connection_info`'s `tcpi_rxbytes`, seen-to-change per leg; note item 17); `test_fe_pow_sqrt`, `test_fe_inv_var` (x86 NASM exports the Mac assembly did not have: `fe_pow_sqrt`, `fe_inv_var` — carried to AArch64 the same night, next entry up) and `test_store_map_magic` (`/proc/self/maps`) were N/A on the Mac; the last still is. x86's map magic went to a dword at st+52 (#323); the Mac keeps st+384.

## 2026-09-27 — the large fixtures fetch from the local Core; test_taproot_block_diff runs on the Mac

- **WAL-3 on Darwin: `secure_lock` sets the core-file limit to 0, soft and hard.** Darwin has no `MADV_DONTDUMP`, so a wallet page could not be kept out of a core file per mapping; until today a Mac relied on the default soft limit of 0, which `ulimit -c` undoes. Now the process that holds a secret can never write a core, and cannot raise the limit back. `test_secure_lock` raises the soft limit first and asserts the zero, the refused raise, and the lock itself (wired, per the kernel's vm map). Trade: no core dumps of the daemon once a wallet is loaded, which is what "excluded from core dumps" in the startup line has meant on x86 all along.

- **`port/osx/fetch_fixtures.sh`** fetches the gitignored fixtures from this Mac's Bitcoin Core (txindex) instead of the x86 box's scratch oracle: `validation/fetch_taproot_blocks.py` now honours `CORE_CLI`, and `port/osx/core_cli.py` is the bitcoin-cli stand-in it gets (JSON-RPC on 8332, credentials from bitcoin.conf, never printed).
- **`test_taproot_block_diff`**: all 36 taproot-dense blocks (825000–825015, 840000–840007, 870000–870007, 850000/1, 860000/1), both directions, 0 failures on the assembly build. It was SKIP on the Mac until today.
- **block413567.raw**: `run_tests.sh` exports `CORE_BENCH_BLOCK` when it is present. `bench_abi_audit` then audits 16 primitives (12 without it) and `test_strip_witness_diff` runs; both PASS. The remaining consumers of that block are the x86-only twin tests.

## 2026-09-26 (night) — the C twins are assembly: every x86 module has an AArch64 assembly counterpart

**Every `port/osx/*_twin.c` that the daemon linked is now AArch64 assembly**: 37 modules in 5 batches. Each twin moved to `port/osx/test_support/` as the differential oracle. The daemon build globs `port/osx/*.{c,S}`, so a twin there can never be linked again by accident. `sc_mul`/`sc_mul_512`, which still tail-called C, are assembly too.

- **The modules:**
  - EC: fe, point, point_ct, ecdsa, pubkey, schnorr, taproot;
  - hashing: muhash, sha1 (the ARMv8 SHA-1 instructions), ripemd160;
  - script: sighash, script, multisig, bech32;
  - chain and consensus: chainwork, cons, headers;
  - storage: utxo, utxo_stats, utxo_store, store, store_fast, idx, utxo_lsm;
  - network and CLI: net, p2p, addrmgr, cli.
- **The method, per module:**
  - a differential fuzz against the renamed twin; where the twin itself was suspect, also against an independent answer (Python bigints, hashlib, real mainnet blocks, real file bytes);
  - the module's own tests;
  - the AAPCS64 probe (a 9/11-argument variant for the stack-argument functions);
  - `run_tests.sh` in full after each batch: 406 PASS, 13 SKIP, 14 N/A, 0 FAIL every time.
- **Real-data check (utxo_lsm):** `bmc_utxo_setinfo --muhash`, built against the assembly and against the twin, over a snapshot of the signet node's UTXO set: 77,497,355 coins at 323,861, identical counts, amount and MuHash.
- **Darwin arm64 ABI points that mattered:**
  - variadic arguments (`open`'s mode, `fcntl`'s arg, `snprintf`'s values) go on the stack;
  - stack arguments are packed by natural size;
  - thread-locals are Mach-O TLVs.
  - Large stack buffers are taken in touched 4 KiB steps, or avoided: cons hashes the stripped tx in pieces rather than copying it into 1 MiB.
- **Bugs the differential tests found in the twins** (production code until today; each twin is corrected with its assembly):
  - `store_fast`: an evicted fd-cache slot kept its closed fd when the re-open failed. Once the number was reused, a read of the old file returned another file's bytes (x86 empties the slot). The map-cache magic sat inside fd-cache slot 7 (x86 too: note item 15), leaking a blk mapping each time.
  - `utxo_lsm`: a failed recount or compaction closed fd 0, and whatever file had it next, because unreached slots were still zero-filled.
  - `chainwork`: `u256_div` lost the borrow when a divisor limb was all-ones.
  - `schnorr`: the e·P negation tested 3 of the 4 Y limbs.
  - `store`: blk names past 99999 were cut to 12 characters.
- **What remains C on the Mac, and why:**
  - `utxo_lsm_mm.c`: the vendored mmap fast path, C on x86 as well;
  - `base32.c`: C on x86 as well;
  - `g_comb_table_data.c`: a data table;
  - `tls_*.c`: thread-local definitions;
  - `darwin_stubs.c`, `bmcshim.c`: Darwin glue.

## 2026-09-26 — the native test sweep: every gated test runs on the Mac, bar 14 that are x86-only by nature

The phase-4 sweep (every `./tests/*` command of `make test`, built natively against `port/osx/daemon_out`) is worked through. **It is repeatable: `port/osx/run_tests.sh` builds the daemon objects, tools and test helpers and runs the whole suite (or named tests) the same way; exit 0 = every test PASS, SKIP or N/A.** Real bugs it found today, all fixed:

- **Mac port:**
  - `node_log_open` used Linux open flags and AT_FDCWD (every open failed);
  - no robust mempool lock on Darwin (MEM-20);
  - `utxo_prefetch` was a no-op: 210 → 78 ns per memtable miss once it was implemented.
- **Shared code:**
  - `wallet_cli`'s passphrase prompt dropped an answer typed right after it (TCSAFLUSH after the prompt);
  - `addr_hist` was not thread-safe under concurrent Esplora `/address`;
  - `getmemoryinfo "mallocinfo"` now refuses as Core does without glibc.
- **Missing twins:** `cli_main`, `multisig_verify`/`p2sh_hash`, an exported `schnorr_x_eq_r`, and `utxo_prefetch_n`.

Test-only stand-ins live in `port/osx/test_support/`, outside the daemon build:

- the frozen field, point and ECDSA references;
- the fe-inline probe;
- the bad-sparse LSM variant;
- the AAPCS64 callee-saved probe (19 registers).

The ABI audits, `test_abi_stack_align`, `test_elf_hardening` (Mach-O) and `test_mpool_get_once` (load emulation, no ptrace) have Darwin branches that check the same property.

**Environment prerequisite.** `test_mux_dial_gate`, `test_dlc_interleave` and `test_dlc_wire_bytes` need distinct loopback IPs, and macOS answers only 127.0.0.1. Without aliases they SKIP with the command; with `sudo ifconfig lo0 alias 127.0.0.{2,3,4} up` all three pass (verified 2026-09-26, aliases removed afterwards).

**x86-only by nature (not run on the Mac).** Each of these checks an x86 ASSEMBLY TWIN, bug for bug, against the C function it was converted from. No production code calls any of these twins on either platform (`txv_parse_asm`'s only reference is a test hook in `tx_verify.c`). Both daemons run the C side, which is covered on the Mac by its own tests.

- `test_txv_parse_diff`, `test_txv_classify_diff`, `test_segwit_classify_diff`, `test_txvb_parse_diff`, `test_txv_pools_diff`, `test_tapagg_diff`, `test_txv_dispatch_diff`
- `test_wv0_drv_diff`, `test_svs_drv_diff`, `test_checksig_diff`, `test_bip143_diff`, `test_taproot_verify_diff`, `test_bip341_diff`
- `test_undo_asm_diff`: `bitcoin_undo.asm` against a frozen copy of the pre-rev-file `undo_log.c`. Both daemons now link `daemon/undo_log.c`, whose on-disk format moved to Core-style rev files in ec2979c2.

## 2026-09-25 (evening) — phase 4: the UTXO set is identical to Core's; three real bugs fixed, one repaired in production

- Attested against a local Bitcoin Core at mainnet 968,570: all five fields
  identical (muhash once printed in Core's byte order). Sample of 16,528
  coins identical to Core's gettxout.
- Fixed: the muhash computation (9634b5a9) and display (c42cc03f, shared);
  fe_mul's dropped fold carry (f4938f99); the LSM twin's duplicate keys and
  unbloomed tombstones (0e3d6ed2), which made 17% of recently spent coins
  answer as unspent on mainnet -- repaired by an offline full compaction
  (set preserved, muhash identical before and after), 0 after.
- Phase 4 is under way: the native sweep's remaining failures are listed in
  the worklog (Round 6).

## 2026-09-25 — the Mac sync pass drifted from x86; synced_headers on quiet legs

- port/osx/bitcoind.S (node_sync_multi, the handshake) was last re-ported
  2026-09-10 and missed x86's later changes. Fixed today (4500868c): the
  fetch gate (one request per block across legs; skip stored blocks) and a
  refused duplicate ending the pass well. Still missing: compact blocks in
  the pass and the version message's live fields (timestamp, per-connection
  nonce, start_height, addr_from port) -- test_cmpct_fallback and
  test_bitcoind fail natively, identically before and after.
- New legs get Core's getheaders from pprev (ad11ac5a, 61eaa0f9), so
  getpeerinfo's synced_headers/synced_blocks read the tip within seconds.
  Mainnet and signet run 61eaa0f9.

## 2026-09-24 (night) — signet IBD green: phase 3 complete; getpeerinfo synced_blocks

- **Signet synced from genesis on 2cb7a418** (`~/bmc_signet/`): 323,566
  headers in 23 s, every block in 21:51, applied to the tip in 25 min, zero
  rejects; tip 323,567 hash identical to mempool.space's. All four chains
  (regtest, testnet4, signet, mainnet) have now synced natively: **phase 3
  is done.** Left: the phase-4 parity sweep, and the LSM apply gap
  (33-47 ms/blk in output-heavy stretches, vs x86's ~13).
- getpeerinfo `synced_headers`/`synced_blocks` were constant -1 (aada0228,
  shared, for main); live on mainnet. Remaining gap: a leg that has
  announced nothing stays -1, where Core reads the tip via a getheaders from
  `pprev` (docs/PARITY_RPC_FIELDS.md).
- build_daemon.sh now rebuilds on any header change (2cb7a418); it had no
  header dependencies, so struct changes could link mismatched objects.
  Nothing stale was in production.

## 2026-09-24 — mainnet at the tip in production; ad4f0d9b reverted; the reorg gap and the int/long twin returns fixed

- **Production (m5ultra, `~/bmc_osx_deploy`):** mainnet IBD finished.
  The UTXO set was rebuilt from the archive after the sorter fix
  (f9368f9e: a u32 index wrapped on a 71M-entry flush, halting at
  274,443). The node reached the tip, 968,463 with IBD false, and
  follows it (968,467 at 23:28Z, 11 peers, 165.2M txouts). Redeployed
  on 9e728d57 at 23:29Z; rollback `bmcbitcoind.pre-9e728d57`.
- **Apply rate ~5 -> ~11.5-14 blk/s (343bc1a7):** the LSM per-thread
  mapping cache was direct-mapped (run_no % 64). The 15 GB base run
  shared a slot with a fresh run, so every lookup remapped both. It is
  now fully associative with LRU. x86 had the same bug, ported to main
  as #299.
- **ad4f0d9b reverted (deab9fe2):** `tx_verify.c` is main's copy whole.
  The testnet4 h=124,864 failure was 182c0d87's no-op semaphores
  (Darwin has no unnamed `sem_init`), not a thread race: no second thread
  calls into tx_verify.c. Shown three ways:
  - on x86 (19f26cfc);
  - natively with the same replay (main's file 18/18 in 3 of 3 runs,
    ad4f0d9b SIGSEGV at 124,864 in 2 of 2;
    `worklog/2026-09-24-ad4f0d9b-repro/build_osx.sh`);
  - on a testnet4 node from the network (synced through all three
    failure heights).
  This also removes the tx_verify.c merge conflict and the gcc -Werror
  blocker between main and bmc_osx.
- **Found by the testnet4 node, fixed:**
  - 56519b5b (shared): the archive check wrongly flagged non-mainnet
    NET-15 frames, and STO-11 then blanked valid blocks.
  - bd1700d4: a hole below the archive tip is now re-fetched under
    `bmc.bootcatchup=0`.
  - **05c01822 (shared, x86 porting to main):** a reorg forking above
    the applied height moved the apply past never-connected blocks.
    Testnet4, 23:01Z: applied 153,876 -> 153,892 with 153,877-887 never
    applied, so the UTXO set was silently wrong. The rewind now only
    moves down, and replacements apply only in turn.
  - **a419e3e0 (osx only):** `chainwork_cmp` and nine store twins
    returned `int` where callers declare `extern long` (the x86 returns
    rax). On arm64 -1 read as 4294967295: lighter chains compared
    heavier, and store_append's failure read as a valid height. main's
    test_reorg passes on arm64 for the first time (19 failures -> 0).
- Also today: the dial storm (Darwin ignores `SO_SNDTIMEO` on connect;
  SCM_RIGHTS sockets arrive dead if the sender exits first), the
  SIGTERM-deaf worker, the 10-minute stop (Darwin's 8 KB socketpair),
  #297's NULL-TLS worker crash, and getpeerinfo 0 on a Mac (9e728d57:
  `TCP_CONNECTION_INFO` for Linux's `TCP_INFO`).
- **Tests that don't run on a Mac as written:**
  - test_dlc_interleave, test_dlc_wire_bytes, test_mux_dial_gate: they
    need 127.0.0.x aliases on `lo0` (root), and the first two use
    Linux-only `TCP_QUICKACK`.
  - test_ir5_sighash_cache: uses Linux's `cpu_set_t`.
  - The six tx_verify `*_diff` tests: they compare against x86 asm twins
    that were never ported.
- Known degrade unchanged: tx_handoff's ring mutex isn't robust on macOS.
  Remaining p3/p4 at the time: signet IBD (done that night), the phase-4
  parity sweep.

## 2026-09-23 — main merged (245 commits, #190–#292); five Darwin guards; serve/store/net re-ports; stop-wait e2e 35/35 on Darwin

- Merge of #190–#292: index runs + trailing builders, the departure
  journal, tx handoff to the download worker, zmq `sequence`, cluster
  mempool completion, stop-waits-for-worker, RPC parity rounds, three new
  harness suites. Conflicts: node_config.c (main's lazy `IV` parse
  supersedes the branch's deferred note/report — same DMN-9 bug, main's
  fix is the keeper) and the 09-12/09-14 worklogs (both streams, as
  before).
- New daemon sources in build_daemon.sh: index_runs, index_trail,
  mempool_journal, tx_handoff, mempool_cluster (merge_index_runs is the
  standalone bmc_merge_index_runs TOOL — own main — not a daemon object).
- Darwin guards: SYS_close_range (notify.c; loop is the path), eventfd →
  pipe pair (zmq_pub.c), posix_fadvise → F_RDADVISE (rpc_chain.c),
  robust-mutex refuse (tx_handoff.c; MEM-20 road, degrade documented),
  and main.c's stop-wait lock-holder scan rebuilt on libproc (KERN_PROC +
  PROC_PIDLISTFDS + PROC_PIDFDVNODEPATHINFO by dev+ino; proc_pidpath for
  comm; PROC_PIDTBSDINFO for is_my_child — the /proc version silently
  orphaned every serve child's SIGTERM at stop; _NSGetExecutablePath for
  /proc/self/exe; proc_exit_pending 0 with our own worker still tracked
  via waitpid + kill(0)).
- Re-ports of changed x86 asm: bitcoin_net's g_p2p_read_hook wrapper
  (net_twin.c, v1+v2, announced plen), bitcoin_serve's
  tx_accept_serve_tx + internal-order inv tip (bitcoin_serve.S),
  bitcoin_store's pos_file_no (+44) invariant + drop-fd/frontier/retake
  (store_twin.c). bitcoin_idx's probe-budget fix was born correct in the
  twin (6fed3a71).
- store_get_at meta[2] high-half garbage caught by main's new
  test_append_unshared_frontier (4 file-no assertions at 2^32+k); masked.
- Gates native green: stop-wait e2e 35/35 (real daemon, 4 cycles — the
  libproc scan names/clears holders, never counts the stopping parent),
  tx_handoff 13/13 (section 6 robust-recovery SKIPped on Darwin — no
  robust mutexes; skipped, not weakened), node_config, frontier, store,
  p2p_msgsize, net, zmq_queue. bmcbitcoind + bmc_wallet_cli LINK OK,
  zero undefined.
- Known degrade recorded: tx_handoff's ring mutex is not robust on
  macOS; a crash mid-hold (two memcpys) stalls the survivor's next
  push. Darwin death-safe lock = follow-up decision.

## 2026-09-12 — main merged (131 commits); daemon relinked green; deploy home is ~/bmc_osx_deploy; mainnet IBD resumed after a 21.5h stall

- Merge cce2f5d7 (#175–#189). Two add/add worklog conflicts resolved by
  keeping both streams (x86 section annotated). Build fixes 045c8c07
  (SYS_ioprio_set guard, build_gen.h generation in build_daemon.sh) and
  061bfeca (four new C twins + four bitcoind.S data symbols). LINK OK,
  zero undefined symbols.
- The deploy runtime (binary, conf, 431 GB mainnet datadir, logs,
  start.sh/stop.sh) moved from /tmp to ~/bmc_osx_deploy/ —
  macOS clears /tmp at boot and daily-cleans 3-day-old files; a reboot
  would have cost the whole IBD. /tmp paths remain as symlinks. The dev
  repo is unchanged at ~/bmc_osx/bitcoinmachinecode.
- Mainnet IBD had been frozen at 777,321 (80.43%) since 09-11 23:13 —
  silent peer death, no redial ("peers exhausted", retry ring every
  2 min). Relaunched on the merged binary (which carries main's newer
  stall/redial work): resumed immediately, 777,681 -> 780,601 in the
  first 90 s, zero consensus failures.
- Push backlog cleared: origin is HTTPS via the gh credential helper,
  pushed through 061bfeca. Remaining p3/p4: signet IBD, mainnet connect
  green, parity sweep.

## 2026-09-11 (night) — FOUR more root causes; testnet4 UTXO connect GREEN end-to-end; node synced + following tip

The session took the port from "one known WV0 divergence" to a fully
synced, live-following testnet4 node. Four distinct bugs, each found by a
faithful differential driver, each with a committed gate:

1. **TLS_ADDR dropped the getter result for CALLEE-SAVED destinations**
   (253bb349). The macro delivered to x0-x17 via save slots only; for
   x19-x28 destinations (three sites: TLS_ADDR x24,_hnd_tab in _hnd_end,
   TLS_ADDR x27,_cms_scstrip0/1 in the CHECKMULTISIG strip) the getter's
   return was silently discarded and the register kept stale garbage ->
   hnd_end's cycle walk elem_move'd to wild addresses (the harness SIGBUS)
   and records resolved through junk (the twin's final EQUAL pushed empty
   -> EVAL_FALSE). The "WV0 zero-length-element divergence" entry below is
   OBSOLETE: script_eval's zero-length handling was correct all along.
   Evidence: wv0_zero_drv.c (real h=124,845 script+stack; was SIGBUS, now
   byte-identical to x86), wv0_full_drv.c (the EXACT daemon entry
   sv_verify_witness_v0 on all four p2wsh inputs: was 4x err=2, now 4x
   err=0), wv0_rep.c (121-prefix-cut sweep, byte-identical).

2. **tx_verify's arenas were shared across threads with no lock**
   (c64ae055). The connect thread ran tx_verify_block_connect_all while
   the same worker process's net thread accepted relayed txs (orphan/1p1c)
   through txv_parse, which bump-resets g_wit_pool and grows g_spk_pool ->
   a mid-connect admission rewrote the pools Phase 1 had just filled:
   inputs classified against a real p2wpkh program verified against ANOTHER
   transaction's spk bytes and witness lengths (witlens=64,64 -- no such
   items exist in the real block) -> bogus rejects + invalidations
   (h=124,864/125,673/126,361). glibc's realloc rarely moves; macOS's
   moves near-always. All entry-path arenas are now __thread.

3. **ecdsa_x_eq_mod_n: dead r+n branch + wrong p-n constant** (4f109a20).
   The twin's compare chain returned on r[3]==PMN[3]==0 where the x86
   falls through per limb -- the second candidate (affine R.x in [n,p))
   was dead code -- AND its PMN_LIMBS transcription was two digits off
   (0x402DA1732FC9BEBF vs asm 0x402DA1722FC9BAEE). Random differentials
   hit the [n,p) band with probability ~2^-127; h=126,683 tx=93 carries a
   CONSTRUCTED signature (sha256 of a brute-forced 16-byte preimage is a
   valid DER signature; r=10B, s=15B) whose R.x sits there. Gate:
   test_ecdsa_xmod.c -- contract pinned across both branches + p-n
   boundary + three Z values; the SAME gate passes against the x86 asm.

4. **txvb worker-pool semaphores are no-ops on macOS** (02b0d077). sem_init
   fails on Darwin (no unnamed semaphores) so BOTH barriers silently
   vanished: workers read uninitialized slots (SIGSEGV at
   txvb_verify_one+100 through a wild spk_pool, killed the connect worker
   four restarts in a row) and txvb_verify_all drained res[] before the
   workers finished. Mutex+condvar with an explicit round generation;
   identical semantics on Linux.

   Also: the remaining static-TLS arrays converted to heap scratch
   (63284ff2) -- p2wpkh_script's TLV getter faulted in the forked connect
   worker (SIGSEGV ACCERR at the TLV write) in shapes no standalone driver
   reproduces; bmc_thread.h's heap-TLS convention is now universal on the
   verify path.

**STATE: testnet4 FULLY SYNCED on the native daemon** -- getblockchaininfo
verificationprogress=1, initialblockdownload=false, blocks=headers=151,987
(151,988+ live), 14.2M txouts, heartbeats clean, DNS-seeded peers, zero
consensus failures since the fixes. Mainnet catch-up continues on the same
binary (79.8% stored at session end, connect engages at the .242 handoff).
Remaining p3/p4: signet IBD, mainnet connect green, parity sweep, push (39+
commits pending on this Mac -- origin publickey still blocked).

## 2026-09-11 (late II) — vfexec zero-size TLS: the real tapscript root cause; one WV0 divergence left

- The h=123,615 tapscript failure was NOT the script_eval semantics: the
  generated TLS header had `__thread unsigned char vfexec[0]` — a
  zero-length condition stack whose writes ALIASED vfexec_sp (the next
  TLS variable). Every OP_IF/ELSE toggle wrote the condition byte over
  the depth: TRUE at depth 1 survived by luck; the OP_ELSE toggle wrote
  0x00 over depth 1 → UNBALANCED_CONDITIONAL at ENDIF. Fixed (ddb687d3):
  vfexec is a lazily-allocated per-thread heap block behind the getter.
  h=123,615 now PASSES; the p2wsh/p2tr driver passes 88/88 (x86 parity);
  the whole script-VM gate set is green.
- NEW divergence found by the continuing connect: h=124,032 and h=124,845
  fail with "p2wpkh signature invalid"/"p2wsh script verification failed"
  (err=2 EVAL_FALSE) — witness-v0 scripts with ZERO-LENGTH initial-stack
  elements (witness {empty,empty,empty,71B-DER-sig,121B-script};
  x86 verifies the same block). The checksig stub differential shows the
  twin's CHECKSIG receiving sig DATA=zeros with the RIGHT length — the
  stack element handling around zero-length elements diverges from the
  x86 inside script_eval (the harness also crashes in hnd_end's cycle
  walk — a second symptom of the same element-move class). This is the
  one remaining consensus-path blocker; the reproducer is
  /tmp/wv0_dbg.c (script+stack from block 124,845 tx#167, stub checksig,
  SIGV_WITNESS_V0) against the ported interp objects.

## 2026-09-11 (late) — the last known consensus blocker: one tapscript divergence

- testnet4 chain IBD complete (151,869 headers+blocks stored, verified);
  the UTXO connect verified 0..123,614 (13.9M txouts live, 6.06 ms/blk
  with the mm path) and halts at h=123,615 on "p2tr tapscript execution
  failed". Isolated with the new differential driver
  (port/osx/tests/p2tr_block_drv.c + p2tr_block_123615.txt: all 88
  taproot inputs of that block): **x86 88/88 pass, osx twin 86/88** --
  tx#57 vin#0 and tx#62 vin#0 fail. Both are 6-item script-path spends
  (witness {sig,sig,preimage,01,script,control}; script =
  IF HASH256 <h> EQUALVERIFY CHECKSIG <32> CHECKSIGADD 2 LESSTHANOREQUAL
  ELSE ... ENDIF). The interpreter mechanics are individually correct
  (fragment bisect: IF/HASH256/EQUALVERIFY/args all fine; the only
  in-fragment failures are the expected CLEANSTACK/EVAL_FALSE) and the
  BIP342 sighash gate is 51/51 -- the divergence needs the REAL
  checksig_fn context (taproot_sighash + schnorr under the 4-deep
  initial stack). The driver itself had three context bugs on the way
  in (num_inputs as byte length, 32-byte prevouts instead of 36-byte
  outpoints, unprefixed spks) -- the x86 fails identically on a wrong
  context, which is how the driver was trusted.
- Status: the tapscript block at h=123,615 now PASSES (vfexec fix); the
  connect advanced to h=124,032/124,845 where p2wsh inputs with
  zero-length initial-stack elements fail with EVAL_FALSE (err=2).
  The x86 verifies the same blocks (r=1). Isolated: the twin's
  script_eval handles the CHECKSIG/SWAP/SHA256 sequence correctly
  through the per-opcode trace (29 opcodes, one checksig callback,
  matching x86), but the final NUMEQUAL evaluates false — the stack
  element handling for ZERO-LENGTH initial-stack elements diverges
  inside script_eval (the harness also faults in hnd_end's cycle walk
  with the same elements). Reproducer: /tmp/wv0_dbg.c-style runs
  against the ported interp objects with the block-124,845 tx#167
  script+stack. THE ONE REMAINING consensus-path blocker.
- Mainnet: 650k+/966k stored (67%) on the fully fixed binary, zero
  consensus failures; the connect engages at the .242 tail handoff.

## 2026-09-11 — testnet4 IBD green; two more real bugs (segwit txid, radix tie-break)

- testnet4 (DNS seeds, public peers, 151,865 headers + all blocks from
  genesis) exposed two bugs the daemon's store-only catch-up could not:
  (1) cons_twin txid_of_span hashed the witness into segwit txids (the
  legacy fix had moved `body` past the witness skip) -- every segwit
  block failed cons_verify; (2) the utxo_lsm_twin radix sorter's 96-bit
  tie-break was direction-inverted -- same-txid tie groups came out of
  the flush DESCENDING and point lookups past the inversion missed, so
  the UTXO apply halted deterministically at h=51,859 (the first memtable
  flush). Both fixed and gated (test_lsm_tie_order.c new; the four LSM
  harnesses + test_cons re-run green). Also: utxo_live_run_budget read
  /proc/meminfo (Linux-only) -> zero compaction budget on macOS.
- Mainnet: 449k+/966k stored, following .242's tail; UTXO connect will
  engage at the handoff (the interp/TLS and LSM fixes above are IN that
  binary now).

## 2026-09-10 — MAINNET IBD RUNNING on Apple Silicon

- The native bmcbitcoind (M1 Max, macOS 26.6) is doing a real mainnet IBD
  right now: 966,400 headers stored (headers.dat 108,236,800 B, ~29 min),
  then blocks from genesis via the boot catch-up against the x86 reference
  node (`connect=192.168.5.242:8332`, which is itself mid-IBD -- the osx
  node follows its tail live). 115,401/966,400 stored (11.9%) at elapsed
  5:01, ~460 blk/s, zero consensus failures. No debugger was usable on
  this machine (lldb attach/launch permission-gated); the crash backtraces
  came from macOS DiagnosticReports .ips files plus an in-worker
  siginfo+backtrace handler.
- Enabling commits: bc38f9e8 (the p2/p3 wave: syscall .S ports + C shims +
  native build + the fixes below) and the diagnostics commit. Regtest IBD
  end-to-end green first: fresh node B pulled 113 blocks from node A over
  the wire (3 chunks, ~10s), UTXO applied 113/113, tip hashes identical.
- Four port bugs the IBD path caught (details in worklog/2026-09-10.md):
  three raw-svc sites still using the Linux nr-in-x8 convention
  (idxscan flock x2, node_log openat -- SIGSYS/SIGSEGV roulette in the
  worker), node_make_version's double-deref of _node_services (SIGSEGV at
  0x809 in the probe handshake), and cons_twin txid_of_span's legacy-tx
  strip offset + cap-semantics confusion (caught by test_cons).

## 2026-09-09 — secp256k1_taproot twin landed; bip341 gate scoped

- **secp256k1_taproot -> taproot_twin.c** (C twin): tagged_hash256,
  tap_branch_hash, tap_leaf_hash, taproot_tweak_pubkey (1 even / 2 odd,
  parity captured before even-normalising), tap_merkle_root.  Gates:
  upstream test_taproot ALL PASS native + 227-record cross-arch
  differential byte-identical vs .242 (tags/msgs to 200 KB, leaf
  compactsize boundaries, tweak rejections x>=p/t>=n, merkle depth 0..8).
- bitcoin_taproot_sighash.c (the bip341/bip342 production C) is
  arch-neutral and needs this twin at link time; its harness
  test_taproot_sighash pulls bitcoin_interp/scriptcodec/sha1, so the
  bip341/342 gate lands with the script VM wave -- the same deferral
  pattern as test_ir10 (script) and test_segwit_sighash (witness_v0).
- Session total so far: bitcoin_keys.S, bitcoin_addr.S, bitcoin_bip32.S
  native; sighash/script/taproot twins; bip143 no-port gate; hmac x25 ABI
  fix; harness UB fix; schnorr bench corrected 273 -> 80 us.  24 commits
  pending push (origin publickey still blocked from this Mac).

## 2026-09-09 — bip143 (no port needed) + bitcoin_script twin; schnorr bench was 3.4x inflated

- **bitcoin_bip143: NO PORT NEEDED.** Production calls bitcoin_segwit.c
  (arch-neutral) directly; the asm module is only the differential harness's
  perf twin.  Gate: native test (BIP143 published example + real block-481824
  tx 562 with the actual witness signature verified through ecdsa_twin under
  the C's sighash + swtx_parse contract) and a 1,635-vector corpus dump
  byte-identical three ways: osx-C == x86-C == x86-ASM.
- **bitcoin_script -> script_twin.c** (C twin): test_script + test_p2pkh
  green native; 18.7 KB cross-arch diff byte-identical; the differential
  caught der_long_len re-masking the first length byte as the count (the
  upstream short-form-only harnesses could not see long-form INTEGERs).
- **pubkey_schnorr_twin.c carried committed bring-up debug inside
  schnorr_verify** (two fe_inv + fprintf per call).  Removed; BIP340
  19/19 re-verified; bench CORRECTED 273.11 -> 79.92 us/verify (3.4x;
  BENCHMARKS_OSX.md updated).  Two process lessons recorded: (1) the first
  removal pass dropped the real point_scalar_mul_fixed(SG,sL) call with the
  debug block -- caught only because bench_schnorr refuses to time a
  fixture that does not verify; (2) hand-transcribed fixture hex carried
  two silent copy errors -- regenerate fixtures programmatically.
- segwit-v0 sighash is now fully Darwin-covered.  Next: secp256k1_taproot
  (tagged_hash256/tweaked_pubkey) to unlock the bip341 gate, then the
  script VM wave.

## 2026-09-09 — keys/addr/bip32 native + sighash twin: wallet derivation covered

- Four modules landed, three as native AArch64 asm (details in
  OSX_ROADMAP.md; commits 3db7bd97, 1092ebee, 5cfccf4d, 404f968b):
  **bitcoin_keys.S** (test_keys 6/6 + 647-record diff), **bitcoin_addr.S**
  (test_addr 5/5 + 56-record diff; the x11-cursor pitfall again),
  **bitcoin_bip32.S** (all four upstream bip32 harnesses + 990-record diff;
  frame-overrun, byte-0-skipping carry loops, and the AAPCS64
  eight-register-arg extkey contract all caught by the gates), and
  **sighash_twin.c** (test_legacy_sighash 500/500 Core vectors +
  test_find_and_delete 23/23 + test_sighash_oob + 143 KB diff).
- REAL PRE-EXISTING PORT BUG fixed: bitcoin_hmac.S used x25 without saving
  it (callee-saved; main's GOT anchor) -- latent until the dbip32 driver,
  which parks x25 across bip32_master -> hmac_sha512. Prologue/epilogue
  now save/restore x25,x26; test_hmac re-verified green. First port bug
  found by a caller's register pressure rather than a gate's value check
  -- the differential drivers earn their keep as ABI stress.
- UPSTREAM HARNESS UB fixed: test_bip32_master.c's sscanf %2x into
  (unsigned*)&kg[i] spills 3 bytes into adjacent frame vars (zeroed
  kg[0..2] and the caller's c[0..2] under clang's layout; the k/c outputs
  were correct all along). Fixed to the unsigned-temp pattern; verified
  green on BOTH arches (.242 re-run).
- With this wave the wallet key-derivation path (seed -> master -> path ->
  xprv/xpub/address) and the legacy sighash preimage builders are fully
  Darwin-covered. Remaining p1: bip143/bip341/bip342, taproot, and the
  script VM (interp/scriptcodec/script/multisig/script_flags).
- Session housekeeping: removed a stale utxo_lsm_twin-*.o.tmp; push still
  blocked from this Mac (origin publickey), 20 commits pending on bmc_osx.

## 2026-09-09 — docs backfill: the point→cons wave (8b341e41..5b7f679f)

- Ten modules landed in a fast wave without per-module state/roadmap
  entries (the worklog jumped from fe_twin to net_twin). Durable record
  now in OSX_ROADMAP.md, evidence from the commits + in-file headers:
  - **secp256k1_point/point_ct** (point_twin.c, point_ct_twin.c,
    g_comb_table_data.c): test_point + test_point_inf native, 1200 +
    1740-record cross-arch diffs byte-identical (8b341e41, 93a4d015).
  - **secp256k1_ecdsa + bitcoin_pubkey/secp256k1_schnorr**
    (ecdsa_twin.c, pubkey_schnorr_twin.c): BIP340 verify native + first
    cross-arch verify benches (BENCHMARKS_OSX.md); fixed sc_inv_var
    `ldp x25,x25` SIGILL (b25968b9).
  - **bitcoin_chainwork/muhash/utxo_stats** (chainwork_twin.c,
    muhash_twin.c, utxo_stats_twin.c): test_chainwork 0F + test_muhash
    green on Core-oracle vectors; test_tmpdir.h Darwin shim (50526b34).
  - **bitcoin_utxo + bitcoin_store_fast** (utxo_twin.c,
    store_fast_twin.c): test_utxo 0F, test_store 0F, bench_store_read
    byte-exact (b611922b; store_twin born here, completed a253ef93).
  - **bitcoin_cons** (cons_twin.c) and **bitcoin_headers**
    (headers_twin.c): test_cons / test_headers green (5b7f679f,
    9f112d91); cons + headers gates re-run green in this session.
- Session housekeeping: removed a stale utxo_lsm_twin-*.o.tmp; push still
  blocked from this Mac (origin publickey), 15 commits pending on bmc_osx.

## 2026-09-09 — bitcoin_net twin: first p2 syscall module landed (C twin)

- `port/osx/net_twin.c`: BIP314 v1 framing + fd plumbing + v2 dispatch +
  upload-pacer hook, all 12 public symbols of asm/bitcoin_net.asm. Gates:
  upstream test_net 19/19, test_p2p_msgsize 14/14 (oversize -3 + no-drain +
  NET-11 checksum), hook-arg smoke, live tcp_connect_ip vs .242:8332, and
  a 240-frame p2p_frame cross-arch differential byte-identical vs the x86
  objects (dnet.c + gen_dnet_vecs.py; includes two 4MB P2P_MAX_MSG frames).
  Commit 45fe22bb.
- Twin bug the upstream-equivalent gates caught: a half-finished edit left a
  DUPLICATED drain loop and checksum-before-drain ordering; x86 order is
  checksum (only when announced<=cap) THEN drain, and *plen_out is written
  AFTER the drain (test_net's post-drain-alignment check pins this).
- headers_twin landed just before this (9f112d91, test_headers all green,
  hst_append returns new count). IBD-path assembly pair bitcoin_net +
  bitcoin_headers is now Darwin-covered. Next: bitcoin_p2p message builders
  (p2p_getheaders etc. -- pure compute) then addrmgr/idx, keeping the
  one-module-one-gate rhythm.

## 2026-09-09 — bitcoin_p2p twin: IBD message layer complete (C twin)

- `port/osx/p2p_twin.c`: p2p_getheaders (Stage A multi-hash locator,
  count 1..252), p2p_getdata_block (MSG_WITNESS_BLOCK 0x40000002), p2p_ping,
  p2p_headers_count, p2p_inv_count, p2p_inv_get. Gates: upstream test_p2p
  18/18 + test_p2p_inv 12/12 native, 130-record cross-arch differential
  byte-identical vs x86 (dp2p.c + gen_dp2p_vecs.py). Commit 57588bdb.
- With net_twin + headers_twin the whole IBD wire path (framing, message
  builders, header store) is Darwin-covered. Next: addrmgr/idx, then the
  big store modules, keeping one-module-one-gate.

## 2026-09-09 — bitcoin_addrmgr twin landed (C twin)

- `port/osx/addrmgr_twin.c`: peers.dat book (init/count/add/get_i/lookup)
  + addr v1/v2 codecs + addr_count. Gates: upstream test_addrmgr 28/28
  (Core-reference codec bytes), 73-record cross-arch differential
  byte-identical vs x86 -- result stream AND the resulting peers.dat file.
  Commit 2725d14b.

## 2026-09-09 — bitcoin_idx twin landed (C twin) + REAL x86 BUG found

- `port/osx/idx_twin.c`: hash->height open-addressing index (init/put/get/
  count/build_from_file), layout-compatible 48B slots. Gates: upstream
  test_idx 12/12, 868-record cross-arch differential byte-identical.
  Commit 6fed3a71.
- THE DIFFERENTIAL FOUND A REAL X86 BUG: 100%-full table -> x86 idx_put
  spins forever. memcmp_exact clobbers r8b; idx_put keeps the probe budget
  in r8 across the call, so after one non-matching memcmp the budget is
  garbage and `dec r8; jz .full` never fires. Production never fills its
  1M-slot table so it was latent. Vectors regenerated to keep <100% load;
  x86 asm fix goes on main (TODO.md).

## 2026-09-09 — bitcoin_store twin landed (C twin); p2 store layer open

- `port/osx/store_twin.c`: the full block store (init/reload/append/get_at/
  get_tip/get_file_fd/prune family/append_shared family/reorg primitives/
  truncate family), 19 public symbols. Gates: upstream test_store 42/42,
  test_truncate 54/54, 69-record differential byte-identical (retval stream
  AND the full cwd file set via tarball compare). Commit a253ef93.
- Note: prune/truncate run against files by bare relative name -- differential
  harness must start in a scratch cwd (stale prune.dat from a previous run
  poisons store_init's gate restore).
- GitHub push still blocked from this Mac (no gh auth, SSH key unregistered);
  9 commits pending on bmc_osx.

## 2026-09-09 — bitcoin_utxo_store twin landed (C twin)

- `port/osx/utxo_store_twin.c`: WAL + checkpoint UTXO persistence (buffered
  WAL, atomic checkpoint publish, torn-tail truncate, init_ro). Gates:
  test_utxo_store + test_utxo_wal_buffer + test_utxo_torn_tail green,
  124-record differential byte-identical (retvals + utxo.dat/utxo.idx).
  Commit 55c76deb. utxo_struct_size added to utxo_twin.c.

## 2026-09-09 — bitcoin_utxo_lsm twin landed (C twin) -- the whale is done

- `port/osx/utxo_lsm_twin.c` (+ vendored utxo_lsm_mm.c): the LSM UTXO store
  -- flush/sorted-runs/bloom/sparse-index/manifest, multi-run get,
  recount/compact/walk k-way merge, tombstone hash. Gates: 6 upstream LSM
  harnesses green native; 229-record differential byte-identical (retvals +
  WAL/runs/manifest file set). Commit b65c12e1. macOS note: the upstream
  mmap fast path is byte-identical but fails CONCURRENT gets under
  clang-21/arm64 -- defaulted off on __APPLE__, twin path is the anchor
  (documented in utxo_lsm_mm.c).

## 2026-09-09 — bitcoin_hash native: first full 6-op module, x86-diff byte-identical

- `port/osx/bitcoin_hash.S` (7 public symbols) gated three ways: upstream
  test_pow_check 13/13 native, 6,485-vector Python-oracle differential 0
  failures, and byte-identical results vs the x86 bitcoin_hash.o/sha256.o run
  on the 9950X3D (192.168.5.242). Driver pair committed (dvh.c /
  gen_bhash_vecs.py) — batched file-based oracles, no popen.
- Driver bug caught by cross-arch diff: sha256d64 out stride is 32B per 64B
  input (Core SHA256D64 shape); assuming 64B out stride silently compared
  stale memory on BOTH arches and "agreed". Cross-arch diffing only proves
  what the driver actually measures.
- x86-vs-osx benchmarking now possible on shared shapes: bench_hash_core +
  bench_fe build on both. x86 reference numbers captured (9950X3D, cores
  16-19): sha256_1MB 2.40 GB/s, fe_mul THRU 5.54ns, ECDSA verify 47.1k/s/core,
  Schnorr 38.4k/s/core.
- IBD status: x86 full mainnet IBD COMPLETE on .242 (tip 961639, progress 1.0,
  760G, /mnt/2tbssd/bmc-bench deployment). OSX native daemon (p3) still
  blocked on p1/p2 module waves.

## 2026-09-09 — p1 progressing: sha512 + ripemd160 + sha1 landed

- sha1 joined ripemd160 as a C twin (gate 10/10 after fixing a LE length
  field the gate caught). Committed straight to bmc_osx (3ee6c5a5).

- sha512.S native, upstream test 4/4. ripemd160 shipped as C twin after
  two failed asm translations (see OSX_ROADMAP pitfalls); 23/23 + 2.08M
  digest thread-stress green. bitcoin_hash done earlier (PR #134).
- Committed straight to bmc_osx (docs+module batch); next modules:
  sha1, bech32, base32, then the secp256k1 family.

## 2026-09-09 — p0 landed: sha256 is the first native module

- `port/osx/sha256.S` (Mach-O AArch64, 7 public symbols) + native gate
  `port/osx/tests/test_sha256_osx.c` (16 checks, 0 failures) + upstream
  `test_cry6_sha_paths.c` linked unchanged against the Mach-O object (7/7).
  Upstream C compiled untouched; only the x86-only CPUID section of
  test_sha256.c needed replacing (Darwin has no CPUID) — the osx gate
  replaces it with a sysctl cross-check. Full evidence in OSX_ROADMAP.md.
- Recurring-pitfall list started in OSX_ROADMAP.md (sp alignment at bl
  sites, x18/x28 reserved, @PAGEOFF, sysctl probes, python -c limits).
- Next: bitcoin_hash (sha256d/block_hash/diff_target/pow_check) on top of
  the proven sha256, then sha1/sha512/ripemd160.

## 2026-09-09 — strategy locked: native port, phased, PR-per-layer

- `port/OSX_STRATEGY.md` merged via PR #130: port-don't-emulate decision,
  measured surface (238 raw syscalls; C layer POSIX-clean except 2 prctl
  uses; no futex/epoll/eventfd), 5 phases (p0 build bridge → p1 pure-compute
  → p2 syscall I/O → p3 daemon → p4 parity), PR branches `osx/pN-*` merged
  --no-ff into bmc_osx with green gates.
- First working PR target: p0 sha256 proof module (Mach-O build + native
  harness + differential fuzz vs hashlib/Python).

## 2026-09-09 — round 0: fresh start on `bmc_osx`

- Branch `bmc_osx` forked from `main` @1dac38ae (upstream through PR #127,
  addnode dials), pushed to origin, local clone at `~/bmc_osx/bitcoinmachinecode`.
- `main` is declared the x86-64 development tree; `bmc_osx` merges from it,
  never develops into it.
- Toolchain verified: Apple clang 21.0.0, macOS 26.6.2, M1 Max (arm64).
- Reuse strategy: arm-port branch (origin) is the algorithm reference — all
  63 modules were ported and differential-verified there — but its syscall
  layer is Linux-only (`svc #0`, nr in x8). Darwin needs `svc #0x80`,
  nr in x16, Mach-O sections/symbols (`_` prefix), no x28 use, PIC via
  adrp/add. Rough rework weight per module (svc counts from arm-port .S):
  utxo_lsm 66, store 42, utxo_store 30, idxscan 19, undo 18, store_fast 17.
- Docs created: `port/OSX_PORT.md`, `port/OSX_ROADMAP.md`, this file.
- Next: pick the first module (pure-compute, no syscalls — e.g. sha256 or
  bitcoin_hash) to prove the Mach-O build+verify loop end to end.

## 2026-09-09 — bitcoin_tx native: bounds fuzz 55M calls + x86-diff byte-identical

- port/osx/bitcoin_tx.S (tx_parse + tx_txid): test_tx 20/20, test_txtxid,
  test_tx_bounds_fuzz 55,232,133 guarded calls 0 faults, 501-vector
  differential byte-identical vs x86 objects on .242 (dtx.c/gen_tx_vecs.py).
- NEW DARWIN PITFALL: `ldp x27,x27,[sp],#16` (Rt==Rt2) is CONSTRAINED
  UNPREDICTABLE — SIGILL on Apple Silicon. Never pair-restore the same
  register twice; pop odd slots with ldr + explicit sp adjust.
- Delegation note: parallel subagent waves time out on this provider (5-12
  API calls in 600s). Porting proceeds serially, coordinator-owned.

## 2026-09-09 — secp256k1_scalar native: 2,306-vector x86-diff byte-identical
port/osx/secp256k1_scalar.S: sc_add/sc_sub/sc_sqr/sc_inv/sc_inv_var/
sc_mul_512/sc_split_lambda native AArch64. sc_mul + sc_mul_512 currently
route to proven C twins (port/osx/sc_mul_c.c, sc_mul_512_c.c) — the AArch64
asm fold drops a DELTA on dense products; root-cause later, C twins are the
correctness baseline. Gates: test_scalar 12/12, test_glv_split 3 campaigns
(1,001,018 + 1,000,000) 0 failures, cross-arch dsl diff vs .242 byte-identical
(800 mul_512/split + 1500 mul/add/sub vectors). Three port bugs the gates
caught: (1) add/adc vs adds/adcs — AArch64 add/adc do NOT write NZCV, every
carry chain needs adds/adcs; (2) sc_mul_512/split frames were aliased over
active locals until a real `sub sp, sp, #N` was added (same class as the
tx epilogue leak); (3) my MULACC expansion dropped the hi term into the
carry chain (cur[k+1] += hi + c, then propagate) — the x86 macro did the
same math but the ARM rewrite skipped it. Commit 131e5171 on osx/p1-scalar,
merged to bmc_osx (2e7b1f07).

## 2026-09-09 — bitcoin_hmac native + sha512.S caller-frame corruption fix
port/osx/bitcoin_hmac.S: hmac_sha512 native (CRY-4 frame-local buffers,
WAL-3 zeroise).  The 400-vector differential vs .242 exposed a REAL bug in
port/osx/sha512.S: the 128-bit BE length field zero loop ran with x13 =
carrier+120 and offsets 112..127, writing carrier[232..247] — outside the
sha512_full frame.  When rem>=112 (two-block pad path) the carrier is pad1
at its_sp+0xc0, so the stray writes hit the CALLER's frame at caller_sp+8..
+23, zeroing hmac's kpad[8..23] and corrupting any HMAC with keylen>=16 and
msglen in 112..127/255 (symptom: only some vectors fail, key-length
dependent).  Fix: offsets -8..7 from x13.  sha512_NIST 4/4 re-verified;
400/400 byte-identical after the fix.  Commit da3f4b6d.

## 2026-09-09 — bitcoin_bip39 native; bitcoin_aes already pure C
port/osx/bitcoin_bip39.S: all four ABI functions native + wordlist_gnu.inc
(the 2048x9 table in __TEXT,__const — __cstring gets tail-merged by the
Darwin linker and silently shifts fixed-width records).  Two port bugs the
gate caught: (1) find_word_index clobbered x22/x23 (unsaved callee-saved in
that helper) destroying the caller's token pointer after the first word —
every mnemonic invalid; (2) the parse tail (entropy extract + checksum
compare) initially fell through to the epilogue returning garbage.  Gate:
test_bip39 24-vector oracle round + WAL-11 canary + negatives, ALL PASS,
same harness green on x86.  bitcoin_aes: pure C upstream, test_aes passes
natively unchanged.  Commits 0c259e99.
