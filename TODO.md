# TODO — arm-port state after 2026-09-04 (the 276-commit main batch merged + ported, deployed as arm-9)

Everything below is landed on `arm-port` and pushed. History lives in
`worklog/2026-09-0{1,2,3}.md`; the per-module port status is
`port/PORT_ROADMAP.md`.

## Done since the last TODO (details in the worklogs)
- [x] CHECKSIG cluster, test_keepup, the post-merge functional fails, the
      sweep's scratch-dir layout — all closed 2026-09-01.
- [x] test_utxo_wal_buffer: the buffered WAL is ported for real (`mac_wr_log`
      appends to `wal_buf`, `mac_flush` drains before it truncates), and it is
      live — the LSM reloaded to the identical live count after two restarts.
      There is now NO functional failure on the board. 92e441e
- [x] Syncs 4, 5 and 6 merged (12 + 10 + 2 commits, all arch-neutral C),
      deployed as arm-3, arm-4 and arm-5 (2026-09-03 18:00 UTC, rollback
      `bitcoind.pre-sync6-20260903`; live=241272739 identical on the fourth
      restart running, 0 invalid / 0 policy, tip advanced in ~6 min).
- [x] Core's oracles rebuilt natively for aarch64 from main's restored
      `core_verify_oracle.cpp`, and `validation/synth_corpus_diff.py` run
      against the ARM interpreter for the first time: 79 cases / 96 rule
      mutations / 7,805 interpreter probes, 0 divergences, 0 engine failures.

## Open (next sessions)
- [x] `SIG_FINDANDDELETE` ordering — fixed 2026-09-03 on both architectures in
      one commit (f7d28ce): the CHECKSIG encoding-error arms run Core's
      CONST_SCRIPTCODE strip before reporting SIG_DER / SIG_HIGH_S /
      SIG_HASHTYPE / PUBKEYTYPE and answer SIG_FINDANDDELETE when it lands.
      The repro exits 0; fuzz_verify_diff now reports 0 code-only mismatches
      over 3 seeds x 20,000 cases; see docs/FEATURE_GAPS.md (Update
      2026-09-03, CLOSED). The repro stays in validation/ as a regression
      check. NOTE (2026-09-04, VOID per aa70c08): the "left for a later
      session" CHECKMULTISIG strip-interleaving concern below is DEAD —
      Core v31's k-loop strips ALL signatures before the matching loop (the
      same structure the port has); the "Core interleaves per-signature"
      claim misread interpreter.cpp:1146. Nothing to redesign.
- [x] The auth half of this item is done: `synth_corpus_diff.py` imports
      `spend_corpus_diff.py` for Engine/ORACLE/SHIM, so spend's module-level
      `_AUTH = _auth()` ran at synth's import time and the synth harness
      demanded `BMC_ORACLE_COOKIE` just to start. The auth is now computed on
      first real rpc() use (spend still needs credentials when it runs; the
      synth run needs nothing) — verified by running the synth harness with no
      cookie env var at all: exit 0, 158/158 rows div=0.
- [x] Archive-gap re-timing: CLOSED 2026-09-03 23:40 UTC — connect bound
      honest but not effective (62.74s / 18.24s / 118.93s vs pre-fix
      20/148/86/50/20); slow boots are the tip-moved boots, residual is the
      catch-up-worker spin-up downstream of connect. Details in the worklog.
- [x] Merge-carried audit parity (SCR-3/SCR-4, SER-1/WAL-1, NET-1) ported to
      ARM 2026-09-04, sweep round 22 green (pass 309 / fail 4 env-only),
      deployed as arm-8 with aa70c08. RPX-1 was arch-neutral C (arrived with
      the merge, nothing to port).
- [x] The NEXT main batch (276 commits, SCR-5/6/7, CRY-1/2, VAL-5/6/8/11)
      merged and ported 2026-09-04: round 24 green (pass 313 / fail 4
      env-only, compared 330 of 363), deployed as arm-9. Sweep gained a `$^`
      deps injector; test_sha256 skipped (x86 CPUID inline asm). Two upstream
      items surfaced and handled: serve-test disarms the powLimit (harness
      principle), arena FAIL-5 updated to the SCR-5 contract with the 252
      single-reject quirk pinned. Details in the worklog.
- [x] The 49-commit batch after the upstream history rewrite (STO-6/7/8,
      UTX-1/3/5, NET-7/8, SER-4, WAL-4, RPC-2, test_redial quarantine)
      merged and ported 2026-09-04: round 25 green (pass 322 / fail 4
      env-only, compared 339 of 374), deployed as arm-10. Upstream also
      rewrote both branches (noreply emails + svc rename) and quarantined
      test_redial independently -- confirming this port's stale-fixture
      diagnosis. The arena single-252 reject quirk (unset reason) remains
      pinned for a future session.
- [x] **UTXO store rebuild — CLOSED 2026-09-05 06:19 UTC, tip caught up, 0
      invalid, mempool admitting: the "tail loses coins" theory was WRONG.**
      What actually happened, in order: (1) the v2 rebuild (0..964000,
      applied_height=964000) swapped in and catch-up failed at **964001**
      (v1 had failed at 965496 — both were the SAME bug, one boot later each).
      (2) The overnight session's flush_wal_tail run (finished 03:55 UTC)
      replayed the entire 705 MB builder WAL — `replayed=11260225`,
      `total_live=165718352` == build_utxo's own final count — proving the
      on-disk WAL covered the whole unflushed window: **no coins were ever
      lost in the tail.** The daemon still failed because of (3) the REAL
      root cause: bitcoin_utxo_lsm.S `.rl_manifest_haveN` compares the
      manifest's entry count against the CALLER's manifest_cap and on
      count > cap branches to `.rl_manifest_bad`, which ZEROES manifest_n /
      next_gen / next_run_no and returns success. The daemon's
      UTXO_LIVE_MANIFEST_CAP=256 < the store's 424 runs → zero runs
      registered → every utxo_lsm_get misses → "missing/already-spent" at
      the first spend. The probe (cap 4096) loaded 424 runs and found every
      coin; the "orphan sweep skipped -- manifest file and memory disagree"
      journal line was the tell. Fix: flush_wal_tail with a 2^24 memtable
      (e89914bd — 2^22's 3.1M fill truncated at ~11.26M records) drained the
      WAL tail into run 423, then `build_migrate_compact data/main 23 1.5`
      compacted 424 runs → 1 run (24.7 min) — which also collapsed ~200 GB
      of run history into a 13.3 GB live-entry run. Post-migration probe:
      get AND walk both find the probe coin; daemon boot reloads in ~1 s,
      manifest_n=1, live=165718352. Catch-up applied 964001..964091, then
      (4) a SECOND, independent bug surfaced at **964092**: the BIP68 pass
      rejected any tx with more than VAL_SEQ_CAP (2048) inputs as
      "bad-txns-nonBIP68-final (past the sequence window)" — tx 840 has
      5,226 inputs and is in Core's chain. Fixed by streaming the sequences
      (val_seq_walk_init/next, no buffer, no cap) instead of refusing:
      d72271fa, test_val_read_tx.c 39 checks / 0 failures, live proof = the
      daemon applied 964092 and resumed. Catch-up then ran to the tip
      unbroken: applied_height 964000 → 965576 at ~0.8 blk/s with script
      evaluation live above assumevalid, heartbeat clean (no DEGRADED),
      txouts=165,594,560, tx_accept +80/s with 0 invalid. **Parity check at
      height 965578 (first full one ever completed — every prior attempt
      errored, see the 09-05 worklog): txouts 165,388,368 == Core EXACT,
      total_amount EXACT, bogosize EXACT — muhash DIFFERS** (ours
      82622e2f…, Core 774e4373…; per-entry serialization verified identical
      to Core v31's TxOutSer, so it is a real content delta invisible to
      count/sum/bogosize — likely a height/coinbase-byte class on coins
      unspent since the rebuild). TWO OPEN ITEMS for next session:
      (a) [CLOSED same session] localize the muhash delta — FOUND: build_utxo
      no-op'd on duplicate-outpoint puts, so the two BIP30 duplicate
      coinbases kept the FIRST appearance's height (91812/91722 vs Core's
      91842/91880); fixed in both builder paths (a69e166a), the live store
      repaired in place by repair_bip30_heights.c (4 WAL records, no
      rebuild), and the closing check is GREEN: **muhash
      9b3acac6…33fd7 IDENTICAL to Core at height 965598** (txouts
      165,361,670 and 20079766.75835718 BTC also equal) — the rebuilt
      store is entry-for-entry Core's chainstate, the first full parity
      check this port has ever completed on mainnet;
      (b) the daemon's running tally is drifted ~208k high (persisted in the
      checkpoint trailer, survives restart, trips gettxoutsetinfo's guard —
      walk is right, counter is wrong; offline utxo_setinfo self-consistent).
      Also: tag/deploy this build as arm-11 through the sweep (built ad-hoc).
- [ ] Standing hazard (small, from the same session): bitcoin_utxo_lsm.S
      `.rl_manifest_haveN` still silently ZEROES the run table when a store's
      manifest exceeds the caller's manifest_cap (`.rl_manifest_bad` returns
      success with manifest_n=0 — every lookup then misses, the exact
      964001 failure class). Make reload fail loudly (UTX-2 already treats
      r<0 as fatal), or have swap scripts refuse a manifest with more than
      UTXO_LIVE_MANIFEST_CAP runs. The pre-catchup compaction loop cannot
      fire in the >cap case (it needs manifest_n >= 2 in memory).- [x] `validation/spend_corpus_diff.py` ran for the FIRST time on this port
      2026-09-04 01:25 UTC, against a real synced Core over the LAN
      (Umbrel node 192.168.5.69:8332, txindex on, verificationprogress=1):
      zero divergences, accept-parity 253/253 real mainnet spends and 2024/2024
      mutations across all six epochs (default-seed run also green: 99/99 +
      594/594). Harness change: RPC_HOST now env-configurable
      (`BMC_ORACLE_RPC_HOST`, default 127.0.0.1). Recipe in the worklog;
      credentials in /etc/bmc-oracle/umbrel.cookie (root-owned 0600, outside
      the repo tree — never committed).
- [ ] env-only, documented, no action: `bench_checkblock` / `bench_hashidx` /
      `bench_idxscan` / `bench_taproot_block` need production data files
      (`block413567.raw`, `./index.dat` in the scratch dir);
      `test_net_timeouts` needs >600s.
- [x] Optional hardening: the x86 auditor's SAVE-AREA-ALIAS check is ported to
      `scripts/abi_callee_saved_audit_a64.py` and gated with
      `make -C port/arm64 abi-a64-check` -- see the 2026-09-03 worklog for what
      it took (a frame walk, symbolic `.equ` frame maps, register-held fixed
      frames) and for the one function it still cannot see.
- [x] Boot's archive-gap phase — CLOSED 2026-09-03 23:40 UTC after the three
      owed arm-7 re-timing restarts: 62.74s / 18.24s / 118.93s vs pre-fix
      20/148/86/50/20 — the 8s connect bound did NOT collapse the phase
      (distribution unchanged). But the slow boots are now explained: boot 3
      is the first where `already current` NEVER arrives because the tip
      genuinely moved under us (booted 965389, network 965391) — the check
      isn't stalled, the network isn't current. The ~100s residual is the
      catch-up worker spin-up: 16 workers print `(connecting)` for ~102s with
      153 confirmed-live peers available, one 1-block span fetched in 0.03s
      once headers land. Connect is bounded; the stall is the handshake /
      SO_RCVTIMEO=15s reads / sequential per-try structure downstream of
      connect. Next lever (optional): bound the workers' first usable peer or
      reuse a confirmed-live peer for tiny spans. Details in the 23:40 UTC
      worklog entry.
- [x] The last 6 unmodelled frames — CLOSED 2026-09-04: the auditor follows
      register-held frame bases (`mov x28,sp` -> `[x28,#TAB]`), alignment-
      clamped sp (`and x9,x9,#-16` as a tracked constant), and argument-sized
      frames as PHANTOM steps (anchors carry the phantom history; two anchors
      compare exactly only when their histories are equal, so every report
      holds for every value of the argument). 761/761 frames followed, zero
      unmodelled; full-tree findings byte-identical to the pre-change
      baseline; abi-a64-check green.
- [x] The gate's own reporting — CLOSED 2026-09-04: parity_sweep.sh now counts
      VERDICT rows (pass+fail+bench-ok), prints and appends
      `compared: X of N plan rows`, and exits 2 when X is 0 — a sweep that
      built and ran nothing can no longer look green. The line is single-field
      so the counting awk can never recount it (the aed6533 class).
