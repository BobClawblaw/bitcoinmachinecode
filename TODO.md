# TODO — arm-port state after 2026-09-07 (IR series CLOSED, origin/main merged through bf4ecd83, round 32 green: pass 370 / fail 4 env-only, and **arm-12 is DEPLOYED**)

Everything below is landed on `arm-port` and pushed. History lives in
`worklog/2026-09-0{1,2,3}.md`; the per-module port status is
`port/PORT_ROADMAP.md`.

## Done since the last TODO (details in the worklogs)
- [x] **The 2026-09-05 upstream batch port — CLOSED 2026-09-06, round 29
      green.** All 15 queued x86 files ported to the AArch64 twins, one
      branch + PR each, merged on module-test green: bitcoin_serve (#45,
      STO-10/NET-5/MEM-10/NET-14), bitcoin_mempool (#34, MEM-21),
      bitcoin_net (#33, NET-11), bitcoin_pubkey (#31, CRY-3),
      bitcoin_store (#44, STO-11), bitcoin_cmpct (SER-4 cs_read was
      already present in the twin — verified, no branch needed),
      bitcoin_hmac (#37, CRY-4/WAL-3), bitcoin_bip39 (#40, WAL-11/CRY-4),
      bech32 (#30, SER-5/WAL-9), sha256 (#36, CRY-6), sha512 (#38),
      bitcoin_txv_parse (#42, VAL-10/SER-3), bitcoin_txv_dispatch (#43,
      VAL-16), bitcoin_chainwork (#35, STO-13), bitcoind (#46, NET-13/DMN-12
      caps + SC1 verified via shared main.c + bmc_cli rename wiring).
      Round-28 baseline (pass 323 / fail 21 / build-fail 5) → round 29
      (pass 344 / fail 5 = the 4 standing env-only bench fails +
      test_utxo_torn_tail, fixed in-sweep by porting UTX-4's second half —
      the torn-WAL-tail truncate in utxo_store_reload, f4462185 — →
      round-29b re-sweep green: pass 345 / fail 4 env-only). Sweep
      round-28 extras root-caused: test_rpc_server, test_rpc_transport,
      test_cli_prompt were the bmc_cli rename missing from
      parity_sweep.sh's build+symlink set (fixed in #46); test_bitcoind was
      the NET-13 port itself. MEM-3/MEM-23/SC1 rode in as arch-neutral C
      with the merge. Details in worklog/2026-09-05.md.
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
- [x] **DEPLOYED arm-12 (2026-09-07 02:37Z).** Candidate md5 `cfe86ed4`, rollback
      `port/arm64/daemon_out/rollback/bitcoind.pre-arm12-20260907` (md5 `36250f97`, the
      round-29 build) — one `cp` + `systemctl restart bmc-arm` to undo it. Gate: sweep
      round 32 on the merged tree (pass 370 / fail 4 env-only / bench-ok 15 / compared
      389 of 432). Post-deploy: 136 confirmed-live peers at boot, UTXO reload ~4 s
      (`live=165321036`, `manifest_n=3`), headers already current, tip advanced
      965871 -> 965872 under the new binary, and 15 min in: connections 5,
      progress 1, mempool admitting, 0 invalid / 0 policy. What it closed: two consensus
      FALSE ACCEPTS (IR-3's unread `hard_fail`, IR-1's ignored STACK_SIZE) and two
      memory-safety holes (IR-3's 8-byte ctx overrun, SCR-2's unbounded `vfexec_push`).
- [ ] **Watch the peer pool — and raise it upstream.** The merged tree carries
      upstream's `1d543d08` (`drop a peer that lacks NODE_WITNESS and stop redialling
      it`), which replaced an arm-port LOCAL workaround (e94c37b9) whose stated reason
      was "peers here advertise 0xc05". That reason turns out to be true of real mainnet
      peers, not just sim fixtures: the filter fired 3 times in the first 15 minutes of
      arm-12 and the node holds 4-5 legs of 8 where the old build held 5-6. The tip
      advances, so the deploy stands. But the drop buys no safety here — the BIP141
      commitment check is what protects the archive, and the 0xc05 advertisers on this
      host demonstrably serve witness blocks — so the ask upstream is a soft preference
      or a config, not a ban. If legs slide toward 0, roll back with the file above.
- [ ] **Upstream defect, found by the sweep:** `7781987c` added an `asm/Makefile` rule
      for `tests/test_par_threads` without committing `asm/tests/test_par_threads.c`,
      and left the target out of the `test:` run list — so x86's own gate never builds
      it and nobody noticed. It is the 8th ARM build-fail row. Either the source wants
      committing upstream or the rule wants deleting.
- [x] **The 7 sweep build-fails are CLOSED (2026-09-07, `0b991b77`).** Not one cause
      but three missing seams from the 2026-09-06 x86 perf batch, each silencing a
      differential that had never run here: (a) `num3072_mul` dispatcher with x86's
      path numbering + the force_path/current_path/cpu_has_* seam (ADX/IFMA honestly
      report 0; 31 Core-vector checks now run the generic body); (b) real
      `utxo_prefetch_n` (PRFM over the home slot; the twin was a no-op) — cost one
      x30 lesson on the way: AArch64 `ret` reads x30, which an inner `bl`
      overwrites, unlike x86's stack-based call/ret; (c) `utxo_lsm_sort_desc` /
      `utxo_lsm_set_sort_mode` exported with an in-code warning that the diff test
      proves flush determinism, not radix==merge (radix body not ported).
      Follow-up (`6d6d5f03`): the flush sort's helpers got the x86 bodies —
      `mac_copy_rec` eight unrolled qword moves, `mac_bloom_h` fully unrolled with
      the prime hoisted — taking bench_lsm_flush_sort at N=4M from 2854 ms to
      **651 ms** (163 ns/key, 393 MB/s), within 20% of x86's merge. Sweep round 37:
      pass 374 / fail 4 env-only / bench-ok 18 / build-fail 1 (upstream's own
      `test_par_threads`) / compared 396 of 432.
- [x] **Port `mac_rsort_desc` -- DONE (2026-09-08, `8a20f7c8`).** MSD radix over
      compact 16-byte entries, x86's shape line for line (three digit variants,
      per-depth counts in .bss, single-bucket skip, <= 32-bucket insertion sort
      with descriptor tie-break, prefetched gather; the order must end in
      mac_rs_final). At N=4M: **152.9 ms** vs merge 654.6 ms -- 4.29x, 1675 MB/s
      (x86: 5.9x; the twin's radix is 1.7x off x86's, plausibly dynamic-shift
      digit extraction + scalar copies). `mac_sort_mode` now defaults to 1
      (radix), matching x86, and `utxo_lsm_sort_desc` really dispatches.
      test_lsm_flush_sort_diff is a REAL equivalence test here now: byte-identical
      runs, radix vs merge, same arrays. Round 43: pass 374 / fail 4 env-only /
      compared 396 of 432 -- ninth consecutive identical sweep.
- [x] **DEPLOYED arm-13 (2026-09-08 05:16 CDT, `8a20f7c8`).** Candidate md5
      `a80f869b` -> live via the two-step rename deploy; rollback
      `rollback/bitcoind.pre-arm13-20260908` (`cfe86ed4` = arm-12). Verified:
      reload 0.18 s, 0 invalid, 146 confirmed-live peers, tip advanced
      966054 -> 966055 under the new binary, mempool admitting. NOTE: logs
      moved to `data/main/debug.log` (#94); journald is lifecycle-only now.
- [ ] **Standing policy (operator, 2026-09-08): deploy new builds as they gate
      green** -- rebuild `bmcbitcoind` after every merged+gated upstream sync,
      two-step deploy, verify boot (reload time, 0 invalid, tip advance,
      mempool, peers), rollback artifact per build. No more holding.
- [ ] **bitcoind.S CC-2 is half-wired:** the hook table exists as data symbols
      (`g_peer_sendcmpct`, `g_cmpct_hook_type`, 130411fb) but the mux never CALLs them
      — no sendcmpct announcement after verack, no hook-selected getdata type. The x86
      daemon does both, so compact-block receive is inert here.
- [x] **The IR-1..IR-17 interpreter-review series — CLOSED 2026-09-07, round 31 green.**
      Ported: IR-1/2/3/4/6/7/8/10/12/13 (a15a8a4c 3711a746 f8c9474f 9cffb4c5 37310ae3
      228e8c5e). Arch-neutral C, nothing to port: IR-5/9/14. x86-side notes with no ARM
      obligation: IR-11/15/16. IR-17 verified already correct in the twin. Two findings
      were on NO queue and are the ones that mattered: **SCR-2's `vfexec` bound had never
      been ported** (1 KiB condition stack with an unbounded push — the 1025th nested
      OP_IF wrote over `vfexec_sp` and the rest of the TLS block; the sweep had been
      reporting it as `IR-4 child killed by signal 11`, and signal 11 is SIGSEGV, not
      the alarm), and **IR-3's taproot ctx** (the twin reserved 96 bytes where
      `taproot_checksig_ctx` is 104, so every tapscript CHECKSIG wrote 8 bytes past the
      ctx onto the script_state's `main_elems` — and nothing read `hard_fail` back, so
      an invalid-sig / empty-pubkey / over-budget tapscript was a silent ACCEPT). Per
      item in `port/PORT_ROADMAP.md`; narrative in worklog/2026-09-06.md Session 11.
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
      (b) [CLOSED same session] re-anchor the daemon's running tally —
      recount_anchor.c (recount from content + flush publishing the honest
      count into the manifest header): the boot now prints live=165356287
      (was ~165.59M), and the bookkeeping verified honest afterward
      (heartbeat tally vs offline walk: one block's net apart, drift zero).
      Origin established by walking the v2 scratch store at h=964000:
      txouts=165718352 == the builder's tally exactly — the builder was
      honest; the fossil entered in the pre-fix daemon era;
      (c) [CLOSED same session] .rl_manifest_bad hardened: any manifest-load
      failure (unreadable/over-cap) now returns -3 — both arches — instead
      of silently proceeding with zero runs; pinned by
      tests/test_lsm_manifest_cap.c (8 checks); utxo_live names the
      compaction remedy for -3;
      (d) [CLOSED same session] sweep round 26 GREEN (pass 322 / fail 4
      env-only / compared 339 of 375) = the arm-11 cycle: the running
      binary carries the BIP68 streaming fix, the hardened reload, and the
      builder BIP30 replace; the node is at tip, mempool admitting, 0
      invalid, and the full-store muhash parity is GREEN (965598).
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
