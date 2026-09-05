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
- [ ] **UTXO store rebuild — the 965018 hole is HEALED but the rebuild's
      tail loses coins (NEXT SESSION, priority):** the store was rebuilt
      offline from the blk archives with the UTX-1/UTX-3-fixed binary
      (build_utxo, 2.6 h, 165,404,120 live entries vs the damaged store's
      241,272,739 — ~76M phantom entries from the old resurrection bug).
      Swapped with full backup (data/main/rollback-store-20260904/); the
      daemon booted the full set via its mmap path and the catch-up PASSED
      965018 (deep history clean through 965495). The rebuild's tail after
      its last durable flush (~h=964890) LOSES coins — apply now fails at
      h=965496 (missing input; the old failure point is gone). Fresh-reload
      validation tools (utxo_probe_one/utxo_reload_check) crash or need
      multi-hours+6GB at 165M scale — only the daemon's mmap boot consumes
      the store. NEXT: re-rebuild with `build_utxo <scratch> 23 1.5 0 964000`
      (~2.5 h), applied_height=964000, swap, and let the daemon's own
      catch-up apply 964001..tip through the battle-tested apply path; fix
      the swap script's unqualified globs first. Full details in the 22:30
      UTC worklog entry; backups intact.
      STATUS 2026-09-04 ~20:15 UTC: v2 rebuild (0..964000) running, ~91%;
      globs fixed + data/swap_rebuilt_store_v2.sh written (v1's files are
      deleted after daemon-stop so v2 fits; rollback-store-20260904 stays
      the standing fallback; applied_height=964000 written pre-swap).
      BONUS: build_utxo gained a VERIFIED -j N pipeline (2654b0d9) —
      byte-identical stores vs serial (the only table delta is a per-run
      CLOCK_MONOTONIC header stamp that serial runs don't share either),
      ~1.2x under I/O contention, serial default unchanged.- [x] `validation/spend_corpus_diff.py` ran for the FIRST time on this port
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
