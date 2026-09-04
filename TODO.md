# TODO — arm-port state after the 2026-09-03/04 session (audit-remediation parity landed, deployed as arm-8)

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
- [x] `validation/spend_corpus_diff.py` ran for the FIRST time on this port
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
- [ ] Covering the last 6 unmodelled frames in the AArch64 ABI auditor needs
      offsets as RANGES: `point_scalar_mul_glv` bases its frame on `x28`
      (`mov x28,sp`, stores as `[x28,#TAB]`) and clamps sp to 16 through `x9`,
      and five `bitcoin_cli` commands size a buffer from an argument. Report
      only an overlap that holds for every value in the range and both become
      checkable; until then `--list-unmodelled` names them with the reason.
- [ ] Also worth a look: the gate's own reporting. Twice on 2026-09-03 main
      produced a green report that had compared nothing (link-check gating `test`
      into silence, and the dead VERIFY/TAPVERIFY oracle). The ARM sweep had the
      same shape — its summary dropped the first result row (NR>1 header
      assumption) and recounted its own summary lines as data; both fixed in
      aed6533, but it still prints no "compared N of M" line, so a sweep that
      built nothing and ran nothing would still look green here.
