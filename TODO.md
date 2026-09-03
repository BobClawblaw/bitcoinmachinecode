# TODO — arm-port state after the 2026-09-03 session (sync 6 deployed as arm-5)

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
      check. Left for a later session, found while implementing: the
      CHECKMULTISIG up-front strip raises SIG_FINDANDDELETE for ANY on-stack
      signature found in the scriptCode BEFORE the matching loop, where Core
      interleaves per-signature (an encoding-invalid sig 0 preempts a later
      signature's FAD in Core, not here) — verdict-safe, BASE-only gate, and
      only reachable when no earlier signature's encoding check has fired.
- [ ] `validation/spend_corpus_diff.py` has never run on this port: it needs a
      synced Bitcoin Core over RPC (`BMC_ORACLE_RPC_PORT`/`BMC_ORACLE_COOKIE`)
      and this box has no Core datadir. `synth_corpus_diff.py` needs neither,
      only `coincurve` (installed in a venv here) and, as of today,
      `BMC_ORACLE_COOKIE` pointed at any readable file — both harnesses
      compute the RPC auth at import time even though the synth one never
      makes an RPC call. Worth making that lazy so the harness runs anywhere.
- [ ] env-only, documented, no action: `bench_checkblock` / `bench_hashidx` /
      `bench_idxscan` / `bench_taproot_block` need production data files
      (`block413567.raw`, `./index.dat` in the scratch dir);
      `test_net_timeouts` needs >600s.
- [x] Optional hardening: the x86 auditor's SAVE-AREA-ALIAS check is ported to
      `scripts/abi_callee_saved_audit_a64.py` and gated with
      `make -C port/arm64 abi-a64-check` -- see the 2026-09-03 worklog for what
      it took (a frame walk, symbolic `.equ` frame maps, register-held fixed
      frames) and for the one function it still cannot see.
- [ ] Boot's archive-gap phase is unexplained and varies 7x (21.87s / 85.46s /
      148.71s / 49.97s on arm-5; each measured boot splits into ~16-18s to
      `confirmed-live peer(s)` plus tens of seconds of silence until ONE peer
      answers `headers: already current`). The phase's own comment claims a
      caught-up node "returns almost instantly (pure disk reads, no network)",
      which the logs contradict -- it opens peers and waits for a height
      answer. Find what bounds that wait (or take the first `already current`
      instead of the peer that happens to reply), then re-time it across three
      restarts before calling anything settled.
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
