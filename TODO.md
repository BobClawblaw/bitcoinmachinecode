# TODO — arm-port state after the 2026-09-03 session

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
- [x] Syncs 4 and 5 merged (12 + 10 commits, all arch-neutral C), deployed as
      arm-3 and arm-4.
- [x] Core's oracles rebuilt natively for aarch64 from main's restored
      `core_verify_oracle.cpp`, and `validation/synth_corpus_diff.py` run
      against the ARM interpreter for the first time: 79 cases / 96 rule
      mutations / 7,805 interpreter probes, 0 divergences, 0 engine failures.

## Open (next sessions)
- [ ] `SIG_FINDANDDELETE` ordering — ours answers `SIG_DER` where Core answers
      `SIG_FINDANDDELETE`, because Core's `FindAndDelete` under
      `CONST_SCRIPTCODE` precedes `CheckSignatureEncoding` and ours sits in the
      C checker callback behind it. Verdict-safe (both reject), present in the
      x86 `interp_checksig` too, so it is a main-side fix that then merges
      down: see `docs/FEATURE_GAPS.md` (Update 2026-09-03) and
      `validation/findanddelete_order_repro.sh`, which exits 0 once fixed and
      can go straight into a regression run.
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
- [ ] Optional hardening: port the x86 auditor's SAVE-AREA-ALIAS check; the
      two untouched perf ports (buffered WAL — done — and `mac_flush`'s 1 MB
      record writer).
- [ ] Also worth a look: the gate's own reporting. Twice on 2026-09-03 main
      produced a green report that had compared nothing (link-check gating `test`
      into silence, and the dead VERIFY/TAPVERIFY oracle). The ARM sweep has
      the same shape — it separates `skip` and `built` from `fail` but prints no
      "compared N of M" line, so the same mistake would pass here unnoticed.
