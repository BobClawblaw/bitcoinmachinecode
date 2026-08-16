# 2026-08-16 — soak scenario configuration (t_5c05b606, scenario rev 1)

Configured the long-duration tip-advance + serve-live soak as a versioned,
one-command-startable scenario. Downstream run card t_eba4b5f8 starts it with
one command; analysis card t_791da7a9 consumes its outputs; fix card
t_fb552620 consumes any anomalies.

## What was delivered (all in `soak/`, tracked in git)

- **`soak_profile.env`** — THE versioned scenario profile (single source of
  truth; `SCENARIO_REV=1`). Knobs: 90-minute default window (composed for 24h+
  runs), 10 s resource sampling, 8 outbound legs, serve port 18444, serve
  load profile (byte-exact `serve_test` probes at heights 1000/30000 every
  120 s) + download probe every 300 s. Changing the scenario = bumping this
  file's rev.
- **`soak_start.sh`** — the one-command runner:
  `bash soak/soak_start.sh`. Preflight (no double-start, store present),
  starts the node (`bitcoind serve <dir> 18444 8` = ONE poll() loop over the
  inbound listener + 8 persistent outbound seed legs), waits for the listener
  to bind (the synchronous boot catch-up runs before the listener comes up —
  recorded honestly), runs the window with NO restarts, writes
  `soak_meta.json` (START_TS/END_TS UTC, tip records start/end, final
  `check_chain` audit).
- **`soak_monitor.py`** — sampler + load profile. Appends one CSV row per
  sample to `logs/samples.csv`: `t_elapsed_s, rss_kb, fd_count, records
  (store tip), listening, serve_ok, serve_bytes, dh`. Writes
  `logs/monitor_summary.json` on exit (start/end TS, RSS/fd min-max, tip
  start/end, serve/download success tallies). Samples only — it never
  signals/kill/restarts the node (the no-restart invariant).
- **`README.md`** — scenario docs: requirement→mechanism table, components,
  load-profile determinism, baseline, handoff notes for t_eba4b5f8 /
  t_791da7a9 / t_fb552620.

## Acceptance evidence (real tool output)

- **One-command start + poll() loop + timestamps:** `bash soak/soak_start.sh`
  ran a 60 s smoke: `START_TS=2026-08-16T03:09:59Z ... END_TS=2026-08-16T03:10:59Z
  (tip 5688 -> 5832 records)` — 144 real mainnet blocks pulled in the window,
  final `check_chain`: ARCHIVE CLEAN (0 holes/dups/hash-mismatch/chain-breaks/
  cons-bad). The node ran the poll() loop continuously; no restarts.
- **Concurrent serve + download, no restart (identical poll loop, loopback):**
  `asm/tests/test_outbound_mux` (exec's the real daemon in `serve-test` mode —
  the same `serve_mux` poll loop against a local mining peer):
  `PASS concurrent inbound: stored block 0 served byte-exact` + `PASS store
  grew after new block mined` + `PASS node serves freshly-mined block 5 (no
  restart)` — ALL TESTS PASSED (0 failures).
- **Real tip advance (live mainnet):** the live store advanced
  5688 → 5832 (smoke) and continued 8211 → 9048+ across later live runs
  (~4-5 blk/s), ARCHIVE CLEAN throughout — real mined blocks, not static.
- **Versioned + reproducible:** profile + runner + monitor are tracked in
  git; `.gitignore` now excludes only run artifacts (`soak/logs/`,
  `soak/run-*/`, `soak-store/`) so the scenario sources stay versioned while
  the growing live archive and per-run output stay out of the tree.

## Notes for downstream cards

- **Boot window:** `serve` runs a synchronous `outbound_catchup()` (one
  node_sync page) BEFORE `serve_mux` binds the listener; on a store far from
  the 962k chain tip this can take minutes-to-hours. The runner waits up to
  10 min for the listener and records the boot phase; the monitor's
  `listening` column captures it. For the 24h+ run (t_eba4b5f8) the store
  should be pre-closed to the tip first (catch-up is then short) so the mux
  window is dominated by the steady-state poll loop — the same steady state
  `test_outbound_mux` proves.
- **t_eba4b5f8:** `nohup bash soak/soak_start.sh >soak/run.log 2>&1 &`,
  composed over the store until 24h+ is covered; `check_chain deep` ARCHIVE
  CLEAN at the end.
- **t_791da7a9:** consume `soak/logs/samples.csv` + `monitor_summary.json` +
  `soak_meta.json` (tip-advance timeline, RSS/fd series, serve/download
  tallies, start/end TS).
- **t_fb552620:** no fix anticipated from the baseline (no leak/stall/fd
  growth); consume any anomalies the full run surfaces.
