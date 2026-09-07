# 2026-09-07 — The daemon is `bitcoinmcd`

The node binary was `asm/daemon/bitcoind`, the same name as Bitcoin Core's
daemon. On a box that runs both, and in every benchmark log, script and
conversation that compares the two, that name was a standing source of
confusion. It is now `asm/daemon/bitcoinmcd`.

What changed: the Makefile target and every test, script and validation
harness that execs or names the binary; the daemon's own log banner
(`===== bitcoinmcd  LOG START`) and its "already running" message; the
current documentation (README, ENGINEERING, OPERATIONS, RPC_LIVE_NODE) and
the deploy convention it describes (`bitcoinmcd.live`, `bitcoinmcd.deploy-*`).

What did not change, and why:

- The sources `bitcoind.asm` and `bitcoind.o` keep their names. They are
  the node core module, not the product.
- The pid file default stays `bitcoind.pid`: it is the value of a
  Core-named key, and Core's default is kept exactly (rule: flags match
  Core; a divergence is discussed first).
- The systemd unit on the reference box is still `bmc-bitcoind.service`
  and runs `bitcoind.live`, a dated deploy snapshot. It is unaffected by
  the rename; the next deploy follows the new convention and renames the
  unit when the operator chooses.
- Historical records (devlog, audits, benchmark reports, earlier worklogs)
  keep the old name: they describe what ran.
- Test names such as `test_bitcoind_sync` keep their names.

`scripts/status.sh` matches either process name. The benchmark harness
outside the repo was patched to build and run `bitcoinmcd`; run 9, already
running on the previous build, is not affected.
