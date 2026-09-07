# 2026-09-07 — Everything we ship starts with `bmc`

Decided today, after the daemon had been renamed once already: our
executables and the files they write carry a `bmc` prefix, so nothing of
ours can be mistaken for, or collide with, a Bitcoin Core file on the same
box.

| was | is |
|---|---|
| `asm/daemon/bitcoind` → `bitcoinmcd` (this morning) | **`asm/daemon/bmcbitcoind`** |
| pid file `bitcoind.pid` → `bitcoinmcd.pid` | **`bmcbitcoind.pid`** |
| `asm/daemon/bitcoin_rpcd` (the standalone RPC daemon) | **`asm/daemon/bmc_rpcd`** |
| unit `bmc-bitcoind.service` (reference deployment) | **`bmcbitcoind.service`** |
| deploy convention `bitcoind.live`, `bitcoind.deploy-*` | **`bmcbitcoind.live`, `bmcbitcoind.deploy-*`** |
| `bmc_cli` | unchanged, already prefixed |

The log banner reads `===== bmcbitcoind  LOG START`. `test_core_parity`
pins `bmcbitcoind.pid` as the one discussed divergence from Core's config
defaults; the `pid` key keeps Core's semantics. The `bmc_rpcd` binary's
own error messages carry its new name; its source stays
`daemon/bitcoin_rpcd.c`, as `bitcoind.asm` stays: sources are modules,
not products.

Not renamed, on purpose: the maintenance tools (`build_utxo`,
`build_tx_index`, `pverify`, `chainwork_build`, `utxo_*`) and
`wallet_cli`. None of them carries a Bitcoin Core file name. They can be
prefixed in one further pass if the rule is meant to cover them too.

## The reference box's unit

The production node still runs as `bmc-bitcoind.service` from
`asm/daemon/bitcoind.live`, a dated snapshot. The rename does not touch
it. `scripts/start.sh`, `stop.sh`, `status.sh` and
`validation/bfi_closing_pass.sh` use `bmcbitcoind` when that unit exists
and fall back to `bmc-bitcoind` until then. Renaming the unit is the
operator's call, since it restarts the production node:

```
sudo systemctl stop bmc-bitcoind
sudo mv /etc/systemd/system/bmc-bitcoind.service /etc/systemd/system/bmcbitcoind.service
sudo mv /etc/systemd/system/bmc-bitcoind.service.d /etc/systemd/system/bmcbitcoind.service.d
# then point ExecStart at asm/daemon/bmcbitcoind.live (a symlink to a fresh bmcbitcoind.deploy-<date> snapshot)
sudo systemctl daemon-reload
sudo systemctl disable bmc-bitcoind; sudo systemctl enable --now bmcbitcoind
```

## Addendum: the reference box's unit was renamed at 09:57Z

Done with the operator's sudo. The same binary the node had been running
(the 2026-09-05a snapshot) was copied to `bmcbitcoind.deploy-20260905a`,
byte-identical, and `bmcbitcoind.live` points at it, so the rename
changed names only, not code. The unit file became
`/etc/systemd/system/bmcbitcoind.service` with its four drop-ins; the
logrotate service and timer descriptions follow. Old unit stopped and
removed, new one enabled and active; the node was back on the network
inside a minute and closed the 40 blocks it had missed with no error in
its log. The log banner still reads `bmc-bitcoind` until the next deploy
puts a build from today's main behind `bmcbitcoind.live`.
