# BLD-3 — credential rotation record

**Date:** 2026-09-05
**Finding:** `docs/audits/CODEBASE_AUDIT_2026-09-03.md` § BLD-3 (LOW) —
a live `bitcoinrpc:<password>` pair for the Core oracle was committed as an
auth fallback in `validation/corpus_diff.py` and `validation/fullchain_diff.py`,
present since `404ea5d` (2026-08-16).

BLD-3 asked for three things: delete the fallback, **rotate the credential**,
and record the rotation here. This is that record.

## Status: the exposed credential is dead, and that is verified

It is dead by **migration**, not by an edit to a config file. The oracle moved
while this audit was in flight:

| | at the time of the leak | now |
|---|---|---|
| datadir | `/storage/bitcoin/data` | `/storage/core-oracle` |
| RPC auth | `rpcuser` / `rpcpassword` | **cookie only** — its conf has no `rpcpassword` line at all |
| RPC port | 8332 | read from its own conf (8335 at the time of writing) |

Verified empirically on 2026-09-05, against the running node:

```
cookie auth        -> HTTP 200   (getblockcount = 965624)
leaked credential  -> HTTP 401   REJECTED
```

and by sweep: the leaked password appears in **no** configuration file on this
host — not the oracle's, not `config/bitcoin*.conf`, not the two benchmark
datadirs — and in no file under `/storage/bitcoinmachinecode` outside `.git`.

**It remains in git history and always will.** That is precisely why the
correct remediation is to make the credential *useless* rather than to try to
erase it: history rewriting on a pushed repository is worse than the exposure,
and cannot recall copies already fetched. The credential authenticates to
nothing.

## Also rotated (defence in depth, not known-exposed)

`config/bitcoin.regtest.conf` and `config/bitcoin.testnet4.conf` carried
plaintext `rpcpassword` values. These were **never committed** (all three
`config/bitcoin*.conf` are gitignored) and bind loopback, so they were not
exposed — but the audit's own INFO note flagged them as mode `0644`, i.e.
readable by any local account.

Both were regenerated (32-byte `secrets.token_urlsafe`) and both are now
`0600`, matching `config/bitcoin.conf`. Nothing was running on either chain and
no script references those files, so no service needed restarting.

| file | before | after |
|---|---|---|
| `config/bitcoin.conf` | 0600, cookie auth | unchanged |
| `config/bitcoin.regtest.conf` | 0644, plaintext | **rotated**, 0600 |
| `config/bitcoin.testnet4.conf` | 0644, plaintext | **rotated**, 0600 |

## A live bug found while verifying this

Both diff tools still pointed at the oracle's **old** location:
`COOKIE_PATH = '/storage/bitcoin/data/.cookie'` (a path that no longer exists)
and `RPC_PORT = 8332` (nothing listening). Since BLD-3's first half had already
replaced the silent credential fallback with a hard failure, every run of
`corpus_diff.py` and `fullchain_diff.py` had been dying on a missing cookie —
the fail-loudly behaviour working exactly as intended, against a target that
had moved.

Both now resolve the oracle from its own `bitcoin.conf` rather than carrying a
second copy of its port, and honour `BMC_ORACLE_COOKIE` / `BMC_ORACLE_HOST` /
`BMC_ORACLE_PORT` so a differently-sited oracle needs no source edit.

## What is NOT claimed

- The leaked password is not removed from git history and cannot be.
- No audit of who may have fetched the repository between 2026-08-16 and this
  rotation was performed; the exposure window is those ~20 days.
- The oracle binds loopback (`rpcbind` in its conf), so exposure was confined
  to accounts on this host for that window.
