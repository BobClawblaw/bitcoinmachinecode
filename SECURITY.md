# Security policy

Bitcoin Machine Code is experimental. It has been through internal and
external security review (`docs/audits/`), but its consensus and
cryptographic assembly have not had an independent human audit. Do not use
it to hold or move funds, and do not run it where a compromise would cost
you something.

## Supported versions

Only `main` is supported. There are no releases with backported fixes; a fix
lands on `main` through a pull request, and its landing note goes in
`docs/releases/`.

## Reporting a vulnerability

Report privately through GitHub: the **Security** tab of this repository,
then **Report a vulnerability**. Do not open a public issue, pull request or
discussion for a suspected vulnerability.

Useful in a report:

- the commit you tested (`git rev-parse HEAD`);
- the component: consensus/validation, P2P parsing, the UTXO store, RPC/REST/
  Esplora, or the wallet;
- steps or an input that reproduces it, and what you expected instead;
- for a consensus finding, what Bitcoin Core v31.1 does with the same input.

## What not to send

Never include live private keys, wallet files, seeds, `.cookie` files, RPC
passwords, onion or I2P keys, or a `bitcoin.conf` with credentials, in a
report or anywhere public. If one of those is part of the problem, say what
kind of secret is involved and leave it out; regenerate it on your side.

## Scope

In scope: the daemon and tools built from `asm/` (`bmcbitcoind`, `bmc_rpcd`,
`bmc_cli`, the wallet), the assembly and C under it, and the default
configuration. REST (`rest=1`, on the RPC listener) and the Esplora facade
(`bmc.esploraport`) are unauthenticated, as Core's REST is, and belong on
loopback or behind a proxy (the configuration table in `README.md`);
a report that they answer without credentials is expected behaviour, but a
way to reach JSON-RPC or the wallet through them is in scope.

Out of scope: the harnesses and oracles under `validation/` and `scripts/`,
and third-party services run beside the node (mempool.space, BlockYard).

## Disclosure

Reports are handled on the private advisory. The fix is developed there or
on a private branch, merged to `main`, and the advisory is published with
the landing note once the fix is in.
