# 2026-09-10 — getnetworkinfo names the build; the download RPC is renamed so a monitor may call it

Two fixes found by reading bmcmonitor's own notes and its RPC allowlist.

## `getnetworkinfo` carries the build's commit

bmcmonitor's `AGENTS.md` records, measured across 2026-09-08 and 09, that two builds on this box answered differently while reporting the same identity:

> one build answers `getnettotals` 0/0 and `getpeerinfo []` with 17 connections, another answers 11.56 MB/s and 21 peers with per-peer byte counts — both reporting `subversion: /BitcoinMachineCode:0.0.1/`, so RPC cannot tell you which one you are talking to

and concludes that "the log banner remains the only build attestation on this box". A monitor therefore could not distinguish a fixed node from a broken one over RPC, and had to build `downloadMeasured`/`uploadMeasured` gates to avoid charting zeros as fact.

`getnetworkinfo` now emits `bmc_build_commit` and `bmc_build_dirty`. They are extension fields, `bmc_` prefixed like `getpeerinfo`'s `bmc_download_worker`, because `subversion` cannot carry this: it goes out on the wire in the version message and Core's semantics for it are the user agent.

The commit comes from a generated `build_gen.h`, rewritten only when the value actually changes (`cmp` before `mv`), so rebuilding at the same commit does not relink the world. Only `rpc_node.o` depends on it. No git available at build time yields `"unknown"`, which the test refuses.

The 0/0 symptom itself is **not** present on the current build: measured on snapshot ae, `getconnectioncount` 9, `getpeerinfo` 9 peers, `getnettotals` with real byte counts. It was build-dependent, which is exactly why the attestation is the durable fix.

## The download RPC keeps its `bmc` prefix; the monitor admits it by read verb

Every command of ours is prefaced `bmc*` (the operator's rule). #180 briefly renamed `bmcgetdownloadinfo` to `getbmcdownloadinfo` to satisfy bmcmonitor's allowlist, which is default-deny over read-shaped prefixes (`get`, `list`, `estimate`, …) and classified `bmc…` as "not recognised as a read-only method". That put the accommodation in the wrong repo, and the name is back.

The monitor now admits the marker **plus a read verb** — `bmcget`, `bmclist`, `bmcestimate`, `bmcverify` — rather than a bare `bmc`, which would have been the hole its own header warns about, pre-authorising a future `bmcsetban` or `bmcimportmempool`. The mutating `bmc` shapes are named explicitly in its deny list, and an unrecognised `bmc*` shape stays denied by default. Landed in bmcmonitor as fdec42f with a test covering all three cases, watched to fail.
