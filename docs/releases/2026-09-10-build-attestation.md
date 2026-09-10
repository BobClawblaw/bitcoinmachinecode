# 2026-09-10 — getnetworkinfo names the build; the download RPC is renamed so a monitor may call it

Two fixes found by reading bmcmonitor's own notes and its RPC allowlist.

## `getnetworkinfo` carries the build's commit

bmcmonitor's `AGENTS.md` records, measured across 2026-09-08 and 09, that two builds on this box answered differently while reporting the same identity:

> one build answers `getnettotals` 0/0 and `getpeerinfo []` with 17 connections, another answers 11.56 MB/s and 21 peers with per-peer byte counts — both reporting `subversion: /BitcoinMachineCode:0.0.1/`, so RPC cannot tell you which one you are talking to

and concludes that "the log banner remains the only build attestation on this box". A monitor therefore could not distinguish a fixed node from a broken one over RPC, and had to build `downloadMeasured`/`uploadMeasured` gates to avoid charting zeros as fact.

`getnetworkinfo` now emits `bmc_build_commit` and `bmc_build_dirty`. They are extension fields, `bmc_` prefixed like `getpeerinfo`'s `bmc_download_worker`, because `subversion` cannot carry this: it goes out on the wire in the version message and Core's semantics for it are the user agent.

The commit comes from a generated `build_gen.h`, rewritten only when the value actually changes (`cmp` before `mv`), so rebuilding at the same commit does not relink the world. Only `rpc_node.o` depends on it. No git available at build time yields `"unknown"`, which the test refuses.

The 0/0 symptom itself is **not** present on the current build: measured on snapshot ae, `getconnectioncount` 9, `getpeerinfo` 9 peers, `getnettotals` with real byte counts. It was build-dependent, which is exactly why the attestation is the durable fix.

## `bmcgetdownloadinfo` → `getbmcdownloadinfo`

The name shipped in #179 was unreachable from the consumer it was written for. bmcmonitor's `server/rpc/allowlist.js` is default-deny over read-shaped prefixes (`get`, `list`, `estimate`, …), so `bmc…` classified as "not recognised as a read-only method".

Widening that allowlist with a `bmc` prefix would be wrong, and the file says why: "a prefix rule like *starts with get* would be a hole, not a guard". A `bmc*` prefix would pre-authorise a future `bmcset*`. Leading with `get` passes the existing rule unchanged, keeps the `bmc` marker so no Core name can ever collide, and needs no change on the monitor side.

Verified: `test_rpc_node` covers both, each watched to FAIL first (`bmc_build_commit` forced to `"unknown"`). Gate `make -j8 -k test` MAKE_EXIT=0, 372 suites.
