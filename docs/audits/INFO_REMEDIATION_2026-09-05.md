# INFO findings — what fixing them actually requires

Audit: `docs/audits/CODEBASE_AUDIT_2026-09-03.md`, 33 INFO findings.
Written 2026-09-05, after the CRITICAL/HIGH/MEDIUM tiers and 57 of 68 LOWs closed.

INFO was the tier nobody costed. This document reads all 33 against the code and
says, for each, what would have to change. It is a plan, not a promise: several
of these should be **closed as "won't fix, documented"**, and saying which is
most of the value here.

Three things are worth knowing before the table.

**INFO is not a synonym for trivial.** `SCR-10` is an unbounded parse loop that
is unreachable only because both callers happen to validate first. `RPC-14` is a
whitelist that fails **open** on a misconfiguration. `CRY-6` means the scalar
SHA-256 body never executes on the gate machine, so a regression in it ships
undetected. Those are latent-defect findings that landed in INFO because nothing
exploits them today.

**Nine of the 33 are documentation drift, and that is the same defect this
remediation has been chasing all week.** BLD-5 corrected nine stale claims; the
INFO tier contains nine more, in `MEM-22`, `VAL-16`, `DMN-14`, `RPC-19`,
`RPC-18`. The pattern is identical and so is the fix: verify against the code,
correct in place, say what it used to claim.

**The audit's own "verified-correct controls" sections are an asset.** Interleaved
with these findings are detailed re-derivations — the `fe_inv` addition chain
checked symbolically to `p-2`, the BIP324 key schedule label-by-label, the LSM
flush ordering, Core's `IsOpSuccess` table. Nothing to fix there, but they are
the closest thing this project has to a written proof of the crypto core, and
they should not be lost when the audit file is eventually archived.

---

## Tier 1 — latent defects. Fix these.

| id | what is wrong | what fixing it requires | effort |
|---|---|---|---|
| **SCR-10** | `tx_legacy_sigops` (`bitcoin_sigops.asm:123-306`) loads `r13 = len` and never compares against it; every varint and script walk indexes `r14` unconditionally. Unreachable today only because both callers pre-validate — the "a distant function already checked this" pattern this repo's own comments warn about. | Bound every read against `r12 + r13`, return 0 on overrun. Test with a truncated transaction through a guard page (`PROT_NONE`) so the overrun faults instead of reading adjacent heap — the technique that proved WAL-14. | M |
| **CRY-6** | `sha256_nia.asm` holds a second SHA-NI body *and the correct CPUID probe*, but is not built. The built dispatcher had the wrong probe (that was CRY-1, fixed). On a SHA-NI machine the gate never executes the scalar `sha256_block`, so a regression there ships undetected. `setb [shani_ready]` also stores 0 for "absent", which the `cmp …,0 / jne` guard reads as "not probed" — the probe repeats on every call. | Three separable pieces: (a) delete `sha256_nia.asm` or promote it to the single implementation — having two bodies where one is dead is the actual hazard; (b) fix the tri-state so "absent" is distinguishable from "unprobed"; (c) add a forced-scalar KAT run to the gate so the fallback is covered on SHA-NI hardware. (c) is the one that has caught nothing yet and would. | M |
| **RPC-14** | With `rpcwhitelistdefault=1` and no `rpcwhitelist` entries, Core denies every user; here `g_wl_n == 0` allows everyone (`rpc_server.c:181`). **Fails open**, on a misconfiguration an operator would reasonably expect to be safe. | Mirror Core's `!user_has_whitelist && g_rpc_whitelist_default` and return 403 before parsing. The second half (an unparseable body from a whitelist-less user gets a parse error instead of 403) falls out of the same reordering. `tests/test_rpc_whitelist.c` already has the harness. | S |
| **RPC-20** | `rpc_node.c:1873-1875`: `tx_txid`'s scratch is 162,008 bytes while the stage accepts 404,000. A transaction whose stripped size exceeds 162 KB gets `-22 "TX decode failed"` instead of the worker's real policy reject. `submitpackage` already uses a 1 MiB scratch. | Size the scratch to the stage limit, as `submitpackage` does. Genuinely a one-line fix with an existing correct example beside it. | S |
| **UTX-11** | `utxo_dump_keys.c:24` treats `slen == 0` as unspendable; Core's `IsUnspendable` and this tree's own `bitcoin_utxo_stats.asm` treat an empty script as **spendable**. Diff-tooling drift — the tool disagrees with the thing it audits. | One-line predicate change, plus a vector with an empty-script coin so the two agree by test rather than by inspection. | S |
| **STO-13** | Chainwork is truncated to 128 bits (`bitcoin_chainwork.asm:334-475`) and `chainwork_add` is a plain add/adc with no saturation. Not reachable — mainnet cumulative work is ~2^97 and `pow_check` rejects the targets that would be needed — but the failure mode if it ever were reached is silent wraparound in fork choice. | Saturating add. Defence in depth; the audit itself rates it "correct as used". | S |

## Tier 2 — real divergences from Core, small and well-defined.

| id | divergence | fix |
|---|---|---|
| **MEM-24** | `getdata(MSG_TX)` is answered with **witness** bytes (`tx_relay.c:1195-1200` and the `bitcoin_serve.asm` getdata arm mask the flag but serve the stored serialization). Core serializes `TX_NO_WITNESS` for a non-witness request. Only pre-segwit peers are affected — they would fail to parse the reply. | Strip the witness on the `MSG_TX` arm. `strip_witness` already exists and is used on the block path; the serve path's own comment already acknowledges the block case. |
| **MEM-23** | `-acceptnonstdtxn` gating differs: `tx_accept.c:655-661` runs legacy-sigop, `bad-txns-too-many-sigops` and `IsWitnessStandard` unconditionally, where Core gates `IsWitnessStandard` on `require_standard`; conversely `standard_checks:481` returns before `tx-size-small`, which Core runs unconditionally. Test-network only. | Move two checks across the `accept_nonstd` branch. Note this now interacts with **SCR-9** (closed 2026-09-05), which put the same switch on the script flags — do them as one change and test the combination. |
| **RPC-16** | `rj_dup` round-trips the `id` through a 64 KiB stack buffer (`rpc_server.c:412-418`); a larger `id` — allowed by the 9 MiB request cap — is silently echoed as `null`. `rj_clone` does it without a cap. | Use `rj_clone`. The capped path exists for no reason the audit could find. |
| **RPC-18** | RPC listener is IPv4-only (`AF_INET`, `inet_pton(AF_INET)`), so `rpcbind=::1` is fatal, `rpc_acl.c:18` seeds a `::1` entry that can never match, and every IPv6 `rpcallowip` is dead. `FEATURE_GAPS.md:1344` lists `rpcbind` as implemented with no IPv4 qualifier. | Either add `AF_INET6` (moderate: socket, `inet_pton`, and `server_thread`'s peer formatting at `:797-798`) or **document the limitation and delete the dead `::1` seed**. The dead seed is the part that actively misleads; fix that either way. |
| **STO-14** | `block_filter.c:196-206` dedups BIP158 elements on the 64-bit SipHash rather than on the script bytes, as Core's `GCSFilter` does. Two scripts colliding on 64 bits give N one less than Core's and a different filter. ~n²/2^65 per block. | Dedup the byte-wise element set before hashing. Negligible probability, but the KAT-backed "byte-identical" claim currently carries an unstated caveat — at minimum state it. |
| **RPX-9** | `decoderawtransaction`/`converttopsbt`/`simulaterawtransaction` reject transactions over 200,000 bytes (`rpc_commands.c:589-591`, `:868`); Core decodes up to ~4 MB. | Raise the cap to the block serialized-size limit. |
| **RPX-8** | `gettxoutproof` without a blockhash lacks Core's coinsview fallback (Core locates the containing block when every requested txid is unspent, even with no txindex), and duplicates `getrawtransaction`'s index-coverage error text nearly verbatim (`rpc_chain.c:1965-1975` vs `:1904-1918`). | The duplicated error block is the cheap half — factor it. The coinsview fallback is real work and may be better left documented. |
| **SCR-11** | `bitcoin_interp.asm:2809-2827` runs signature/pubkey encoding checks before the FindAndDelete callback; Core's `EvalChecksigPreTapscript` runs FindAndDelete first. Verdicts agree — only the reported error differs when a script trips both. | Reorder, or document. Policy-only, no verdict changes. Low value either way; listed for completeness. |

## Tier 3 — documentation drift. Same defect as BLD-5.

These need no code. Each is a claim the code contradicts.

- **MEM-22** — `tx_relay.c:15-31` claims "no re-announcement" and "no BIP339 wtxidrelay"; **both are implemented in that same file** (`txrelay_announce`, `TXR_MSG_WTX`). `FEATURE_GAPS.md:1405-1406` lists `zmqpubsequence` as implemented while `node_config.c:750-765` refuses it and `zmq_pub.c` never publishes the topic. `zmq_pub.c:26-33` says a slow subscriber has its message dropped; `:471` closes the subscriber instead.
- **VAL-16** — `README.md:26-28` claims consensus `MAX_MONEY` range checks and `FEATURE_GAPS.md:561-563`/`:1998-2004` claim the CVE-2010-5139 shape matches Core and that every non-script consensus rule is checked chain-wide. Per VAL-1..VAL-6 none of these held on the block path. Also: `bitcoin_txv_dispatch.asm:188-196` omits the `g_txv_script_checks` short-circuit that `tx_verify.c:1093` has. No production caller today, but the differential will diverge the first time it runs with assumevalid on — a trap for a future reader.
- **DMN-14** — six small items, of which two are real: the SIGCHLD reaper counts every non-worker child as inbound, so `startupnotify`'s intermediate child drifts `g_inbound_n` low by one; and `main.c:492`'s `lsock` never checks `socket()`, so a failure is reported as "bind failed" (`bind(-1)` → EBADF). Also `FEATURE_GAPS.md:1326` marks `peertimeout` implemented — wrong, per DMN-3.
- **RPC-19** — `rpc_node.c:572-583` says the node keeps no ban list and has no RPC ping path; both exist. `rpc_server.h:1-27` describes a loopback-only server. `rpc_server.c:607-618` says the accept loop is serial — it has been a pool since 2026-09-01; only *execution* is serial. (`rpc_server.c:512-514`, the fourth item, was corrected by RPC-6 on 2026-09-05.)
- **RPC-15** — start-up ordering: the listener starts at `main.c:6026`, `rpcauth` registers at `:6048`, the cookie is written at `:6055`. The window is fail-closed, and `g_rpcauth[]` is written while workers may read it — a torn read can only reject. **Reordering the three calls removes both issues**, so this one is a two-line fix rather than a doc change.

## Tier 4 — accepted risks. Recommend closing as "won't fix, documented".

- **CRY-7 / WAL-19** — the wallet ECDSA nonce is `sha256d(z || priv)`: deterministic, key- and message-bound, constant-time in `k`, low-S normalised. Not RFC 6979, so signatures are not byte-comparable with Core's. The specific gaps — `z` fed to `sc_add` unreduced (~2^-128), `k == 0` / `r == 0` unchecked (2^-256), `bip32_master` accepting `IL >= n` (2^-128) — are all negligible-probability. **Worth doing anyway:** reduce `z` mod `n` and reject `k`/`r`/`s == 0` with a counter retry. Cheap, removes a class of argument. Adopting RFC 6979 is a bigger decision (interoperability vs. churn in every signature vector) and should be taken deliberately, not as audit cleanup. One item here is a real bug, not a probability: `rpc_wallet_ops.c:248-262` accepts an xprv whose scalar is 0 or ≥ n, where Core's `CExtKey` rejects it — **that one should be fixed**.
- **CRY-8** — AES: the lazy inverse S-box build is an idempotent racy write (benign on x86); the padding check and S-box are variable-time. Correctly scoped out for at-rest wallet encryption, since no attacker-chosen ciphertext is decrypted online. Close.
- **NET-16** — the node sends `/Satoshi:25.0.0/` on feeler and block-relay-only handshakes and `/Satoshi:0.18.0/` with a fabricated `start_height 789000` on the seednode path, neither matching its own `node_ua_buf`. This misrepresents the node to peers and to network crawlers. It is listed here not because it is hard but because it is a **decision, not a defect** — someone chose it. It should be made explicitly, and documented, rather than left in the code unremarked.
- **NET-17** — onion/I2P inbound violations call `ctl_ban_add("onion-inbound/32")`, which `subnet_parse` later rejects, so nothing is enforced but a fixed-size ban-list slot is consumed per event and `ctl_ban_add` returns 0 silently when full. Small and worth fixing: skip the ban call for non-IP peer descriptors.
- **STO-13**, **SCR-11** — see above; both are "correct as used".

## Tier 5 — build and process. Mostly hygiene, one real gap.

- **BLD-7 — the only one here with teeth.** `grep fsanitize` finds only *prose* in `LOG.md` claiming corpora were run under `-fsanitize=address,undefined`. There is no `make test-asan` or `SAN=1` knob, so **nobody can reproduce those runs**, including the person who did them. The C P2P/RPC parsers are exactly what `HARDEN_CC` was added for. A `SAN=1` build of the C-only harnesses (`test_rpc_json`, `test_rpc_json_depth`, `test_p2p_msgsize`, `test_addr_ingest_parse`, `test_v2transport`, `test_node_config`) is cheap and turns a claim into a command. **Recommended.**
- **BLD-6** — the gate is one recipe with 348 command lines, and a recipe stops at its first failing line even under `-k`, so an early failure silently skips everything after it. `gate-log-check` exists precisely to detect that. Structural, understood, mitigated — no change recommended beyond keeping `gate-log-check` gated.
- **BLD-8** — vector provenance. Five generators are independent Python models rather than Core oracles: `gen_cmpct_expected.py`, `gen_p2sh_vectors.py`, `gen_taproot_scriptpath_vectors.py`, `gen_multi_p2wpkh.py`, `gen_fe_sqrt_vectors.py`. Not circular, but the weaker of the two kinds, and `taproot_scriptpath_vec.h` records what that costs: three vectors carried a wrong control-byte parity and passed because the verifier ignored the bit. Also `gen_script_flags.py` is manual after a Core upgrade and nothing asserts the committed header still matches the Core tree on disk. **Recommended:** a gate rule that re-runs `gen_script_flags.py` and diffs, so a Core upgrade cannot silently desync the flag table.
- **BLD-9** — `scripts/start.sh`/`stop.sh`/`status.sh` drive a *system* `bitcoind`, not `asm/daemon/bitcoind`, and do not match README's quick start. (The dangerous `killall bitcoind` fallback was already removed during this remediation.) Repoint or delete.
- **BLD-10** — repo hygiene, re-verified clean: 997 tracked files / 22 MB, nothing over 5 MB, `git status` clean, no key material in tracked files **other than BLD-3**. No action.

---

## Recommended order

1. **RPC-14** — the only fail-open finding in the tier.
2. **SCR-10** — the only unbounded parse loop; guard-page test.
3. **BLD-7** — makes an unreproducible claim reproducible, and would find more of the above.
4. **RPC-20, UTX-11, RPC-16, RPC-15, WAL-19's xprv check** — one-liners with obvious right answers; batch them into a single gate run.
5. **MEM-24, MEM-23, RPX-9** — Core-parity divergences; do MEM-23 together with SCR-9's `-acceptnonstdtxn` switch.
6. **CRY-6** — delete the dead file, fix the tri-state probe, add the forced-scalar KAT.
7. **Tier 3 documentation** — one commit, in the shape BLD-5 used.
8. **Decide and record** NET-16 (impersonated user agents) and RPC-18 (IPv4-only RPC). Both are choices masquerading as findings.

Not recommended: RFC 6979 adoption, IPv6 RPC, and `gettxoutproof`'s coinsview
fallback — each is real work for a benefit that should be argued on its own
merits rather than inherited from an audit checklist.

**Out of band — CLOSED later the same day:** BLD-3. The Core oracle node's RPC
password was in git history; rotation was manual work on that host and no code
change closed it. Done and recorded in
`docs/audits/BLD-3_CREDENTIAL_ROTATION_2026-09-05.md`, with the exposed pair
proven dead against the live node (cookie auth 200, leaked pair 401). The
history caveat stands: the old value remains in git and cannot be removed
without a rewrite.
