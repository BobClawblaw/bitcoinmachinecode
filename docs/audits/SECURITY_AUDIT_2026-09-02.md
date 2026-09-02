# SECURITY AUDIT — /storage/bitcoinmachinecode

**Audit date:** 2026-09-02 (UTC)
**Auditor:** independent review (Hermes Agent)
**Tree state:** `main` @ `d87adba` (clean working tree); live node = deploy `bitcoind.deploy-20260902ai` (from `ac64d46`), running as the unprivileged service account
**Scope:** full tree — crypto, consensus/validation, P2P/BIP324, RPC, wallet, storage/LSM, build system, secrets hygiene, host/deployment integration. Prior audits (`docs/audits/SECURITY_AUDIT_2026-08-29.md`, `AUDIT_RESPONSE_2026-08-30.md` + addendum) read first; every claimed fix re-verified against current source and the deployed binary.
**Method:** targeted line-level source review of every claim relevant to security, live system state read from `ss`/`ps`/`stat`/`readelf`/`nm`/systemd units, exhaustive git-history sweep (all 1,221 commits), live RPC auth probes (loopback), config and log content review.

Severity scale: CRITICAL / HIGH / MEDIUM / LOW / INFO.

---

## Executive summary

This is a full validating Bitcoin node — consensus and crypto hand-written in x86-64 NASM with a C orchestration layer — running **live on mainnet** at block ≈ 965,104 with a real (funds-free) HD wallet. Two prior audit rounds and their remediation are documented unusually honestly in-tree.

**Headline: every 2026-08-29 finding that was marked fixed is verifiably fixed in both source and the deployed binary.** Eight of eleven closed, one (structural hand-written asm) correctly left open as a project property, misbehaviour scoring now has real callers, and the two most recent production incidents (2026-09-01) were fail-closed data-integrity events with the right final design.

The security-relevant risk profile in September 2026 is dominated by things no patch retires:

1. **Structural (HIGH, unchanged):** consensus-critical logic is hand-authored assembly with a documented history of optimizer- and codegen-sensitive failures. This audit found concrete Makefile evidence (item N1 below) that `-O2`+ has, in specific harnesses, produced **wrong block parses** — pinned away with `-O0`/`-O1` per target rather than root-caused. The live daemon is `-O2`.
2. **New incident class (HIGH, current):** the 2026-09-01 UTXO incident produced **2,596 resurrected spends** — the node briefly accepted coins that were already spent, i.e. the false-accept/double-spend direction, in production, for hours, caught only by muhash parity against Core. The fix (halt-on-absent-coin) is correct, fail-closed, and verified live — but this is the same structural property as item 1, now proven in a running node.
3. **Credential hygiene is genuinely clean now (was the prior audit's messiest area):** the RPC password is gone from live config, auth is cookie-only (verified live: 401/401/200), wallet passphrase lives outside the datadir root-owned, and the git-history purge is verified complete across all 1,221 commits reachable from all refs (only the `<REDACTED-PURGED-20260829>` placeholder remains; the leaked password itself was the trivially weak value `bitcoin`, already public and now deleted rather than rotated).

**No new CRITICAL findings. No new HIGH code finding beyond the structural one.** Four MEDIUMs, a set of LOWs, and a substantial list of verified-positive controls below.

---

## 1. Re-verification of the 2026-08-29 audit (independent, not on trust)

| # | Prior finding | Claimed status | Verified status | Evidence |
|---|---|---|---|---|
| 1 | Weak v2 wallet encryption (2048-iter PBKDF2, custom CTR/MAC, key reuse) | Resolved (wallet regenerated in strong container) | **VERIFIED-FIXED for the live wallet; weak format still ships in code** | `data/main/bmcwallet.enc` header reads `BMCWENC1` (hexdump confirmed); `asm/daemon/wallet_crypter.c:37` `#define WC_ITERS 100000` with Core's BytesToKeySHA512AES (lines 5,40). BUT `asm/wallet_store.c:20,153` still writes/loads `BMCWAL v2` at 2048 iterations (see NEW finding N4). |
| 2 | Plaintext passphrase beside the wallet | Resolved | **VERIFIED-FIXED** | No `*.pass` anywhere under `data/`; `walletpassfile=/etc/bmc/wallet.pass` (`config/bitcoin.conf:83`); `/etc/bmc/wallet.pass` is `0640 root:<service group>` — readable by service account, writable only by root. Refusal rules present in code: `asm/daemon/wallet_pass.c:59-60` refuses world-accessible (`mode & 0007`) and group-writable (`mode & 0020`); not-a-regular-file refused at :56. Live boot log: "encrypted wallet adopted and unlocked from the configured passphrase source". |
| 3 | Hand-written consensus asm with false-ACCEPT history | Not closeable | **OPEN — and re-enforced by this audit** (see N1 and §4) | See below. |
| 4 | RPC plaintext password + history exposure | Resolved (password), history rewrite declined | **VERIFIED-FIXED (password gone; purge complete)** | `grep rpcpassword config/bitcoin.conf` → comments only. Live probes: unauth POST → 401, wrong cookie → 401, real cookie → 200. Full-history sweep: **all 1,221 commits from all refs** (incl. `arm-port`, tags, worktree refs) — every `rpcpassword=` line contains only the placeholder; zero pre-purge values reachable from this clone. Caveat carried from the project's own worklog: GitHub retains unreachable objects by SHA until GC; moot since the value was weak and is deleted. |
| 5a | `crt_amount_to_sat` overflow | Resolved | **VERIFIED-FIXED** | `asm/rpc_commands.c:681-684` `CRT_MAX_MONEY`/`CRT_MAX_WHOLE` defined; bound applied **during accumulation** and `sat > CRT_MAX_MONEY` rejected at `:710`. Pinned by `tests/test_rpc_amount` (in gate). |
| 5b | Missing consensus `MAX_MONEY` | Resolved | **VERIFIED-FIXED** | `asm/bitcoin_txval_modern.c:99` `MV_MAX_MONEY 2100000000000000ULL`; per-output `if (v > MV_MAX_MONEY) return 0;` and **per-iteration** running-total `if (T->out_total > MV_MAX_MONEY) return 0;` at :203-:205 — exactly Core's `CheckTransaction` order (CVE-2010-5139 shape); validated against 1,172 real mainnet txs per the remediation doc. |
| 6 | P2P framer had no message-size limit | Resolved | **VERIFIED-FIXED** | `asm/bitcoin_net.asm:71` `P2P_MAX_MSG equ 4000000`; `cmp eax, P2P_MAX_MSG / ja .oversize` at :567 **before** any drain; distinct `-3` at :644. Same bound enforced on the BIP324 path. |
| 7 | `peer_misbehaving()` had zero callers | Partially resolved (one caller) | **VERIFIED-FIXED with scope — now TWO scored classes; still partial** | Serve loop wires the `-3` oversize announcement (`asm/bitcoin_serve.asm:95` `viol_oversize`, hook call at :1607) **and** `inv/getdata` above `MAX_INV_SZ` (`:96 viol_invsz`, :1591) → `serve_violation_report` (`asm/daemon/main.c:1243-1246`, hooked at :6277) → `peer_misbehaving(...,100,...)` → shared file-backed ban list `ctl_ban_add` (`:1249-1262`), enforced on dial+accept. Shared-table scoring visible at `:1304-1321` (parent+children share `g_node_status->misbehavior`). Still unwired: duplicate-inv spam, malformed addr/tx/block payloads, handshake failures (see N3). |
| 8 | ZMQ `tcp://*` bind; poll in hot loop | Resolved | **VERIFIED-FIXED** | `asm/daemon/zmq_pub.c:169-175` — `*` refused with an explicit message; `0.0.0.0` still available for operators who mean it. Poll moved to a dedicated thread (`:92-102` comments, mutex around `subs/nsubs`), TSan-clean per the remediation doc. Live node: ZMQ listeners 28332/28333 are **127.0.0.1-only** (verified with `ss`). |
| 9 | Weak ELF hardening (RWE stack, no BIND_NOW) | Resolved | **VERIFIED-FIXED on the live binary** | `readelf -lW` on the deployed `bitcoind.deploy-20260902ai`: `GNU_STACK ... RW` (not RWE); `readelf -d`: `FLAGS BIND_NOW`, `FLAGS_1 NOW`. `HARDENFLAGS := -Wl,-z,relro,-z,now` at `asm/Makefile:2469`. Residual: still `EXEC` (non-PIE, forced by the asm's absolute addressing), only 1 `__stack_chk` symbol, no FORTIFY (see N7). |
| 10 | Datadir file hygiene | Resolved | **VERIFIED** | `data/` is `0750`; `.cookie` 0600, `bmcwallet.enc` 0600, `walletkeys.dat` 0600, `walletscan.dat` 0600, `addressbook.dat` 0600, `onion_v3_private_key` 0600. Remaining 0644 files in `data/main/` are `undo_*.dat`/`bfilters.dat`/`blk*.dat`/`addr_index.dat` — chain data, not sensitive. `peerclaims.*` 0665 are transient worker lock files. |
| 11 (prior §deployment) | `LimitCORE=infinity` | **NOT DONE** (operator direction) | **STILL OPEN** | `/etc/systemd/system/bmc-bitcoind.service` still carries `LimitCORE=infinity` and zero sandbox directives (see N5). |

Prior follow-up items I specifically checked because they were "near-term" recommendations:

- **JSON parser depth counter: DONE.** `asm/rpc_json.c:361-368` counts container depth **before recursing**, `RJ_MAX_DEPTH = 512` matching Core's UniValue limit; boundary pinned by `tests/test_rpc_json_depth.c`.
- **RPC start on cookie alone: DONE.** `tests/test_rpc_start_policy` in gate; incident 2's start-gate bug is pinned.

## 2. New findings

| # | Severity | Where | Finding |
|---|---|---|---|
| N1 | **MEDIUM** | `asm/Makefile:917-922, 2474-2478` | Optimizer-dependent **wrong block parses** pinned away, not root-caused |
| N2 | **MEDIUM** | structural (§3) | 2026-09-01 incident proves false-accept was reachable in production |
| N3 | **MEDIUM** | `asm/bitcoin_serve.asm` | Misbehaviour scoring wired for only 2 of the ~6 violation classes the code already detects |
| N4 | **MEDIUM** | `asm/wallet_store.c:20,153` | The weak `BMCWAL v2` format (2048-iter KDF, custom CTR/MAC, key reuse) still ships and is still written by the CLI path |
| N5 | **MEDIUM** | systemd unit | `LimitCORE=infinity` on a process that holds the decrypted wallet seed, with no sandbox directives |
| N6 | **LOW** | `/etc/systemd/system/bmc-logrotate.service` + `logs/main/` | root-run `logrotate` with `copytruncate` on a directory writable by the service user — local overwrite primitive if the service account is compromised |
| N7 | **LOW** | build | No `-fstack-protector-strong`, no `_FORTIFY_SOURCE`, non-PIE, no `-Werror` |
| N8 | **LOW** | `config/bmcwallet.testnet4.pass` | Dev wallet passphrase still on disk (0600) for testnet |
| N9 | **LOW/INFO** | host | P2P 8332 on `0.0.0.0` with no host firewall (INPUT policy ACCEPT); host also runs docker bridges, a VPN overlay, and Samba (nmbd on 0.0.0.0:137/138) |
| N10 | **INFO** | `asm/rpc_server.c:748-757`, `main.c:5811-5816` | "RPC cannot leave loopback" is now a config-gated property, not an impossibility — gating is correct (Core semantics, fail-closed ACL parse) |
| N11 | **INFO** | repo hygiene | 69 deploy binaries (2.1 GB), stale `.worktrees/` + `.claude/worktrees/privbcast` full source copies (older vulnerable code paths on disk), 5 `config/bitcoin.conf.bak-*` (verified: no live credentials, comments only) |

### N1 (MEDIUM) — Compiler-flag-dependent block parsing, pinned rather than fixed

The Makefile documents, twice, that aggressive C optimization changes **validation results**:

> `tests/test_bitcoind_sync`: "Built at -O0: ... provably works at -O0, but gcc -O2's main register/stack layout triggers a **latent sha256_full deep-frame-overlap crash** in this specific networked harness."
> `pverify`: "Built at -O1 (not -O2/-O3): the deep asm call chain ... **mis-parses a block** when the C driver is compiled at aggressive -O2+, a documented codegen interaction."

A block parse that changes with the *C driver's* optimization level means the asm↔C calling contract is being violated somewhere (stack layout, red zone, callee-saved discipline) — the same class of defect as the historical `SETcc` false-accept incident. The project mitigates with two genuinely good tools (`scripts/abi_stack_audit.py`, `abi-check`/`callee-saved-check` in the 313-target test gate) and full-chain differentials — and the daemon itself (built -O2) has passed hash-for-hash against Core across the entire chain. But the root cause of the `sha256_full` frame overlap and the pverify mis-parse remains open, and the daemon shares those exact objects. This is the strongest *concrete* expression of why finding 3 (structural) has never been closable: the differential is what protects consensus, not the ABI audit.

**Recommendation:** treat `sha256_full` frame overlap as an open defect with a fix target, not a build comment; run the fullchain differential on every compiler version bump; consider UBSan/ASan harnesses in CI even if too slow for the gate.

### N2 (MEDIUM, current-state of structural) — false-accept was reachable in production (2026-09-01, fixed same-day)

Read carefully, the incident is a **consensus-integrity event**: a UTM-LSM sparse-sampling bug made ~10-15% of point lookups through a freshly flushed run miss; with undo-capture ON (`undo_capture_and_del` = get-then-del), a miss returned 0, the apply path read 0 as "already absent, crash-resumed" and **skipped the spend** — leaving 2,596 spent coins live. For several hours the live node carried a chainstate that would have **accepted double-spends**, detected only by muhash parity against Core (offline repair deleted the resurrected spends; muhash re-identical at 965,085 → 965,104).

The fix (verified live in `asm/daemon/utxo_live.c`): an absent coin at spend-apply is now classified as store inconsistency → block fails, **lookup-free rollback**, `g_halted=1` halts UTXO tracking for the process life (`:613, :1028, :2071`), with recovery gated and never blind (`874c1a8` + `tests/test_utxo_recover_gate`). This is exactly the right fail-closed design — false-reject/halt instead of silent false-accept — deployed as `ai` with reload exact and muhash identical at 965,104. It counts as a *positive* response to a *serious* event; it stays on this list because it is the empirical proof for the structural HIGH and because a future miss in a different lookup site still needs the same treatment.

### N3 (MEDIUM) — anti-DoS scoring still narrow

Wired today: oversized message announcement (100 pts), inv/getdata vector above `MAX_INV_SZ` (100 pts). Not wired, though the code detects these violations: malformed addr/tx/block payloads failing parse, handshake protocol failures, duplicate-inv spam. A peer can still cycle through non-scored offence types with no ban consequence. Ban machinery itself is sound (shared file-backed list, /32 auto-ban, NOBAN permission respected, lock held-by-dead recovery at `main.c:1105`).

### N4 (MEDIUM) — the weak v2 store format was retired from the live node, not from the codebase

`asm/wallet_store.c` still documents and implements `BMCWAL v2`: PBKDF2-HMAC-SHA512 at **2,048 iterations**, salt-less, custom CTR (keystream `sha512(u32le(i)‖0)⊕K`) and prefix-MAC `sha512(K‖"BMCWAL-tag"‖ct)` with the same K keying both. The CLI writes it. Any future user of the CLI path, any imported store, any backup of an old store re-enters the system through the door the wallet migration closed. The strong `BMCWENC1` container exists and is now used everywhere that matters.

**Recommendation:** make `wallet_store.c` refuse to *write* v2 (write `.enc` only), keep read for migration with a loud log line, and delete the format once no read path can select it.

### N5 (MEDIUM) — core dumps + auto-unlock + no sandbox

The unit runs the daemon that **auto-unlocks the wallet at boot from `/etc/bmc/wallet.pass`** (decrypted seed resident in process memory for the service lifetime) with `LimitCORE=infinity` and none of `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `PrivateTmp`, `RestrictAddressFamilies`. The 2026-08-30 remediation doc records a mnemonic leaked through a *debugger backtrace* — the identical exposure class a core dump of this process provides, with `Restart=on-failure` making crashes an expected event (the 09-01 worklog records several). `core_pattern` here pipes to apport, which limits the blast radius on *this* host, but the unit is the wrong template for any other machine.

**Near-free fix:** `LimitCORE=0`, `NoNewPrivileges=yes`, `ProtectHome=read-only` (datadir is under /storage, not home), `PrivateTmp=yes`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`. The notify-hook exec requirement is the only directive needing care.

### N6 (LOW) — root logrotate over a service-user-writable directory

`bmc-logrotate.service` runs the root logrotate on `/storage/bitcoinmachinecode/logs/*/*.log`; `logs/main/` is `0775 <service user>:<service group>` and the live log is `0644 root:root`. A compromised service account (which on this host also belongs to the sudo group) can replace a log path with a symlink/inode under a root `copytruncate` rotation — a local overwrite/DoS primitive against root-owned files. Fix: `owner` directive in the logrotate stanza, or mode `0750 logs/main` with the daemon writing and logrotate running as `su <service user> <service group>`.

### N7-N9 (LOW/INFO)

- Build: `CFLAGS := -no-pie -O2 -Wall` (no `-Werror`, no stack-protector-strong, no FORTIFY); only the daemon link carries `relro,now`. PIE is genuinely constrained by the hand asm; the other three flags are not — add them to the daemon link and to C objects built with security-relevant code.
- `config/bmcwallet.testnet4.pass` (0600): a testnet passphrase on disk; the daemon's own refusal rules exist for exactly this pattern — the CLI dev convenience is the last `.pass` in the repo. Delete it; env-only for testnet.
- Host exposure: P2P `0.0.0.0:8332` (and IPv6) with **no host firewall filtering INPUT** (default policy ACCEPT); reachable from the host's LAN interface and its VPN-overlay interface. That is intentional for a relay node; the unfiltered coexistence with nmbd (0.0.0.0:137/138), avahi, and docker bridge interfaces is the host's problem, not the node's — but a node whose README says "machine you can afford to lose" deserves a tightly filtered INPUT chain. Also: root-owned log files being `tail`'d by user processes is benign in current state (owner root, tailers run as the service user); the earlier concern from the 08-29 report is reduced but see N6.

## 3. Verified live-system state (not inferred)

- Sockets: `0.0.0.0:8332` + `[::]:8332` (P2P, both node processes), `127.0.0.1:8331` (RPC, parent), `127.0.0.1:28332/28333` (ZMQ). RPC **cookie-only** (no rpcuser/rpcpassword anywhere), verified 401/401/200 by live probe.
- Processes: parent + forked worker, both running as the unprivileged service account; wallet locked→auto-unlocked per log line at boot; ZMQ loopback only.
- `readelf` on the live deploy: non-PIE `EXEC` (known), `GNU_STACK RW`, `BIND_NOW`/`NOW`, 1 stack-chk symbol.
- Git: working tree clean; remote is a **public** GitHub repo; history purge verified across **1,221/1,221 commits, all refs**.
- Secrets sweep of tracked content: no private keys, mnemonics, tokens, or cloud credentials found (only BIP39/BIP32 test vectors in fixtures/validation). `seeds.txt`, `good_internet_peers.txt`, `internet_peers.txt` are public-network data, not operator secrets. No SUID/SGID files; no world-writable code files; one outbound symlink (`data/signet` → `/mnt/archive/bmc-signet/signet`).
- Test/safety surface: 313 test binaries in `make test` + `abi-check`, `callee-saved-check`, `prereq-check`, `runlist-check`, `link-check`, `gate-log-check` meta-auditors (gate-log audit is itself self-tested — a checker that is checked); full-chain hash-for-hash differential `validation/fullchain_diff.py` against Core's on-disk blk files is the consensus oracle and the muhash parity check ran clean at 965,104 on the live deploy.

## 4. Prior-audit items that are now OBSOLETE-CORRECTED

- The 08-29 finding "RPC is loopback-only *by construction* (no code path to widen)" is no longer the architecture: `rpcbind` is now implemented (`rpc_server.c:748-757`) with Core's exact gate — binding to a non-loopback address **requires** `rpcallowip`, and a malformed `rpcallowip` is **fatal at startup** (`main.c:5797-5806`), matching Core's `InitHTTPAllowList`. The current config sets neither, so the live bind is loopback (verified). The old "impossible" property became a "gated, fail-closed, Core-identical" property. Acceptable; worth knowing the impossibility is gone.
- "Misbehaviour machinery has zero call sites" is obsolete — two scored classes now (N3 above).

## 5. Positive controls (verified this round, do-not-regress list)

1. Constant-time RPC `auth_ok`: all credential arms evaluated every time (`by_pass`/`by_cookie`/`by_auth`), `ct_eq` folds the longer operand, empty-config-password cannot authenticate (`rpc_server.c:274-293`).
2. `wenc_encrypt` **verify-before-destroy**: container re-opened from disk, unsealed, payload compared byte-for-byte before the plaintext store is unlinked; failure keeps the wallet (`wallet_enc_state.c:116-152`); payload/seal buffers zeroized.
3. `wallet_pass.c` refuses weak-mode/datadir-internal passphrase files with loud logging — the refusal is paired with accepted-mode tests so it cannot rot into refuse-everything.
4. `MAX_MONEY` consensus check: per-output AND per-iteration running total, with the reasoning about why check-at-the-end fails to prevent u64 wrap recorded in-comment (`bitcoin_txval_modern.c:180-205`).
5. P2P framer rejects `> 4,000,000` announced with a distinct error code before touching the drain loop, and returns *without consuming* the trailing bytes.
6. BIP324/ElligatorSwift: ephemeral secret zeroized on every teardown path (`crypto_bip324_transport.c:127,183`), ECDH hash order fixed by role (`crypto_ellswift_ecdh.c:10-13`), v1-fallback and `MSG_PEEK` behaviour test-pinned.
7. JSON depth counter, 9 MiB request cap, `service_conn` incremental header scan; `signer` popen argument is operator-configured with correct single-quote escaping (`rpc_signer.c:33-45`, `sq()`); wallet names validated to `[A-Za-z0-9._-]` with leading-dot rejection (`rpc_wallet_ops.c:105-112`).
8. Ban system: shared table with hold-by-dead recovery, NOBAN honoured **before** scoring, full-list-no-silent-evict.
9. Halt-on-absent-coin (`utxo_live.c:613`) + lookup-free rollback + gated recovery — the fail-closed pattern applied correctly under an active incident.
10. `prune=0`, `privacy=1`, `dbcache` sized against a documented OOM; DNS-over-proxy privacy (`test_privacy_dns`, six predicates pinned); chain-vs-datadir mismatch refusal.

## 6. Prioritized remediation

**This week**
1. Unit hardening: `LimitCORE=0`, `NoNewPrivileges=yes`, `ProtectHome=read-only`, `PrivateTmp=yes`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` (N5).
2. Make `wallet_store.c` refuse to write v2; log-and-migrate on read (N4).
3. Delete `config/bmcwallet.testnet4.pass` (N8).

**Near-term**
4. Root-cause `sha256_full` deep-frame overlap and the pverify `-O2` mis-parse; until closed, run fullchain_diff on every toolchain bump (N1).
5. Extend `peer_misbehaving` wiring to malformed-payload and handshake-failure sites; add a metric for "violations detected but unscored" so the gap can't silently persist (N3).
6. logrotate: `su <service user> <service group>` / `owner` + `0750` on `logs/main` (N6).
7. Add `-fstack-protector-strong -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2` to the daemon C objects where the asm ABI permits (N7).

**Ongoing**
8. Keep fullchain muhash/mu3072 parity as a release gate; publish the attestation height.
9. Randomized differential script/sighash fuzzing against Core (still open from the prior round).
10. Prune stale `.worktrees`/deploy binaries or move rollback snapshots to a guarded directory — 2.1 GB and two full source copies of older code are a deploy-the-wrong-binary hazard (N11).

## 7. Overall judgment

The project's remediation discipline is verifiable, not aspirational: every closed finding survived an independent re-read of source *and* the deployed binary's own program headers, and the credential-hygiene failures of the first two weeks (public repo password, `.pass` file, leaked mnemonic) are all genuinely gone from the live system. What remains is what the README already warns: consensus logic in hand-authored assembly whose correctness no in-repo tooling fully bounds — with the 09-01 incident as proof that the failure mode (false-accept through a lying store lookup) is real, and the fix process (fail-closed halt + oracle parity) as proof it can be survived. Run it as the README says: study-only, no funds near it, and apply the unit hardening this week.

*Report generated 2026-09-02. All file paths relative to `/storage/bitcoinmachinecode/` unless absolute. Every live claim (sockets, perms, unit content, ELF flags, RPC responses, history sweep 1221/1221) was read from live tool output during this audit.*

---

## Remediation record (2026-09-02, same day; each item verified on the live host, not inferred)

| # | Status | What was done | Evidence |
|---|--------|---------------|----------|
| N3 | **PARTIAL, deliberate** | Three more classes scored: a `tx` too short or unparseable, a `block` shorter than a header (both in `bitcoin_serve.asm`, shared tail `.viol_report_next`), and a malformed / >MAX_ADDR_TO_SEND `addr`/`addrv2` on the download legs (`addr_ingest_msg_v` out-param -> `tx_relay.c` -> `txr_report_violation_fd` in main.c, fd -> leg host). **Not** scored, on purpose: a block that fails `cons_verify` (one-bit result; a false-reject in OUR verifier would ban every honest peer -- self-partition, see N1/N2), handshake failures (`node_handshake` returns one code for a timeout and a protocol error; Core scores only "non-version message first"), and duplicate-inv spam (Core rate-limits it, does not discourage). Core itself no longer grades: `Misbehaving()` is discourage-or-nothing, which the existing 100-point hook already matches. | `tests/test_serve_violation` (+3 cases), new `tests/test_addr_ingest_violation`, both gated |
| N4 | **FIXED** (`a831866`) | `wallet_store.c` writes only the strong container; legacy files upgrade in place on open | `tests/test_wallet_store` on genuine legacy fixtures; the upgrade also fired on a real legacy testnet4 wallet copy |
| N5 | **FIXED (host)** | `/etc/systemd/system/bmc-bitcoind.service.d/50-hardening.conf`: `LimitCORE=0`, `NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome=read-only`, `PrivateTmp`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, kernel-tunables/modules/cgroups protection, `RestrictSUIDSGID`, `LockPersonality`, `RestrictRealtime` | restarted 06:41 UTC: `/proc/<pid>/status NoNewPrivs=1`, core limit 0, reload exact, tor onion service + i2p session + privbcast all up, wallet state unchanged (locked at boot as before -- the passfile is a signing-time source, not a boot unlock) |
| N6 | **FIXED (host + repo)**, and worse than reported | logrotate had **never run**: 3.21 refuses a config that is group-writable *or not root-owned*, and the tracked file is both in a checkout. Root now reads its own copy `/etc/bmc/logrotate-bmc.conf` (the tracked file is the documented source, installed deliberately with `install -o root`); the rotation runs as the service user (`su svc svc`); the logs are svc-owned. | forced run: euid switched to 1000, 4.46 MB log rotated to `.1` (svc:svc), daemon kept appending; unit run through systemd clean |
| N7 | **FIXED where possible; premise corrected** | Ubuntu's gcc already applied `-fstack-protector-strong` and `_FORTIFY_SOURCE=2` by default (proved by compiling with them explicitly disabled); they are now explicit in the Makefile so any toolchain builds the same. Full RELRO + `BIND_NOW` added to every shipped tool link -- `wallet_cli` (holds the seed) had **neither**. `-Werror` **not** added: the tree carries 433 warnings, 209 of them `-Wincompatible-pointer-types`, the exact class behind incident #49; that is a cleanup pass of its own, not a flag. | `readelf`: BIND_NOW on all six tools; GNU_RELRO on all but `wallet_cli`, whose asm objects' section layout makes the linker decline the segment (residual) |
| N11 | **DONE** | 67 deploy snapshots deleted (3 kept: rollback depth 2), `.worktrees/t_reorg_stage_b` (306 MB, unregistered) removed, both feature worktrees removed after merge | 2.1 GB -> 91 MB of snapshots; `git worktree list` = main only |
| N1 | **EVIDENCE ADDED; structural part stays open** | The two quoted "-O0" harnesses had been -O2 since 08-23 (stale comments, now corrected). The two rules genuinely below -O2 (`test_sigops`, `pverify`) rebuilt at -O2: test passes; pverify -O1 vs -O2 identical over 481824-481900 / 700000-700100 / 965000-965100. Pins lifted. No rule in the tree avoids -O2 any more. | Makefile comments carry the evidence; rerun `fullchain_diff.py` on toolchain bumps |
| N8 | **DONE** | `config/bmcwallet.testnet4.pass` deleted (never tracked); `walletpassfile=` dropped from the untracked testnet4 config. The wallet it unlocked is provably empty. | `ls config/*.pass` -> none |
| §6.8 | **DONE** | Parity attestation heights published: `docs/PARITY_ATTESTATION.md` | -- |
| -- | **ADDED** (operator request) | Manual wallet decryption with no passphrase on disk: `wallet_cli` prompts with echo off / reads a pipe; `bitcoin_cli -stdinwalletpassphrase` / `-stdin` (Core semantics) | `tests/test_cli_prompt` drives both binaries through a real pty |
| N7 (-Werror) | **DONE** (same day, later) | 287 + 27 + 77 unique warning sites fixed at the root; `WARNFLAGS := -Wall -Werror` on every C compile (also the 57 object rules that had never had `-Wall`). Real bugs surfaced: an 8-byte store into a 4-byte local in three tx_accept.c functions (the incident-#49 class), a 64-vs-80-byte stride mismatch in main.c's catch-up peer tables that corrupted `peers.good` and the manual-peer check, an unchecked RPC reply-header write, a 340-byte watch-only descriptor field under a 512-byte reader, an unchecked pruned-marker write in archive_verify.c, two test-only out-of-bounds writes and an uninitialized prev-hash. nasm warnings (22 lines, 6 kinds) remain non-fatal. | gate 318/318 green with 0 warnings; worklog 2026-09-02 has the full list |
