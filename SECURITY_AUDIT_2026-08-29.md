# SECURITY AUDIT — /storage/bitcoinmachinecode

**Auditor:** independent review (Hermes Agent, GLM-5.3-Flash-EXL3 via custom provider), 2026-08-29
**Scope:** full tree — crypto (`asm/`), consensus/verification, P2P networking, JSON-RPC server + wallet, daemon process model, configuration, secrets hygiene, deployment surface.
**Method:** line-level source review of the C layers, targeted disassembly-level review of the assembly hot paths, live inspection of the running service (systemd unit, listening sockets, process tree, file permissions, open fds), git history sweep for credential leaks, and cross-checks against the project's own prior audits (`validation/SECURITY_AUDIT.md` PASS 1/2).

The node under audit is **live**: `bmc-bitcoind.service` is running on mainnet at tip ≈ 964,626, P2P listener on `0.0.0.0:8332`, embedded RPC on `127.0.0.1:8331`, running as an unprivileged local user.

Severity scale: CRITICAL / HIGH / MEDIUM / LOW / INFO.

---

## Executive summary

This is a full Bitcoin node written substantially in hand-authored x86-64 assembly plus C, produced at AI speed and already running against mainnet with a real wallet store present. Its security posture is **unusual and mostly self-aware**: the codebase documents its own incidents with unusual honesty, has already been through two internal audit passes (one CRITICAL timing leak found and fixed), and shows genuine security discipline in many places (constant-time compares, sanitized notify hooks, loopback-only RPC, fail-closed archive repair).

But the fundamental claims of the README stand: this software is experimental, has had ~50 production incidents that each *existed in production first*, and no independent human audit existed before this report. The findings below include one HIGH that is structural (the wallet's at-rest encryption and RPC-credential handling sit on a custom, non-standard crypto construction), several MEDIUMs that are realistic attack vectors on a live node, and a set of LOW/INFO hygiene items.

**Headline findings:**

| # | Severity | Finding |
|---|----------|---------|
| 1 | HIGH | Wallet "encryption" (v2 store) uses PBKDF2-SHA512 at **2048 iterations** and a custom SHA512-CTR construction with a KDF output reused as both cipher key and MAC key; Core-compatible container (`bmcwallet.enc`) is much stronger (100k iters, AES-256-CBC, master-key wrap), but the node ships and loads the weak v2 format on the live datadir |
| 2 | HIGH | A wallet passphrase is persisted in **plaintext** next to the encrypted wallet (`data/bmcwallet.dat.pass`, mode 0600) — the dev convenience explicitly documented in-code, present on the live node |
| 3 | HIGH | Structurally: every consensus-critical parse/verify path is hand-written assembly that has already produced false-ACCEPT divergences (documented `SETcc` incident) that no replay can detect; residual risk is unquantifiable by inspection alone |
| 4 | MEDIUM | `auth_ok()` (RPC): `by_pass` compares against `strlen(pass)` of the *configured* password, but the constant-time `ct_eq` folds tail bytes — correct — **however** the config plaintext password remains the primary credential; `rpcauth`/cookie exist but the live `config/bitcoin.conf` still uses `rpcpassword=` plaintext (mode 0600, gitignored, but the value also lives in git **history** from commits ≤ `65371fc` before redaction) |
| 5 | MEDIUM | `crt_amount_to_sat()` computes `whole*100000000 + frac` in `long long` with **no overflow check** on `whole` — a malicious/buggy caller with a huge integer amount wraps silently |
| 6 | MEDIUM | `wallet_store.c` `make_tag()` and `ctr_xor()` implement a **non-standard** MAC (`sha512(K‖"BWCT"‖ct)`) and CTR nonce (`sha512(u32le(i)‖0)⊕K`) that are not interoperable with anything and were not designed by a cryptographer |
| 7 | MEDIUM | ZMQ publisher binds `tcp://*` when configured with `*` (documented), and its frame-length check accepts `len ≤ sizeof inbuf − 16` but reads frame body with `hn+len` bounds that allow a hostile subscriber to stall the worker's `zmqpub_poll()` (bounded per-sub, but poll() runs in the download-worker loop) |
| 8 | MEDIUM | The `p2p_read()` framer drains oversize messages in 64-byte chunks **without any cap on total drain** — a peer announcing a ~4 GB message forces the child to read and discard it all (no protocol-level MAX_SIZE enforcement like Core's `0x02000000`) |
| 9 | LOW/INFO | ELF hardening is weak: `GNU_STACK RWE` (executable stack — from NASM objects), non-PIE (`-no-pie`), no `BIND_NOW`/RELRO-full, only 1 stack-chk symbol, no FORTIFY |
| 10 | LOW/INFO | Git history once contained the live `rpcpassword` (purged by redaction commit, but old blobs remain reachable in local clone history) |

No CRITICAL finding survived from the previous audits: the signing path is now constant-time end-to-end (`point_scalar_mul_ct`, constant-shape `sc_mul`/`sc_inv`), and the reproduced OOB read from PASS 1 is fixed.

---

## System context (verified live, not assumed)

- Service: `bmc-bitcoind.service`, running as an unprivileged local user, `ExecStart=asm/daemon/bitcoind serve data`, `Restart=on-failure`, `TimeoutStopSec=900`, supplementary group for the tor control-socket access.
- Process model: parent (accept + RPC thread) + forked download worker; **fork-per-inbound-connection** with a hard inbound cap (`CFG_INBOUND_LIMIT()` = maxconnections − outbound − block-relay − feeler) enforced by a `SIGCHLD` counting reaper — accept-and-close when full. This is a real DoS control, properly implemented.
- Listening sockets (from `ss`): `0.0.0.0:8332` + `[::]:8332` (P2P, both processes), `127.0.0.1:8331` (RPC, parent only). RPC is loopback-only by construction (`bind` is hardcoded `INADDR_LOOPBACK` in `rpc_server_start()`; there is no code path to bind elsewhere — `rpcbind` is on the "not implemented, named at boot" list). **Good.**
- Host also has a VPN-overlay interface and a LAN interface; the P2P port is reachable on both.
- Datadir perms: mixed — `data/` is 0755, wallet files 0600 (good), but `walletscan.dat` is 0644, `peers2.dat`/`index.dat`/`headers.dat` are 0664/0644, and the datadir itself is world-readable/traversable. On a single-user box this is acceptable; on a shared host it is not.

---

## FINDING 1 — HIGH — Weak custom at-rest encryption for the live wallet (v2 store format)

**Files:** `asm/wallet_store.c`, `asm/bitcoin_bip39.asm` (`bip39_mnemonic_to_seed`), `asm/bitcoin_aes.c` / `asm/daemon/wallet_crypter.c` (the *other*, stronger path).

**What the code does.** `bmcwallet.dat` (the store loaded at boot by the daemon and CLI) uses format v2:

- KDF: `K = bip39_mnemonic_to_seed("", pass)` = PBKDF2-HMAC-SHA512(password=pass, salt="", **2048 iterations**, 64 bytes).
- Cipher: custom CTR — keystream block *i* = `sha512(u32le(i) ‖ 8 zero bytes)` **XORed with K**, so K is both the PBKDF2 output and the cipher key material.
- MAC: `tag = sha512(K ‖ "BWCT" ‖ ct)[0..31]` — again keyed by the same K.

**Why this is HIGH:**

1. **2048 iterations is ~50× weaker** than the 100,000 iterations the project itself chose for its *other* container (`WC_ITERS` in `wallet_crypter.c`), and orders of magnitude below modern KDF practice (Argon2/200k+ PBKDF2). A stolen `bmcwallet.dat` is brute-forceable at a rate limited only by SHA512 throughput — roughly millions of guesses/sec/GPU.
2. **Key reuse across roles.** The same 64 bytes K key the CTR keystream *and* the MAC. This is the classic "key separation" violation; it has no known practical break here, but it is exactly the shape of construction that fails in ways discovered later.
3. **The MAC is unkeyed-hash-with-key-prefix** (`sha512(K‖msg)`) rather than HMAC — a subtle domain-separation差 and length-extension-adjacent pattern. Not exploitable as written (SHA-512 prefix-MAC), but it is not a reviewed construction.
4. **Inconsistent security between two containers in the same tree.** `bmcwallet.enc` (Core-compatible BytesToKeySHA512AES, 100k iters, AES-256-CBC, master-key wrap) is *much* better — and it is the format `encryptwallet` writes. The live datadir contains the **v2** format (`od` confirms header `BMCWAL v2`), so the live wallet is protected by the weak one.

**Exploitability.** Requires theft of the wallet file (local attacker, backup leak, compromised host). Given 0600 perms and single-user host, likelihood is moderate-low; impact is total wallet loss.

**Recommendation.**
- Migrate the boot wallet to the `bmcwallet.enc` container format (or at minimum raise v2's iteration count and derive separate enc/MAC keys via HKDF — the HKDF module shipped in the last commit makes this trivial).
- Retire `wallet_store.c`'s custom CTR/MAC entirely; one crypto path, already reviewed, is better than two.

---

## FINDING 2 — HIGH — Plaintext passphrase persisted beside the encrypted wallet

**Files:** `asm/daemon/wallet_cli.c` (`passfile_write`, `passfile_read`), `asm/rpc_wallet_ops.c` (`wop_wallet_pass`), `asm/daemon/main.c` (boot loader).

The code deliberately writes the wallet secret to `<store>.pass` (0600) as a "DEV convenience," and both the daemon boot path and the RPC wallet-loading path **read it automatically**. The live tree contains `data/bmcwallet.dat.pass` (0600, 22 bytes) and `testnet4-e2e/testnet4/bmcwallet.dat.pass` (0605 — note group/other *read* on that one).

The design goal — avoid pairing ciphertext and key in one file — is defeated by writing the key into the same directory with a guessable name. Any read-primitive over the datadir (or any backup of it) yields both.

**Recommendation.** Remove the `.pass` auto-read from the daemon's boot path (keep env `BMC_WALLET_PASS` only, or prompt). If the dev file must exist, refuse to start the *production* unit when it is present.

---

## FINDING 3 — HIGH (structural) — Hand-written consensus assembly with a documented false-ACCEPT history

The README and LOG.md are unusually honest here: the `SETcc` incident produced consensus divergence **in the false-accept direction**, in a way "no chain replay could detect." Every script/segwit/taproot/sighash check that guards ~$2T of chain value is hand-authored assembly (`bitcoin_interp.asm` ~99 KB, `secp256k1_*.asm`, `bitcoin_sighash.asm`, taproot sighash C+asm mix). The interpreter's core limits match Core (`MAX_STACK_SIZE 1000`, `MAX_SCRIPT_ELEMENT_SIZE 520`, `MAX_SCRIPT_SIZE 10000`, `MAX_OPS_PER_SCRIPT 201`), and the differential harnesses (`validation/fullchain_diff.py`, per-op vector generators, guard-page bounds tests) are genuinely strong for a project of this kind.

But inspection cannot bound the risk of a subtle mis-verification that accepts an invalid spend. This is the load-bearing reason the README's "treat as untrusted" warning remains correct even after every item below is fixed.

**Recommendation.** Keep the oracle differential running continuously against tip-following Core; add property-based differential fuzzing (random script/stack generation) rather than only curated vectors; publish a machine-readable attestation of "diff clean as of height H."

---

## FINDING 4 — MEDIUM — RPC credential model: plaintext password still primary; history exposure

Verified state:

- `config/bitcoin.conf` (live, 0600, gitignored): `rpcuser=bitcoin`, `rpcpassword=<43-char secret>`.
- `rpcauth` (HMAC-SHA256-salted) and `.cookie` auth are implemented and enabled by default (`rpccookie=1`); the cookie file is 0600 in the datadir.
- `auth_ok()` compares all three arms every time (no oracle on *which* matched) and uses a correct constant-time compare that folds the tail of the longer input.
- **However**, git history: commits `394c518`→`65371fc` (Aug 15–29) carried the live password in `config/bitcoin.conf`. Commit `65371fc` untracked the file and a later redaction pass replaced the value in *reachable-from-HEAD* blobs, but the pre-redaction blobs are still reachable from `origin/main` history (`0af01b7`'s parent chain contains the original). The remote is **public**, so anything pushed before redaction is burned regardless of local history rewriting.

Also: the `bitcoind` binary reads credentials into `static char user[128], pass[256]` and passes them to the RPC thread; `rpc_http_post()` (client side) sends `Authorization: Basic %s` correctly (the earlier suspicion of a literal `***` was a terminal-rendering artifact of my own tooling — hexdump-verified the format string contains `%s`).

**Recommendation.**
- Rotate the RPC password now (it must be considered public).
- Delete `rpcpassword=` from the live config and rely on rpcauth + cookie; the code already supports both.
- For history: `git filter-repo --replace-text` + force-push, and rotate everything that was ever in the tree (the project's own commit message admits "purging that is a..." — finish the sentence).

---

## FINDING 5 — MEDIUM — Integer overflow in BTC amount parsing

`asm/rpc_commands.c` `crt_amount_to_sat()`:

```c
static long long crt_amount_to_sat(const char* s){
    long long whole=0, frac=0; int fdig=0, seen=0;
    if (*p=='-') return -1;
    while (*p>='0'&&*p<='9'){ whole=whole*10+(*p-'0'); p++; ... }
    ...
    return whole*100000000LL + frac;
}
```

`whole` accumulates unbounded until signed overflow (UB; in practice wraps). A crafted JSON-RPC amount string of ~19+ digits wraps to a negative or arbitrary value; `cmd_sendtoaddress` then checks `sat <= 0` (catches only some wraps) and casts to `unsigned long long`. Wallet-side this is gated by coin selection (insufficient funds), but `createrawtransaction`/`simulaterawtransaction` paths parse amounts from unauthenticated RPC input on a live node.

Core's `ParseFixedPoint` rejects amounts that do not fit int64 satoshis *and* the money-range check (`MAX_MONEY = 21e14 sat`) is enforced at tx-validation. I searched this tree for a `MAX_MONEY`/21M-consensus check on output values and **found none** in `bitcoin_txval_modern.c` or the tx parsers — the fee check is `sum_in >= out_total` in u64 (wrapping adds possible only with >64-bit sums, which requires ≥5 max-value outputs — then `out_total` wraps and a "negative fee" check passes). Realistically unexploitable against honest chain data, but a malicious *submitted* block/tx could probe it if any value-overflow path exists upstream; Core's consensus would reject the same block anyway, so divergence risk is the concern, not theft.

**Recommendation.** (a) Bound `whole` to ≤ 2,100,000,000,000,000 during parse and reject beyond; (b) add the consensus `MAX_MONEY` check per output and on `out_total` in `txv_connect_body`/`txval_modern` — it is currently missing relative to Core.

---

## FINDING 6 — MEDIUM — P2P framer has no protocol-level message size limit

`bitcoin_net.asm` `p2p_read()`:

- Reads the 24-byte header, verifies magic, copies command, then `tocopy = min(announced, cap)`, reads that, and **drains the remainder in a 64-byte loop until EOF or error**.
- There is no check anywhere equivalent to Core's `MAX_SIZE` (0x02000000) rejection. A peer that announces `length = 0xFFFFFFFF` forces the forked serve child to consume ~4 GB from the socket at 64 bytes/read syscall — a slow-loris-style resource draw per inbound connection (bounded by the inbound fork cap, but each leg can hold a child alive indefinitely doing this).
- Callers cap their own buffers (1 MiB in `multipeer`, 2 MiB relay payload), so there is **no memory overflow** — the issue is unbounded work, not corruption. `-maxreceivebuffer` sizes SO_RCVBUF but does not stop the drain loop.

**Recommendation.** Enforce `announced <= 0x02000000` in the framer (one `cmp/ja` after loading `announced`) and return a distinct error code; treat violation as misbehaviour points.

---

## FINDING 7 — MEDIUM — Misbehaviour scoring is plumbed but never called

`daemon/main.c` implements a full `peer_misbehaving()` (100-point threshold, shared ban list, /32 auto-ban, lowest-score eviction) and `ctl_is_banned()` is enforced on both dial and inbound accept. **But a repo-wide search shows `peer_misbehaving()` has zero call sites.** The comment "a peer could send malformed message after malformed message and the node would keep talking to it" is still literally true — the machinery exists, nothing drives it. The only sanctions are: inbound cap, upload cap, and addr-ingest quotas.

**Recommendation.** Wire `peer_misbehaving()` into the places the code already detects protocol violations: oversize announced length (Finding 6), duplicate-inv spam, malformed addr/tx/block messages, handshake failures. This is the highest-leverage hardening available in the tree.

---

## FINDING 8 — MEDIUM — ZMQ publisher: `tcp://*` binding and worker-loop coupling

`daemon/zmq_pub.c`:

- `zp_bind()` accepts `*` and maps it to `INADDR_ANY` — matching Core, but on this host it would expose block/tx payloads to the LAN. Currently unconfigured (no ZMQ sockets in the live process), so latent.
- `zmqpub_poll()` runs inside the **download worker's** hot loop (`main.c:4218`). A subscriber that connects and then dribbles greeting bytes keeps `zp_consume` returning early with data pending; the per-connection recv loop is non-blocking and bounded, but 32 subscribers × repeated poll iterations each loop pass is a tax on block catch-up. Subscription filters are capped (16×64 bytes, `len > sizeof inbuf − 16` rejected) — bounds are sound.
- Frame length check uses `sizeof s->inbuf - 16` as the cap and the reader only consumes when the *whole* frame is buffered — a subscriber sending a 500-byte frame header claim stalls that sub's slot but cannot overflow (bounds checked before copy). OK.

**Recommendation.** Default the `*` expansion to a hard error (require an explicit interface), and move `zmqpub_poll()` out of the catch-up loop when a catch-up batch is in progress.

---

## FINDING 9 — LOW — ELF/build hardening is weak

Verified with `readelf` on `asm/daemon/bitcoind`:

- `GNU_STACK` is **RWE** (executable stack) — inherited from NASM objects lacking `.note.GNU-stack` sections. This silently defeats NX for the whole process.
- Non-PIE (`-no-pie` in CFLAGS; required by the asm's absolute addressing) → no ASLR for the main image.
- `GNU_RELRO` present but partial; no `BIND_NOW` (`DT_FLAGS` lacks `BIND_NOW`/`FLAGS_1 NOW`).
- Exactly one `__stack_chk` symbol (tests use fortify; the daemon build does not), no `-D_FORTIFY_SOURCE`.
- Not stripped (fine), dynamically linked to libc only.

**Recommendation.** Add `section .note.GNU-stack noalloc noexec nowrite progbits` to every `.asm` (mechanical, low-risk, kills RWE stack). Where asm permits, switch to `-fPIE`-compatible RIP-relative addressing (much of it already uses `DEFAULT REL`); add `-Wl,-z,relro,-z,now -fstack-protector-strong`.

---

## FINDING 10 — LOW — Filesystem hygiene

- Datadir world-readable (0755) with `blk*.dat`, `chainwork.dat`, `bfilters.dat` at 0644 — chain data is public anyway; acceptable, but `peers2.dat` (0644) leaks the node's peer graph to local users; 0600 would match Core.
- `walletscan.dat` 0644 contains wallet address-activity metadata — should be 0600.
- `testnet4-e2e/testnet4/bmcwallet.dat.pass` is mode **0605** (world-readable) — dev secret readable by any local user. Fix perms; better, delete it.
- `append.lock` 0664 and the addrbook rebuild path uses `O_TRUNC` on a live book (documented, deliberate, with forensics copy — fine).
- `.cookie` 0600 — good. `onion_v3_private_key` 0600 — good.

---

## FINDING 11 — INFO — Positive controls worth keeping (verified, not assumed)

A short list of things this codebase does **right**, which a future contributor must not regress:

1. **Constant-time crypto on secret paths.** `point_scalar_mul_ct` (w=4 windowed, fixed-pattern), constant-shape `sc_mul` carry chain (the earlier truncation bug is fixed and documented), `sc_inv` fixed 255-iteration square-and-multiply, constant-time `poly1305_verify`, and RPC `ct_eq` folds the tail of the longer operand (no length-prefix oracle). The two prior audit findings here are genuinely fixed.
2. **Authenticate-before-decrypt** in `chacha20poly1305_decrypt` (no plaintext written on bad tag) — explicitly reasoned in comments.
3. **Notify-hook sanitization** (`daemon/notify.c`): substituted values filtered to `[A-Za-z0-9._:/-]`, double-fork, SIGPIPE/SIGCHLD reset — better than several production codebases.
4. **Loopback-only RPC bind** with no code path to widen it; `rpcallowip`/`rpcbind` listed as unimplemented rather than half-implemented.
5. **Inbound connection budget** enforced by process counting, accept-and-close at capacity, rate-limited logging.
6. **Fail-closed archive integrity** (`archive_verify.c`): duplicate-hash detection with documented rationale (BIP30 pairs excluded correctly), truncate-to-known-good repair, explicit logging before discard.
7. **Chain separation**: per-chain datadir subtrees, chain-tagged logs, and (HEAD commit) refusal to run one chain's node against another chain's archive.
8. **Config honesty**: ~90 unimplemented Core options are *named at boot* rather than silently ignored; a test asserts the list and implementation move together.
9. **Upload cap** measured from `/proc/<pid>/io` against `-maxuploadtarget`, enforced at accept time.
10. **No shell injection on the RPC `signer` path**: `popen` argument is operator-configured (`-signer=`), values are single-quote-escaped with a correct escaper (`sq()`), and only `enumerate`/`displayaddress` are forwarded.
11. **Tor control path**: cookie auth, service key persisted 0600, ADD_ONION ServiceID validated against the v3 checksum before announcement.
12. **Wallet name validation** (`wop_name_ok`) rejects path separators and leading dots before any `wallets/<name>/` mkdir.

---

## Things I checked that are NOT vulnerabilities (negative results, for the record)

- `rpc_http_post` sends real Basic credentials (format string verified by hexdump + compiled reproduction; my first read of `Basic ***` was a rendering artifact).
- `auth_ok` empty-password guard: `if (!*pass) by_pass = 0;` prevents empty-credential auth even when the config password is empty (and `serve_start_rpc` refuses to start RPC with empty user/pass at all).
- `service_conn` request buffer: growth-capped at 9 MiB, `Content-Length` honored, header-end scan resumes incrementally (no quadratic rescan), oversize → connection closed.
- `rj_parse` JSON: no explicit depth limit in the parser, **but** the serializer/dup paths that could recurse (`rj_dup`, `rj_w`) operate on values already parsed; hostile nesting depth is bounded by the 9 MiB request cap rather than a counter. Deep-nesting stack exhaustion is theoretically reachable with a few hundred thousand nested arrays within 9 MiB — the daemon's RPC thread would crash the *parent* process (it runs on a thread of the serve parent, not a forked child). Worth a depth counter; flagged as LOW rather than MEDIUM only because the listener is loopback-only.
- Mempool dump reader: full bounds discipline (`pos + tl + 16 > fsz` style checks everywhere, `get_cs` avail-bounded); `count` unbounded but each iteration consumes ≥17 bytes so the file size bounds the loop; no alloc from untrusted lengths (single `malloc(fsz)`).
- `mempool_dump_read` V2 XOR path bounds the key offset correctly (`pos % 8`).
- `bsub_txlen`/`block_check_witness_commitment`: all spans bounds-checked; witness scratch sized `ntx*32` with explicit cap check.
- `crt_amount_to_sat` rejects negatives and >8 decimals (only the `whole` overflow in Finding 5).
- `asmap_load` mmaps read-only and validates no length-dependent state before use; `asmap_lookup_raw` is bit-bounded by `nbytes`.
- `i2psam`/`socks5` clients: all reply reads length-bounded, no `strcpy` into fixed buffers from wire data.
- `torcontrol` `read_reply` line buffer bounded at 1024 with discard-on-overflow; AUTHENTICATE hex from cookie file, not peer input.
- No `system()`/`popen()` on any peer-influenced path (only `chainctl.c`'s operator-driven orchestration script, `rpc_signer.c`'s operator-configured signer, and notify hooks with sanitized substitution).
- No `getenv`-driven security decisions beyond `BMC_WALLET_PASS` (documented dev path) and test hooks.
- `wallet_secret_write` refuses to write when the passphrase is empty (no accidental plaintext secrets).
- `wop_name_ok` + `wop_wallet_mkdir` prevents wallet-name path traversal; `restorewallet` verifies the backup loads before installing.

---

## Deployment-surface observations (live host)

1. The P2P listener is on `0.0.0.0` and the host has a LAN IP plus a VPN-overlay IP, both of which can reach it. For an experimental node that is the point — but consider `-bind=` to the specific interface if the LAN is not trusted.
2. Two `tail -f bitcoind.current.log` processes run as **root** in the datadir tree — root-owned readers of a user-writable log directory are a local privesc pattern (log rotation/symlink games). Not a finding against this codebase, but fix it.
3. `LimitCORE=infinity` in the unit: a segfaulting daemon writes full core dumps containing wallet keys (the process holds the derived seed in `g_wallet_seed`). Cores land wherever `kernel.core_pattern` points. Recommend `LimitCORE=0` or a guarded core dir, since `Restart=on-failure` implies cores will actually be produced.
4. The service runs `Restart=on-failure` with a 10 s delay and burst limiting — sound. `TimeoutStopSec=900` matches the documented compaction-window rationale.
5. systemd hardening directives absent: `ProtectSystem=strict`, `PrivateTmp=`, `NoNewPrivileges=`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `SystemCallFilter=`. The daemon needs broad fs access to the datadir and (via notify hooks) arbitrary exec, so a strict sandbox needs care — but `NoNewPrivileges=yes` plus `ProtectHome=read-only` (datadir is under /storage) would be nearly free.

---

## Prioritized remediation plan

**Do now (this week):**
1. Rotate the RPC password; delete `rpcpassword=` from the live config (cookie auth is already enabled); purge/rewrite git history on origin and re-clone.
2. Delete `data/bmcwallet.dat.pass`; change the testnet4 pass file perms; decide on env-var-only unlock for production.
3. Add the missing consensus `MAX_MONEY` per-output/total checks (Finding 5b) and bound `crt_amount_to_sat` (Finding 5a).
4. Fix `GNU_STACK RWE` via `.note.GNU-stack` sections; add `-Wl,-z,relro,-z,now`.
5. `LimitCORE=0` in the unit; `NoNewPrivileges=yes`.

**Near term:**
6. Wire `peer_misbehaving()` into the violation sites; add the framer `MAX_SIZE` check.
7. Migrate the boot wallet store to the `bmcwallet.enc` container (100k iters, AES-CBC, key separation) or harden v2 in place; deprecate the custom CTR/MAC.
8. Tighten datadir file modes (walletscan 0600, peers 0600, datadir 0750).
9. Add a parser recursion-depth counter (defense-in-depth, loopback or not).

**Ongoing:**
10. Keep the Core-oracle differentials running against the live tip; add randomized differential fuzzing for script/sighash; publish periodic attestation of divergence counts.

---

## Overall judgment

For AI-authored consensus-critical assembly, this is an exceptionally disciplined codebase: bounds-checking is consistent, failure paths mostly fail closed, self-deception is treated as the enemy, and the internal audit trail is real work rather than theater. The two previous audit findings in the crypto core are genuinely fixed. What remains is (a) the structural risk that motivated the README's warning, which no amount of internal review retires, (b) a weak custom KDF/encryption path protecting the live wallet, (c) credential hygiene that leaked once and is not yet fully cleaned, and (d) anti-DoS machinery that exists but is not connected.

None of the findings above require a redesign; all are incremental. The project's own deployment advice — "run it only if you are studying it, on a machine you can afford to lose, with no funds anywhere near it" — remains correct today, and is now backed by a specific, actionable list rather than a general caution.

*Report generated 2026-08-29. All file paths relative to `/storage/bitcoinmachinecode/` unless absolute. Every "verified live" claim in the System context section was read from `ss`, `ps`, `/proc/<pid>/fd`, systemd unit files, and `stat` output during this audit, not inferred.*
