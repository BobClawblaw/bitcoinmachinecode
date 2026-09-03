# CODEBASE AUDIT — full module-by-module review

**Audit date:** 2026-09-03 (UTC)
**Tree state:** `main` @ `b6d2c54` (clean working tree), `https://github.com/BobClawblaw/bitcoinmachinecode`
**Auditor:** Claude (Fable 5.1), run as thirteen parallel module reviewers plus a coordinating pass that independently re-verified every CRITICAL finding and a sample of the HIGH findings against the source. This is an AI review. It does not change the README's statement that the consensus and cryptographic assembly has not had an independent human audit.
**Scope:** the whole tree, split into thirteen modules (listed in §4). Every file named in a module's scope was read in full unless the module report says it was skimmed or not read.
**Method:** line-level source reading with caller/callee tracing; comparison against Bitcoin Core semantics named by function or BIP; existing tests cited as coverage evidence; a handful of findings reproduced with scratch programs linked against the repo's own objects (UTXO store) or run in a scratch datadir (daemon). No file in the repository was modified during the review, no full build was run, and the live node and `data/` were not touched. A Bitcoin Core source checkout exists on this host at `/storage/bitcoin-core-source` (v31.99 development tree); the script-interpreter reviewer traced every finding against it, the other reviewers cited Core from their knowledge of its source and marked the places where they were unsure. Prior audits (`SECURITY_AUDIT_2026-08-29.md`, `SECURITY_AUDIT_2026-09-02.md` and the responses) were read first; every prior finding that falls inside a module was re-verified and the result is in §3.

**Severity scale:** CRITICAL / HIGH / MEDIUM / LOW / INFO.
**Verdicts:** CONFIRMED = the reviewer traced the path end to end in the source (or reproduced it). PLAUSIBLE = a real concern with one step the reviewer could not verify.

---

## 1. Executive summary

**Headline: the block-connect path enforces script validity, UTXO existence, PoW and the BIP30/BIP141 rules, but not the rest of Bitcoin Core's `CheckBlock`/`ConnectBlock`.** Two CRITICAL and five HIGH findings in the validation module (§6.3) together mean that a block Core rejects can be accepted, stored and applied by this node:

| # | Missing rule | Core reference | Finding |
|---|---|---|---|
| 1 | Coinbase: subsidy + fee cap, null prevout, scriptSig 2..100 bytes, BIP34 height | `ConnectBlock` `bad-cb-amount`, `CheckTransaction` `bad-cb-missing`/`bad-cb-length`, `ContextualCheckBlock` `bad-cb-height` | **VAL-1 (CRITICAL)** |
| 2 | `MAX_MONEY` on outputs and sums, `fee >= 0` | `CheckTransaction`, `Consensus::CheckTxInputs` | **VAL-2 (CRITICAL)** |
| 3 | Block weight, serialized size, sigop cost | `CheckBlock` `bad-blk-length`, `ConnectBlock` `bad-blk-sigops` | VAL-3 / SCR-6 (HIGH) |
| 4 | nLockTime finality and BIP68 sequence locks | `ContextualCheckBlock` `bad-txns-nonfinal`, `SequenceLocks` | VAL-4 / MEM-1 (HIGH) |
| 5 | Header timestamp (MTP, +2h) and version rules on the P2P/IBD path | `ContextualCheckBlockHeader` | VAL-5 (HIGH) |
| 6 | CVE-2012-2459 merkle mutation | `CheckBlock` `bad-txns-duplicate` | VAL-6 (HIGH) |
| 7 | Inbound `block` push accepted under self-chosen nBits, no powLimit | `AcceptBlockHeader`, `CheckProofOfWork` | VAL-7 / NET-5 / VAL-11 / NET-6 (HIGH) |

The coordinating pass verified items 1, 2 and 4 directly. On item 2, the only `MAX_MONEY` logic in the tree (`asm/bitcoin_txval_modern.c:99`) lives in a function with **zero call sites**; the 2026-09-02 audit's "VERIFIED-FIXED" entry for finding 5b checked that the code exists, not that anything runs it. The README's "MAX_MONEY range checks" and FEATURE_GAPS' "now matching Core, verified against 1,172 real mainnet transactions" are therefore wrong for the block path. On item 1, `tx_verify_block_connect_all` deliberately starts at transaction index 1 (signatures only), and the apply loop's `live_on_input` skips only the null prevout, so a coinbase naming a real outpoint deletes that coin and a coinbase naming a fake one halts UTXO tracking.

**The script interpreter itself has three CRITICAL accept-direction divergences**, each traced against Core's `interpreter.cpp` on this host and re-verified by the coordinating pass:

- **SCR-1** — `MAX_STACK_SIZE` is enforced per stack: `stack_push` compares only its own depth against 1,000 and the interpreter never adds the altstack, so a script can hold 2,000 live elements. Core checks `stack.size() + altstack.size()` after every opcode.
- **SCR-2** — the condition stack `vfexec` is a 1,024-byte buffer with no bounds check in `vfexec_push`, and `vfexec_sp` sits immediately after it. Tapscript has no opcode limit, so more than 1,024 nested `OP_IF`s overwrite the depth counter and an unbalanced script passes. This is also an attacker-controlled out-of-bounds write reachable from P2P.
- **SCR-3** — tapscript `OP_CHECKSIG`/`OP_CHECKSIGADD` return false for an empty signature before looking at the public key. Core raises `TAPSCRIPT_EMPTY_PUBKEY` for an empty key regardless of the signature; the error constant exists in the assembly and is never raised. `OP_0 OP_0 OP_CHECKSIG OP_NOT` is valid here and invalid in Core.

The interpreter is otherwise a faithful port: the legacy, BIP143 and BIP341 sighash builders (including the SIGHASH_SINGLE bug, annex, codeseparator and SINGLE-without-output cases), control-block and merkle handling, the validation-weight budget, witness-program dispatch, CScriptNum rules, DER strictness, CLTV/CSV semantics and the flag schedule all match Core. None of the three CRITICALs is reachable by the existing differential harnesses: they draw small random scripts and Core-signed spends, so the stack never approaches 1,000, nesting never approaches 1,024 and empty-key spends are never generated.

Two further HIGH consensus findings are in the **false-reject** direction (a valid block would be refused, splitting this node off the chain): taproot spends whose co-input scriptPubKey is 253 bytes or longer (VAL-9 / SCR-5), hybrid-encoded public keys (CRY-2), and CSV's version test using a signed compare so nVersion >= 0x80000000 is treated as < 2 (SCR-4).

**Remotely reachable memory-safety defects, all CONFIRMED:**

- **NET-1 (HIGH)** — `getblocktxn` writes up to 65,535 u16 indexes into a 1,024-byte static buffer. Unauthenticated, any peer.
- **VAL-8 / SER-2 (HIGH)** — 64-bit CompactSize wrap in `tx_parse` moves the cursor before the buffer; an unsolicited `block` message crashes the serve child.
- **SER-1 / WAL-1 (HIGH)** — `bech32_decode` has no length cap; a ~300-character address on any address-taking RPC overflows a 256-byte stack buffer with chosen bytes. Authenticated RPC.
- **RPX-1 (HIGH)** — `verifytxoutproof` copies hashes before bounding `nTx`; a ~9 MB proof writes ~1.3 MB past a static buffer. Authenticated RPC.

**Availability:** the SHA-NI dispatcher tests the F16C CPUID bit instead of the SHA bit, so the daemon executes an illegal instruction on the first hash on most Intel CPUs before Ice Lake (CRY-1, invisible on the Zen 5 development machine); the BIP324 responder spins at 100% CPU on a partial v1 prefix (NET-2); inbound connections have no inactivity timeout or eviction, and `-peertimeout` is parsed but unused (NET-3 / DMN-3); the mempool wedges permanently above 65,536 entries (MEM-2).

**Data integrity, several reproduced:** a partial prefix compaction resurrects spent coins by generation tie-break (UTX-1, reproduced); a WAL reload that overfills the memtable is accepted as success and the next flush makes the loss permanent (UTX-2, reproduced); a crash mid-reorg leaves the UTXO set rewound with the old applied height and no undo files (STO-1); BIP158 filters over 64 KiB inherit stale bits from the previous filter, which the coordinating pass confirmed and which is probably already present in the live index (STO-2); prune compaction can truncate retained block data (STO-4); there is no single-instance lock on the datadir, so two daemons become two UTXO writers (DMN-1, reproduced in a scratch datadir).

**What is right.** The cryptographic kernels were checked step for step against libsecp256k1 and are correct, including the constant-time signing ladder, GLV split, ECDSA and BIP340 verifiers, MuHash3072, ChaCha20-Poly1305 with auth-before-decrypt, and the BIP324 key schedule. PoW retargeting including testnet4 and BIP94, chainwork, BIP30, the BIP141 commitment, assumevalid semantics, coinbase maturity, signet BIP325 layers and the taproot exception block are correct. The 2026-09-01 incident fixes are present and test-pinned. Credential hygiene is clean, hardening flags are now uniform across every C compile and the daemon link, the systemd unit is sandboxed, and the prior audit's optimizer-pin finding (N1) has been closed and root-caused. The bounded C wire-format readers and their assembly twin are solid and guard-page fuzzed; the weaknesses are concentrated in the older `bitcoin_tx.asm`, `bech32.asm` and `bitcoin_cmpct.asm`.

**Documentation drift** is material: README and FEATURE_GAPS claim MAX_MONEY enforcement, BIP152 in both directions, an implemented `peertimeout`, an unimplemented `whitebind`, no sibling eviction and an accurate misbehaviour-scoring list, and each of these contradicts the code (VAL-16, NET-9, DMN-3, BLD-5, NET-7).

### Finding counts

| Module | Prefix | CRITICAL | HIGH | MEDIUM | LOW | INFO | Total |
|---|---|---|---|---|---|---|---|
| Cryptographic primitives | CRY | 0 | 2 | 1 | 2 | 3 | 8 |
| Script interpreter and sighash | SCR | 3 | 3 | 1 | 2 | 2 | 11 |
| Transaction/block validation, PoW, chain params | VAL | 2 | 7 | 2 | 4 | 1 | 16 |
| UTXO set (LSM, WAL, compaction) | UTX | 0 | 2 | 4 | 4 | 3 | 13 |
| Block archive, undo, reorg, indexes, pruning | STO | 0 | 4 | 4 | 4 | 2 | 14 |
| P2P networking, BIP324, addrman, IBD | NET | 0 | 5 | 5 | 5 | 2 | 17 |
| Mempool, policy, relay, fees, notifications | MEM | 0 | 5 | 8 | 8 | 3 | 24 |
| Daemon orchestration, config, deployment | DMN | 0 | 1 | 5 | 7 | 1 | 14 |
| RPC transport, JSON, server, node RPCs | RPC | 0 | 0 | 4 | 9 | 7 | 20 |
| Chain, raw-tx, util, mining RPCs | RPX | 0 | 1 | 1 | 5 | 2 | 9 |
| Wallet, descriptors, miniscript, PSBT | WAL | 0 | 1 | 4 | 13 | 2 | 20 |
| Build, tests, validation harness, docs | BLD | 0 | 0 | 2 | 3 | 5 | 10 |
| Wire-format parsing and encoding | SER | 0 | 1 | 3 | 2 | 0 | 6 |
| **Total** | | **5** | **32** | **44** | **68** | **33** | **182** |

Several defects were found independently by two reviewers and appear under two IDs; they are cross-referenced in §2 and counted twice in the table above. The distinct CRITICAL+HIGH issue count after de-duplication is 29.

---

## 2. Priority list (CRITICAL and HIGH, de-duplicated, in suggested fix order)

| Rank | Finding(s) | Severity | One line | Reach |
|---|---|---|---|---|
| 1 | VAL-1 | CRITICAL | Coinbase never checked on block connect: no subsidy/fee cap, non-null prevout applied as a spend, no scriptSig length, no BIP34 height | miner |
| 2 | VAL-2 | CRITICAL | No `MAX_MONEY` / value-range / `fee >= 0` on the block path; the only such code has no callers | miner |
| 3 | SCR-1 | CRITICAL | `MAX_STACK_SIZE` enforced per stack, never over `stack + altstack`: scripts run with up to 2,000 live elements | miner (false accept) |
| 4 | SCR-2 | CRITICAL | Condition stack `vfexec` has no bounds check; > 1,024 nested `OP_IF`s in tapscript overwrite `vfexec_sp`: OOB write plus false accept of an unbalanced script | any peer / miner |
| 5 | SCR-3 | CRITICAL | Tapscript CHECKSIG/CHECKSIGADD with an empty signature returns false before the pubkey is examined; `TAPSCRIPT_EMPTY_PUBKEY` never fires | miner (false accept) |
| 6 | VAL-3, SCR-6 | HIGH | No block weight, serialized-size or sigop-cost limit | miner |
| 7 | VAL-4, MEM-1 | HIGH | No nLockTime finality or BIP68 sequence-lock check in block connect or mempool admission; non-final txs enter GBT | miner / any peer (mempool) |
| 8 | VAL-6, SER-6 | HIGH | CVE-2012-2459 merkle mutation undetected: a mutated block is stored under the real hash and apply fails forever | any peer, zero PoW |
| 9 | VAL-7, NET-5, VAL-11, NET-6 | HIGH | Inbound `block` push appended to the archive under self-chosen nBits; `pow_check` has no powLimit/negative/overflow test and `diff_target` writes below its buffer | any peer |
| 10 | VAL-5, NET-4, DMN-2 | HIGH | Boot header fetch stores headers with no PoW, nBits or work check and no count bound; header timestamp/version rules unenforced on P2P/IBD | first live peer at boot |
| 11 | VAL-9, SCR-5 | HIGH | Taproot spend with a co-input prevout scriptPubKey >= 253 bytes is false-rejected | chain split on a valid block |
| 12 | CRY-2 | HIGH | Hybrid public keys (0x06/0x07) rejected; Core consensus accepts them | chain split on a valid block |
| 13 | SCR-4 | HIGH | CSV `nVersion < 2` uses a signed compare; Core compares `uint32_t`: false reject for nVersion >= 0x80000000 | chain split on a valid block |
| 14 | CRY-1 | HIGH | SHA-NI dispatch tests CPUID.1:ECX bit 29 (F16C) not CPUID.7:EBX bit 29 (SHA): SIGILL on first hash on most pre-Ice-Lake Intel | every install on such hardware |
| 15 | NET-1 | HIGH | `getblocktxn` index parser writes up to 65,535 u16 into a 1,024-byte static: remote OOB write | any peer |
| 16 | VAL-8, SER-2 | HIGH | 64-bit CompactSize wrap in `tx_parse` moves the cursor before the buffer: remote SIGSEGV | any peer |
| 17 | SER-1, WAL-1 | HIGH | `bech32_decode` has no length cap: stack and `.bss` overflow from any address-taking RPC | authenticated RPC |
| 18 | RPX-1 | HIGH | `verifytxoutproof` heap overflow: `nTx` bound checked after the hash copy | authenticated RPC |
| 19 | NET-2 | HIGH | BIP324 responder v1-detection spins at 100% CPU on a partial prefix; timeout never fires | any peer |
| 20 | NET-3, DMN-3 | HIGH | No inbound inactivity timeout or eviction; `-peertimeout` unused; idle sockets exhaust the inbound budget | any peer |
| 21 | UTX-1 | HIGH | Generation tie-break resurrects spent coins after a partial prefix compaction (reproduced) | organic |
| 22 | UTX-2 | HIGH | WAL reload that overfills the memtable is accepted as success; first flush makes the loss permanent (reproduced) | unclean stop |
| 23 | STO-1 | HIGH | Crash mid-reorg leaves the UTXO set rewound, old applied height, no undo files; coinstats adopts it | crash during reorg |
| 24 | STO-2 | HIGH | BIP158 builder zeroes only 64 KiB of a reused 1 MiB buffer; filters > 64 KiB inherit stale bits (coordinator confirmed) | organic, likely live |
| 25 | STO-3 | HIGH | Missing undo file read as "no spends": filter and address indexes silently wrong after a > 200-block catch-up burst | organic |
| 26 | STO-4 | HIGH | Prune compaction assumes a monotonic layout above the prune height; violation truncates retained block data | prune + hole |
| 27 | DMN-1 | HIGH | No single-instance lock on the datadir; two daemons become two archive/UTXO writers (reproduced) | operator |
| 28 | MEM-2 | HIGH | `worst_chunk` returns 0 above 65,536 entries: byte-full pool wedges with no eviction or fee-floor rise | organic congestion |
| 29 | MEM-3, MEM-4, MEM-5 | HIGH | Parent links truncated at 24, claims/outreg tables drop entries when full, TrimToSize evicts the incoming tx's own parent: pool holds txs whose inputs no longer exist and GBT includes them | any peer |

---

## 3. Re-verification of prior audits

| Prior finding | Prior status | This audit | Where |
|---|---|---|---|
| 08-29 #1 / 09-02 N4 — weak `BMCWAL v2` wallet format | v2 still written | **Closed.** Only v3/wcrypt is written; v2 is read-only and upgraded in place on open | WAL-20 |
| 08-29 #3 / 09-02 N1, N2 — hand-written consensus asm; `-O0/-O1` pins around wrong block parses | Open (structural); N1 pinned not root-caused | **N1 closed.** Every pin is gone, root-caused to ABI incidents #27/#31, enforced by `abi-check` (run: OK, 1,223 sites, 0 misaligned) and `callee-saved-check` (run: OK, 432 functions). The "deep-frame overlap" in `sha256_full` cited by 09-02 could not be reproduced. Structural finding remains open, and this audit's §1 shows false-accept is not hypothetical | BLD, CRY |
| 08-29 #5a — `crt_amount_to_sat` overflow | Fixed | Verified fixed | RPX |
| 08-29 #5b — consensus `MAX_MONEY` | "VERIFIED-FIXED" | **Not fixed.** The code exists in `bitcoin_txval_modern.c` and has no call sites; nothing on the block path or the mempool path runs it | **VAL-2** |
| 08-29 #6 — P2P framer size limit | Fixed | Verified: 4 MB cap before the drain, both v1 and v2 | NET |
| 08-29 #7 / 09-02 N3 — misbehaviour scoring | "inv/getdata scored" | Partially correct: `inv` is scored via `serve_inv_bounds`; `getdata` still parses a single-byte count with no payload bound and is not scored | NET-7 |
| 08-29 #8 — ZMQ `tcp://*`, poll in hot loop | Fixed | Verified; publisher and topics correct | MEM |
| 08-29 #9 / 09-02 N7 — ELF hardening, no stack protector / FORTIFY | Partially | **Closed.** `-fstack-protector-strong -D_FORTIFY_SOURCE=2 -Werror` on every C compile, full RELRO + BIND_NOW on the daemon link; still non-PIE by necessity | BLD, DMN |
| 08-29 #11 / 09-02 N5 — `LimitCORE=infinity`, no sandbox | Open | **Closed.** Unit runs with `LimitCORE=0`, `NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome=read-only`, `PrivateTmp`, address-family and kernel restrictions | DMN |
| 09-02 N6 — root logrotate over a service-writable directory | Open | Closed: logrotate reads a root-owned copy and rotates as the service user | DMN |
| 09-02 N10 — RPC loopback is config-gated | INFO | Present as described | RPC |
| 09-02 N11 — deploy binaries, stale worktrees, `.bak` confs | Open | Improved: snapshots 69 → 8 (243 MB), worktrees gone; `.bak` confs 5 → 7 | BLD-10 |
| JSON depth 512, cookie-only start policy, constant-time auth | Fixed | Verified | RPC |
| 09-01 incidents (header sync genesis answer; resurrected spends) | Fixed | Both fixes present and test-pinned on the paths they cover. Three sibling defects of the resurrected-spend shape remain on other paths (UTX-1, UTX-2, UTX-10), and the boot header fetch that caused incident 1 still stores headers without PoW (NET-4) | UTX, NET, DMN |
| 09-03 diff review of `699e244` (this morning) | New | All three `getaddressinfo` ownership defects, the `getnetworkinfo` proxy fields and the `gettxoutproof` fallback are still present | WAL-6, RPC-9, RPX-3, RPX-8 |

---

## 4. Cross-cutting observations

1. **The block-connect path is a script verifier, not `ConnectBlock`.** When the C transaction validator (`bitcoin_txval_modern.c`) was retired in favour of `tx_verify.c`, its non-script checks (value range, coinbase shape) were not carried over, and weight, sigops, finality and header-context rules were never written. The differential corpus that gives the project its confidence (`consensus_diff.py`, `fuzz_verify_diff`) compares script results, so it cannot see any of this. A `CheckBlock`/`ContextualCheckBlock`/`ConnectBlock` checklist ported item by item, with a test per item, is the single most valuable piece of work this audit can recommend.
2. **Two generations of parser for the same bytes.** The bounded C readers (`txv_rd_cs`, `read_cs`, `strip_witness`) and their assembly twin `bitcoin_txv_parse.asm` are canonical-enforcing, capped and fuzzed. The older `bitcoin_tx.asm` (`tx_parse`/`tx_txid`, used by `cons_verify` and the serve path), `bech32.asm` and `bitcoin_cmpct.asm` predate that discipline and hold most of the memory-safety findings (VAL-8, SER-2, SER-3, SER-1, NET-1, SER-4).
3. **Process-global scratch buffers.** `sha512.asm`, `bitcoin_hmac.asm`, `bech32.asm`, `bitcoin_bip39.asm`, the compact-block `s_idxbuf`, the 1 MiB filter buffer and the RPC `g_last_auth_user` are all static state reached from paths that are now multi-threaded or size-unbounded (CRY-4, WAL-11, NET-1, STO-2, RPC-2). The 16-thread RPC pool added on 2026-09-01 turned several of these from latent to live.
4. **Return-value width.** `utxo_lsm_put` returns its error through a 32-bit register copy so `-1` arrives as `0xFFFFFFFF` and callers comparing against `-1` silently drop the coin (UTX-3). The same defect was fixed in `utxo_lsm_del` and the stale comment about it survives (UTX-13). A grep for `mov r..d, eax` around every `-1` return in the LSM would be cheap.
5. **Durability ordering.** The applied-height checkpoint is fsynced before the WAL and undo data it certifies (UTX-4), `blk*.dat`/`index.dat` appends are not fsynced (STO-11), the wallet store is written without fsync (WAL-4) and `mempool.dat` likewise (MEM-19). Each is individually survivable; together they mean a power loss can leave the archive, UTXO set, wallet and mempool disagreeing in ways boot detects but does not repair.
6. **Indexes trust absent inputs.** Both the block-filter and address-index tails treat a missing undo file as "no spends" (STO-3), and `getblockfilter` serves a prevout-less filter in the same case (STO-8).
7. **Documentation runs ahead of the code** in the places an operator would rely on: `MAX_MONEY`, BIP152 receive, `peertimeout`, `whitebind`, misbehaviour classes, `zmqpubsequence`, the "155 methods" count, the `-O0` note in ENGINEERING.md, and the PARITY_ATTESTATION entries for deploys `ar`..`av` (BLD-5, VAL-16, NET-9, DMN-3, MEM-22).
8. **The test suite pins happy paths.** It is large (313 gated harnesses) and the kernels are vector-pinned, but no HIGH finding in this audit has a test: nothing sends an over-long address, an oversized proof, a 65,535-index `getblocktxn`, a partial v1 prefix, a coinbase with a prevout, a block over weight, or a crash between reorg steps. The gate also hard-fails on any host without `/storage/bitcoin-core-source` (BLD-2) and `make clean` deletes a tracked source file (BLD-1).

---

## 5. Suggested remediation order

1. Fix the three interpreter CRITICALs (SCR-1: check `sp + alt_sp` against 1,000 after every opcode; SCR-2: bound `vfexec_push`; SCR-3: examine the pubkey before the empty-signature shortcut under tapscript) and the CSV signed compare (SCR-4). Add a test for each that the differential harness cannot generate today.
2. Port Core's `CheckBlock`, `ContextualCheckBlock` and `ConnectBlock` non-script checks into `apply_block_inner` (VAL-1, VAL-2, VAL-3, VAL-4, VAL-6) and gate the inbound `block` push and boot header fetch on `pow_check` with powLimit plus the nBits schedule (VAL-7, VAL-5, VAL-11). Add one test per rule. Then correct README and FEATURE_GAPS.
3. Fix the four remote memory-safety defects (NET-1, VAL-8/SER-2, SER-1, RPX-1); each is a one-line bound. Add over-long-input tests for every parser of peer or RPC bytes.
4. Fix the CPUID probe (CRY-1) by building the probe from `sha256_nia.asm`, and add a gate test that forces the scalar path.
5. Fix the two false-rejects (VAL-9, CRY-2) after checking mainnet history for hybrid-key spends.
6. UTXO durability: UTX-1, UTX-2, UTX-3, UTX-4, STO-1, then DMN-1's datadir lock.
7. Index correctness: STO-2 (and a rebuild of the live filter index), STO-3, STO-4.
8. Availability: NET-2, NET-3/DMN-3, MEM-2, MEM-3/4/5.
9. Everything MEDIUM and below in the module reports, in the order the module authors give.

---

## 6. Module reports

Each module report below is reproduced as written by its reviewer, with headings demoted one level. Line numbers refer to `b6d2c54`. Paths are repository-relative; where a report omits the `asm/` prefix it is implied.



---

### 6.1 Cryptographic primitives — review

**Scope:**
- Fully read: `asm/secp256k1_fe.asm`, `asm/secp256k1_fe_inline.inc`, `asm/secp256k1_scalar.asm`, `asm/secp256k1_scalar_c.c`, `asm/secp256k1_point.asm`, `asm/secp256k1_point_ct.asm`, `asm/secp256k1_glv_c.c`, `asm/secp256k1_ecdsa.asm`, `asm/secp256k1_schnorr.asm`, `asm/secp256k1_taproot.asm`, `asm/bip340_sign.c`, `asm/musig2.c`, `asm/bitcoin_pubkey.asm`, `asm/bitcoin_keys.asm`, `asm/bitcoin_muhash.asm`, `asm/sha256.asm`, `asm/sha256_nia.asm`, `asm/sha512.asm`, `asm/sha1.asm`, `asm/bitcoin_hmac.asm`, `asm/bitcoin_hash.asm`, `asm/bitcoin_sha3.c`, `asm/bitcoin_aes.c`, `asm/crypto_chacha20.c`, `asm/crypto_poly1305.c`, `asm/crypto_hkdf.c`, `asm/crypto_fe_sqrt.c`.
- Skimmed: `asm/ripemd160.asm` (header, `ripemd160` entry/padding at 1874-2021, and the prologue of `rmd160_compress`; the ~1,700 unrolled round lines were not audited by hand — `tests/test_ripemd160` pins vectors), `asm/g_comb_table.inc` (structure only: 64x15 entries x 64 bytes = 7,680 `dq`, matches the comb loader's indexing at `secp256k1_point.asm:965-970`).
- Read for caller context only: `asm/bitcoin_checksig.asm:150-210`, `asm/bitcoin_interp.asm` (DER/LOW_S grep), `asm/wallet_core.c:190-250`, `asm/rpc_server.c` (exec lock), `asm/bitcoin_bip39.asm:737-800`, `asm/wallet_store.c`, `asm/rpc_wallet_ops.c`, `asm/daemon/wallet_enc_state.c`.
- Not read: `asm/cuda/*`, `asm/bitcoin_bip32.asm`, `asm/bitcoin_bip39.asm` body, `asm/crypto_bip324_transport.c`, `asm/crypto_ellswift_ecdh.c`.

**Summary:** The field, scalar and point arithmetic is careful and well argued (carry proofs in comments, canonical invariants stated and honoured, GLV split identity-checked at runtime, fixed-shape signing ladder), and the ECDSA/BIP340 verifiers match libsecp256k1's algebra step for step, including the projective `x(R) == r` tests and the `r + n` second candidate. MuHash3072, Poly1305, ChaCha20, AES-256-CBC, HKDF, SHA-1/256/512, SHA3 and the taproot helpers are faithful transcriptions of their references. Two findings matter. (1) `sha256_block`'s SHA-NI dispatch tests the wrong CPUID bit (CPUID.1:ECX[29] is F16C, not SHA) so every Intel CPU from Ivy Bridge through Comet Lake, and most pre-Ice-Lake Xeons, will execute `sha256rnds2` and die with SIGILL on the first hash. (2) `pubkey_parse` rejects hybrid (0x06/0x07) 65-byte keys that libsecp256k1 accepts in consensus, a reachable false-reject divergence (a block spending such an output is valid to Core and invalid here). Everything else is LOW/INFO: `x >= p` not rejected in key decoding (unexploitable without a 2^223 discrete-log search), process-global scratch in `sha512.asm`/`bitcoin_hmac.asm` with an unbounded copy and retained key material, and a silent-failure path in `bip340_sign.c` that no current caller reaches. Confidence: high on the arithmetic and the two headline findings; the hybrid finding's *historical* reachability (whether a mainnet spend already exists) could not be verified offline, but it is reachable today by construction.

#### Findings

| ID | Severity | Location | Title | Verdict |
|---|---|---|---|---|
| CRY-1 | HIGH | `asm/sha256.asm:196-209` | SHA-NI dispatch keys off CPUID.1:ECX bit 29 (F16C), not CPUID.7:EBX bit 29 (SHA) — SIGILL on CPUs with F16C but no SHA-NI | CONFIRMED |
| CRY-2 | HIGH | `asm/bitcoin_pubkey.asm:180-187, 306-309` | Hybrid public keys (0x06/0x07) rejected; Core consensus accepts them — false-reject divergence in CHECKSIG/CHECKMULTISIG | CONFIRMED |
| CRY-3 | LOW | `asm/bitcoin_pubkey.asm:201-216, 332-348`; `asm/secp256k1_schnorr.asm:213-225` | Key decoding does not reject `x >= p` / `y >= p`; Core (`secp256k1_fe_set_b32_limit`, BIP340 `lift_x`) does | CONFIRMED (divergence), unexploitable |
| CRY-4 | MEDIUM | `asm/bitcoin_hmac.asm:23-26, 108-120`; `asm/sha512.asm:75-77, 131` | Process-global scratch: thread-unsafe SHA-512 schedule and HMAC buffers, unbounded message copy into a 1,160-byte `.bss` buffer, key-derived pad retained after return | CONFIRMED |
| CRY-5 | LOW | `asm/bip340_sign.c:59-68, 90-101`; `asm/musig2.c:54-60, 134, 179, 222, 251-274` | `bip340_sign` silently uses uninitialised nonce/challenge for messages > 4,032 bytes; MuSig2 uses static buffers and never consumes/zeroises `secnonce` | CONFIRMED (latent) |
| CRY-6 | INFO | `asm/sha256_nia.asm`; `asm/sha256.asm:196-209` | Dead `sha256_nia.asm` carries the *correct* probe but is not built; scalar fallback never exercised by the gate on this box; negative probe result never cached | CONFIRMED |
| CRY-7 | INFO | `asm/wallet_core.c:194-207` (outside file list) | Wallet ECDSA nonce is `sha256d(z||d)`, not RFC 6979; `z >= n` and `r == 0` edge cases unhandled | CONFIRMED (negligible probability) |
| CRY-8 | INFO | `asm/bitcoin_aes.c:43-48, 170-173` | Lazy ISBOX build is an unsynchronised write; PKCS#7 check is variable-time; S-box lookups are table-driven (documented) | CONFIRMED (benign) |

##### CRY-1 (HIGH) — SHA-NI dispatch probes the F16C bit, not the SHA bit
- Location: `asm/sha256.asm:196-209` (`sha256_block` dispatch); correct probe exists at `asm/sha256_nia.asm:52-70` but that file is not in the build (`grep sha256_nia asm/Makefile asm/build.sh` → nothing).
- Description: `sha256_block` runs `mov eax,1 / cpuid / bt ecx,29 / setb [shani_ready]` and then tail-jumps to `sha256_block_shani`, which executes `sha256rnds2`/`sha256msg1`/`sha256msg2`. CPUID leaf 1, ECX bit 29 is **F16C** (half-precision conversion). The SHA extensions flag is CPUID.(EAX=7,ECX=0):EBX bit 29 — which is exactly what the unused `cpu_has_sha_ni` in `sha256_nia.asm` checks. On this development box (Zen 5) both bits are set, so the bug is invisible.
- Failure scenario: run any binary in the tree (daemon, `bitcoin_cli`, every test) on an Intel Ivy Bridge, Haswell, Broadwell, Skylake, Kaby Lake, Coffee Lake or Comet Lake core, or any Xeon before Ice Lake-SP: F16C is present, SHA-NI is absent; the first `sha256_block` call (e.g. hashing the genesis header at startup) raises SIGILL. The scalar fallback is never reached. This is a crash-on-start for the majority of the installed x86-64 base of the last decade. Additionally, on a CPU where the probe *does* say "no SHA" (F16C absent), `shani_ready` is written 0, which the guard at line 196 treats as "not yet probed", so the serialising `cpuid` re-runs on every block.
- Core reference: n/a (Core's `sha256.cpp` `inline bool AVXEnabled/SHANI` uses `cpuid(7,0)` EBX bit 29).
- Suggested fix: probe leaf 7 sub-leaf 0 EBX bit 29 (and, as Core does, also require SSE4.1/SSSE3 for the `pshufb`/`pblendw`/`palignr` instructions the body uses); store a tri-state flag (0 unknown / 1 yes / 2 no). Delete or build `sha256_nia.asm` rather than keeping a divergent copy. Add a test that forces the scalar path (e.g. by exporting a setter for the flag) so the fallback is exercised on SHA-NI machines.
- Verdict: CONFIRMED.
- Test coverage: none. `tests/test_sha256.c` calls `sha256_block` through the dispatcher, so on this machine it only ever runs the SHA-NI body; the scalar body is not in the gate, and no test asserts the CPUID leaf.

##### CRY-2 (HIGH) — Hybrid public keys rejected; Core accepts them in consensus
- Location: `asm/bitcoin_pubkey.asm:180-187` (33-byte branch accepts only 0x02/0x03) and `:306-309` (65-byte branch accepts only 0x04). Callers treat a parse failure as "signature false": `asm/bitcoin_checksig.asm:196-198` and `:283-285` (`jz .zero`), likewise `bitcoin_multisig.asm`, `bitcoin_witness_v0.c`, `bitcoin_segwit.c`.
- Description: libsecp256k1's `secp256k1_eckey_pubkey_parse` (eckey_impl.h), which `CPubKey::Verify` uses through `secp256k1_ec_pubkey_parse`, accepts a 65-byte key whose first byte is 0x04, **0x06 or 0x07**; for 0x06/0x07 it additionally requires `y` parity to match (0x07 = odd) and then runs the on-curve check. Core's `IsCompressedOrUncompressedPubKey` rejects hybrids only under `SCRIPT_VERIFY_STRICTENC`, a policy flag that is never set for block validation. So for legacy and P2SH (and P2WSH/P2SH-P2WPKH v0, whose CHECKSIG uses the same `CPubKey::Verify`) a valid ECDSA signature over a hybrid-encoded key passes in Core.
- Failure scenario: an output `OP_DUP OP_HASH160 <hash160(0x06||X||Y)> OP_EQUALVERIFY OP_CHECKSIG` (or bare P2PK, bare multisig, or any P2SH/P2WSH redeem script embedding a hybrid key) is spent with a correct signature. The transaction is non-standard (STRICTENC) so it will not relay, but any miner can include it. Core accepts the block; this node's `pubkey_parse` returns 0, CHECKSIG evaluates false, the script fails, the block is rejected → the node forks off the chain in the false-reject direction. Whether such a spend already exists in mainnet history could not be verified offline (one secondary source claims none on mainnet; testnet3 has them); if one exists below `assumevalid` the default sync would not have noticed because scripts are skipped there. `docs/FEATURE_GAPS.md:647` states `pubkey_parse` "= Core's `IsFullyValid`", which is not accurate for hybrids.
- Core reference: `secp256k1_eckey_pubkey_parse` (libsecp256k1 `src/eckey_impl.h`), `CPubKey::Verify` (`src/pubkey.cpp`), `IsCompressedOrUncompressedPubKey`/`CheckPubKeyEncoding` (`src/script/interpreter.cpp`, STRICTENC only). Also `script_tests.json` "hybrid pubkey" cases in Core's test suite.
- Suggested fix: in the 65-byte branch accept 0x04/0x06/0x07; after the on-curve check, for 0x06/0x07 reject when `(y.limb0 & 1) != (tag == 0x07)`. Make sure the STRICTENC check in the interpreter (`bitcoin_interp.asm:2751-2760`) is the *only* place hybrids are refused (it already is on the policy path). Add the hybrid vectors from Core's `script_tests.json` to `tests/test_pubkey.c` and `tests/test_scriptverify_parity`.
- Verdict: CONFIRMED (divergence by code reading; historical occurrence unverified).
- Test coverage: none for hybrids (`tests/test_pubkey.c` covers 0x02/0x03/0x04, off-curve, non-residue and bad length only).

##### CRY-3 (LOW) — `x >= p` (and `y >= p`) not rejected when decoding keys
- Location: `asm/bitcoin_pubkey.asm:201-216` (compressed: bytes → limbs, no compare against `P_LIMBS`), `:332-348` (uncompressed: same for x and y); `asm/secp256k1_schnorr.asm:213-225` (`lift_x` via `pubkey_parse([0x02||pk])`, no `pk < p` check). By contrast `asm/secp256k1_taproot.asm:418-431` does check `internal_x < p`.
- Description: Core's `secp256k1_fe_set_b32_limit` fails the parse when the 32-byte value is `>= p`, and BIP340 `lift_x` fails for `x >= p`. Here the raw limbs are used as-is; `fe_mul`/`fe_sqr` reduce any 256-bit input correctly (proved in the Python model), so the on-curve test is really performed on `x mod p`, and on success the **non-canonical** limbs are returned in `qx`/`qy`. Downstream `point_add_mixed`'s doubling/opposite detection compares limbs (`secp256k1_point.asm:334-358`) and explicitly assumes canonical operands.
- Failure scenario: a key encoding `X = x' + p` with `x' < 2^32 + 977` decodes here as the point `(x', y)` and is rejected by Core. To turn that into an accept/reject split an attacker needs a valid signature under `(x', y)`, i.e. the discrete log of a point whose x-coordinate is below 2^33 — a ~2^223 search. For Schnorr the same holds (the 32-byte program/tapscript key `>= p`). No practical exploit; the observable behaviour today is "both reject". It is still a semantic divergence and a canonicality-invariant violation.
- Core reference: `secp256k1_fe_set_b32_limit` (field_impl.h), `secp256k1_xonly_pubkey_parse`, BIP340 `lift_x`.
- Suggested fix: 4-limb compare against `P_LIMBS` in both branches (and `y` in the uncompressed branch), and in `schnorr_verify` before calling `pubkey_parse` (mirroring `taproot_tweak_pubkey`).
- Verdict: CONFIRMED (divergence), unexploitable in practice.
- Test coverage: none (no `x >= p` vector in `tests/test_pubkey.c` or `tests/test_schnorr*.c`).

##### CRY-4 (MEDIUM) — Process-global scratch in SHA-512/HMAC: thread-unsafe, unbounded copy, key material retained
- Location: `asm/sha512.asm:75-77` (`Wbuf: resb 640` in `.bss`, used by every `sha512_block` at `:131`); `asm/bitcoin_hmac.asm:23-26` (`kpad: resb 128`, `tmp: resb 1160`), message copy at `:108-120` with no bound.
- Description: three separate defects in the same construction. (a) `sha512_block` builds its 80-word schedule in a global; two threads hashing concurrently corrupt each other's digests silently — the exact class that produced the schnorr false-reject incident (`secp256k1_schnorr.asm:43-61`). Today every SHA-512 user (BIP32/BIP39 in `bitcoin_bip32.asm`, `bip32_ckdpub.c`, `rpc_commands.c:3426`, `wallet_crypter.c`, `wallet_store.c`) runs under `rpc_server.c`'s `g_exec_lock` (`:548`, `:683`), so it is latent rather than live — but nothing enforces that. (b) `hmac_sha512` copies `msglen` bytes to `tmp+128` with capacity 1,032 and no check. BIP32 callers pass 37 bytes; BIP39 PBKDF2 passes `12 + passlen`. `passlen` is bounded to 255 on the RPC path (`rpc_wallet_ops.c:613`) but is `strlen(getenv("BMC_WALLET_PASS"))` in `wallet_store.c:250-251` and a CLI argument in `wallet_cli.c:538`, so an operator-supplied passphrase over ~1,020 bytes writes past `tmp` into whatever follows in `.bss` (`bitcoin_bip39.asm`'s own 512-byte `m39_salt` overflows first, at ~504 bytes — that file is outside this module). (c) `kpad` holds the padded HMAC key (BIP32 parent chain code, or the mnemonic in PBKDF2) and `tmp[192..255]` the inner digest; neither is zeroised, so secret-derived material persists in `.bss` for the process lifetime.
- Failure scenario: (a) a future caller of BIP32 derivation from a `tx_verify` worker or the ZMQ/i2p threads yields wrong child keys — `getnewaddress` handing out an address nobody can spend. (b) `BMC_WALLET_PASS` of 1,100 bytes → global memory corruption on wallet load. (c) a memory-disclosure bug elsewhere reveals the chain code / mnemonic.
- Core reference: Core's `CHMAC_SHA512`/`CSHA512` keep state in the object; `memory_cleanse` on secrets.
- Suggested fix: move `Wbuf` to the stack frame (`sha512_block` already has `rbp`-relative temporaries; 640 bytes fits) and `kpad`/`tmp` into `hmac_sha512`'s frame with an explicit `msglen` bound (or a streaming HMAC over `sha512_block`); zeroise before return. Add a `tests/test_sha512_thread_stress` like the ripemd160/schnorr ones.
- Verdict: CONFIRMED.
- Test coverage: `tests/test_sha512`, `tests/test_hmac` (vectors only, single-threaded, short messages); no bound or thread test.

##### CRY-5 (LOW) — `bip340_sign` silent failure on long messages; MuSig2 statics and nonce handling
- Location: `asm/bip340_sign.c:59-68` (`tagged()` returns without writing `out` when `al+bl+cl > 4096`), used at `:90-101` for the aux, nonce and challenge hashes; `asm/musig2.c:54-60` (`static u8 buf[64+8192]`), `:134` (`static lbuf`), `:179` (`static buf`), `:222` (`static buf`), `:251-274` (`musig2_partial_sign` does not zeroise/consume `secnonce`).
- Description: for `msglen > 4032`, `kh` and `eh` are uninitialised stack; `k0` and `e` come from whatever was there, the signature is garbage, and `s = k + e*d` is emitted with an attacker-unknown but non-random `k`. All current callers pass 32-byte sighashes (`miniscript_sign.c:86`, `rpc_commands.c:1871, 2278`), so this is unreachable today; it is a footgun for the next caller (BIP340 explicitly allows arbitrary-length messages and the API advertises it). `d`, `k`, `t` are not cleansed after signing. MuSig2's static buffers are safe only because RPC is serialised; BIP327 requires the secret nonce to be deleted after one use and the implementation leaves that entirely to the caller (`rpc_commands.c:3527`).
- Failure scenario: a future `signmessage`-style RPC that signs a user-supplied long message with BIP340 produces an invalid signature computed with a stack-derived nonce; two such calls with the same stack state give the same `k` and, with attacker-known messages, leak `d` — if `e` were computed correctly. (Here `e` is also garbage, which is what currently prevents the classic nonce-reuse recovery; that is luck, not design.)
- Core reference: libsecp256k1 `secp256k1_schnorrsig_sign_custom` (streams the tagged hash, no length cap; `secp256k1_memclear` on secrets); BIP327 "Nonce Generation … the secnonce must be deleted".
- Suggested fix: make `tagged()` return a status and fail the sign on overflow, or hash incrementally; `memset` secrets; in `musig2_partial_sign` overwrite `secnonce` with zeros on success; move statics to the stack.
- Verdict: CONFIRMED (latent).
- Test coverage: `tests/test_bip340_sign` (Core vectors, ≤ 100-byte messages), `tests/test_musig2` (BIP327 vectors). No long-message or reuse test.

##### CRY-6 (INFO) — Dead accelerator file, untested scalar fallback, negative-probe caching
- Location: `asm/sha256_nia.asm` (not referenced by `asm/Makefile`/`build.sh`); `asm/sha256.asm:196-209`.
- Description: `sha256_nia.asm` contains a second SHA-NI body plus the *correct* CPUID probe, but is not built; the built dispatcher in `sha256.asm` has the wrong probe (CRY-1). On a SHA-NI machine the gate never executes the scalar `sha256_block` body, so a regression there would ship undetected. `setb [shani_ready]` stores 0 for "absent", which the `cmp …,0 / jne .shani_known` guard reads as "not probed", so the probe repeats every call.
- Suggested fix: as in CRY-1; delete `sha256_nia.asm` or make it the single implementation; add a forced-scalar KAT run.
- Verdict: CONFIRMED.
- Test coverage: none for the fallback path.

##### CRY-7 (INFO) — Wallet ECDSA nonce is not RFC 6979 (file outside this module's list)
- Location: `asm/wallet_core.c:194-207` (`k = sha256d(z || priv)`), `:212-237`.
- Description: The signing path is constant-time in `k` (`point_scalar_mul_ct`, `sc_inv`, `sc_mul`), deterministic and secret-dependent, which is sound. It is not RFC 6979, so signatures are not byte-comparable with Core's; `k` is never checked for 0 (probability 2^-256); `z` is fed to `sc_add` unreduced (`sc_add` assumes `< n`, violated with probability ~2^-128); `r == 0` is not rejected. Low-S normalisation is applied.
- Suggested fix: reduce `z` mod `n` before `sc_add`; reject `k == 0`/`r == 0`/`s == 0` and retry with a counter; consider RFC 6979 for interoperability. Hand to the wallet reviewer.
- Verdict: CONFIRMED (negligible probability).
- Test coverage: `tests/test_keys`, wallet sign/verify round trips.

##### CRY-8 (INFO) — AES implementation notes
- Location: `asm/bitcoin_aes.c:43-48` (lazy `ISBOX` build, unsynchronised `g_isbox_ready`), `:170-173` (PKCS#7 check with early exit), S-box lookups throughout.
- Description: The lazy inverse S-box build is an idempotent racy write (benign on x86). The padding check and the S-box are variable-time; the file documents the latter as out of scope for at-rest wallet encryption, which is reasonable since no attacker-chosen ciphertext is decrypted online.
- Verdict: CONFIRMED (benign).
- Test coverage: `tests/test_aes` (FIPS-197 C.3), `wallet_crypter` parity with OpenSSL per FEATURE_GAPS.

#### Verified-correct controls

- **Field arithmetic** (`asm/secp256k1_fe.asm`): `fe_add` (106-145) and `fe_sub` (165-186) canonicalise with a single conditional ±C fold; the argument at 82-99 is right (sum < 2p, one subtract suffices). `fe_mul` (261-442): 512-bit schoolbook with two ADCX/ADOX chains, two folds by C = 2^32+977, the fold-2 carry re-folded (401-410, the 2026-08-21 lost-carry fix), one conditional subtract; the bound proof at 233-247 checks out (u4 < 2^33+2, u4·C < 2^67, no second carry). `fe_sqr` (481-556) shares `.reduce`. `fe_inv` (649-724): I re-derived the addition chain symbolically — x223·2^23 + x22, ·2^5 + a, ·2^3 + x2, ·2^2 + a = 2^256 − 2^32 − 979 = p − 2 exactly; fixed sequence, no secret-dependent branch. Inline macros (`secp256k1_fe_inline.inc:101-161`) preserve canonicality; `FE_ADD_TAIL`'s merged predicate (`CF1 | CF2`) is correct for canonical inputs as argued at 76-97. Pinned by `tests/test_fe`, `test_fe_inline`, `test_fe_repr`, `test_fe_inv_chain` (symbolic exponent check), `validation/fe_oracle.py`, `fe_mul_model.py`, `run_fe_diff.py`, `stress_fe`.
- **Scalar arithmetic** (`asm/secp256k1_scalar.asm`): `sc_add` (101-180) branch-free DELTA fold + one conditional subtract with a correct bound argument (126-130); `sc_sub` (186-228) branch-free; `sc_mul` (246-478) full-length carry chains (the 2026-08-21 fix at 288-298), 8 DELTA folds (3 would suffice; harmless), 3 conditional subtracts (1 suffices), constant instruction shape; `sc_inv` (496-569) fixed 255-iteration Fermat over the public exponent; `sc_inv_var` (601-812) Stein xgcd with the `(x+n)/2` 257th-bit halving handled (789-800), rejects 0, only used on public `s`. `sc_split_lambda` (916-1023) mirrors libsecp's `secp256k1_scalar_split_lambda` including the 2^128 rounding overflow limb (941-944) and *always* runs the `k == r1 + λ·r2` identity check, falling back to the plain ladder on failure. GLV constants transcribed from libsecp and re-derived by `validation/glv_split_oracle.py`; `tests/test_glv_split`, `test_glv_wnaf`, `test_glv_pointmul`, `test_scalar`, `stress_scalar.py`.
- **Point arithmetic** (`asm/secp256k1_point.asm`): Z=0 operand guards in `point_add` (722-743) and `point_add_mixed` (288-307) — load-bearing for the GLV ladder that starts at infinity; equal-x/opposite-y detection on canonical limbs (334-358, 785-809); `point_double` correct for a=0 Jacobian (100-222, in-place safe, Y1·Z1 captured before the output write at 190-199). `point_scalar_mul_fixed` (923-1059) indexes the comb table as `((j*15)+(d-1))*64`, matching `g_comb_table.inc`'s layout; k=0 → infinity. `point_scalar_mul_glv` (1095-1385): odd-multiples table on the isomorphic curve, `globalz` back-scaling (1223-1258) consistent with `secp256k1_ge_table_set_globalz`, β-table for the λ stream, final `R.z *= ZG`, `and rsp,-16` before calling gcc code (1112). `tests/test_point`, `test_point_inf`, `test_point_repr` (limb-exact vs frozen `point_ref.asm`), `test_scalarmul`, `run_pointmul_diff.py`, `stress_pointmul`.
- **Constant-time signing ladder** (`asm/secp256k1_point_ct.asm`): Renes–Costello–Batina complete formulas (Alg. 7 at 113-290, Alg. 9 at 303-410, b3 = 21), exactly 256 double-and-add-always iterations, 12-cmov select (506-515), no secret-indexed memory, branch-free infinity canonicalisation (540-582). Used by `bitcoin_keys.asm:118`, `bip340_sign.c`, `musig2.c`, `wallet_core.c`. Prior-audit CRITICAL (timing leak) re-verified fixed. `tests/test_scalarmul_ct`, `run_pointmul_ct_diff.py`, `stress_pointmul_ct`.
- **ECDSA verify** (`asm/secp256k1_ecdsa.asm`): `0 < r,s < n` (90-118, 269-278), `w = s^-1` variable-time on public data only, `u1 = z·w` with `z` reduced implicitly by `sc_mul` (Core reduces `z` mod n too), `P = u1·G + u2·Q` with infinity rejected (353-357), projective `x(P) == r (mod n)` with the `r + n < p` second candidate exactly as `secp256k1_ecdsa_sig_verify` (136-232, `p − n` constant at 83-84 matches libsecp). DER, BIP66, LOW_S and STRICTENC are enforced in the interpreter (`bitcoin_interp.asm:2652-2760`, `der_sig_strict`), not here — correct layering. `tests/test_ecdsa`, `test_ecdsa_inverse` (drives the `r+n` branch, unreachable by real vectors), `test_ecdsa_glv_switch`, `ecdsa_verify_ref.asm` differential.
- **BIP340 verify** (`asm/secp256k1_schnorr.asm`): `lift_x` even-y (213-225), `r < p` (227-256), `s < n` (258-287), `e = tagged_hash mod n` with per-call stack preimage (288-363; the thread-safety incident fix re-verified — no `.data` buffer remains), `R = s·G − e·P` with `−Y` computed as `p − Y` (399-416), infinity rejected (423-427), projective `x(R) == r` (443-448), affine parity via one inversion (454-469), message length bounded before the copy (208-211). `tests/test_schnorr` (Core `bip340_test_vectors.csv`), `test_schnorr_diff` (one-limb-apart compare), `test_schnorr_thread_stress`.
- **Taproot helpers** (`asm/secp256k1_taproot.asm`): `TapTweak`/`TapLeaf`/`TapBranch` tags; lexicographic branch ordering via `repe cmpsb` with the correct CF sense (189-193, 605-612); `t >= n` rejected (389-416); `internal_x >= p` rejected (418-431); Q at infinity rejected (464-469); tweaked-Y parity returned (492-525) — the 2026-08-26 control-block-parity false-accept fix re-verified; `tap_leaf_hash` bounds the script against the 4 MiB TLS buffer before writing (256-262); all scratch in `.tbss`. `tests/test_taproot*`, `validation/diff_bip341_corpus.py`.
- **BIP340 sign / MuSig2** (`asm/bip340_sign.c`, `asm/musig2.c`): BIP340 reference algorithm (aux xor, nonce tag, negate for odd P and odd R, `s = k + e·d`); BIP327 KeyAgg (`pk2` rule, `L`), tweak (`g`, `gacc`, `tacc`), nonce-coefficient `b`, `R = R1 + b·R2` with the `R = G` fallback, partial-sign self-check, aggregation. `pt_from_bytes` in `musig2.c:79-90` *does* reject `x >= p`. `tests/test_bip340_sign`, `test_musig2` (BIP327 vectors), `test_musig2_psbt`.
- **MuHash3072** (`asm/bitcoin_muhash.asm`): `num3072_mul` (244-407) is a faithful transcription of `Num3072::Multiply` including `mulnadd3`'s truncated `d2·n` (310-311), `muln2`, `addnextract2`, the `IsOverflow`/carry double `FullReduce`; `ToNum3072` = SHA256 → ChaCha20 (nonce 0, counter 0, 6 blocks) written straight into LE limbs (538-561); `Finalize` performs `Multiply(1)` with the pre/post overflow reductions and a single SHA256 (621-676). Denominator omitted is sound for insert-only use. `tests/test_muhash` against `validation/muhash_oracle.cpp` vectors; live muhash parity with Core at 965,104.
- **ChaCha20-Poly1305** (`asm/crypto_chacha20.c`, `asm/crypto_poly1305.c`): RFC 8439 quarter-round and state layout; Poly1305 in poly1305-donna-32 limb form with the clamp (34-38), pad bit handling (48, 99-102), branch-free final reduction (113-122); AEAD key from block 0, data from block 1, pad16/len64 framing (157-187); **authenticate-before-decrypt** (208-212) and constant-time tag compare (147-151). `tests/test_chacha20`, `test_poly1305` (RFC vectors).
- **HKDF/HMAC-SHA256** (`asm/crypto_hkdf.c`): RFC 2104/5869 including the 32-zero-byte default salt (47-51) and `T(n)` chaining. `tests/test_hkdf`.
- **fe_sqrt** (`asm/crypto_fe_sqrt.c`): libsecp's `(p+1)/4` chain, result verified by squaring (79-82). `tests/test_fe_sqrt`.
- **Hashes**: SHA-256 scalar body and padding (`sha256.asm:210-566`), SHA-NI body (575-744, translated from the canonical Intel routine), `sha256d64` two-lane merkle kernel with `.rodata` padding blocks (`bitcoin_hash.asm:343-429`), SHA-512 rounds/padding with 128-bit length (`sha512.asm:120-421`; save area above `rbp` after the callee-saved fix), SHA-1 (`sha1.asm`), RIPEMD-160 padding with LE bit length (`ripemd160.asm:1919-1960`), SHA3-256 Keccak-f (`bitcoin_sha3.c`). `pow_check` compares big-endian bytes MSB first (`bitcoin_hash.asm:233-245`). I found no frame overlap in `sha256_full` (`sha256.asm:447-566`: all locals are `rsp`-relative below six pushes), so the "deep-frame overlap" cited in the 09-02 audit (N1) is not visible in this file; I could not reproduce it and it stays open.
- **AES-256-CBC** (`asm/bitcoin_aes.c`): FIPS-197 key schedule with the AES-256 extra SubWord (64-79), correct ShiftRows/MixColumns/inverse (81-133), PKCS#7 (137-174). `tests/test_aes`.

#### Coverage and limits

- Not done: hand-verification of the 80 unrolled RIPEMD-160 rounds; the CUDA tier; `bitcoin_bip32.asm`/`bitcoin_bip39.asm` (the BIP39 `m39_salt` 512-byte global copy at `bitcoin_bip39.asm:751-764` has no `passlen` bound and overflows before CRY-4(b) does — the wallet reviewer should pick that up); BIP324 transport/ElligatorSwift (they consume the primitives reviewed here).
- I did not confirm whether a hybrid-key spend exists in mainnet history (CRY-2). The next step is to scan the archive: every P2PKH/P2PK/P2SH input whose pushed pubkey is 65 bytes with first byte 0x06/0x07 — the `txindex` build tools can do this offline; if any exists below the assumed-valid height, a `-assumevalid=0` replay would halt there.
- I did not run the test binaries; all coverage statements are from reading `asm/tests/*.c` and `asm/validation/*`.
- Worth doing next: a forced-scalar SHA-256 KAT in the gate; hybrid and `x >= p` vectors in `test_pubkey`/`test_scriptverify_parity`; a SHA-512/HMAC thread-stress test; a `bip340_sign` long-message test; moving all remaining `.bss` crypto scratch (`sha512.asm`, `bitcoin_hmac.asm`, `bitcoin_bip39.asm`) onto the stack, since the project has already been bitten twice by this pattern.


---

### 6.2 Script interpreter and signature hashing (consensus) — review

**Scope:**
- Files fully read: `asm/bitcoin_interp.asm`, `asm/bitcoin_scriptcodec.asm`, `asm/bitcoin_scriptverify.c`, `asm/bitcoin_witness_v0.c`, `asm/bitcoin_taproot_sighash.c`, `asm/bitcoin_sighash.asm`, `asm/bitcoin_sigops.asm`, `asm/bitcoin_script_flags.asm` + `asm/script_flags_consts.inc`, `asm/bitcoin_tapagg.asm`, `asm/bitcoin_strip_witness.asm`, `asm/bitcoin_script.asm`, `asm/bitcoin_segwit.c` (segwit_v0_sighash and strip_witness; the p2wpkh/p2wsh helper verifiers were not read), the witness/taproot dispatch in `asm/daemon/tx_verify.c` (lines 165-200, 385-400, 560-610, 760-810, 867), the sigop-cost code in `asm/daemon/tx_accept.c` (445-585), `tests/LEGACY_INTERP_GAP.md`.
- Files skimmed (header + globals + Makefile linkage only): `bitcoin_bip143.asm`, `bitcoin_bip341.asm`, `bitcoin_taproot_verify.asm`, `bitcoin_checksig.asm`, `bitcoin_segwit_classify.asm`, `bitcoin_scriptverify_drv.asm`, `bitcoin_witness_v0_drv.asm` — these are differential "twins" of the C files, linked only into `tests/*` (not in `DAEMONOBJS`, Makefile:100-110), so the C side is the consensus path; `bitcoin_multisig.asm` (no callers in daemon/rpc/wallet); `secp256k1_taproot.asm` (only `tap_leaf_hash` capacity and `tap_merkle_root` ordering, lines 76-100, 250-275, 551-640); `validation/gen_script_flags.py` (extraction logic and exception-hash byte reversal).
- Not read: `script_error_codes.h`, `script_flags_consts.h` (generated), `bitcoin_taproot_ctx.h` (struct only), the ECDSA/Schnorr verifiers behind `ecdsa_verify` / `schnorr_verify` / `pubkey_parse` (crypto module).
- Core reference used: `/storage/bitcoin-core-source/src/script/interpreter.cpp` (grepped, rule 1), `script.cpp`, `primitives/transaction.h`, `consensus/tx_verify.cpp`.

**Summary:** The interpreter is a faithful opcode-by-opcode transcription of `EvalScript` for the common paths, and the three sighash builders (legacy, BIP143, BIP341) match Core field for field including the historical quirks. The differential harnesses are real and have clearly paid off. But the module has three CONFIRMED consensus false-accepts that the differentials cannot see because their generators never reach the shape: (1) the 1000-element stack limit is enforced per stack instead of over `stack + altstack`; (2) the condition stack (`vfexec`) is a 1024-byte TLS buffer with no bounds check, so a tapscript with >1024 nested `OP_IF`s corrupts `vfexec_sp` and can make an unbalanced script succeed; (3) tapscript `OP_CHECKSIG`/`OP_CHECKSIGADD` short-circuit an empty signature before the checker runs, so Core's "empty signature with empty pubkey fails the script" rule never fires. Two CONFIRMED false-rejects follow: the CSV `nVersion < 2` test is a signed compare (Core's `version` is `uint32_t`), and any transaction mixing a P2TR input with a >=253-byte prevout scriptPubKey is refused by the taproot aggregate builder. The block-level 80,000 sigop-cost limit is not enforced anywhere (cross-module, but sigop counting was assigned here). One P2P-reachable out-of-bounds read exists in `OP_CHECKMULTISIG` (operand reads precede the stack-depth checks). Confidence in the findings is high — every one was traced end to end against the Core source on disk; test coverage for all of them is absent.

#### Findings

| ID | Severity | Location | Title | Verdict |
|---|---|---|---|---|
| SCR-1 | CRITICAL | `asm/bitcoin_scriptcodec.asm:151-157`, `asm/bitcoin_interp.asm:2364-2366` | MAX_STACK_SIZE enforced per stack, not over `stack + altstack` (false accept) | CONFIRMED |
| SCR-2 | CRITICAL | `asm/bitcoin_scriptcodec.asm:44-47, 766-776` | Condition stack `vfexec` has no bounds check; >1024 nested IFs in tapscript overwrite `vfexec_sp` (memory corruption + false accept) | CONFIRMED |
| SCR-3 | CRITICAL | `asm/bitcoin_interp.asm:2822-2827, 2874-2876` | Tapscript CHECKSIG/CHECKSIGADD with empty signature skips the checker, so `TAPSCRIPT_EMPTY_PUBKEY` never fires (false accept) | CONFIRMED |
| SCR-4 | HIGH | `asm/bitcoin_interp.asm:2336-2338` | CSV `nVersion < 2` uses a signed compare; Core compares `uint32_t` (false reject for version >= 0x80000000) | CONFIRMED |
| SCR-5 | HIGH | `asm/daemon/tx_verify.c:396`, `asm/bitcoin_taproot_sighash.c:383-386`, `asm/bitcoin_txval_modern.c:349` | Any tx with a P2TR input and a >=253-byte prevout scriptPubKey is rejected (false reject) | CONFIRMED |
| SCR-6 | HIGH | `asm/bitcoin_sigops.asm` (callers: `daemon/tx_accept.c:521`, `daemon/main.c:5693` only) | Block sigop-cost limit (MAX_BLOCK_SIGOPS_COST 80,000) is not enforced at block connection (false accept) | CONFIRMED (absence; cross-module) |
| SCR-7 | MEDIUM | `asm/bitcoin_interp.asm:2178-2181, 2946-2953, 2998-3006`; `asm/bitcoin_scriptcodec.asm:130-135, 325-345` | OP_CHECKMULTISIG reads operands below the stack bottom before its depth check (P2P-reachable OOB read; error-code divergence) | CONFIRMED (read), crash PLAUSIBLE |
| SCR-8 | LOW | `asm/bitcoin_script.asm:37-140` | `der_parse_sig` rejects long-form DER lengths that Core's lax parser accepts (pre-BIP66 blocks only) | CONFIRMED |
| SCR-9 | LOW | `asm/daemon/tx_verify.c:867`, `asm/bitcoin_txval_modern.c:36`, `asm/bitcoin_interp.asm:770-786` | Mempool/relay runs consensus flags only; the interpreter's policy arms are inert and the DISCOURAGE_* / WITNESS_PUBKEYTYPE / SIGPUSHONLY / CONST_SCRIPTCODE-in-unexecuted-branch rules are not implemented | CONFIRMED |
| SCR-10 | INFO | `asm/bitcoin_sigops.asm:123-306` | `tx_legacy_sigops` walks the transaction with no bounds checks against `txlen` | CONFIRMED (not reachable today) |
| SCR-11 | INFO | `asm/bitcoin_interp.asm:2809-2827` vs `bitcoin_scriptverify.c:186-193` | CONST_SCRIPTCODE FindAndDelete check runs after encoding checks (Core: before); error-code only | CONFIRMED |

##### SCR-1 (CRITICAL) — MAX_STACK_SIZE enforced per stack, not over `stack + altstack`
- Location: `asm/bitcoin_scriptcodec.asm:151-157` (`stack_push`: `cmp rax, MAX_STACK_SIZE` against the target stack's own `sp`), same in `stack_push_copy` (:179-183), `stack_dup_index` (:835-839), `stack_insert_index` (:917-920); `asm/bitcoin_interp.asm:2364-2366` (`.next_op` performs no combined check); alt stack buffers are a full 1000 records (`asm/bitcoin_scriptverify.c:290`, `asm/bitcoin_taproot_sighash.c:1097`).
- Description: Core's rule, checked after every opcode, is `if (stack.size() + altstack.size() > MAX_STACK_SIZE) return SCRIPT_ERR_STACK_SIZE` (interpreter.cpp, end of the `for` body in `EvalScript`). Here the main stack may hold 1000 elements and the alt stack another 1000 independently, so a script may run with up to 2000 live elements.
- Failure scenario: P2WSH witnessScript = 900 x `OP_0`, then 200 x `OP_TOALTSTACK`, then 200 x `OP_0`, then `OP_1` (1301 bytes, 401 counted opcodes <= 201? no: 200 TOALTSTACK + 1 = 201 opcodes, under the limit; pushes are not counted). After the last pushes the totals are main 901 / alt 200 = 1101 > 1000. Core: `SCRIPT_ERR_STACK_SIZE`, input invalid. This node: `stack_push` sees `sp = 900 < 1000` and succeeds; the script continues and can end truthy after enough `OP_2DROP`s only if opcodes remain — simpler: a tapscript has no opcode limit at all, so `900 x OP_0, 200 x OP_TOALTSTACK, 200 x OP_0, 550 x OP_2DROP, 200 x OP_FROMALTSTACK, 100 x OP_2DROP, OP_1` is accepted here and rejected by Core. A block containing such a spend is accepted by this node and rejected by the network (chain split, accept direction). The mempool accepts and relays it too.
- Core reference: `EvalScript`, `MAX_STACK_SIZE` check (`stack.size() + altstack.size()`), interpreter.cpp.
- Suggested fix: after every opcode in `.next_op` (or inside the four push helpers, given both `sp`s), fail with `SCRIPT_ERR_STACK_SIZE` when `main_sp + alt_sp > 1000`. Keep the per-buffer capacity guard as a memory-safety backstop.
- Verdict: CONFIRMED.
- Test coverage: none. `tests/fuzz_script_diff.c` scripts are <= 4096 bytes with random opcodes and never approach 1000 elements; `tests/test_interp.c` has one TOALTSTACK round-trip vector (line 208).

##### SCR-2 (CRITICAL) — Condition stack `vfexec` has no bounds check
- Location: `asm/bitcoin_scriptcodec.asm:44-47` (`vfexec: resb 1024` immediately followed by `vfexec_sp: resq 1` in `.tbss`), `:766-776` (`vfexec_push` writes `[vfexec + sp]` and increments with no compare against 1024).
- Description: Core's `ConditionStack` is unbounded (a vector). For BASE/WITNESS_V0 the 201-opcode limit bounds nesting, but under `SIGVERSION_TAPSCRIPT` there is no opcode limit and no script-size limit, so a leaf script can contain any number of `OP_IF`/`OP_NOTIF`. The 1025th push writes one byte past the buffer — into `vfexec_sp` itself (same object, same section, no alignment between them). With unexecuted `OP_IF`s (`dil = 0`), the 1025th push stores 0 into the low byte of `vfexec_sp` (0x400 -> 0x400, then inc -> 0x401) and the 1026th stores 0 into byte 1 (0x401 -> 0x001, inc -> 2). The condition stack now claims depth 2 while 1026 conditionals are open.
- Failure scenario: tapscript `OP_0 OP_IF <1026 x OP_IF> OP_ENDIF OP_ENDIF OP_1`. Core: at end of script `vfExec` is non-empty -> `SCRIPT_ERR_UNBALANCED_CONDITIONAL`, input invalid. This node: after the two `OP_ENDIF`s `vfexec_depth() == 0`, `OP_1` executes, `.loop_done` sees depth 0, the stack is `[1]`, the tapscript succeeds — a spend Core rejects is accepted (chain split, accept direction), and the same input reaches the mempool from any peer. Independently of the exact layout, this is an attacker-controlled out-of-bounds write into thread-local storage from P2P input.
- Core reference: `EvalScript` / `ConditionStack`, `ExecuteWitnessScript` (no nesting or opcode limit for `SigVersion::TAPSCRIPT`).
- Suggested fix: bound `vfexec_push` (fail the script with an internal error, or grow the buffer to the maximum a 4 MB witness can express and check against it). Core has no limit, so the only correct choice is a capacity large enough for any script that fits in a block (~4,000,000 bytes) plus a hard check.
- Verdict: CONFIRMED.
- Test coverage: none (`grep -i "nested\|vfexec"` over tests finds nothing; `fuzz_script_diff` scripts are <= 4096 bytes).

##### SCR-3 (CRITICAL) — Tapscript empty signature skips the empty-pubkey rule
- Location: `asm/bitcoin_interp.asm:2822-2827` (`interp_checksig`: `test rbx, rbx / jnz .cs_call` then, unless `SCRIPT_VERIFY_CONST_SCRIPTCODE` is set, `jz .false` — the callback is never called for an empty signature), `:2874-2876` (`interp_checksig_add`: unconditional `test rbx,rbx / jz .false`). The rule that is skipped lives in the callback at `asm/bitcoin_taproot_sighash.c:768-772` (`if (publen == 0) { c->hard_fail = 1; return 0; }`), whose own comment says "the empty-signature case cannot return early here".
- Description: Core's `EvalChecksigTapscript` (interpreter.cpp:357-395, verified on disk) evaluates the pubkey-size rules regardless of whether the signature is empty: `if (pubkey.size() == 0) return set_error(serror, SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY)`. The comment in Core is explicit: "the script execution fails when using empty signature with invalid public key". Here, for sigversion TAPSCRIPT with an empty signature, the interpreter pushes `false` (CHECKSIG) or adds 0 (CHECKSIGADD) and continues; `hard_fail` is never set. Consensus block flags never include CONST_SCRIPTCODE, so the `.cs_call` path is never taken for empty signatures in block validation.
- Failure scenario: tapscript leaf `OP_0 OP_0 OP_CHECKSIG OP_NOT` (or `OP_0 OP_0 OP_0 OP_CHECKSIGADD OP_NOT`), spent with an empty initial stack. Core: script fails (`TAPSCRIPT_EMPTY_PUBKEY`). This node: CHECKSIG pushes empty, `OP_NOT` pushes 1, cleanstack passes, spend accepted. Accept-direction consensus divergence reachable by anyone who commits such a leaf.
- Core reference: `EvalChecksigTapscript`, interpreter.cpp:377-378.
- Suggested fix: under `SIGVERSION_TAPSCRIPT` always call the checker (the C callback already implements Core's full sequence including the validation-weight charge only for non-empty signatures); keep the empty-signature shortcut for BASE/WITNESS_V0 only. Also note `SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE` (policy) is not implemented (see SCR-9).
- Verdict: CONFIRMED.
- Test coverage: none — no test mentions `EMPTY_PUBKEY` or an empty tapscript pubkey; `tests/fuzz_verify_diff` only uses Core-signed spends; `fuzz_script_diff` does not run sigversion 3.

##### SCR-4 (HIGH) — CSV `nVersion < 2` is a signed compare
- Location: `asm/bitcoin_interp.asm:2336-2338` (`mov eax, [r12+112] / cmp eax, 2 / jl .csv_unsatisfied`). The value comes from `sv_get_locktime_context` (`bitcoin_scriptverify.c:144`, raw 4 bytes) / `tx_parse` (`bitcoin_taproot_sighash.c:1123`).
- Description: Core's `CTransaction::version` is `uint32_t` (primitives/transaction.h:293) and `CheckSequence` does `if (txTo->version < 2) return false;` (interpreter.cpp:1800) — unsigned. `consensus/tx_verify.cpp:51` uses the same unsigned test for BIP68. A transaction with version >= 0x80000000 therefore has BIP68/BIP112 enforced by Core; `jl` treats it as negative and unconditionally fails the CSV.
- Failure scenario: a transaction with `nVersion = 0xFFFFFFFF` spending a P2WSH/tapscript output whose script contains `<n> OP_CHECKSEQUENCEVERIFY`, with a satisfying `nSequence`. Core: valid. This node: `SCRIPT_ERR_UNSATISFIED_LOCKTIME`, block rejected — the node forks off the chain the moment such a transaction is mined (no miner cooperation needed beyond inclusion; the transaction is otherwise standard except for its version).
- Core reference: `GenericTransactionSignatureChecker::CheckSequence`, interpreter.cpp:1790-1801.
- Suggested fix: `cmp eax, 2 / jb .csv_unsatisfied` (unsigned). Check the block-level BIP68 evaluation for the same mistake (none was found in `daemon/`, see "Coverage and limits").
- Verdict: CONFIRMED.
- Test coverage: `tests/test_csv_disable_flag.c:53` and `tests/test_cltv_csv.c:160-162` only use versions 1 and 2; `fuzz_script_diff.c:118` draws `txv` from {1, 2}.

##### SCR-5 (HIGH) — Taproot aggregate rejects any prevout scriptPubKey >= 253 bytes
- Location: `asm/daemon/tx_verify.c:396` (`if (sl >= 0xfd) { *reason = "prevout script too large for taproot aggregate sighash"; return 0; }` inside `tapagg_build`, run for every transaction that has at least one P2TR input, over ALL its inputs), `asm/bitcoin_tapagg.asm:102-104` (same in the twin), `asm/bitcoin_txval_modern.c:349` (mempool builds the same one-byte-length run). The format assumption is in `asm/bitcoin_taproot_sighash.c:383-386` (`ts_agg_hashes` comment: callers "refuse a scriptPubKey >= 253 bytes outright").
- Description: BIP341's `sha_scriptpubkeys` covers every spent output of the transaction, including non-taproot ones. Core's `PrecomputedTransactionData::Init` hashes them with a proper `CompactSize`; there is no size limit (a scriptPubKey may be up to `MAX_SCRIPT_SIZE` = 10,000 bytes and still be spendable). This code chose a single-byte length encoding for the internal run and turned that into a rejection.
- Failure scenario: a transaction whose input 0 spends a 1-of-8 bare multisig output with uncompressed keys (spk = 1 + 8*66 + 2 = 531 bytes, consensus-valid and spendable, non-standard) and whose input 1 spends a P2TR output with a valid key-path signature. Core: valid. This node: the whole transaction is rejected before any signature is checked; a block containing it is rejected and the node stalls on the fork (reject direction). The same tx is also refused by the mempool.
- Core reference: `PrecomputedTransactionData::Init` / `SignatureHashSchnorr` (`sha_scriptpubkeys`), interpreter.cpp.
- Suggested fix: encode the spks run with a real compactsize (the reader `ts_agg_hashes` already parses one via `read_cs`; only the writers in `tx_verify.c:396`, `bitcoin_tapagg.asm`, `bitcoin_txval_modern.c:349` need to change) and drop the `>= 0xfd` refusal.
- Verdict: CONFIRMED.
- Test coverage: none; `docs/FEATURE_GAPS.md` does not document this divergence (grep for `253`/`0xfd` finds nothing), although the code comment at `tx_verify.c:172-181` shows the author was aware of the literal.

##### SCR-6 (HIGH) — Block sigop-cost limit is not enforced
- Location: `asm/bitcoin_sigops.asm` provides `script_sigops`/`script_sigops_accurate`/`tx_legacy_sigops`; their only callers are the mempool policy path (`asm/daemon/tx_accept.c:449-541`, `txacc_sigop_cost`, standardness 16,000 cap at `:660`) and `getblocktemplate` (`asm/daemon/main.c:5693-5695`, explicitly a lower bound). `grep -rni sigop` over `asm/*.asm asm/*.c asm/daemon/*.c` finds no use in block connection (`daemon/utxo_live.c`, `daemon/tx_verify.c`, `bitcoin_cons.asm`), and no `80000`/`MAX_BLOCK_SIGOPS` anywhere.
- Description: Core's `ConnectBlock` accumulates `GetTransactionSigOpCost(tx, view, flags)` (legacy x4 + P2SH accurate x4 when P2SH is active + witness sigops) and rejects the block with `bad-blk-sigops` when `nSigOpsCost > MAX_BLOCK_SIGOPS_COST` (80,000). Nothing in this tree does that.
- Failure scenario: a block whose transactions contain, e.g., 20,001+ bare `OP_CHECKSIG` outputs (or 1,001+ bare CHECKMULTISIG outputs at 20 each) is under the weight limit but over 80,000 sigop cost. Core rejects it; this node accepts and follows it (accept direction).
- Core reference: `ConnectBlock` (validation.cpp) `nSigOpsCost`, `GetTransactionSigOpCost` (consensus/tx_verify.cpp).
- Suggested fix: in block connection, sum `tx_legacy_sigops(tx)*4` for every tx (including coinbase), plus `script_sigops_accurate(redeemScript)*4` for P2SH inputs when P2SH is active, plus witness sigops (P2WPKH 1, P2WSH accurate count of the witnessScript, wrapped forms likewise) when WITNESS is active; reject when > 80,000. The per-script counters here already match `CScript::GetSigOpCount` (verified below).
- Verdict: CONFIRMED by absence (this is block-validation territory; the block reviewer should confirm no enforcement lives outside `asm/`).
- Test coverage: `tests/test_sigops.c` covers the counters only.

##### SCR-7 (MEDIUM) — OP_CHECKMULTISIG reads below the stack bottom
- Location: `asm/bitcoin_interp.asm:2178-2181` (`.cms_go` calls `interp_checkmultisig` with no `interp_require_depth`), `:2946-2953` (reads `stacktop(1)` at index `sp-1` with no `sp >= 1` check), `:2998-3006` (reads `m` at index `sp-(nKeys+2)` with no `sp >= nKeys+2` check; the only depth check is at `:3025-3031`, after both reads). `stack_elem_ptr` (`asm/bitcoin_scriptcodec.asm:130-135`) is documented "No bounds check" and multiplies a negative index into a pointer below `main_elems`; `scriptnum_decode` (`:325-345`) then loops over the full garbage `len` field regardless of the overflow flag.
- Description: Core checks `(int)stack.size() < i` before each of the three reads (`i = 1`, then `i = nKeysCount + 2`, then `i += nSigsCount`) and returns `SCRIPT_ERR_INVALID_STACK_OPERATION`. Here `OP_16 OP_CHECKMULTISIG` on a stack of depth 1 reads the record at `main_elems - 17*528` (8,976 bytes before the buffer), and `OP_CHECKMULTISIG` on an empty stack reads `main_elems - 528`. The stacks are `malloc(528000)` buffers (`bmc_thread.h` `BMC_TLS_BUF`), i.e. mmap'd chunks; what precedes them depends on allocation order (in `sv_verify_script` it is `copy_e`; in `sv_verify_witness_v0` and the tapscript path it is whatever the allocator placed there).
- Failure scenario: any peer relays a spend of a P2WSH output whose witnessScript is `OP_16 OP_CHECKMULTISIG` with an empty initial stack (the attacker creates the output first; cost: dust). The verdict is always a failure (the later depth check or a garbage `SIG_COUNT`/`SCRIPTNUM` error), so there is no consensus divergence, but (a) the error code differs from Core's under policy flags, and (b) if the garbage `len` is large, `scriptnum_decode` reads `len` bytes from an address before the mapping — a SIGSEGV of the verifying worker if the preceding page is unmapped. The differential did not catch this because `tests/fuzz_script_diff.c:33` uses static `.bss` arrays surrounded by zeroed memory (garbage `len = 0` -> `nKeys = 0` -> the same `INVALID_STACK_OPERATION` Core reports).
- Core reference: `EvalScript` `OP_CHECKMULTISIG` arm, the three `if ((int)stack.size() < i)` checks.
- Suggested fix: insert `sp >= 1` before reading `n` and `sp >= nKeys + 2` before reading `m` (both `SCRIPT_ERR_INVALID_STACK_OPERATION`), and have `scriptnum_decode` stop accumulating past `maxsize` (or clamp `len` to 520) as defence in depth.
- Verdict: CONFIRMED (out-of-bounds read); crash PLAUSIBLE (depends on the heap layout of the verifying thread).
- Test coverage: none targets an under-populated CHECKMULTISIG stack.

##### SCR-8 (LOW) — `der_parse_sig` is stricter than Core's lax DER parser
- Location: `asm/bitcoin_script.asm:37-140`: byte 1 (sequence length) is ignored and `0x02` is required at offset 2; R/S lengths are taken as single raw bytes.
- Description: Core verifies ECDSA through `ecdsa_signature_parse_der_lax` (`src/pubkey.cpp`), which accepts long-form lengths (`0x81 xx`, `0x82 xx xx`) for the sequence and for each INTEGER (skipping leading zero length bytes, up to 3 significant bytes). Under `SCRIPT_VERIFY_DERSIG` (height >= 363,725) `der_sig_strict` runs first and both parsers agree on everything it lets through, so this only matters for pre-BIP66 blocks evaluated with `assumevalid=0`. A historical signature with a long-form length would be rejected here and accepted by Core.
- Failure scenario: replay of a pre-363,725 block containing such a signature stalls the node. No such signature is known to exist on mainnet; the project's earlier full archive replay would have hit it if it did.
- Core reference: `ecdsa_signature_parse_der_lax`, `src/pubkey.cpp`.
- Suggested fix: port the lax parser (sequence and integer long-form lengths, leading-zero skipping) or document the divergence in `FEATURE_GAPS.md`.
- Verdict: CONFIRMED (code divergence); impact PLAUSIBLE only.
- Test coverage: `tests/test_dersig_encoding.c` covers strict DER; nothing covers lax long-form.

##### SCR-9 (LOW) — Relay path runs consensus flags only; several policy rules missing
- Location: `asm/daemon/tx_verify.c:867` (`tx_verify_mempool` uses `script_flags_for_block(next_height, zero32)`), `asm/bitcoin_txval_modern.c:36` (`MV_WITNESS_FLAGS` = P2SH|DERSIG|NULLDUMMY|CLEANSTACK|CLTV|CSV|WITNESS). No production caller sets STRICTENC, LOW_S, NULLFAIL, MINIMALDATA, MINIMALIF, SIGPUSHONLY, CONST_SCRIPTCODE, WITNESS_PUBKEYTYPE, DISCOURAGE_UPGRADABLE_NOPS/WITNESS_PROGRAM/TAPROOT_VERSION/PUBKEYTYPE or DISCOURAGE_OP_SUCCESS. Of those, DISCOURAGE_UPGRADABLE_NOPS (`bitcoin_interp.asm:770-786` treats NOP1/4-10 as plain NOPs regardless of flags), DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM / TAPROOT_VERSION (`tx_verify.c:795`, `bitcoin_taproot_sighash.c:1039`), DISCOURAGE_UPGRADABLE_PUBKEYTYPE (`bitcoin_taproot_sighash.c:774-786`), WITNESS_PUBKEYTYPE (`interp_pubkey_encoding_ok`, `bitcoin_interp.asm:2733-2755`) and CONST_SCRIPTCODE's "OP_CODESEPARATOR in an unexecuted BASE branch" rule (Core interpreter.cpp:484-486; here `.not_push` at `:563-571` skips non-IF opcodes when not executing) are not implemented at all.
- Description / failure: the mempool accepts and relays transactions Core treats as non-standard (high-S signatures, non-minimal pushes, upgradable NOPs, uncompressed keys in segwit, unknown witness versions, OP_SUCCESS leaves, etc.). Not a consensus issue; a relay-policy divergence and a mild DoS surface (this node will forward such transactions to peers that will penalise nothing but drop them). The 2026-09-02 FEATURE_GAPS entry describing NULLFAIL/LOW_S/STRICTENC/CONST_SCRIPTCODE as "arrived in the interpreter" is accurate for the interpreter but they are unreachable from the daemon.
- Core reference: `STANDARD_SCRIPT_VERIFY_FLAGS` (policy/policy.h), `MemPoolAccept::PolicyScriptChecks`.
- Suggested fix: pass `STANDARD_SCRIPT_VERIFY_FLAGS` (minus what `acceptnonstdtxn` disables) on the mempool path and implement the missing DISCOURAGE_* arms.
- Verdict: CONFIRMED.
- Test coverage: `tests/test_interp_core_vectors`, `test_verify_core_vectors` exercise the flags directly against the interpreter; nothing tests the daemon's flag selection.

##### SCR-10 (INFO) — `tx_legacy_sigops` has no bounds checks
- Location: `asm/bitcoin_sigops.asm:123-306` (`r13 = len` is loaded and never compared; every varint and script walk indexes `r14` unconditionally).
- Description: both callers (`daemon/tx_accept.c:521` after its own full parse, `daemon/main.c:5693` on mempool-resident transactions) pass pre-validated transactions, so it is not reachable with malformed input today. It is the "a distant function already checked this" pattern the project's own comments warn about (`bitcoin_taproot_sighash.c` `ts_agg_hashes` note).
- Suggested fix: bound every read against `r12 + r13` and return 0 on overrun.
- Verdict: CONFIRMED (latent).
- Test coverage: `tests/test_sigops.c` (well-formed inputs only).

##### SCR-11 (INFO) — CONST_SCRIPTCODE check ordering for OP_CHECKSIG
- Location: `asm/bitcoin_interp.asm:2809-2827` runs `interp_sig_encoding_ok` and `interp_pubkey_encoding_ok` before the callback, which performs the FindAndDelete/`SIG_FINDANDDELETE` test (`bitcoin_scriptverify.c:186-193`). Core's `EvalChecksigPreTapscript` runs FindAndDelete first. Verdicts agree (both fail); only the reported error differs when a script trips both. Policy-only.
- Verdict: CONFIRMED.

#### Verified-correct controls

- Script size: `MAX_SCRIPT_SIZE` 10,000 applied to BASE/WITNESS_V0 only, skipped for tapscript (`bitcoin_interp.asm:396-404`), matching `EvalScript`.
- Push size 520 checked on every `GetOp` including unexecuted branches (`:476-479`); opcode count `> OP_16` for BASE/V0 only, `OP_RESERVED` not counted (`:483-495`); disabled opcodes rejected regardless of `fExec` (`:498-530`); `OP_VERIF`/`OP_VERNOTIF` fail inside unexecuted branches because they fall within the IF..ENDIF window (`:563-571` -> `.bad_opcode`); `OP_RESERVED`, `OP_VER`, `OP_RESERVED1/2`, `0xbb..0xff` are BAD_OPCODE when executed; `OP_NOP1/4-10` are no-ops (consensus-correct, `:770-786`); `OP_CHECKSIGADD` is BAD_OPCODE outside tapscript (`:2135-2139`); CHECKMULTISIG is `TAPSCRIPT_CHECKMULTISIG` in tapscript (`:2170-2175`).
- Tapscript `OP_SUCCESSx` table (`is_opsuccess`, `:2437-2477`) matches `IsOpSuccess`; the prescan runs before the initial-stack count/size limits in the taproot driver (`bitcoin_taproot_sighash.c:874-891, 1063-1073`), exactly Core's `ExecuteWitnessScript` order.
- `CScriptNum`: 4-byte default / 5-byte for CLTV/CSV (`SNUM_MAX` macro, `:190-197`), minimal-encoding rule under MINIMALDATA (`bitcoin_scriptcodec.asm:302-319`), sign handling (`:330-346`), serialisation (`:352-410`); `CastToBool` negative-zero (`:417-441`); `CheckMinimalPush` including the 0x81 case (`:596-644`); `GetOp` truncation checks (`:651-713`).
- Arithmetic results are proper 0/1 booleans (the SETcc/movzx fixes, `:1590-1596, 1687-1731`); `OP_WITHIN` `min <= x < max` (`:1799-1806`); `OP_PICK`/`OP_ROLL` `n < 0 || n >= size` (`:1276-1296`).
- MINIMALIF: unconditional under tapscript, gated on the flag under WITNESS_V0, absent under BASE (`:792-822`).
- CLTV (`:2240-2296`) mirrors `CheckLockTime` (threshold type match, `nLockTime > tx.nLockTime`, `SEQUENCE_FINAL`), CSV (`:2317-2361`) masks with `0x0040ffff`, checks the input's disable bit and type flag, operand disable bit tested on the low 32 bits only (the 2026-09-02 fix holds) — apart from SCR-4.
- CHECKMULTISIG: `nKeys` 0..20 with `SCRIPT_ERR_PUBKEY_COUNT`, `nOpCount += nKeys` re-check (`:2969-2975`), `nSigs` 0..nKeys, up-front FindAndDelete of every signature under BASE only with CONST_SCRIPTCODE error (`:3072-3120`), per-pair encoding checks inside the loop (`:3140-3155`), Core's NULLFAIL-then-NULLDUMMY precedence with SIG_DER taking priority (`:3170-3212`), pops `nKeys+nSigs+3`, CHECKMULTISIGVERIFY pop-or-fail (`:2193-2213`).
- OP_CODESEPARATOR sets `pbegincodehash` only when executed and records the BIP342 `codesep_pos` (`:2013-2028`), threaded to the tapscript checker via `interp_slice[2]`.
- Strict DER (`bitcoin_scriptcodec.asm:538-591`) is `IsValidSignatureEncoding` check-for-check with in-bounds argument; LOW_S bound and STRICTENC hashtype rule (`bitcoin_interp.asm:2665-2716`), pubkey encoding (`:2733-2755`), Core's error precedence SIG_DER > SIG_HIGH_S > SIG_HASHTYPE.
- `VerifyScript` shape (`bitcoin_scriptverify.c:329-392`): SIGPUSHONLY, scriptSig then scriptPubKey, stack copy for P2SH, push-only requirement, redeemScript from the copy, CLEANSTACK gated on the flag.
- Witness dispatch (`daemon/tx_verify.c:771-801`): P2TR only with the TAPROOT flag, otherwise v1 is "anyone can spend"; scriptSig must be empty for native programs (WITNESS_MALLEATED); P2SH-wrapped programs require exactly one minimal push whose hash160 matches (`bitcoin_witness_v0.c:134-151`, WITNESS_MALLEATED_P2SH); P2SH-wrapped v1 is NOT taproot (`is_p2sh` semantics) and passes as unknown version; witness on a non-witness script is rejected (WITNESS_UNEXPECTED); v0 programs of length other than 20/32 -> WRONG_LENGTH.
- Witness v0 driver (`bitcoin_witness_v0.c:175-214`): P2WPKH exactly 2 items and the implied `76a914..88ac` scriptCode; P2WSH witnessScript popped before the 520-byte item check; implicit cleanstack and CastToBool.
- BIP143 (`bitcoin_segwit.c:393-497`): hashPrevouts/hashSequence gated on ANYONECANPAY, hashSequence and hashOutputs gated on SINGLE/NONE, SINGLE with `nIn < nout` hashes only that output else zeros, scriptCode as compactsize+bytes, amount, nSequence, locktime, 4-byte hashtype, double-SHA256.
- Legacy sighash (`bitcoin_sighash.asm:658-1090`): SIGHASH_SINGLE out-of-range returns `uint256(1)` before any serialisation (`:747-773`), OP_CODESEPARATOR stripped at opcode boundaries (`:776-787`), ANYONECANPAY emits only `nIn`, NONE/SINGLE zero other inputs' sequences, SINGLE emits `nIn+1` outputs with `CTxOut()` (value -1, empty script) for `j < nIn`, hashtype appended as the raw 32-bit value; `parse_varint` LE accumulation is correct.
- BIP341 (`bitcoin_taproot_sighash.c:430-590`): hash_type validity (`<= 3 || 0x81..0x83`), SIGHASH_DEFAULT -> ALL, `sha_prevouts/amounts/scriptpubkeys/sequences` skipped for ANYONECANPAY, `sha_outputs` in place, `spend_type = ext_flag*2 + annex`, annex hash = SHA256(compactsize||annex), SIGHASH_SINGLE with `n_in >= nout` fails outright (the 2026-08-22 fix is intact), ext = tapleaf||key_version 0||codesep_pos.
- Taproot verify (`:945-1147`): annex only when >= 2 items and first byte 0x50; key path = exactly one remaining item; 64/65-byte Schnorr rule and 65-byte-with-0x00 rejection (`:610-616, 727-729`); control-block size 33 + 32k, k <= 128; merkle commitment run at every leaf version; internal key must parse; output-key parity bit checked; unknown leaf versions succeed; weight budget = serialised size of the FULL witness + 50, 50 per non-empty signature (`:1075-1079`, `:760-764`); initial-stack count and 520-byte checks; CLTV/CSV flags and real tx context (incident #16 fix holds); `hard_fail` sticky.
- `tap_merkle_root` (`secp256k1_taproot.asm:551-640`) orders `k`/`node` lexicographically as `ComputeTaprootMerkleRoot` (`repe cmpsb` computes node - k; `jb` -> node||k); `tap_leaf_hash` capacity is 4 MiB - 70 (`:255-262`), above any block-sized script.
- Flag schedule (`bitcoin_script_flags.asm:56-196`) equals `GetBlockScriptFlags`: P2SH|WITNESS|TAPROOT unconditional, DERSIG/CLTV/CSV/NULLDUMMY at 363725/388381/419328/481824, BIP16 exception -> 0, taproot exception -> P2SH|WITNESS; exception hashes generated from Core's `chainparams.cpp` and byte-reversed to internal order (`validation/gen_script_flags.py:144`); testnet4/signet/regtest heights generated likewise.
- Sigop counters (`bitcoin_sigops.asm:46-117`) match `CScript::GetSigOpCount` (accurate uses the immediately preceding OP_N, anything else resets to 20); the mempool's P2SH and witness sigop cost (`daemon/tx_accept.c:473-541`) follows `GetP2SHSigOpCount`/`CountWitnessSigOps`.
- `strip_witness` (C `bitcoin_segwit.c:296-380`, asm twin `bitcoin_strip_witness.asm`) produces the `SERIALIZE_TRANSACTION_NO_WITNESS` form; the legacy sighash is computed over it (`tx_verify.c:529-540`).
- Prior-audit items re-verified: the CSV `test rax, 0x80000000` sign-extension bug (audit N7) is fixed (`bitcoin_interp.asm:2330`); the 2026-09-02 policy arms (MINIMALDATA scriptnum, MINIMALIF code, 0x81 push, STRICTENC pubkey, NULLDUMMY precedence, NULLFAIL, LOW_S, CONST_SCRIPTCODE) are present in the interpreter.

#### Coverage and limits

- Not verified: the ECDSA/Schnorr/x-only-key primitives (`ecdsa_verify` rejecting r/s = 0 or >= n, `pubkey_parse`, `schnorr_verify`, `taproot_tweak_pubkey` on an invalid internal key) — the crypto reviewer's module. The findings above assume they are correct.
- The witness-item pool and per-input parsing in `daemon/tx_verify.c` (TXV_MAX_WIT_ITEMS, 500k-item inputs) and `bitcoin_txval_modern.c` were only read where the script dispatch touches them.
- Cross-module observation for the block-validation reviewer: no block-level transaction finality (`IsFinalTx`, `bad-txns-nonfinal`) or BIP68 sequence-lock (`SequenceLocks`, `bad-txns-nonfinal` for relative locks) enforcement was found in `daemon/utxo_live.c`, `daemon/tx_verify.c` or `bitcoin_cons.asm` (grep for `nonfinal|IsFinal|SequenceLock|prevheight|LOCKTIME_VERIFY_SEQUENCE` returns nothing). If that is right it is an accept-direction consensus gap at least as serious as SCR-6, and the same signed/unsigned `version` question as SCR-4 applies to it.
- The pre-BIP66 lax-DER question (SCR-8) could be settled by running `validation/spend_corpus_diff.py` over blocks below 363,725 with the oracle, which the harness already supports.
- Next steps I would take: extend `tests/fuzz_script_diff.c` to (a) sigversion 3 with a real-shaped checker, (b) scripts up to 20 KB with heavy TOALTSTACK/IF nesting, (c) `txv` drawn from the full 32-bit range; add the five shapes in SCR-1..5 as fixed vectors in `tests/test_interp_core_vectors` / `synth_corpus_diff.py`.


---

### 6.3 Transaction and block validation, headers, PoW, chain params — review

**Scope:**
- Fully read: `asm/bitcoin_tx.asm`, `asm/bitcoin_txv_parse.asm`, `asm/bitcoin_txv_dispatch.asm`, `asm/bitcoin_txv_classify.asm`, `asm/bitcoin_txval_modern.c`, `asm/bitcoin_verify.c`, `asm/bitcoin_cons.asm`, `asm/bitcoin_pow_rules.c/.h`, `asm/bitcoin_headers.asm`, `asm/daemon/tx_verify.c`, `asm/daemon/tx_accept.c`, `asm/daemon/chainparams.c`, `asm/daemon/signet.c/.h`, `asm/daemon/signet_block.c`, `asm/daemon/signet_verify.c`, `asm/daemon/minchainwork.c`, `asm/daemon/chainwork_build.c`, `asm/daemon/verify.c`, `asm/daemon/pverify.c`, `asm/daemon/check_chain.c`, `asm/daemon/block_witness.c`, `asm/daemon/block_strip.c`.
- Skimmed: `asm/bitcoin_txv_pools.asm` (arena twins), `asm/bitcoin_chainwork.asm` (header comment, `compact_to_target_le`, persistence functions; the 256-bit divider body was not re-derived).
- Read outside the module because the module's callers live there: `asm/daemon/utxo_live.c` 560-665 and 880-1330 (`apply_block_inner`, the only block-connect pipeline), `asm/daemon/utxo_walk.h`, `asm/daemon/main.c` 2905-3165 (boot header fetch) and 4975-5060 (submitblock), `asm/daemon/reorg.c` 395-560, `asm/bitcoind.asm` 1335-1500 and 1795-2000, `asm/bitcoin_serve.asm` 672-830 (`.do_block`), `asm/bitcoin_hash.asm` 105-262 (`diff_target`/`pow_check`), `asm/bitcoin_segwit.c` `strip_witness`.
- Core reference on disk: `/storage/bitcoin-core-source` (v31.99); constants and reason strings below were grepped there, not recalled.

**Summary:**
The script-verification half of block connection (tx_verify.c + its asm twins) is careful and Core-faithful: prevout classification, maturity, witness-program rules, taproot gating including the 692261 exception, the BIP141 commitment rule, BIP30's exact gate, and the nBits schedule (`pow_check_bits`) are all correct. The other half of Core's `CheckBlock` / `ContextualCheckBlock` / `ConnectBlock` is largely **absent**: the connect pipeline (`utxo_live.c:apply_block_inner`) never checks block weight, sigop cost, coinbase scriptSig length or null prevout, BIP34 height, subsidy/fee (`bad-cb-amount`), `MAX_MONEY` on inputs/outputs, `nLockTime`/BIP68 finality, header timestamp/version rules, or merkle mutation (CVE-2012-2459). A miner can therefore create coins and delete arbitrary UTXOs on this node; a non-mining peer can permanently stall UTXO tracking with a mutated copy of any new block, pollute the archive with zero-work blocks via the inbound push path, feed unchecked headers at boot, or crash a process with a wrapping CompactSize. README/FEATURE_GAPS claims about `MAX_MONEY` and "every non-script consensus rule" are wrong for the block path. Confidence in the findings is high (every path traced end to end); severity ordering is my judgement.

#### Findings

| ID | Severity | Location | Title | Verdict |
|----|----------|----------|-------|---------|
| VAL-1 | CRITICAL | `asm/daemon/utxo_live.c:1146-1305`, `asm/bitcoin_cons.asm:127-131` | Coinbase is never checked: no subsidy/fee cap, non-null prevout applied as an unverified spend, no scriptSig length, no BIP34 height | CONFIRMED |
| VAL-2 | CRITICAL | `asm/daemon/utxo_live.c:1146-1305`, `asm/daemon/utxo_walk.h:60-67` | No `MAX_MONEY` / value-range / `fee >= 0` check anywhere on the block-connect path | CONFIRMED |
| VAL-3 | HIGH | `asm/daemon/utxo_live.c:1146-1305` | No block weight / serialized-size / sigop-cost limits | CONFIRMED |
| VAL-4 | HIGH | `asm/daemon/utxo_live.c:1146-1305` | `nLockTime` / BIP68 finality (`bad-txns-nonfinal`) not enforced | CONFIRMED |
| VAL-5 | HIGH | `asm/daemon/main.c:2949-3012`, `asm/daemon/reorg.c:418-430`, `asm/daemon/utxo_live.c:1140` | Header timestamp (MTP / +2h) and version rules unenforced on the P2P/IBD path; boot header fetch stores headers with no PoW at all | CONFIRMED |
| VAL-6 | HIGH | `asm/bitcoin_cons.asm:172-182`, `asm/bitcoin_serve.asm:695-790`, `asm/daemon/main.c:5390-5397` | CVE-2012-2459 merkle mutation not detected: mutated block stored under the real hash, apply fails forever (zero-PoW permanent stall) | CONFIRMED |
| VAL-7 | HIGH | `asm/bitcoin_serve.asm:672-790`, `asm/bitcoin_hash.asm:195-250` | Inbound `block` push appends any block chaining to our tip under its own self-chosen nBits (no powLimit, no schedule, no header membership) | CONFIRMED |
| VAL-8 | HIGH | `asm/bitcoin_tx.asm:185-197, 311-314, 401-404, 543-577` | 64-bit CompactSize wrap moves the parse cursor before the buffer: remote SIGSEGV from an unsolicited `block` message | CONFIRMED |
| VAL-9 | HIGH | `asm/daemon/tx_verify.c:385-391` | Taproot spend with a co-input whose prevout scriptPubKey is >= 253 bytes is false-rejected (chain split on a valid block) | CONFIRMED |
| VAL-10 | MEDIUM | `asm/bitcoin_tx.asm:92-126`, `asm/daemon/tx_verify.c:239-245`, `asm/daemon/block_witness.c:63-77` | Blocks Core cannot deserialize are accepted: non-canonical CompactSize; marker+flag with all-empty witness stacks | CONFIRMED |
| VAL-11 | MEDIUM | `asm/bitcoin_hash.asm:116-172, 195-250` | `pow_check` has no powLimit / negative / overflow test; `diff_target` writes below its buffer for exponents > 34 | CONFIRMED |
| VAL-12 | LOW | `asm/daemon/chainparams.c:170` | testnet4 `min_chain_work_hex` is signet's value, not Core's | CONFIRMED |
| VAL-13 | LOW | `asm/daemon/signet.c:81-85`, `asm/daemon/signet_block.c:204` | Truncated push inside the commitment script: Core truncates and continues, this node rejects the block | CONFIRMED |
| VAL-14 | LOW | `asm/daemon/main.c:4992-5017` | submitblock pre-check uses mainnet-only retarget (no testnet4 min-difficulty / BIP94) before the dry run | CONFIRMED |
| VAL-15 | LOW | `asm/daemon/tx_accept.c:377`, `asm/daemon/block_strip.c:51`, `asm/daemon/signet_block.c:128`, `asm/daemon/utxo_walk.h:53` | Residual `sl + 4` wraps of the incident-#36 class | CONFIRMED (bounded) |
| VAL-16 | INFO | `README.md:26-28`, `docs/FEATURE_GAPS.md:561-563, 1998-2004`, `asm/bitcoin_txv_dispatch.asm:188-196` | Documentation contradicts the code; asm dispatch twin lacks the assumevalid gate (test-only) | CONFIRMED |

##### VAL-1 (CRITICAL) — Coinbase is never checked: no subsidy/fee cap, non-null prevout applied as an unverified spend, no scriptSig length, no BIP34 height
- Location: `asm/bitcoin_cons.asm:127-131` (only `n_in == 1` is required of tx 0); `asm/daemon/utxo_live.c:1276-1281` (`tx_verify_block_connect_all` starts at t=1, `tx_verify.c:1485`); `asm/daemon/utxo_live.c:581-583` (`live_on_input` skips only the exact null outpoint, otherwise `undo_capture_and_del`s whatever tx 0 references); `asm/daemon/utxo_live.c:625-645` (`live_on_output` puts any value).
- Description: Core's `CheckTransaction` (consensus/tx_check.cpp:50) requires the coinbase scriptSig to be 2..100 bytes and `vin[0].prevout.IsNull()` (`bad-cb-length`/`bad-cb-missing`, validation.cpp:3968); `ContextualCheckBlock` requires the BIP34 height push at height >= 227931 (`bad-cb-height`, validation.cpp:4173); `ConnectBlock` requires `vout total <= fees + GetBlockSubsidy` (`bad-cb-amount`, validation.cpp:2623). None of these exist here. There is no subsidy function on the connect path at all (`gbs_subsidy` in rpc_chain.c serves only RPC). The whole-block duplicate-outpoint pass and the in-block index skip the null outpoint, so a non-null coinbase prevout is never looked at by any verifier, but Phase 5 deletes it from the UTXO set.
- Failure scenario: a miner produces a block whose coinbase (a) pays itself 1,000,000 BTC, and/or (b) has `vin[0].prevout` = any existing UTXO (e.g. a large exchange output). This node: `cons_verify` passes (n_in==1), no verifier touches tx 0, Phase 5 `undo_capture_and_del` removes that UTXO and `utxo_lsm_put` creates the inflated outputs. Core rejects the block. The node follows a chain no Core node accepts, with a UTXO set that has both destroyed a third-party coin and minted new ones.
- Core reference: `CheckTransaction` (tx_check.cpp), `CheckBlock` "bad-cb-missing", `ContextualCheckBlock` "bad-cb-height", `ConnectBlock` "bad-cb-amount" / `GetBlockSubsidy`.
- Suggested fix: in `apply_block_inner` Phase 0, after `tx_parse` of tx 0: require null prevout (all-zero hash, index 0xffffffff), scriptSig length in [2,100], BIP34 height push (chain-specific `BIP34Height`, `script_flags_consts.inc` already carries the height), and reject any later tx with a null prevout. Sum every non-coinbase tx's (inputs − outputs) during Phase 1 (the resolver already yields every input value) and enforce `cb_out <= fees + subsidy(height, halving_interval)` with Core's `halvings >= 64 -> 0` rule.
- Verdict: CONFIRMED.
- Test coverage: none. `test_cons.c` pins only "non-coinbase-first" (n_in != 1). `validation/consensus_diff.py` mutations (`mutations()` at line 128) never touch coinbase amount, prevout or scriptSig.

##### VAL-2 (CRITICAL) — No `MAX_MONEY` / value-range / `fee >= 0` check on the block-connect path
- Location: `asm/daemon/utxo_walk.h:60-67` (raw `u64 value` handed to `live_on_output`), `asm/daemon/utxo_live.c:625-645`, `asm/daemon/tx_verify.c:1379-1385` (values are cached in `in->value` but never summed or compared).
- Description: The only `MAX_MONEY` logic in the tree is `bitcoin_txval_modern.c:203-205` (`mv_parse`), which `tx_accept.c` explicitly retired from the accept path ("stays only for its vector tests", `tx_accept.c:326-331`). Nothing on the block path checks `0 <= nValue <= MAX_MONEY`, the running output total, the input total (`bad-txns-inputvalues-outofrange`, tx_verify.cpp:187), or `value_in >= value_out` (`bad-txns-in-belowout`, tx_verify.cpp:197). README line 27 and FEATURE_GAPS 561-563 ("now matching Core, verified against 1,172 real mainnet transactions") describe the mempool parser, not consensus.
- Failure scenario: a mined block contains a valid-signature tx spending 1 BTC and creating outputs totalling 21,000,000 BTC (or one output of 2^63+ satoshi, which is negative to Core and `bad-txns-vout-negative`). Scripts verify, so `tx_verify_block_connect_all` accepts; Phase 5 stores the outputs. Core rejects. Chain split with inflation on this node. Secondary: the `u64` running total can wrap in `live_on_output` callers (e.g. coinstats), and values >= 2^63 enter the LSM.
- Core reference: `CheckTransaction` (vout-negative / vout-toolarge / txouttotal-toolarge), `Consensus::CheckTxInputs` (inputvalues-outofrange, in-belowout, fee MoneyRange).
- Suggested fix: per-output and running-total `MoneyRange` in Phase 0 (a 10-line addition to the `utxo_walk_tx_io` output loop), and per-tx `sum(in) >= sum(out)` with `MoneyRange` on both sums in Phase 1 (`txvb_classify` already receives `value`); accumulate fees for VAL-1.
- Verdict: CONFIRMED.
- Test coverage: `tests/live_money_range_chain.c` and the unit test drive `mv_test_parse` (the retired mempool parser); nothing drives the block path.

##### VAL-3 (HIGH) — No block weight / serialized-size / sigop-cost limits
- Location: `asm/daemon/utxo_live.c:1101-1305` (no size accounting anywhere); `asm/bitcoin_cons.asm` (only a per-txid scratch cap). The only `4000000` in the node is the P2P frame cap (`bitcoin_net.asm:71`) and GBT (`rpc_chain.c:122`).
- Description: Core rejects `GetBlockWeight(block) > MAX_BLOCK_WEIGHT` (validation.cpp:4196), `nSigOpsCost > MAX_BLOCK_SIGOPS_COST` (validation.cpp:2581, using `GetTransactionSigOpCost` with P2SH/witness accounting), and the base-size pre-check in `CheckBlock` (:3993 `bad-blk-sigops` legacy count). The P2P frame cap of 4,000,000 bytes bounds the *serialized* size but is not the weight rule (a 3.9 MB block with 1.5 MB of non-witness bytes has weight > 6M) and there is no sigop accounting at all (`tx_legacy_sigops`/`script_sigops_accurate` exist for policy only, `tx_accept.c:455-520`).
- Failure scenario: a mined block of weight 6,000,000 or with 200,000 sigops is accepted here and rejected by Core; chain split.
- Core reference: `ContextualCheckBlock` "bad-blk-weight", `ConnectBlock` "bad-blk-sigops", `MAX_BLOCK_WEIGHT`, `MAX_BLOCK_SIGOPS_COST`, `WITNESS_SCALE_FACTOR`.
- Suggested fix: compute `3*stripped_size + total_size` in Phase 0 (stripped length = `strip_witness` length or `tx_len − witness bytes`, both already parsed) and reject > 4,000,000; add `GetTransactionSigOpCost` using the existing policy walkers with the prevout scripts Phase 1 already resolves.
- Verdict: CONFIRMED.
- Test coverage: none.

##### VAL-4 (HIGH) — `nLockTime` / BIP68 finality not enforced
- Location: `asm/daemon/utxo_live.c:1101-1305`, `asm/daemon/tx_verify.c` (nowhere reads `locktime`/`sequence` except through the CLTV/CSV opcodes in `bitcoin_interp.asm:2264-2350`).
- Description: Core's `ContextualCheckBlock` rejects any tx that is not `IsFinalTx(tx, height, MTP)` (validation.cpp:4163) and `ConnectBlock` rejects BIP68 `SequenceLocks` failures for version >= 2 txs at/after CSVHeight (validation.cpp:2569). Here the transaction-level rules do not exist; only the script opcodes are implemented, and those only run when a script uses them.
- Failure scenario: a mined block includes a tx with `nLockTime = height + 100` and a non-final `nSequence` on some input (or a v2 tx with a relative lock of 1000 blocks against a fresh prevout). Signatures are valid; this node accepts, Core rejects. Chain split.
- Core reference: `IsFinalTx`, BIP113 (MTP as the time reference), BIP68 `CalculateSequenceLocks`/`EvaluateSequenceLocks`.
- Suggested fix: Phase 1 already resolves every prevout's creation height; add MTP computation from `g_bip30_store` headers (the same `powr_hdr_from_store` reader), then per tx `IsFinalTx` and, for version >= 2 above CSVHeight, BIP68 with `SEQUENCE_LOCKTIME_DISABLE_FLAG/TYPE_FLAG/MASK` and the 512-second granularity (prevout MTP for time-based locks).
- Verdict: CONFIRMED.
- Test coverage: none.

##### VAL-5 (HIGH) — Header timestamp/version rules unenforced on the P2P/IBD path; boot header fetch stores headers with no PoW
- Location: `asm/daemon/main.c:2949-3012` (`dlc_fetch_headers`: continuity + overlap identity only, then `hst_append`); `asm/daemon/reorg.c:418-430` (`headers_chain_valid`: PoW + linkage) and `:511-522` (nBits schedule) — no time/version; `asm/daemon/utxo_live.c:1140-1145` (only `bad-diffbits`); `asm/daemon/main.c:5005-5021` (time rules exist only for submitblock).
- Description: Core's `ContextualCheckBlockHeader` rejects `nTime <= MTP(prev)` ("time-too-old", :4109), `nTime > now + 2h` ("time-too-new", :4125) and legacy `nVersion` below the BIP34/66/65 thresholds ("bad-version", :4132); `CheckBlockHeader` rejects headers failing PoW before anything is stored. Here the boot/catch-up header phase writes whatever a peer sends to `headers.dat` (positional by height) after checking only that it links; PoW is never evaluated on that path (`pow_check` is called only from `reorg.c` and `cons_verify`). The first live peer answering `getheaders` can append up to 2,000 headers × 1,000 rounds of garbage above our tip. Nothing later truncates headers that never get a block (`dlc_headers_rollback` runs only inside the same fetch), so the block downloader requests hashes no one has and the sync stalls until an operator intervenes.
- Failure scenario (headers): a malicious peer among the first `DLC_HDR_TRY_PEERS` at boot serves our tip + 500 fabricated headers with random nonces. All 500 are stored. Block download for tip+1 never succeeds. Zero PoW cost. (Timestamps): a miner produces a block with `nTime = MTP − 1000` or `now + 3h`; this node connects it, Core rejects it.
- Core reference: `CheckBlockHeader`, `ContextualCheckBlockHeader`, `CBlockIndex::GetMedianTimePast`, `MAX_FUTURE_BLOCK_TIME`.
- Suggested fix: in `dlc_fetch_headers`, run `pow_check` and `pow_check_bits` (the chain rules are already registered in `utxo_live`/`reorg`) plus the MTP/2h/version checks per header before `hst_append`; add the same three contextual checks to `apply_block_inner` next to the `bad-diffbits` gate and to `reorg_analyze`.
- Verdict: CONFIRMED.
- Test coverage: `tests/fakepeer_headers.c` / `test_ibd_headers.c` exercise continuity; nothing feeds a bad-PoW or bad-time header to the boot path.

##### VAL-6 (HIGH) — CVE-2012-2459 merkle mutation not detected; a mutated block is stored under the real hash and stalls UTXO tracking permanently
- Location: `asm/bitcoin_cons.asm:172-182` (merkle compare only); `asm/bitcoin_hash.asm` `merkle_root` duplicates the odd trailing node with no mutation flag; storage happens before connect in both receive paths (`asm/bitcoin_serve.asm:695-790`, `asm/bitcoind.asm:1815-1840`); rejection handling `asm/daemon/main.c:5390-5397` ("recovery refused ... will retry from the checkpoint").
- Description: Core computes `BlockMerkleRoot(block, &mutated)` and rejects with `bad-txns-duplicate` (validation.cpp:3872) *without* marking the hash invalid, so the genuine block can still be accepted later. Here, a block `[A,B,C,C]` has the same root as `[A,B,C]`, passes `cons_verify` (tx-count field matches the walk), passes the hash guard (same header), and is appended to the archive under the real hash. `apply_block_inner` then fails on `bad-txns-inputs-duplicate` (utxo_live.c:1269), which is classified as a consensus reject; the daemon retries the same stored block on a backoff forever and the genuine block, when it arrives, is dropped as a duplicate hash (`serve.asm:719-724`).
- Failure scenario: an attacker with one inbound connection (or as the peer serving our block download) relays, for each new block, a copy with its last transaction duplicated, racing the honest copy. No mining. UTXO tracking halts at that height ("DEGRADED"), indexes and mempool reconciliation stop, and the archive holds a block Core would never have stored.
- Core reference: `CheckBlock` "bad-txns-duplicate", `BlockMerkleRoot(mutated)`, `merkle.cpp` mutation detection (equal adjacent hashes at any level).
- Suggested fix: detect the mutation in `merkle_root` (or in `cons_verify` before it: at every level, if `hash[i] == hash[i+1]` for an even i, fail) and refuse to store; also make a consensus reject of a stored block re-fetch the body from another peer rather than retry the same bytes.
- Verdict: CONFIRMED.
- Test coverage: none (`consensus_diff.py` mutations are byte flips, not tx duplication).

##### VAL-7 (HIGH) — Inbound `block` push appends any block chaining to our tip under its own self-chosen nBits
- Location: `asm/bitcoin_serve.asm:672-790` (`.do_block`: `cons_verify` → hash unknown → `store_validates_prevhash` → `idxscan_append_locked`); `asm/bitcoin_hash.asm:195-250` (`pow_check` compares the hash only against the header's own target).
- Description: The inbound path never consults `headers.dat`, never runs `pow_check_bits`, and `pow_check` has no `powLimit` bound (VAL-11). So a header with `nBits = 0x207fffff` (target 2^255) satisfies PoW with the first nonce tried. If its prevhash is our tip hash and its hash is new, the block is written to the archive at tip+1. Core's `ProcessNewBlock` would fail `CheckProofOfWork` (target > powLimit) and `ContextualCheckBlockHeader` (`bad-diffbits`) before storing anything.
- Failure scenario: any inbound peer sends such a block at zero cost. The archive gains a bogus tip; `apply_block_inner` rejects it (`bad-diffbits`, utxo_live.c:1144) and the daemon enters the same retry-forever loop as VAL-6. Whether the reorg machinery later displaces the bogus tip when the real block arrives was not traced end to end (PLAUSIBLE that it self-heals via cumulative work; the UTXO stall is CONFIRMED regardless), and the attacker can repeat at every height.
- Core reference: `CheckProofOfWork`, `ContextualCheckBlockHeader`, `AcceptBlockHeader` (a block body is only accepted for a header already validated and indexed).
- Suggested fix: require the pushed block's header to already be the next entry in `headers.dat` (or run `pow_check_bits` + time rules against the store) before `idxscan_append_locked`; add the `powLimit` comparison to `pow_check`.
- Verdict: CONFIRMED (storage and stall); PLAUSIBLE (self-heal).
- Test coverage: none for an unsolicited block with off-schedule nBits.

##### VAL-8 (HIGH) — 64-bit CompactSize wrap in `tx_parse`/`tx_txid` moves the cursor before the buffer: remote SIGSEGV
- Location: `asm/bitcoin_tx.asm:185-197` (`lea rbx,[r9+r15]; cmp rbx,r11; ja .fail` with `r15` from an 8-byte `0xff` varint), likewise `:311-314` (output script), `:401-404` (witness item), and `tx_txid` `:543-577`. Unbounded 1-byte varint reads at `:93`, `:152`, `:216`, `:268` (`mov eax,[r9]` without `r9 < r11`).
- Description: With `scriptlen = 2^64 − K`, `r9 + r15` wraps to `r9 − K`, which is `<= end`, so both bounds pass and the cursor becomes `r9 − K + 4`. For large K the next read (`mov eax,[r9]` at `:216`) faults; for small K the parser walks backwards over earlier bytes and returns a `tx_len` that `cons_verify` adds to `idx` (`bitcoin_cons.asm:123-126`, itself a wrapping add). The C parsers were fixed for this class (incident #36, `tx_verify.c:487-492`), but `tx_parse` — the front-line parser run by `cons_verify` on every received block, in the serve child on any unsolicited `block` message and in the download worker — was not.
- Failure scenario: an inbound peer sends `block` = header with `nBits=0x207fffff` (passes `pow_check`, VAL-11) + one tx whose first input scriptlen is `ff 00 00 00 00 00 ff ff ff` (−2^40). `cons_verify` runs before the hash guard (`serve.asm:686-695`); `tx_parse` dereferences `buffer − 2^40` and the serve child dies with SIGSEGV. Repeating costs nothing. On the outbound path the same message from the download peer kills the download worker.
- Core reference: `ReadCompactSize` with `MAX_SIZE` (32 MiB) range check (serialize.h:340-360).
- Suggested fix: bound-check every read (`cursor < end` before the 1-byte case) and use the subtraction form (`avail < sl || avail − sl < 4`) in all four loops of `tx_parse` and the two of `tx_txid`; additionally reject any CompactSize > `MAX_SIZE`.
- Verdict: CONFIRMED (by code reading; not executed against the live node per the brief).
- Test coverage: none. `tests/test_txv_cs_maxsize.c` covers only the C `txv_parse`; `test_tx.c`/`test_cons.c` have no wrapping-length case.

##### VAL-9 (HIGH) — Taproot spend with a co-input prevout scriptPubKey >= 253 bytes is false-rejected
- Location: `asm/daemon/tx_verify.c:385-391` (`if (sl >= 0xfd) { *reason = "prevout script too large for taproot aggregate sighash"; return 0; }`) and `:427-433`; the packed array format `sp[w++] = (u8)sl` feeds `taproot_verify_input`.
- Description: BIP341's `sha_scriptpubkeys` is over each prevout `scriptPubKey` serialized as a `CScript` (CompactSize length + bytes). The aggregate arena encodes the length in one byte and refuses anything >= 253 instead of emitting a 3-byte CompactSize. Any consensus-valid scriptPubKey up to `MAX_SCRIPT_SIZE` may be spent; e.g. a bare `1-of-8` multisig with uncompressed keys is 531 bytes, and any OP_DROP-padded script is minable.
- Failure scenario: a miner includes a tx spending a P2TR output and a 300-byte bare-multisig output. Core: valid. This node: block rejected, the chain stalls on a valid block (chain split in the false-reject direction).
- Core reference: BIP341 `sha_scriptpubkeys`, `PrecomputedTransactionData::Init`.
- Suggested fix: size the packed array with `cs_size(sl) + sl` and write a CompactSize prefix; update `secp256k1_taproot.asm`/`bitcoin_taproot_sighash.c` to read a CompactSize (the mempool-only `txval_modern.c:349-350` has the same limit and can share the fix).
- Verdict: CONFIRMED.
- Test coverage: none; not listed in FEATURE_GAPS.

##### VAL-10 (MEDIUM) — Blocks Core cannot deserialize are accepted: non-canonical CompactSize; witness marker with all-empty stacks
- Location: `asm/bitcoin_tx.asm:92-126` and every varint decoder in the block path (`tx_verify.c:239-245` `txv_rd_cs`, `txv_parse.asm` `RDCS`, `block_witness.c:12-20`, `utxo_walk.h`) accept `fd 01 00` for 1; `block_witness.c:63-77` sets `has_witness` only for a non-empty stack; `strip_witness` (`bitcoin_segwit.c:302+`) accepts empty stacks and re-serializes canonically.
- Description: Core's `ReadCompactSize` throws `non-canonical ReadCompactSize()` (serialize.h:345-357) and `UnserializeTransaction` throws `Superfluous witness record` (transaction.h:230) when marker+flag are present but every stack is empty; such a block message is unparseable to Core and the block can never be accepted by the network. Here both parse cleanly; txids are computed over the verbatim bytes so the merkle root can be made to match, and a legacy-input tx with an empty witness section still verifies via `legacy_tx_view`. Only the signet solution (`signet.c:175-190`) and `bitcoin_strip_witness.asm` insist on canonical encodings.
- Failure scenario: a miner produces a block containing one tx whose `n_in` is encoded as `fd 01 00`, or a legacy-input tx with `00 01` marker and `00` witness stacks. This node follows it; every Core node rejects the message.
- Core reference: `ReadCompactSize`, `UnserializeTransaction` (`Superfluous witness record`, `Unknown transaction optional data`).
- Suggested fix: make the shared varint readers reject non-canonical encodings and `> MAX_SIZE`; in `bw_walk_tx`, reject a segwit-marked tx with all-empty stacks.
- Verdict: CONFIRMED.
- Test coverage: none.

##### VAL-11 (MEDIUM) — `pow_check` has no powLimit / negative / overflow test; `diff_target` writes below its buffer
- Location: `asm/bitcoin_hash.asm:116-172` (`diff_target`: `r9 = target+31−(exp−3)`, then up to 3 byte writes downward with no lower bound), `:195-250` (`pow_check` compares hash vs the header's own target only).
- Description: Core `CheckProofOfWorkImpl` fails on `fNegative || bnTarget == 0 || fOverflow || bnTarget > powLimit`. Here a header with exponent 0x20+ or a mantissa with bit 23 set yields an enormous target; exponents >= 35 make `diff_target` write 1-3 bytes below `target_be` into `hash_be` and, for exponents near 0xff, ~220 bytes below the frame (below rsp, so a stack scribble rather than a control-flow corruption). `bitcoin_chainwork.asm:compact_to_target_le` already fixed the same routine with bounds checks, so the two copies have drifted. This is what makes VAL-7 and VAL-8 zero-cost.
- Failure scenario: see VAL-7/VAL-8; independently, the OOB write is a latent memory-safety defect on an attacker-controlled header.
- Core reference: `CheckProofOfWork`, `arith_uint256::SetCompact`.
- Suggested fix: reuse `compact_to_target_le`'s bounded conversion in `pow_check`, reject mantissa bit 23, exponent > 34, zero target, and compare against `g_chainp->pow_limit_bits`.
- Verdict: CONFIRMED.
- Test coverage: `tests/live_pow.c`/`test_pow_rules.c` cover the schedule with real headers; no hostile-nBits case.

##### VAL-12 (LOW) — testnet4 minimum chain work is signet's value
- Location: `asm/daemon/chainparams.c:170` (`"...0b463ea0a4b8"`, identical to the signet default at `:193`). Core v31.99 `kernel/chainparams.cpp:366` testnet4 = `0000000000000000000000000000000000000000000009a0fe15d0177d086304`; `:457` signet = `...0b463ea0a4b8`.
- Failure scenario: the testnet4 anti-DoS floor is ~4×10^9 times lower than Core's; a low-work testnet4 fork clears `reorg_work_meets_minimum` when it should not. No mainnet effect.
- Suggested fix: paste Core's testnet4 value; add the three floors to `test_chainparams.c` against the Core source (the file already has the Core tree available).
- Verdict: CONFIRMED.
- Test coverage: `test_chainparams.c` asserts genesis hashes, not the work floors.

##### VAL-13 (LOW) — Signet: a truncated push in the commitment script is a hard reject here, a silent truncation in Core
- Location: `asm/daemon/signet.c:35-52, 81-85` (`script_next` returns −1 on a truncated push, `signet_extract_solution` returns −1) → `signet_block.c:204` `bad-signet-commitment-malformed`. Core `FetchAndClearCommitmentSection` loops `while (GetOp(...))`; a failing `GetOp` ends the loop and, if a header was already found, the truncated tail is simply dropped from `replacement`.
- Failure scenario: a signet signer whose coinbase commitment output ends with a dangling `0x4d 0xff 0xff` after a valid solution push: Core validates the signature over the truncated script; this node rejects the block. Signer-controlled only; default-signet operators would not produce it.
- Suggested fix: on `script_next < 0`, stop the loop instead of failing, matching `GetOp` semantics.
- Verdict: CONFIRMED.
- Test coverage: `test_signet_*` use real and generated vectors; no truncated-push vector.

##### VAL-14 (LOW) — submitblock pre-check uses a mainnet-only retarget before the chain-aware dry run
- Location: `asm/daemon/main.c:4992-5003` (`rpc_chain_retarget(tip_bits, span)` with `(tip+1) % 2016` only; no min-difficulty walk-back, no BIP94 first-block base) ahead of `utxo_live_dryrun_block`, which does run `pow_check_bits` with the chain's rules.
- Failure scenario: on testnet4 a valid min-difficulty block (20-minute rule) submitted via `submitblock` is answered `bad-diffbits`; on a BIP94 boundary the expected bits differ. Mining-RPC only, no P2P effect.
- Suggested fix: delete the pre-check and rely on the dry run, or call `pow_expected_bits` with `g_chainp`'s rules.
- Verdict: CONFIRMED.
- Test coverage: `test_rpc_chain.c` retarget vectors are mainnet.

##### VAL-15 (LOW) — Residual `sl + 4` wraps of the incident-#36 class
- Location: `asm/daemon/tx_accept.c:377` (`txacc_tx_output`, resolving a package/mempool parent's output from peer-supplied bytes), `asm/daemon/block_strip.c:51` (`bs_tx_len`, own archive bytes), `asm/daemon/signet_block.c:128` (`find_commitment`), `asm/daemon/utxo_walk.h:53`.
- Description: `(end − p) < sl + 4` wraps for `sl` in `[2^64−4, 2^64−1]`, moving `p` back by 0..4 bytes. All four are bounded (no far-OOB) and the block-path ones are preceded or followed by a correct parser (`txvb_parse_tx`), so this is hygiene; `tx_accept.c:377` runs on a mempool parent that has already passed `tx_verify_mempool`, so a wrapping length cannot reach it in practice.
- Suggested fix: use the split form already used at `tx_verify.c:487`.
- Verdict: CONFIRMED (bounded).
- Test coverage: `test_txv_cs_maxsize.c` for the fixed sites only.

##### VAL-16 (INFO) — Documentation contradicts the code; asm dispatch twin lacks the assumevalid gate
- `README.md:26-28` claims consensus `MAX_MONEY` range checks; `docs/FEATURE_GAPS.md:561-563` says the CVE-2010-5139 shape is "now matching Core"; `:1998-2004` says "every non-script consensus rule [is] still checked for the whole chain". Per VAL-1..VAL-6 none of these hold on the block path. The 2026-08-29 audit finding 5 ("integer overflow in BTC amount parsing") was closed for the mempool/RPC parser only.
- `asm/bitcoin_txv_dispatch.asm:188-196` omits the `g_txv_script_checks` short-circuit that `tx_verify.c:1093` has; the twin is only driven by `tests/test_txv_dispatch_diff.c` (no production caller found), so no behavioural effect today, but the differential will diverge the first time it is run with assumevalid on.
- Verdict: CONFIRMED.

#### Verified-correct controls
- `pow_expected_bits` / `pow_retarget_bits` (`asm/bitcoin_pow_rules.c:117-182`): 40-byte multiply/divide with truncation, `[T/4, 4T]` clamp, powLimit cap, Satoshi's 2015-gap timespan, testnet4 20-minute exception and walk-back stopping at the period boundary, BIP94 first-block base, regtest `fPowNoRetargeting` — all match `pow.cpp` `GetNextWorkRequired`/`CalculateNextWorkRequired`. Wired at apply (`utxo_live.c:1140`) and fork evaluation (`reorg.c:519`).
- Chain params (`asm/daemon/chainparams.c`): mainnet/testnet4/signet/regtest `powLimit`, `fPowAllowMinDifficultyBlocks`, `enforce_BIP94`, halving intervals, mainnet and testnet4 `nMinimumChainWork` (mainnet only — see VAL-12), all three `defaultAssumeValid` hashes match Core v31.99 `kernel/chainparams.cpp`; genesis blocks are derived and hash-asserted at selection (`:263-304`); signet magic is `sha256d(CompactSize||challenge)[0..4]` (`:219-232`), matching `CSigNetParams`.
- BIP30 gate (`utxo_live.c:896-993`): exact Core semantics including the two hash-matched repeats, the BIP34-ancestor test resolved by hash, and the `>= 1,983,702` re-enforcement; fails closed when unresolvable.
- BIP141 commitment (`block_witness.c:84-114`): last matching `OP_RETURN 0x24 aa21a9ed` output, nonce exactly one 32-byte item, `sha256d(witness_root || nonce)` with coinbase wtxid 0, `unexpected-witness` when no commitment or segwit inactive; `segwit_active` derived from the NULLDUMMY flag bit (height 481824, `script_flags_consts.inc:20`), which is Core's `DeploymentActiveAfter(prev, SEGWIT)`.
- Per-input classification (`tx_verify.c:1385-1440`, twin `bitcoin_txv_classify.asm`): coinbase maturity `height − uheight >= 100`, `MAX_SCRIPT_SIZE` cap on prevout spk, taproot only when the TAPROOT flag is set (692261 exception via `script_flags_for_block`), P2SH-wrapped v1 treated as unknown-version pass, `p2wpkh` exactly 2 items, `p2wsh` non-empty, witness-program scriptSig must be empty, `SCRIPT_ERR_WITNESS_UNEXPECTED` for a witness on a non-program spk; legacy sighash over the witness-stripped view (`legacy_tx_view`).
- Whole-block duplicate-outpoint check before verification (`utxo_live.c:1252-1272`), and in-block chained spends resolve only against strictly earlier txs (`bidx_get`).
- assumevalid (`tx_verify.c:1010-1019`, `utxo_live.c:375-390`): skips only script evaluation; structural, maturity and UTXO checks still run; submitblock dry run forces checks on (`utxo_live.c:1330`).
- Signet (`signet.c`, `signet_verify.c`, `signet_block.c`): genesis exemption, `to_spend`/`to_sign` byte layouts (null outpoint index 0xffffffff, `OP_0 <72 bytes>`, witness marker only when the stack is non-empty), canonical solution parse with trailing-byte rejection, `BLOCK_SCRIPT_VERIFY_FLAGS` = P2SH|DERSIG|NULLDUMMY|WITNESS, unknown witness version accepted, witness on a non-program challenge rejected — all match `signet.cpp`.
- Chainwork (`bitcoin_chainwork.asm`): `work = (~target)/(target+1) + 1` exactly as `GetBlockProof`; `compact_to_target_le` bounds-checks the exponent; `minchainwork.c` byte-reverses Core's big-endian hex into the 16-byte LE accumulator and fails closed on an unrepresentable floor.
- Block-connect script verification is exercised by a large differential corpus against real Core (`fuzz_verify_diff`, `test_verify_core_vectors`, `consensus_diff.py`, 09-02/09-03 FEATURE_GAPS entries); prior-audit N1/N2 (false-accept history) are outside this module's remit and were not re-verified here.

#### Coverage and limits
- Not executed: none of the crash/DoS scenarios (VAL-6, VAL-7, VAL-8) were run against a binary, per the brief's prohibition on touching the live node; each is traced by reading every instruction on the path.
- Not re-derived: the `u256_div` restoring-division body in `bitcoin_chainwork.asm`, the SHA-NI merkle batching in `bitcoin_hash.asm`, and `bitcoin_verify.c`'s interpreter (no production caller of `verify_script` was found — it is an oracle for `test_verify_p2sh`; the live interpreter is `bitcoin_scriptverify.c`/`bitcoin_interp.asm`, owned by the script reviewer).
- Not traced: whether the reorg machinery displaces a zero-work tip appended by VAL-7 once the honest block arrives; how `main.c` reacts when the download worker dies (VAL-8) — restart semantics belong to the daemon reviewer.
- Next steps I would take: (1) write a `tests/test_block_rules.c` that feeds `apply_block_inner` (via `utxo_live_dryrun_block`) synthetic blocks for each of VAL-1..VAL-6 and VAL-10, since `consensus_diff.py`'s mutation list (`validation/consensus_diff.py:128-164`) contains none of these shapes; (2) extend `test_txv_cs_maxsize.c` to `tx_parse`/`tx_txid`; (3) a differential of `tx_parse` vs Core's deserializer over the corpus of non-canonical/superfluous-witness encodings; (4) pin chainparams work floors against `/storage/bitcoin-core-source`.


---

### 6.4 UTXO set (LSM store, memtable, WAL, compaction, snapshots, set-info) — review

**Scope:**
- Fully read: `asm/bitcoin_utxo_lsm.asm` (all 4374 lines), `asm/bitcoin_utxo_store.asm`, `asm/bitcoin_utxo.asm`, `asm/bitcoin_utxo_stats.asm`, `asm/utxo_lsm_mm.c`, `asm/utxo_snapshot.{c,h}`, `asm/daemon/utxo_live.c` (all), `asm/daemon/utxo_setinfo.c`, `asm/daemon/utxo_setinfo_rpc.c`, `asm/daemon/lsm_manifest.{c,h}`, `asm/daemon/lsm_state.h`, `asm/daemon/build_utxo.c`, `asm/daemon/flush_wal_tail.c`, `asm/daemon/build_migrate_compact.c`, `asm/daemon/utxo_reload_check.c`, `asm/daemon/utxo_repair_del.c`, `asm/daemon/utxo_dump_keys.c`, `asm/daemon/utxo_probe_one.c`, `docs/devlog/INCIDENT_2026-09-01_oom_and_resurrected_spends.md`.
- Skimmed: `asm/daemon/merge_only.c` (block-archive shard merger, not UTXO — misfiled in my list), `asm/daemon/undo_log.c` (only `undo_capture_and_del` and the append/fsync story), `asm/daemon/coinstats_index.c` (only `csi_on_remove`/`csi_serialize`), `asm/daemon/main.c` (recovery call site 5355-5400, `reap_children`, worker signal setup, txoq service), `asm/rpc_chain.c` `cmd_gettxoutsetinfo`, `asm/tests/test_compact_manifest_order.c`, the Makefile link rules, Core `compressor.cpp`, `kernel/coinstats.cpp`, `script.h`, `coins.cpp`.
- Not read: the other 50+ UTXO tests beyond their names/greps; `asm/validation/diff_utxo_setinfo.py` beyond its header.
- Two scratchpad-only test programs were compiled against the repo's existing `.o` files (nothing in the repo modified) to confirm UTX-1, UTX-2 and UTX-3 empirically; sources under `scratchpad/utxtest/`.

**Summary:** The store's basic machinery is sound and unusually well-commented: run files are sorted and Bloom-gated with identical hashing on both write and read paths, the manifest is published tmp+fsync+rename+dir-fsync after the run is fsynced and the WAL is truncated only after that, the memtable's probes are bounded, and the incident-2026-09-01 fix (absent coin at apply => block fails, lookup-free rollback, sticky halt, gated recovery) is complete for the apply path. I found three confirmed defects of the same "resurrected/lost coin" family the incident belongs to, all reachable without an adversary: (1) the k-way merge used by compaction AND by the ground-truth walk breaks ties by *generation*, but a partial prefix compaction gives the merged run a generation above its newer survivors, so a second compaction resurrects every coin whose tombstone sits in a survivor and the walk counts it live immediately (proven with a 65-run repro); (2) `utxo_live_init` accepts the reload's `-2` (memtable filled during WAL replay) as success, after which the first put flushes the truncated memtable and truncates the WAL — permanent loss of every record past the fill point, reachable by any unclean stop late in a bulk catch-up; (3) `utxo_lsm_put` returns `0xFFFFFFFF` instead of `-1` on a WAL drain failure, so `live_on_output` silently drops the coin. Beyond these: the checkpoint is fsynced but the WAL and undo files it certifies are not (power-loss inversion), a failed manifest publish during background-compaction adoption deletes the only copy of the merged run, and an unreadable/oversized manifest is silently treated as empty. Confidence is high on UTX-1..3 (executed), high on UTX-4..6 (traced end to end), lower on the snapshot-format item.

#### Findings

| ID | Severity | Location | Title | Verdict |
|---|---|---|---|---|
| UTX-1 | HIGH | `asm/bitcoin_utxo_lsm.asm` ~3520-3525 (`out_gen = next_gen`), ~3810-3832 (`.cc_find_loop` tie), ~3215-3237 (`.rc_find` tie) | Gen-based tie-break resurrects spent coins after a partial prefix compaction; walk/recount count them live | CONFIRMED (repro) |
| UTX-2 | HIGH | `asm/daemon/utxo_live.c:463-467`, `asm/bitcoin_utxo_lsm.asm` ~2440 (`cmp rax,-1` after `utxo_store_reload`), ~2530 (`.rl_wal_del` overflow) | Reload with a memtable smaller than the WAL tail is accepted as success; first flush makes the truncation permanent; tombstone rescan truncates silently | CONFIRMED (repro) |
| UTX-3 | MEDIUM | `asm/bitcoin_utxo_lsm.asm` ~1105 (`mov r14d, eax`) / ~1129 (`mov eax, r14d`); `asm/daemon/utxo_live.c:702`, :1509 | `utxo_lsm_put` returns 4294967295, not -1, on a WAL write failure; callers compare against -1 and drop the coin silently | CONFIRMED (repro) |
| UTX-4 | MEDIUM | `asm/daemon/utxo_live.c:543-567` (`persist_applied_height`), `asm/bitcoin_utxo_store.asm` (`mac_wr_log`, `utxo_store_reload` `.rep_close`), `asm/daemon/undo_log.c:93` | Checkpoint fsynced before the WAL/undo data it certifies; torn WAL tail is never truncated on reload | CONFIRMED |
| UTX-5 | MEDIUM | `asm/daemon/lsm_manifest.c` `lsm_manifest_adopt_child` (commit-then-publish), `asm/daemon/utxo_live.c:249-255` | Adoption publish failure unlinks the merged run the in-memory manifest now depends on | CONFIRMED |
| UTX-6 | MEDIUM | `asm/bitcoin_utxo_lsm.asm` ~2385-2400 (`.rl_manifest_bad`, `ja .rl_manifest_bad` on `manifest_n > cap`) | Unreadable or over-capacity manifest is silently treated as absent (empty run set), reload reports success | CONFIRMED |
| UTX-7 | LOW | `asm/utxo_snapshot.c:96-98` | dumptxoutset compresses uncompressed P2PK without Core's `IsFullyValid` gate; file may be unloadable by Core | PLAUSIBLE |
| UTX-8 | LOW | `asm/bitcoin_utxo_lsm.asm` `.fl_finish_reset` (~2355-2368) | WAL `ftruncate`/`lseek` results unchecked after a flush | CONFIRMED |
| UTX-9 | LOW | `asm/utxo_lsm_mm.c:298-330`, `asm/bitcoin_utxo_lsm.asm` `.ml_scan_loop` | Record scan not bounded by `nrec`/`sparse_off`; walks into the sparse-index trailer | CONFIRMED |
| UTX-10 | LOW | `asm/daemon/utxo_live.c:1521-1523` (`del_created_on_output`) | Disconnect/rollback still gates a delete on a point lookup — the incident's shape, un-halted | CONFIRMED (shape) |
| UTX-11 | INFO | `asm/daemon/utxo_dump_keys.c:24` | Tool re-implements `IsUnspendable` with the empty-script case inverted | CONFIRMED |
| UTX-12 | INFO | `asm/bitcoin_utxo_lsm.asm` `.rl_recount` | Any non-empty WAL tail at boot forces a full k-way recount (minutes on mainnet) | CONFIRMED |
| UTX-13 | INFO | `asm/daemon/flush_wal_tail.c:106-110` | Stale comment about `utxo_lsm_del` returning 0xFFFFFFFF (now fixed in the asm); the same defect survives in `utxo_lsm_put` (UTX-3) | CONFIRMED |

##### UTX-1 (HIGH) — Gen-based tie-break resurrects spent coins after a partial prefix compaction
- Location: `asm/bitcoin_utxo_lsm.asm`: `utxo_lsm_compact` assigns the merged run `out_gen = [lst+96]` (fresh `next_gen`, ~line 3520, and the header comment "compaction's merged run adopts a FRESH gen"); `.cc_find_loop` (~3810-3832) and `mac_lsm_recount`'s `.rc_find` (~3215-3237) break equal-key ties with "this wins only if `this.gen > best.gen`"; `.cc_shift_loop` (~3970) places the merged entry at index `lo` below the survivors.
- Description: `utxo_lsm_get` orders runs by manifest *index* (fixed 2026-08-20 after a production incident, pinned by `tests/test_compact_manifest_order.c`). The two k-way merges order by *generation*. After `utxo_lsm_compact` with `manifest_n > COMPACT_MAX_RUNS (64)` — the classic "oldest 64" batch with survivors — the merged run M sits at index 0 with a gen HIGHER than every survivor. Any key with a PUSH in M and a DEL (or a newer PUSH, e.g. the BIP30 coinbase overwrite) in a survivor is then resolved by both merges to M's stale PUSH. The lookup path is right; the walk and the next compaction are wrong.
- Failure scenario (executed, scratchpad `utxtest/t2.c` = the repo's `test_compact_manifest_order.c` plus a walk and a second `utxo_lsm_compact`): PUT A (run 1), 63 dummy runs, DEL A (run 65); compact → manifest [M, run65]; `utxo_lsm_get(A)` = absent (test passes); `utxo_lsm_walk` visits **65** entries (counter says 64: A counted live); second `utxo_lsm_compact` → `utxo_lsm_get(A)` = FOUND value 999999. A spent coin is back on disk, in the only remaining run.
- Reachability: `utxo_live_recover()` (`utxo_live.c:786-798`) loops the classic `utxo_lsm_compact` when the manifest is full (`manifest_cap` = 256 → four 64-run rounds); `daemon/build_migrate_compact.c` loops it over an 8192-cap manifest. In the daemon the post-recovery gate (`utxo_live_verify_after_recovery`, walk == counter == pre-count) will catch it — but only by HALTING, so full-manifest recovery can never succeed on a real set, and the walk it relies on is itself the mis-counting merge. The leveled picker (`lsm_compact_pick`) never yields `lo == 0` with survivors, so the background path is safe today; the classic entry point is the hazard.
- Core reference: LevelDB (Core's chainstate) resolves duplicates strictly by level/sequence order; a compaction output never outranks a newer level.
- Suggested fix: break ties by manifest index (higher index wins, exactly `utxo_lsm_get`'s rule) in both `.cc_find_loop` and `.rc_find`, and/or give a prefix merge `out_gen = max(input gens)` when survivors exist (run_no stays fresh, so the mmap-cache (run_no, gen) key remains unique). Extend `test_compact_manifest_order.c` with a walk count and a second compaction.
- Verdict: CONFIRMED (repro).
- Test coverage: `test_compact_manifest_order.c` checks only `get()` after one compaction; nothing walks or compacts twice with survivors.

##### UTX-2 (HIGH) — Reload into an undersized memtable is accepted; the first flush makes the truncation permanent
- Location: `asm/daemon/utxo_live.c:463-467` (`int ok = have_prior_state ? (r != -1) : (r == 1)`); `asm/bitcoin_utxo_lsm.asm` `mac_lsm_reload_impl` (`call utxo_store_reload; cmp rax,-1; je .rl_fail; mov r15,rax` — `-2` passes and is returned as the "replayed count"); `.rl_wal_del` (`cmp rax,[r12+72]; jae .rl_wal_close` — tombstone rescan stops silently at `tomb_cap`); `asm/bitcoin_utxo_store.asm` `.full` (returns -2, comment says "daemon/utxo_live.c turns it into 'memtable too small for the WAL tail'" — it does not; `grep -- '-2' utxo_live.c` has no handler).
- Description: `utxo_store_reload` stops at the first `utxo_put == 2` and returns -2 with the memtable holding only the records up to the fill point. `utxo_lsm_reload` propagates -2; `utxo_live_init` treats anything but -1 as success and logs `live=N`. The memtable is now at/above `fill_threshold`, so the next `utxo_lsm_put` (first block's coinbase, or a ghost-rollback restore) immediately runs `mac_flush`, which writes the truncated memtable to a run, publishes the manifest and **ftruncates the WAL** (`.fl_finish_reset`) — the dropped records are gone from the only place they existed. In the same window the tombstone rescan silently stops at `tomb_cap` (131072 in steady state), so DELs past that point are lost too (spent coins resurrect once the run-resident PUSH is no longer shadowed).
- Failure scenario: bulk catch-up (2^22 slots, flush at 3.1M live / 8.4M ops, WAL up to ~600 MB) is killed (SIGKILL/OOM/power) when `tip - applied < utxo_bulk_gap_blocks (50000)` and `utxo.dat < 256 MB` (`utxo_live.c:376-408`). Boot picks steady-state sizing (2^16 slots, 64 MB blob, tomb_cap 131072). Executed in scratchpad `utxtest/t3.c`: 300 WAL records reloaded into a 64-slot table → `utxo_lsm_reload` returns **-2** and `utxo_lsm_count` = 64. In the daemon the log would then show a plausible `reload ... live=N`, the next put flushes, and the set is permanently short by every record past the fill point (later blocks spending those outputs are rejected as "missing UTXO" forever — classified consensus-reject, retried from the checkpoint, never halted).
- Core reference: Core's `CCoinsViewDB` has no equivalent window; `LoadBlockIndex`/chainstate load either succeeds or aborts.
- Suggested fix: in `utxo_live_init` treat any `r < 0` as fatal and print the -2 remedy (bulk sizing / `flush_wal_tail`); make `utxo_lsm_reload` fail (not stop) when `tomb_n` reaches `tomb_cap`; size the bulk decision from the WAL's *record count* (or always bulk-size when `utxo.dat` is larger than the steady-state `op_threshold` worth of bytes, ~12 MB) instead of the 256 MB heuristic.
- Verdict: CONFIRMED (repro of the store layer; daemon acceptance by code reading).
- Test coverage: `test_utxo_probe_bound.c` pins `utxo_put == 2`; nothing pins that a reload returning -2 is refused by the daemon or that the tombstone rescan refuses to truncate.

##### UTX-3 (MEDIUM) — `utxo_lsm_put` returns 0xFFFFFFFF, not -1, on a WAL write failure
- Location: `asm/bitcoin_utxo_lsm.asm` `utxo_lsm_put`: `call utxo_store_put` / `mov r14d, eax` (~1105) ... `.lp_skip_flush: ... mov eax, r14d` (~1129). `utxo_store_put` returns a 64-bit -1 (`.fail: mov rax,-1`); the 32-bit copy zero-extends it. Callers: `utxo_live.c:702` (`if (r == -1 || r == 2) ctx->fatal = 1`), `:1509` (`undo_restore_cb`), `utxo_live_test_seed`.
- Description: when the 1 MB WAL buffer has to drain mid-block (a block with >1 MB of WAL records — ~11k outputs — or after a previous transient failure) and the drain fails (ENOSPC, EIO), `utxo_store_put` returns -1 *before* touching the memtable; `utxo_lsm_put` hands back 4294967295; `live_on_output` sees neither -1 nor 2, does not set `fatal`, and the created output is in neither the memtable nor the WAL. The block-boundary drain (`apply_block_at`) retries the *earlier* buffered bytes and, if the disk recovered, succeeds and the checkpoint lands: the coin is permanently absent.
- Failure scenario: executed in scratchpad `utxtest/t3.c` — after 16644 puts through a read-only WAL fd the drain fails; `utxo_lsm_put` returned `4294967295 (0xffffffff)`, `r == -1` false, `r == 2` false, and `utxo_lsm_get` of that key returned 0.
- Core reference: `CCoinsViewCache::AddCoin` cannot fail silently; a failed `BatchWrite` aborts the node.
- Suggested fix: `movsxd r14, eax` / `mov rax, r14` (or compare in 64 bits); the same file already fixed exactly this for `utxo_lsm_del` (`flush_wal_tail.c` comment). Make callers check `r < 0`.
- Verdict: CONFIRMED (repro).
- Test coverage: none (no test injects a WAL write failure).

##### UTX-4 (MEDIUM) — Checkpoint is fsynced before the WAL/undo data it certifies; torn WAL tail is never truncated
- Location: `asm/daemon/utxo_live.c:543-567` `persist_applied_height` (`utxo_store_wal_drain` = `write(2)` only, then tmp+fsync+rename+dir-fsync of the height file); `asm/bitcoin_utxo_store.asm` — `fsync` appears only in `utxo_store_sync` (never called by the LSM) and `utxo_store_close`; `undo_log.c:93` opens `O_APPEND`, no fsync; `utxo_store_reload` sets `log_len` = file size (SEEK_END) and stops replay at the first short/unknown record (`.rep_close`) without truncating.
- Description: the design (comments in `utxo_store.asm` and `utxo_live.c:596-612`) explicitly covers same-machine process death via the page cache, not power loss / kernel crash. On power loss, the 12-byte checkpoint (fsynced) can survive while the WAL pages for the blocks it covers do not: the reloaded set is BEHIND the checkpoint, catch-up resumes at applied+1, and the lost blocks' spends resurrect and their outputs vanish silently (the ghost guard cannot see it — the undo files are unsynced too). Secondly, a partially written last record stays in the file; every later append lands *after* it, and every future reload stops at the torn record, dropping everything appended since (the daemon keeps appending because `log_len` was measured as the file size).
- Failure scenario: hard reset while catching up (exactly the 2026-09-01 host outage; the report notes it was survived because `Dirty` happened to be 0). Block N's WAL bytes are in the page cache only, `utxo_applied_height.dat`=N is on disk → after reboot muhash diverges by block N's ops; nothing detects it until a parity check.
- Core reference: `CCoinsViewDB::BatchWrite` writes the batch with `fSync=true` and the best-block marker inside the same batch (`CDBBatch` + `WriteBatch(batch, true)`); block/undo files are `FlushBlockFile`'d before `FlushStateToDisk` writes the chainstate.
- Suggested fix: `fsync(log_fd)` (and the block's undo file) inside `persist_applied_height` before the rename — one fsync per checkpoint (batched every 64 blocks / 2 s during catch-up). On reload, `ftruncate(log_fd, consumed)` (or at least set `log_len`/the fd offset to the consumed offset) when a torn record is found.
- Verdict: CONFIRMED (by reading; not executed).
- Test coverage: `test_utxo_crash_recovery`, `test_utxo_catchup_crash_resume`, `test_utxo_ghost_resume` all simulate `_exit`, which cannot lose page-cache writes; none simulates a torn record or lost tail.

##### UTX-5 (MEDIUM) — Adoption publish failure deletes the merged run the in-memory manifest depends on
- Location: `asm/daemon/lsm_manifest.c` `lsm_manifest_adopt_child`: "commit to memory, publish, then clean up" — `memcpy(lst->manifest_buf, nb, ...)`, `lst->manifest_n = total`, then `if (lsm_manifest_publish(...) != 0) return -1; /* memory now ahead of disk; harmless: inputs still exist */`. Caller `asm/daemon/utxo_live.c:249-255` on `!= 0`: `unlink_run(g_cmp_child_run)` and logs "old run set kept".
- Description: the comment and the caller disagree with the code. After a publish failure (ENOSPC/EIO on `utxo_manifest.dat.pub` — plausible right after a compaction temporarily doubled disk usage) the in-memory manifest already names the child's merged run M and no longer names the inputs; `compact_adopt` then unlinks M. Every lookup through M now fails (`open` fails → mm path returns FALLBACK → asm path returns -1 → `utxo_lsm_get` = -1 → verification errors); worse, the next `mac_flush` publishes the in-memory manifest, so the on-disk manifest names a deleted run and drops the (still present, now orphaned) inputs. On restart reload fails; the inputs survive only because the orphan sweep requires a successful reload, and recovery needs hand-editing the manifest.
- Failure scenario: background compaction finishes; `write()`/`fsync()` of the .pub file fails with ENOSPC → M unlinked → next flush → manifest broken on disk.
- Suggested fix: publish first, commit to memory only on success (build `nb` into a temporary `lsm_state` for `lsm_manifest_publish`), and never unlink `g_cmp_child_run` once memory references it.
- Verdict: CONFIRMED (by reading).
- Test coverage: `test_compact_async.c` exercises the success path only.

##### UTX-6 (MEDIUM) — Unreadable or over-capacity manifest is silently treated as absent
- Location: `asm/bitcoin_utxo_lsm.asm` `mac_lsm_reload_impl`: `.rl_manifest_haveN: cmp rax,[r12+112]; ja .rl_manifest_bad`; `.rl_manifest_bad` zeroes `manifest_n/next_gen/next_run_no` and continues; short read / bad magic take the same path. Return value is the WAL replay count (success).
- Description: a manifest with more runs than the caller's `manifest_cap` (daemon 256; tools 4096; `build_utxo`/`migrate` write up to 8192), a truncated manifest, or an I/O error all yield "no runs, WAL only" with no error. In the daemon: `utxo_live_init` logs a plausible line; if `undo_<applied+1>.dat` exists the boot ghost-rollback issues puts/dels, which can cross `fill_threshold` and `mac_flush` — publishing a manifest that names only the new run. The real runs are now orphans, and the next boot's `lsm_manifest_sweep_orphans` (on-disk == in-memory now) deletes them. In the read-only tools/RPC (`utxo_setinfo`, `scantxoutset`, `dumptxoutset`, `utxo_dump_keys`) the answer is the WAL tail alone, reported as `consistent: true`.
- Suggested fix: fail the reload (`-1`) on any manifest read error or `manifest_n > manifest_cap`; add a CRC/length to the manifest header.
- Verdict: CONFIRMED (by reading).
- Test coverage: none.

##### UTX-7 (LOW) — dumptxoutset compresses uncompressed P2PK without Core's `IsFullyValid` gate
- Location: `asm/utxo_snapshot.c:96-98` (`spklen == 67 && spk[0]==65 && spk[1]==0x04 && spk[66]==0xac` → kind `4|(spk[65]&1)`); comment admits "mirrors that gate on the prefix and length alone".
- Description: Core `compressor.cpp:47-50` compresses a 65-byte P2PK only if `pubkey.IsFullyValid()`; otherwise it is written raw (`VARINT(len+6)`). Mainnet's UTXO set contains bare P2PK outputs with non-curve 0x04 keys; for those our snapshot carries kind 4/5 + x, which Core's `DecompressScript` cannot decompress (the point is not on the curve) → `loadtxoutset` deserialization failure / hash mismatch.
- Suggested fix: run the x/parity through the secp256k1 decompress routine already in the tree before choosing kinds 4/5; fall back to raw.
- Verdict: PLAUSIBLE (Core behaviour verified in source; the existence of such coins in the current set not verified here).
- Test coverage: `test_utxo_snapshot.c` pins 14 real coins, all with valid keys.

##### UTX-8 (LOW) — WAL `ftruncate`/`lseek` failures after a flush are ignored
- Location: `asm/bitcoin_utxo_lsm.asm` `.fl_finish_reset` (~2355-2368): `ftruncate(log_fd,0)` and `lseek(0)` results unchecked, then `log_len = 0`.
- Description: on EIO the old generation stays in `utxo.dat` while new records are written from offset 0 over it; a later reload replays the new records and then whatever stale bytes follow (misparse, or — at an aligned boundary — stale PUSHes applied after newer DELs).
- Suggested fix: check both syscalls; treat failure as a flush error (return -1 before clearing the memtable).
- Verdict: CONFIRMED (by reading).

##### UTX-9 (LOW) — Record scan is not bounded by the records region
- Location: `asm/utxo_lsm_mm.c:298-330` (loop bound `pos + 37 > s->len`), `asm/bitcoin_utxo_lsm.asm` `.ml_scan_loop` (bound = short read).
- Description: for a target greater than every key in the run (reached whenever the Bloom passes — with a saturated 4 MiB filter on 30M-record bulk runs it passes almost always) the scan continues past the last record into the sparse-index trailer, parsing key/offset entries as records with random `slen` skips. The C path is bounds-checked (no OOB); a false hit needs a 36-byte match at a garbage-aligned position. Wasted I/O and a fragile invariant, not a correctness defect today.
- Suggested fix: stop at `sparse_off` (or `records_start + ...` via `nrec`).
- Verdict: CONFIRMED (by reading).

##### UTX-10 (LOW) — Disconnect/rollback deletes are still gated on a point lookup (incident shape, un-halted)
- Location: `asm/daemon/utxo_live.c:1521-1523` (`if (utxo_lsm_get(...) != 1) return;` in `del_created_on_output`), used by reorg disconnect, ghost rollback and partial-apply rollback.
- Description: the incident fix halts on a lying lookup in `live_on_input`. The mirror path trusts a miss to mean "never created" and silently skips the delete; a future lookup bug of the incident's kind would leave a disconnected block's outputs live (phantom coins) with no signal, unless `g_store_inconsistent` was already set. The gate exists only to keep the O(1) tally honest.
- Suggested fix: delete unconditionally (a tombstone over an absent key is a no-op) and fix the tally from the undo record/created-output counts, or cross-check the number of skipped deletes against what the undo file implies.
- Verdict: CONFIRMED (shape only; no live defect).

##### UTX-11 / UTX-12 / UTX-13 (INFO)
- `utxo_dump_keys.c:24` treats `slen == 0` as unspendable; Core's `IsUnspendable` (and `bitcoin_utxo_stats.asm`) treats an empty script as spendable — diff tooling drift.
- Any non-empty WAL tail at boot forces `mac_lsm_recount` (a full k-way merge over every run) because the v2 manifest cannot say whether the tail is folded (incident #45 fix). On the 165M-entry set that is minutes of boot with the SIGTERM-exit window `main.c` documents; a "folded through offset" field in the manifest would remove it.
- `flush_wal_tail.c:106-110` documents the 32-bit `-1` defect for `utxo_lsm_del`, which is fixed in the asm (`.ld_err: mov rax,-1`), while the identical defect is live in `utxo_lsm_put` (UTX-3).

#### Verified-correct controls
- **Incident 2026-09-01 fix is complete on the apply path.** `live_on_input` r==0 → `g_store_inconsistent=1; g_halted=1; fatal` (`utxo_live.c:609-615`); rollback deletes without a lookup under inconsistency (`:1512-1520`); catch-up refuses while halted (`:572`); `main.c:5371-5390` classifies failures, compacts only for store-error+full-manifest, and `utxo_live_verify_after_recovery` walks and halts on mismatch. Pinned by `tests/test_utxo_lost_tombstones{,_bad}`, `test_lsm_lost_tombstones`, `test_utxo_recover_gate`. The sparse-offset trigger is fixed on both writers (`mac_flush` adds `mac_fl_fill` to `SEEK_CUR`, ~2185; compaction uses `mac_out_tell`, ~3850), pinned by `test_sparse_offsets`/`test_lsm_flush_sparse`.
- **Flush ordering** (`mac_flush`): WAL drain → run written → run `fsync` → manifest tmp written+`fsync` → `rename` → dir `fsync` → WAL `ftruncate` → memtable/tombstone reset. Process death at any point before the truncate leaves the WAL as a superset that replays into a duplicate (newer-gen) run; a reader in the same process sees the manifest entry before the memtable is cleared (store order on x86). Manifest `rename` is atomic; manifest capacity is checked before any run-file work (~1990).
- **Compaction crash safety**: output run fsynced before publish; inputs unlinked only after; a crash between publish and unlink orphans files that the guarded boot sweep removes (`lsm_manifest_sweep_orphans` refuses unless on-disk == in-memory).
- **Background child protocol**: run_no/gen reserved for the child immediately after `fork()` (`utxo_live.c:352`), defer-unlink/defer-publish set only in the child, the parent's flush hook adopts a finished child before touching the manifest, adoption validates exactly one unknown run and no input in the child's list, `lsm_mm_invalidate_all()` after adoption, inputs unlinked only when no longer named. Adopted order = child's list (older gens) then runs flushed since fork (higher gens) — gen-ascending by index. Shutdown SIGKILLs the child (its partial run is an orphan). `SIGCHLD` flip to `SIG_DFL` is restored; the worker forks no other children meanwhile (`tx_verify.c` is pthread-based).
- **Bloom filter**: writer and both readers hash the same 36 bytes with the same three seeds, FNV-1a 32-bit, `& (bloom_bits-1)` derived from the header (`mac_bloom_h` ≡ `bloom_h` in `utxo_lsm_mm.c`); tombstones set bits too; saturation only costs false positives (`test_lsm_bloomsat`). No false negative is possible.
- **Key order**: `mac_cmp_key` = big-endian qword compare = unsigned bytewise order = `memcmp` in the C path; sort, sparse search, scan, and both merges use it; the LE-byte order of `vout` is documented in FEATURE_GAPS and only affects `hash_serialized`, which is refused.
- **Memtable bounds**: `utxo_put` reports 2 after a full lap; `utxo_get`/`utxo_del` bound their probes at the home slot (incident #32); backward-shift deletion keeps "empty terminates a probe"; `fill_threshold = 3/4 slots` flushes before the table fills; `tomb_cap = op_threshold` so a generation cannot overflow the tombstone list; `desc_cap = 3*slots ≥ fill+tomb`.
- **Lookup under a flush window**: single writer; verification threads call `utxo_lsm_get` only in phases 1-4 (no put/del in flight); the txoq IPC and `utxo_live_resolve` run at the worker's quiescent point; mm cache is per-thread with (run_no, gen, epoch) validation and the mapped header's gen re-checked.
- **Unspendable filter** `utxo_script_unspendable` = Core `CScript::IsUnspendable` exactly (`size()>0 && *begin()==OP_RETURN || size()>MAX_SCRIPT_SIZE`), applied at write time in both writers (`utxo_live.c:638`, `build_utxo.c`) and at read time in `utxo_stats_add`; empty script is spendable. Genesis coinbase skipped by hash in both writers (`genesis_skip.h`). Duplicate coinbase = del+put overwrite (Core `AddCoins overwrite=fCoinbase`, `utxo_live.c:678-689`); non-coinbase duplicate logged, kept (documented).
- **MuHash serialization** `bitcoin_utxo_stats.asm` = Core `TxOutSer`: `outpoint(32+4 LE) || (height<<1|coinbase) u32 LE || nValue i64 LE || CompactSize(len) || script`; bogosize 50+len; digest rendered byte-reversed like `uint256::GetHex`. `csi_on_remove` folds the same serialization into the denominator; MuHash is order-independent so add/remove ordering is irrelevant. `gettxoutsetinfo` omits `disk_size`/`hash_serialized_3`/`total_unspendable_amount` — documented divergence (FEATURE_GAPS, `rpc_chain.c:3815`), not re-reported.
- **Integer sizes**: height u32 in WAL/run/blob (packed with coinbase byte), value u64, counts u64, slen u16 on disk (≤10000 after the filter); `lsm_run_lookup_mm` bounds `slen ≤ 65536`; `utxo_store_reload`'s script scratch sits 64 KiB below `rbp`; the get path publishes `slen` as a full 8-byte store (incident #49).
- **Set-info readers** are read-only by construction (`utxo_lsm_reload_ro`, no `utxo.idx` creation) and fail closed on any datadir change (triple fingerprint including the directory entry).
- Prior-audit re-verification: SECURITY_AUDIT_2026-09-02 item "halt-on-absent-coin + lookup-free rollback + gated recovery" — re-verified, present at the cited lines. ADDENDUM item "`test_utxo_recover` does not link" — a Makefile rule now exists (`Makefile:881-894`); not built here.

#### Coverage and limits
- Did not build/run the daemon-level tests or the 50+ UTXO tests; coverage claims come from reading their headers/greps. Did not read `undo_log.c`, `coinstats_index.c`, `tx_verify.c` beyond the cited functions, nor `main.c` beyond the recovery/txoq/signal sites — a reviewer of those modules should confirm no other thread calls `utxo_lsm_get` while the worker applies a block (I found only the txoq service point and `utxo_live_resolve`, both documented as quiescent).
- UTX-4's power-loss reasoning is by construction; I did not attempt a filesystem-level fault injection. UTX-7 needs a scan of the live set for 65-byte non-curve P2PK outputs to become CONFIRMED (`utxo_dump_keys` would do it).
- Next: (1) fix UTX-1's tie-break and re-run `test_compact_manifest_order` with the added walk/second-compaction checks (my `utxtest/t2.c`); (2) make `utxo_live_init` refuse `r < 0` and size bulk mode from the WAL's record count; (3) audit every asm→C return for 32-bit `-1` truncation (`grep -n 'mov eax, r1[0-9]d\|mov eax, -1' asm/*.asm` on exported entry points); (4) add `fsync` of the WAL and undo file to the checkpoint and truncate torn tails on reload; (5) reorder adopt_child to publish-then-commit.


---

### 6.5 Block archive, undo log, reorg, optional indexes, pruning — review

**Scope**
- Files fully read: `asm/bitcoin_store.asm`, `asm/bitcoin_store_fast.asm`, `asm/bitcoin_undo.asm`, `asm/bitcoin_idx.asm`, `asm/bitcoin_idxscan.asm`, `asm/block_filter.c`, `asm/block_filter.h`, `asm/daemon/reorg.c`, `asm/daemon/reorg.h`, `asm/daemon/undo_log.c`, `asm/daemon/archive_verify.c`, `asm/daemon/archive_reindex.c`, `asm/daemon/tx_index_tail.c`, `asm/daemon/txosp_tail.c`, `asm/daemon/addr_index_tail.c`, `asm/daemon/coinstats_index.c`, `asm/daemon/bfilter_index.c`, `asm/daemon/serve_cfilters.c`, `asm/daemon/dumpblock.c`, `asm/daemon/locator_build.c`, `asm/daemon/chainctl.c`; the unapply/recovery/catch-up sections of `asm/daemon/utxo_live.c` (1470-1790, 2055-2270); `block_work`/`chainwork_add`/`chainwork_cmp`/`store_chainwork_truncate` in `asm/bitcoin_chainwork.asm`; the reorg wiring, choke point, prune wiring and submitblock connect path in `asm/daemon/main.c`; `cmd_getblockfilter` in `asm/rpc_chain.c`.
- Files skimmed: `asm/daemon/build_block_filters.c` (header, buffer setup, append loop), `asm/daemon/build_tx_index.c` (pass 2), `asm/daemon/build_addr_index.c`, `asm/daemon/build_txospender_index.c` (allocation/size handling only), `asm/bitcoind.asm` (append call sites only), `asm/bitcoin_serve.asm` (append call site only).
- Not read: the rest of `utxo_live.c` (UTXO reviewer), `bitcoin_utxo_lsm.asm`, `bitcoin_headers.asm`, `rpc_chain.c` outside getblockfilter.
- Docs read: `docs/devlog/INCIDENT_2026-09-01_header_sync_genesis_answer.md`, `docs/ENGINEERING.md` §1.1/§5.3, storage-relevant parts of `docs/FEATURE_GAPS.md`, the two prior audits (storage-relevant lines).

**Summary**
The archive/undo/reorg layer is well guarded against the failure modes the project has already lived through (non-monotonic layout, duplicate-hash junk, torn undo tails, ghost blocks, the append-lock hold across a reorg), and the fork-choice predicate is correct (strictly-heavier cumulative work, first-seen on ties, bad-diffbits enforced). The headline problems are in what has *not* been exercised yet: (1) a crash in the middle of a reorg's disconnect phase leaves the UTXO set rewound by up to 100 blocks while `utxo_applied_height.dat` still names the old tip and every undo file has been discarded — there is no recovery path, and the coinstats index adopts the stale state as valid; (2) the BIP158 builder zeroes only the first 64 KiB of its output buffer and ORs bits into a reused static buffer, so any filter larger than 64 KiB built after another large one is corrupted (filter header chain diverges from Core from that height on); (3) the daemon's index tails treat a *missing* undo file as "block spent nothing", so after any catch-up burst longer than the 200-block undo window the block-filter and address indexes are silently built without prevouts; (4) `store_prune`'s compaction validates layout/holes only at or below the prune height and will `ftruncate` retained block data when a hole or out-of-order record sits above it in the boundary file. Two MEDIUMs concern the unlocked, stale-offset `store_append` used by `submitblock` and malformed/inconsistent `cfheaders`/`cfcheckpt` replies. Confidence is high on all CONFIRMED items: each was traced end to end in the code; none is covered by an existing test.

#### Findings

| ID | Severity | Location | Title | Verdict |
|---|---|---|---|---|
| STO-1 | HIGH | daemon/reorg.c:680-735, daemon/utxo_live.c:1737-1780 | Crash mid-disconnect leaves the UTXO set rewound with the old applied height and no undo files; coinstats adopts the wrong state | CONFIRMED |
| STO-2 | HIGH | block_filter.c:218 | BIP158 builder zeroes only 64 KiB of the output buffer; filters >64 KiB inherit stale bits from the previous filter | CONFIRMED |
| STO-3 | HIGH | daemon/bfilter_index.c:248, daemon/addr_index_tail.c:224, utxo_live.c:2258-2262 | Missing (pruned) undo file is read as "no spends": filter and address indexes silently wrong after a >200-block catch-up burst | CONFIRMED |
| STO-4 | HIGH | bitcoin_store.asm:690-775 (`store_prune`), daemon/archive_verify.c:534-560 | Prune compaction assumes no holes / monotonic layout *above* the prune height; violation ftruncates retained block data | CONFIRMED |
| STO-5 | MEDIUM | daemon/main.c:5034, bitcoin_store.asm:958-1075 | `submitblock` connect uses the unlocked `store_append` with a `cur_file_pos` that shared appends never refresh | CONFIRMED |
| STO-6 | MEDIUM | daemon/serve_cfilters.c:159-213 | `cfheaders`/`cfcheckpt` become malformed when the count is rewritten across a varint width boundary; clamp echoes the original stop hash; `cfheaders` cap is 1000 not Core's 2000 | CONFIRMED |
| STO-7 | MEDIUM | daemon/reorg.c:801-812, daemon/main.c:5458-5520 | Mempool is not reconciled after a reorg (comment stale): disconnected-block txs never re-offered, replacement-block txs at heights ≤ old tip never removed | CONFIRMED (impact on GBT PLAUSIBLE) |
| STO-8 | MEDIUM | rpc_chain.c:3160-3180 | `getblockfilter` fallback serves a filter with no prevout elements for a block whose undo file is absent, contradicting its own error text | CONFIRMED |
| STO-9 | LOW | daemon/reorg.c (no hst calls), daemon/main.c:3077-3090 | `headers.dat` is not rewound on reorg; mirror holds the losing branch until the next boot's self-heal | CONFIRMED |
| STO-10 | LOW | daemon/main.c:347 (`serve_idx_topup`), :382-405 | Forked serve children keep a pre-reorg hash→height table; getdata for a losing-branch hash serves the replacement block at that height | PLAUSIBLE |
| STO-11 | LOW | bitcoin_store.asm:958-1075, daemon/archive_verify.c:183 | No fsync on `blk*.dat`/`index.dat` appends and no per-block checksum; a power loss can leave an index record over unwritten bytes that boot detects but does not repair | CONFIRMED |
| STO-12 | LOW | daemon/archive_verify.c:512-535, reorg.h:29 | No `MIN_BLOCKS_TO_KEEP`-style floor: a small budget can prune inside the reorg/undo window; no prune/txindex interaction guard | CONFIRMED |
| STO-13 | INFO | bitcoin_chainwork.asm:334-475 | Chainwork is 128-bit (Core: 256-bit); exact for every reachable nBits once bad-diffbits is enforced, no saturation | CONFIRMED |
| STO-14 | INFO | block_filter.c:196-206 | Element de-duplication is on the 64-bit SipHash, not on script bytes (Core dedups elements first) | CONFIRMED |

##### STO-1 (HIGH) — Crash mid-disconnect leaves the UTXO set rewound with the old applied height and no undo files
- Location: `asm/daemon/reorg.c:680-735` (disconnect loop, then `archive_truncate_safe`, then `utxo_live_rewind_to`), `asm/daemon/utxo_live.c:1737-1780` (`utxo_live_unapply_block`, `utxo_live_rewind_to`).
- Description: `reorg_execute` unapplies heights `tip..fork+1` one block at a time. Each `utxo_live_unapply_block` restores spent coins and deletes created outputs through the WAL (durable immediately), then calls `undo_discard(height)` (utxo_live.c:1764). The persisted applied height is only rewritten *after the whole loop* by `utxo_live_rewind_to(fork_height)` (reorg.c:748), which is also the only call that commits the coinstats state (`persist_applied_height` → `csi_commit`). Nothing marks "disconnect in progress".
- Failure scenario: SIGKILL/OOM/power loss after the first `utxo_live_unapply_block` returns (up to 100 blocks later). On boot: `utxo_applied_height.dat` = old tip T; `index.dat` tip = T (truncation not reached) ; `undo_T.dat` … gone (discarded); `utxo_live_recover_partial_block` looks for `undo_(T+1).dat`, finds nothing, reports "nothing to do"; catch-up sees `tip <= applied` and does nothing. The live set is now the state at T−k while every consumer believes it is at T. Coins spent in blocks T−k+1..T are live again (double-spend acceptance until the fail-closed halt trips on some later missing prevout), outputs created there are gone. `csi_boot` adopts `coinstats.dat` because its stored height equals the applied height, so the parity instrument reports a digest that does not describe the set. If instead the crash lands between `archive_truncate_safe` (reorg.c:723) and `utxo_live_rewind_to` (reorg.c:748): index tip = fork, applied = T > tip; `utxo_live_catchup` returns 0 (`tip <= g_applied_height`) and the new branch's blocks at fork+1.. are appended and never applied — permanent divergence with no log line.
- Core reference: `DisconnectTip` → `CCoinsViewDB::BatchWrite` writes the coins delta and the best-block hash in one LevelDB batch (`DB_BEST_BLOCK` / `DB_HEAD_BLOCKS` sentinel), so a crash mid-reorg reloads to a consistent (height, set) pair and `ReplayBlocks` finishes the job.
- Suggested fix: per-block ordering `persist_applied_height(h-1)` → unapply(h) (idempotent: restore-then-delete over the retained undo file) → `undo_discard(h)`; a crash after the persist and before the discard then lands in the existing ghost-block recovery path (`undo_(applied+1).dat` exists → rollback). Additionally make boot refuse (or truncate index to `applied`) when `applied > index tip`, and have `csi_boot` refuse adoption unless a "clean shutdown/commit" marker matches.
- Verdict: CONFIRMED.
- Test coverage: none. `tests/test_reorg.c` forks per case for isolation only; `test_utxo_crash_recovery`/`test_utxo_ghost_resume` cover crashes during *apply*, not during *disconnect*.

##### STO-2 (HIGH) — BIP158 builder zeroes only 64 KiB of the output buffer
- Location: `asm/block_filter.c:218` `memset(out + o, 0, cap - o > 65536 ? 65536 : cap - o);` with `bw_bit` (`block_filter.c:96-100`) only ever OR-ing 1-bits.
- Description: every caller passes a reused buffer: `bfilter_index.c:242-250` (static `malloc(BFI_MAX_FILTER)`), `build_block_filters.c:528,701` (`static u8 filter[1u<<20]`), `rpc_chain.c:3189` (`static unsigned char flt[1<<20]`). Bytes at offset ≥ 65536 keep whatever the previous filter left there. A basic filter is ~2.6 bytes/element (P=19 plus unary), so any block with more than ~25k distinct scriptPubKeys+prevout scripts crosses 64 KiB.
- Failure scenario: the offline backfill (or the live tail) builds a >64 KiB filter for block A, then a >64 KiB filter for block B: B's bytes past 64 KiB are `A_bits | B_bits`. The stored filter, its `sha256d`, and every filter header after B (`bf_header` chains `prev_header`) differ from Core's; `getcfheaders`/`getcfcheckpt` answers diverge from every honest node from B onward, and light clients matching against B's filter get false positives (extra 1-bits push decoded deltas off the grid, effectively decoding garbage). Blocks with >25k elements exist on mainnet (consolidation and inscription-era blocks), so the live whole-chain index (`bfilters.dat`) is very likely to contain such filters unless the buffer happened to be clean each time.
- Core reference: `GCSFilter::BuildBitstream` writes into a fresh `std::vector<unsigned char>`; `BlockFilter` for a block is a pure function of block + undo.
- Suggested fix: `memset(out + o, 0, cap - o)` (or track the highest byte written and zero up to it), and add a KAT with a synthetic block whose filter exceeds 64 KiB, run twice through the same buffer.
- Verdict: CONFIRMED.
- Test coverage: `tests/test_block_filter.c` uses two real blocks (501726, 700038) with small filters; nothing exceeds 64 KiB.

##### STO-3 (HIGH) — Missing undo file read as "no spends": filter and address indexes silently wrong after a long catch-up burst
- Location: `asm/daemon/undo_log.c:180` / `asm/bitcoin_undo.asm` (`undo_replay` returns **0** for an absent file, −1 only for a torn one); consumers `bfilter_index.c:248` `if ((ur < 0 && h != 0) || c.overflow) return 0;`, `addr_index_tail.c:224` `if (ur < 0 || !c.ok) return 0;`. Undo retention: `utxo_live.c:2258-2262` prunes to `[applied-199, applied]` at the *end* of `utxo_live_catchup`, which runs before the new-block choke point (`main.c:5458`) that feeds the tails.
- Description: a block with no non-coinbase inputs never creates its undo file, so the code cannot distinguish "absent" from "pruned" and chooses to proceed. `utxo_live_catchup` applies every block up to the archive tip in one call (`utxo_live.c:2085`, no per-call cap) and then prunes undo files below `applied-199` (cursor sweep of up to 20000 heights per call). Only afterwards does the worker loop `zh = last_seen_tip+1 .. now_tip` and call `bfi_on_block`/`axt_on_block` for each height.
- Failure scenario: the index is already adopted (`g_dfd >= 0`; the 144-block adoption guard only protects the *first* adoption). The node falls >200 blocks behind while running (network outage of ~1.5 days, a long compaction, or the parallel-downloader path at `main.c:5122-5127` which writes thousands of blocks and `continue`s straight into an apply-first catch-up). Catch-up applies N>200 blocks, prunes undo for the first N−200, then the choke point builds filters for those heights from block bytes only: `bf_basic_build` with `n_prevouts = 0`. Every one of those filters lacks its spent-prevout elements; the header chain diverges from Core; a light client is told those blocks do not touch its coins. `axt_append_block` writes ADDs with no DELs, so `getaddressbalance` over-reports every address spent in those blocks. Nothing is logged.
- Core reference: `BlockFilterIndex::CustomAppend` reads undo via `m_chainstate->m_blockman.ReadBlockUndo` and *fails the index* (returns false) when undo is unavailable; Core also never prunes undo below the index's position while the index is enabled.
- Suggested fix: make the "absent" case explicit — either have `undo_capture` always create the file per applied block (even empty), or have `undo_replay` return a distinct code for ENOENT and have the tails/RPC refuse to build when the block has non-coinbase inputs but no undo file (the input count is available from the block, as `utxo_live_can_unapply` already does). Also do not prune an undo file below the lowest tail watermark (`bfi_count`, `axt_covered`).
- Verdict: CONFIRMED.
- Test coverage: `validation/bfi_burst_regression.sh` covers the *adoption* guard only; `tests/test_bfilter_index.c` and `tests/test_addr_index_tail.c` do not remove undo files before a gap close.

##### STO-4 (HIGH) — Prune compaction assumes no holes / monotonic layout above the prune height
- Location: `asm/bitcoin_store.asm:690-775` (`store_prune` `.cmploop`/`.cmpdone`), guard `asm/daemon/archive_verify.c:534-560` (`archive_prune_decide`: `archive_layout_monotonic(ph)` and `archive_first_hole(ph)` — both bounded at `ph`), wiring `main.c:7148-7199`.
- Description: `store_prune` unlinks every file below the boundary file F, then walks `h = ph, ph+1, …` re-packing records while `rec.file_no == F`, and finally `ftruncate(F, new_off)`. It assumes every height stored in F appears as one contiguous run starting at `ph`. The verdict that green-lights it checks layout and holes only for heights `≤ ph`.
- Failure scenario A (hole above `ph` in F): a sync-in-progress archive with a hole at H > ph (the 09-01 incident log shows "282 holes in [0,968954]" as a normal state). At `h = H` `read_idx_rec` returns an all-zero record, `file_no = 0 ≠ F` → `.cmpdone` → `ftruncate(F, new_off)`: every block of F stored after H's slot is destroyed while its index record still points into F. The catch-up then reads a short block ("hole/short block … stopping catch-up short") at the first destroyed height, and the hole-fill cannot re-fetch it because the record is non-zero. If F is `blk00000.dat` (F == 0) the zero record "matches", `size = 0`, and a bogus 8-byte frame from offset 0 is copied over the compacted stream instead.
- Failure scenario B (non-monotonic above `ph`): heights `ph..ph+k` live in F, `ph+k+1` in F+1, `ph+k+2` back in F (parallel downloader interleaving). The loop stops at `ph+k+1`, truncates F, and destroys `ph+k+2`.
- Core reference: `BlockManager::FindFilesToPrune`/`UnlinkPrunedFiles` delete whole files only when every block in the file is below the prune target (per-file `nHeightFirst/nHeightLast`); Core never re-packs a file.
- Suggested fix: extend both guards to the whole index (`archive_layout_monotonic(tip)`, `archive_first_hole(tip)`), or better, retire the in-place compaction and always use `archive_prune_file_granular` (which already mirrors Core's whole-file rule and needs neither assumption).
- Verdict: CONFIRMED.
- Test coverage: `tests/test_prune.c` uses fully populated, monotonic fixtures; `tests/test_prune_nonmonotonic.c` exercises only the file-granular path.

##### STO-5 (MEDIUM) — `submitblock` connect uses the unlocked `store_append` with a stale `cur_file_pos`
- Location: `asm/daemon/main.c:5034` `store_append(store_buf, bh, sblk, slen)`; `asm/bitcoin_store.asm:958-1075` (`store_append` seeks to `st+32` and takes no flock); `store_append_shared_x` (`bitcoin_store.asm:1129-1290`) and `idxscan_append_locked` (`bitcoin_idxscan.asm:255-345`) never write `st+32`.
- Description: every other live writer (worker legs via `node_sync_multi` → `idxscan_append_locked`; inbound serve children via `bitcoin_serve.asm:789`; catch-up workers via `store_append_shared`) appends at `SEEK_END` under `append.lock`. `store_append` instead writes at the in-memory `cur_file_pos`, which is refreshed only by `store_reload`/`store_append`/`store_truncate_to`, and ignores the lock. `store_reload` itself derives `cur_file_pos` from the tip record's end, which is wrong when the tip is not the physically last frame (non-monotonic tails; `archive_reindex.c` re-appends the tip precisely to work around this).
- Failure scenario: worker's last `store_reload` happened at the start of the previous `utxo_live_catchup`. An inbound serve child appends network block T+1 (under the lock) just before the miner's `submitblock` for height T+1 arrives; the worker still sees tip T and `applied == tip`, passes the dry run, and `store_append` writes the submitted block over the child's frame at the same file offset and over index record T+1. If the submitted block is larger than the child's, the tail of the write overruns block T+2's frame (if the child appended two); T+2's index record now points at a corrupted frame and catch-up fails there. With no flock the two writes can also interleave byte-wise.
- Core reference: `BlockManager::SaveBlockToDisk` under `cs_LastBlockFile`; one writer position.
- Suggested fix: route `submitblock` (and `main.c:754`) through `idxscan_append_locked`; delete or quarantine `store_append` for empty-store use only (genesis injection).
- Verdict: CONFIRMED (mechanism); the race window is narrow.
- Test coverage: none for concurrent submitblock + inbound append.

##### STO-6 (MEDIUM) — `cfheaders`/`cfcheckpt` malformed when the count is rewritten; clamp semantics differ from Core
- Location: `asm/daemon/serve_cfilters.c:159-186` (kind 1) and `:190-212` (kind 2); range clamp `:133-134`.
- Description: (a) the reply is laid out with `varint(n)` at width `nw`, hashes start at `hdr_end = w + nw`; when fewer entries are available, `cf_put_varint(out + w, got)` rewrites the count *in place* without moving the hashes. If `n ≥ 253` but `got < 253` the new varint is 1 byte and 2 stale bytes remain between it and the first hash: the payload is unparseable. Reachable whenever the filter index lags the tip by more than ~100 blocks (adoption pending, or STO-3's gap close having closed the index) and a peer asks for a range crossing the lag. (b) `getcfheaders` is clamped to 1000 while Core's `MAX_GETCFHEADERS_SIZE` is 2000, and both clamps keep the *original* `stop_hash` in the reply while returning fewer entries, so a compliant client (which checks `count == stop_height − start_height + 1`) rejects the message and disconnects. (c) When `start−1`'s filter is not in the index, `prev` is silently zero (line 168-172) instead of refusing.
- Core reference: `ProcessGetCFHeaders`/`PrepareBlockFilterRequest` (net_processing.cpp): oversize requests → `Misbehaving` + disconnect; `MAX_GETCFILTERS_SIZE = 1000`, `MAX_GETCFHEADERS_SIZE = 2000`; a reply always covers exactly `[start, stop]`.
- Suggested fix: build the header after the hashes are counted (write hashes into a temp region, then emit varint + memmove), refuse rather than partially answer, and use 2000 for cfheaders.
- Verdict: CONFIRMED.
- Test coverage: none hermetic (`validation/p2p_inbound_probe.py` is a live probe of the happy path).

##### STO-7 (MEDIUM) — Mempool not reconciled after a reorg
- Location: `asm/daemon/reorg.c:801-812` (explicit "mempool NOT reconciled" with a stale rationale: the shared mempool `mp_ext_area` now exists in the worker, see `main.c:5510-5516`); `reorg_mempool_reconcile` has no caller outside tests.
- Description: after `reorg_execute`, the choke point processes only heights `last_seen_tip+1 .. now_tip`. Transactions confirmed only on the losing branch are never re-offered to the pool (Core's `disconnectpool`), and transactions in replacement blocks at heights `≤ last_seen_tip` are never removed (`tx_accept_block_connect_h` is not called for them). If the reorg does not raise the tip (same-height replacement, possible across a retarget boundary), nothing fires at all.
- Failure scenario: the pool retains transactions already confirmed on the new branch; `getblocktemplate` built from the pool includes them and the resulting block is invalid (spends already-spent prevouts). PLAUSIBLE — I did not read the template builder to confirm it does not re-check prevouts against the set. Transactions from the losing branch are lost to relay until re-broadcast.
- Core reference: `Chainstate::DisconnectTip` → `disconnectpool.addTransaction`; `UpdateMempoolForReorg`; `ConnectTip` → `removeForBlock` for every connected block.
- Suggested fix: call `reorg_mempool_reconcile` (already tested) from `reorg_execute`'s caller with the disconnected blocks, and run the choke-point loop from `fork_height+1` after a reorg (`last_seen_tip = fork_height`).
- Verdict: CONFIRMED (unwired); GBT impact PLAUSIBLE.
- Test coverage: `tests/test_reorg.c` tests `reorg_mempool_reconcile` in isolation only.

##### STO-8 (MEDIUM) — `getblockfilter` fallback serves a prevout-less filter for a block whose undo file is absent
- Location: `asm/rpc_chain.c:3160-3180`: `ur = g_undo_replay(h, …)`; refusal only on `ur < 0`. `undo_replay` returns 0 for ENOENT.
- Description: the error text promises "no filter is served rather than a wrong one" for blocks outside the undo window, but the absent-file case returns 0 records, not −1, so the filter is built from outputs only and returned with a header computed from the *wrong* filter. Reached whenever the persistent index does not cover `h` (index not built, or shorter than `h`) and `h` is below `tip−200` (or is a block whose undo was pruned).
- Core reference: `getblockfilter` errors with "Filter not found" when the index has no entry; it never constructs one ad hoc.
- Suggested fix: treat `ur == 0` with a non-zero non-coinbase input count as "unavailable" (count inputs from the block, as `utxo_live_can_unapply` does).
- Verdict: CONFIRMED.
- Test coverage: none.

##### STO-9 (LOW) — `headers.dat` is not rewound on reorg
- Location: `asm/daemon/reorg.c` (no `hst_*` call); `dl_header_mirror_topup` (`main.c:3077-3090`) only appends above `hst_count`.
- Description: after a reorg the mirror keeps the losing branch's headers at `fork+1..old_tip`, and the top-up appends the new blocks above `old_tip` (whose `prev` does not link to the mirror's entry at `old_tip`). `archive_trim_derived_tails` repairs it on the next boot. Runtime consumers are limited to the RPC headers count (FEATURE_GAPS line 663) and the boot header sync, so impact is a wrong `getblockchaininfo.headers`/header-by-height until restart.
- Suggested fix: truncate `headers.dat` to `(fork_height+1)*112` in `rebuild_hash_index_after_reorg` and let the top-up re-derive.
- Verdict: CONFIRMED.
- Test coverage: none.

##### STO-10 (LOW) — Forked serve children keep a pre-reorg hash→height table
- Location: `asm/daemon/main.c:347` (`serve_idx_topup` adds heights ≥ `g_htidx_next` only), `:382-405` (parent rebuild).
- Description: a long-lived inbound child forked before the reorg maps the losing-branch hashes to `fork+1..old_tip` and never learns the replacement hashes at those heights. A `getdata` for a losing-branch hash returns the replacement block (wrong block for the requested hash — Core drops unrequested blocks and may score the peer); a `getdata` for a replacement hash at `h ≤ old_tip` yields `notfound`.
- Suggested fix: version the index (parent bumps a generation in shared status on reorg; child rebuilds when it sees a change) or verify `block_hash(served) == requested` before sending.
- Verdict: PLAUSIBLE (I did not trace the child's request path end to end).
- Test coverage: none.

##### STO-11 (LOW) — No fsync on archive appends and no per-block checksum
- Location: `asm/bitcoin_store.asm:958-1290` (no syscall 74/75 anywhere in the store; only `archive_repair_duplicates` fsyncs, `archive_verify.c:183`).
- Description: the frame is `[len][magic][block]` with no checksum; a block's index record is written after its bytes but neither is flushed. On power loss the index record can persist while the block bytes are unwritten (different files, no ordering), leaving a record over zeros. `archive_check` (`checkblocks=6`, level 3) detects "bad frame magic"/hash mismatch at boot but only logs (`main.c:7107-7113`); `archive_trim_derived_tails` only validates records above the chainwork count, and `reorg_chainwork_sync` will happily append zero work for an all-zero header, so the bad record is never cut. Catch-up then stops at that height every boot ("hole/short block") with no self-heal. ENGINEERING.md §5.3 describes the design as durable via append-only + positional layout, which does not cover this.
- Core reference: `FlushBlockFile` fsyncs the block file before the index is updated; the index is only pointed at flushed data.
- Suggested fix: `fdatasync(blk)` before the index write on the tip path (cheap at tip rate), and extend the boot self-heal to zero (hole) any tail record whose frame magic/hash does not match, so the catch-up refetches it.
- Verdict: CONFIRMED.
- Test coverage: `test_archive_check` pins detection, nothing pins repair.

##### STO-12 (LOW) — No minimum-retention floor when pruning; no prune/txindex guard
- Location: `asm/daemon/archive_verify.c:512-535` (`archive_prune_height_for_budget`), `reorg.h:29` (`REORG_MAX_DEPTH 100`), `utxo_live.c:137` (`UTXO_UNDO_WINDOW 200`), `node_config.c:671-677`.
- Description: the retained height is purely budget-driven. Core keeps at least `MIN_BLOCKS_TO_KEEP = 288` regardless of budget; here a 550 MiB budget of 4 MB blocks retains ~137 blocks, inside the undo window and near the reorg depth cap; `reorg_execute`'s pre-flight then refuses (`read_stored_block` returns −3) for any fork below the prune height, and `reorg_chainwork_sync` records zero work for pruned heights. Not corrupting (fail-closed), but a pruned node can be stuck on a losing branch. Core also refuses `-prune` with `-txindex`; here `txindex.dat` is rebuilt offline and the reader verifies against the archive, so a pruned block just fails the lookup — acceptable, but undocumented.
- Suggested fix: floor `ph` at `tip − max(288, UTXO_UNDO_WINDOW)`; document the txindex interaction in FEATURE_GAPS.
- Verdict: CONFIRMED.
- Test coverage: none.

##### STO-13 (INFO) — Chainwork is 128-bit
- Location: `asm/bitcoin_chainwork.asm:334-475`.
- `block_work = (~target / (target+1)) + 1` truncated to the low 128 bits; `chainwork_add` is a plain add/adc with no saturation; `chainwork_cmp` compares high limb then low. Mainnet cumulative work is ~2^97, per-block ~2^80; overflow needs a target below 2^128, which `pow_check` cannot pass at real difficulty and `bad-diffbits` (`reorg_analyze`) rejects before work is summed. Tie-break: `chainwork_cmp(cand, ours) > 0` is required, so equal work keeps the first-seen chain (matches Core's `CBlockIndexWorkComparator` + `nSequenceId`). Core uses `arith_uint256`; the difference is not reachable but worth a saturating add for defence in depth.
- Verdict: CONFIRMED (correct as used).

##### STO-14 (INFO) — Element dedup on the 64-bit SipHash rather than script bytes
- Location: `asm/block_filter.c:196-206`.
- Core's `GCSFilter` dedups the element *set* (byte-wise) before hashing and uses that count as N. Here dedup is on the raw SipHash output; two distinct scripts colliding on 64 bits would yield N one less than Core's and a different filter. Probability ~n²/2^65 per block — negligible, but note the KAT-backed "byte-identical" claim carries this caveat.
- Verdict: CONFIRMED.

#### Verified-correct controls
- Fork choice requires strictly greater cumulative work and `-minimumchainwork` (`reorg.c:614-624`); equal work → no reorg (first-seen). Candidate headers get PoW + linkage (`headers_chain_valid`, `reorg.c:409-421`), nBits schedule (`pow_check_bits`, `reorg.c:490-503`), depth cap `REORG_MAX_DEPTH=100 ≤ UTXO_UNDO_WINDOW=200`, fork-point re-assert (`reorg.c:565-572`).
- Nothing destructive before staging: every replacement block is downloaded, hash-matched to its header and `cons_verify`'d into `reorg_stage.dat` first (`reorg.c:1077-1105`); undo completeness is proven per height by record count == input count (`utxo_live_can_unapply`, utxo_live.c:1477-1497) before the point of no return.
- Disconnect order is LIFO across blocks (`reorg.c:695`); within a block restore-then-delete gives the correct set for same-block spend chains (`utxo_live.c:1737-1766`); coinbase flag and creation height are restored from the undo record (`undo_restore_cb`, utxo_live.c:1504-1512; capture at `undo_capture_and_del`).
- The append lock is held for the whole reorg and the reconnect uses the `_nolock` append so the hold is not dropped (`reorg.c:660-670`, `bitcoin_store.asm:1097-1127`); `store_validates_prevhash` gates every reconnected block (`reorg.c:772`).
- `store_truncate_to` refuses a non-monotonic archive (`store_layout_monotonic`, `bitcoin_store.asm:1362-1420`) and `archive_truncate_safe` falls back to the index-only truncate (`archive_verify.c:299-306`); the incident that motivated it is pinned by `test_truncate_guard*`, `test_archive_truncate_nonmonotonic`.
- Reorg rolls the index tails back: `txit_on_truncate`, `tsp_on_truncate` (watermark), `axt_on_truncate` (physical truncate by height, `addr_index_tail.c:312-331`), `bfi_on_truncate` (records + data + header count, `bfilter_index.c:302-322`); coinstats folds unapply events incrementally (`csi_on_add/remove`).
- Undo torn-tail handling: strict reader for the reorg pre-flight, tolerant reader for boot recovery only (`undo_log.c:170-215`, mirrored in `bitcoin_undo.asm`, differential-tested by `test_undo_asm_diff`); `undo_discard` after unapply prevents O_APPEND prepend contamination.
- Ghost-run recovery is multi-block and descending (`utxo_live_recover_partial_block`, utxo_live.c:1677-1720); checkpoint is tmp+fsync+rename.
- Boot self-heal (`archive_trim_derived_tails`, `archive_verify.c:800-905`) cuts zero tails, unlinked records above the chainwork count, a diverged header mirror, and over-long chainwork — pinned by `test_archive_trim`; duplicate-hash repair zeroes records instead of truncating (`archive_repair_duplicates`).
- Prune refuses below a sync hole (`ARCHIVE_PRUNE_REFUSE_HOLE`, `archive_verify.c:551-555`, `main.c:7183-7187`) and the file-granular path never touches the tip's file, marks records with the 0xFFFFFFFF sentinel that `store_get_at` honours (`bitcoin_store.asm:412-436`).
- 64-bit offsets throughout (`data_pos` u64 in the record, `pread64` with `r10`, `off_t` in C); file numbers/positions bounded by the 128 MiB rollover; index arithmetic uses `imul rax, 48` on 64-bit heights.
- fd hygiene: `open_file` closes the previous descriptor; the read cache is direct-mapped 8 slots (`bitcoin_store_fast.asm`); the mmap cache 4 slots; `reorg.c` keeps one header fd and closes it; `serve_cfilters` opens three fds per request and closes them; `undo_log.c` keeps one fd across a block.
- BIP158 constants and element rules: P=19, M=784931, SipHash key = first 16 bytes of the block hash, empty and OP_RETURN scripts excluded, coinbase input excluded (no undo record), Golomb-Rice quotient unary + 19-bit remainder, `CompactSize(N)` prefix, header chain `sha256d(sha256d(filter)||prev)` with zero genesis prev (`block_filter.c`), KAT against blocks 501726/700038 (`test_block_filter`).
- `bfilter_index` writes data before record before count and reconciles the smaller of header count vs file size at open (`bfi_open`, `bfilter_index.c:81-116`); adoption judged against the chain tip, not the burst height.
- Hash index keyed in wire order (`idx_build_from_file`), probe budget bounded, full 32-byte compare (`bitcoin_idx.asm`); `idxscan_append_locked` enforces prev-links-to-tip inside the critical section (incident #46).

#### Coverage and limits
- I did not read the LSM (`bitcoin_utxo_lsm.asm`) or `apply_block_at`; STO-1's consequences assume the WAL writes in `undo_restore_cb`/`del_created_on_output` are durable before the crash, which the file's own comments state.
- I did not trace the serve child's getdata path or the template builder, hence STO-10 and the GBT half of STO-7 are PLAUSIBLE.
- `bitcoin_headers.asm` (hst_*) was not read; STO-9's runtime impact is inferred from FEATURE_GAPS and the absence of `hst_` callers in the serve/reorg paths.
- Next: write a fault-injection test for the disconnect loop (kill after k unapplies, reboot, compare the set to a reference), a >64 KiB filter KAT built twice into one buffer, a prune fixture with a hole above `ph`, and a cfheaders test where the index is shorter than the requested range with `n ≥ 253 > got`.


---

### 6.6 P2P networking, transport, address management, peer policy, IBD — review

**Scope**

Files fully read: `asm/bitcoin_net.asm`, `asm/bitcoin_p2p.asm`, `asm/bitcoin_serve.asm`, `asm/bitcoin_cmpct.asm`, `asm/bitcoin_addrmgr.asm`, `asm/bitcoin_addr.asm` (wallet address helper, not networking), `asm/crypto_bip324.c/.h`, `asm/crypto_bip324_fs.c/.h`, `asm/crypto_bip324_transport.c/.h`, `asm/crypto_ellswift.c/.h`, `asm/crypto_ellswift_ecdh.c`, `asm/crypto_ellswift_enc.c`, `asm/crypto_hkdf.c` (first 80 lines), `asm/daemon/v2transport.c`, `dialer.c`, `netaddr.c`, `netperm.c`, `net_policy.c`, `net6.c`, `subnet.c`, `socks5.c`, `i2psam.c`, `torcontrol.c`, `addr_ingest.c`, `addr_self.c`, `addrbook.c`, `serve_addr.c`, `serve_invbounds.c`, `upload_cap.c`, `txrecon.c`, `private_broadcast.c`, `relay_policy.c`, `minchainwork.c`.
Also read (outside the listed set, because the P2P logic lives there): `asm/daemon/main.c` lines 447-460, 640-700, 955-1330, 1584-1812, 1913-1940, 1978-2200, 2509-2600, 2780-3345, 6189-6527; `asm/daemon/tx_relay.c` 515-531, 787-852, 1028-1245; `asm/bitcoind.asm` 92-420 (both handshakes), 514-760 (`node_sync_multi`), 1620-1700 (`node_ibd_blocks` guard); `asm/bitcoin_hash.asm` 100-260 (`diff_target`/`pow_check`); `asm/daemon/utxo_live.c` 1059-1145; `asm/daemon/reorg.c` 395-445; `docs/devlog/INCIDENT_2026-09-01_header_sync_genesis_answer.md`.
Files skimmed (first 30 lines, standalone tools not linked into `daemon/bitcoind` per `DAEMONSRCS` in `asm/Makefile:2543`): `addrgather.c`, `asmap.c` (header comment only), `crawler.c`, `discover.c`, `seedprobe.c`, `peertest.c`, `testpeer.c`, `inbound_client.c`, `liveclient.c`, `multipeer.c`, `paribd.c`, `paribd_asm.c`, `unified_ibd.c`, `blk_submit.c`.
Not read: `asm/crypto_chacha20.c`, `asm/crypto_poly1305.c` (AEAD internals; constant-time tag compare not verified), `asm/bitcoin_idxscan.asm` beyond the `idxscan_append_locked` link check, `asm/daemon/reorg.c` beyond the header-validity section, the rest of `main.c`/`tx_relay.c`/`bitcoind.asm`.

**Summary**

The framer, BIP324 cipher/key schedule, ElligatorSwift, SOCKS5/Tor/I2P plumbing, relay-policy gates and the per-response address quotas are carefully done and mostly match Core. Both prior-audit items re-verify: the 4 MB announced-length cap is enforced before the drain (`bitcoin_net.asm:567`), and misbehaviour scoring has real callers (`bitcoin_serve.asm:1602-1650`, `main.c:1182-1200`). The serious problems are in what the serve loop and the boot header fetch *accept*: a remote out-of-bounds write in the `getblocktxn` index parser (NET-1), a CPU-burning infinite loop in the BIP324 responder's v1 detection (NET-2), no inbound inactivity timeout or eviction (NET-3), a boot header fetch that stores peer headers with no proof-of-work check and no count bound (NET-4), and an inbound `block` path that appends to the durable archive after only `cons_verify` + prev-hash, with a `pow_check` that accepts nBits Core rejects (NET-5/6). Compact-block serving only works for blocks under 253 transactions and there is no compact-block receive path at all, contrary to README/FEATURE_GAPS (NET-9). Confidence is high on the parser/loop findings (traced end to end); the archive-pollution consequences of NET-5 are traced to the append and marked PLAUSIBLE beyond it.

#### Findings

| ID | Severity | Location | Title | Verdict |
|---|---|---|---|---|
| NET-1 | HIGH | `asm/bitcoin_serve.asm:1441-1503` | `getblocktxn` index parser writes up to 65535 u16 entries into a 1024-byte static (`s_idxbuf`) — remote OOB write | CONFIRMED |
| NET-2 | HIGH | `asm/daemon/v2transport.c:205-235` | BIP324 responder v1-detection loop spins forever at 100% CPU on a partial v1 prefix; the 8 s timeout never fires | CONFIRMED |
| NET-3 | HIGH | `asm/daemon/main.c:6411-6482`, `asm/bitcoin_net.asm:149-188`, `asm/bitcoind.asm:267-300` | Inbound connections have no read/inactivity timeout and there is no eviction: `CFG_INBOUND_LIMIT` idle sockets block all inbound service | CONFIRMED |
| NET-4 | HIGH | `asm/daemon/main.c:2951-3034` (`dlc_fetch_headers`), `main.c:2829-2860` (`dlc_span`) | Boot header fetch stores peer headers with no PoW, nBits or chain-work check and no count bound; a zero-work header chain of any length is accepted and drives `index.dat` growth and 16 download workers | CONFIRMED |
| NET-5 | HIGH | `asm/bitcoin_serve.asm:672-812` (`.do_block`) | An inbound `block` push is appended to the durable archive after `cons_verify` + prev-hash only: no nBits schedule, no timestamp/MTP, no contextual checks. Core rejects at `AcceptBlockHeader`/`ContextualCheckBlockHeader` | CONFIRMED (append), PLAUSIBLE (stall/reorg consequences) |
| NET-6 | MEDIUM | `asm/bitcoin_hash.asm:110-175, 196-250` | `diff_target`/`pow_check` lack Core's negative-mantissa, overflow and powLimit checks; exponents ≥ 32 write below the target buffer on the stack | CONFIRMED |
| NET-7 | MEDIUM | `asm/bitcoin_serve.asm:831-850` | `getdata` still parses a single-byte count with no payload bound — the bug fixed for `inv` on 2026-08-30; >252-entry getdata from Core is misparsed; the 09-02 audit's "inv/getdata scored" statement is wrong for getdata | CONFIRMED |
| NET-8 | MEDIUM | `asm/bitcoin_serve.asm:1085-1111` | `getheaders` uses only the first locator hash; unknown first hash → serve 2000 headers from genesis (the served-side mirror of the 09-01 incident); stop hash ignored | CONFIRMED |
| NET-9 | MEDIUM | `asm/bitcoin_cmpct.asm:510-538, 548-570, 679-683`; `asm/bitcoin_serve.asm:383-411` | BIP152 serve side only handles blocks with < 253 txs (tx count read as one byte); `cmpctblock` is not dispatched at all on receive; README/FEATURE_GAPS claim "both directions, full message handling" | CONFIRMED |
| NET-10 | MEDIUM | `asm/daemon/addrbook.c:399-422`, `addr_ingest.c:82-103`, `main.c:6189-6210` | Address manager is a flat 65536-entry book with oldest-`last_seen` eviction; no tried/new split, no source-group bucketing, no collision/terrible logic; attacker-supplied timestamps evict legitimate entries | CONFIRMED |
| NET-11 | LOW | `asm/bitcoin_net.asm:552-595` | v1 framer never verifies the 4-byte payload checksum; Core disconnects on mismatch | CONFIRMED |
| NET-12 | LOW | `asm/crypto_bip324_transport.c:327-339` | A decoy packet received in `RECV_VERSION` is treated as the version packet; Core skips decoys and takes the first non-decoy | CONFIRMED (benign today) |
| NET-13 | LOW | `asm/bitcoind.asm:296-303, 150-160` | Version messages > 256 bytes fail the handshake (Core allows UA up to 256 bytes, ≈350-byte version) | CONFIRMED |
| NET-14 | LOW | `asm/bitcoin_serve.asm:899-905` | Compact-block short-id nonce is a fixed constant (`0x0123456789abcdef`); Core draws a random nonce per block | CONFIRMED |
| NET-15 | LOW | `asm/daemon/main.c:3196` | `dlc_worker` hardcodes the mainnet magic into every archive frame it writes, on every chain | CONFIRMED |
| NET-16 | INFO | `asm/daemon/net_policy.c:293`, `addr_ingest.c:180` | Feeler/block-relay handshakes and the seednode gather impersonate Bitcoin Core user agents | CONFIRMED |
| NET-17 | INFO | `asm/daemon/main.c:1182-1200, 6368-6380` | Onion/I2P inbound violations score `"onion-inbound"` / a b32 name as an IP and add an unparseable `/32` to the shared ban list | CONFIRMED |

##### NET-1 (HIGH) — `getblocktxn` index parser overflows `s_idxbuf`
- Location: `asm/bitcoin_serve.asm:1441-1503`; buffer at `:145` (`s_idxbuf: times (512*2) db 0`).
- Description: `.do_getblocktxn` reads the CompactSize count at `pl_buf+32` (`:1462-1474`, accepting the 0xfd form → up to 65535) and then, for every index, does `mov word [s_idxbuf + rdx*2], ax; inc qword [s_idxn]` (`:1496-1498`) with no comparison against the 512-entry capacity. The cursor `rbx` is also never compared with `s_plen`, so a short message parses stale bytes from earlier traffic. The only precondition is that the 32-byte hash names a block we hold (`node_serve_block_by_hash`, `:1450-1457`).
- Failure scenario: a peer sends `getblocktxn` for any known block with count 0xfd 0xff 0xff and 65535 one-byte diffs. The loop writes 131070 bytes starting at `s_idxbuf`, running over `s_diffshift`, `s_blen_spill`, `s_txptr`, `s_txlen`, `s_j` (`:146-150`) and 130 KB into `mp_area`/`mp_blob`. `s_blen_spill` (the block length handed to `block_tx_at`) now holds four attacker-chosen 16-bit values as one 64-bit length; `block_tx_at` (`bitcoin_cmpct.asm:548-621`) walks `sb_buf` with that bogus bound, `tx_parse` returns garbage lengths, and `memcpy_len` (`:1538-1546`) copies `s_txlen` bytes into `bt_buf` — a crash of the serve child at best, a controllable overwrite of the .data segment at worst. Even without corruption, the u16 truncation (`ax`) lets indexes wrap past 65536, so with a legal 512-entry request repeated indexes are impossible but with the overflow they are not.
- Core reference: `BlockTransactionsRequest` deserialisation caps each index at `MAX_SIZE`, rejects `offset > uint16 max`, and `ProcessGetBlockTxn` rejects `req.indexes.size() > block.vtx.size()` with `Misbehaving(100, "getblocktxn with out-of-bounds tx indices")`.
- Suggested fix: bound `s_idxn` to 512 (or to `block_txcount`) before every store, bound `rbx` against `pl_buf + s_plen`, reject the message (and score it) when a diff would exceed the block's transaction count, and reject a 32-bit index. Sizing `s_idxbuf` for `SERVE_TXID_CAP` would also be appropriate.
- Verdict: CONFIRMED.
- Test coverage: `tests/test_bip152_loop.c:96` requests indexes [1,3] only; no test sends a count above 512 or a truncated request.

##### NET-2 (HIGH) — BIP324 responder spins forever on a partial v1 prefix
- Location: `asm/daemon/v2transport.c:205-235`; called from the forked inbound child at `main.c:6432` with `timeout_ms = 8000`.
- Description: the peek loop polls for `POLLIN`, `recv(MSG_PEEK)` up to 16 bytes, and `continue`s when `n <= peeked` (`:226`) without touching `elapsed`. `advance()` stays in `BIP324_RECV_MAYBE_V1` while the peeked bytes match the v1 prefix but are fewer than 16 (`crypto_bip324_transport.c:251-266`). Peeked bytes remain in the receive queue, so `poll` returns immediately every iteration.
- Failure scenario: a peer connects and sends `f9 be b4 d9 76 65 72 73` (8 bytes of `magic || "vers"`) and nothing else. The child loops `poll → recv(PEEK) → continue` with no sleep, pinning one core indefinitely; `g_inbound_n` counts it as an inbound slot. N such connections pin N cores and consume N of the ~189 inbound slots (`CFG_INBOUND_LIMIT`, `main.c:803`) with no timeout. A legitimate v1 peer whose version header is split across two TCP segments spins the same way until the second segment lands.
- Core reference: `V2Transport::ProcessReceivedMaybeV1Bytes` is fed by the socket handler with real reads; Core additionally enforces `PEER_CONNECT_TIMEOUT`/`m_connected`-based handshake timeouts (`net.cpp InactivityCheck`).
- Suggested fix: when `n <= peeked`, sleep the poll slice and charge it to `elapsed` (or poll on a separate 1-byte-more condition), and put an overall deadline on the whole handshake independent of `poll` results.
- Verdict: CONFIRMED.
- Test coverage: `tests/test_v2transport.c:150-181` writes a complete v1 `version` in one call; no partial-prefix test.

##### NET-3 (HIGH) — no inbound inactivity timeout, no eviction
- Location: `main.c:6411-6482` (accept + fork), `main.c:447-457` (`peer_sock_buffers` sets only SO_RCVBUF/SO_SNDBUF), `bitcoind.asm:267-300` (`node_accept_handshake` blocks in `p2p_read`), `bitcoin_net.asm:149-188` (`fd_read_full` loops on `read` with no poll), `bitcoin_serve.asm:369-379`.
- Description: an accepted socket gets no `SO_RCVTIMEO`, no `alarm`, and the parent has no per-child handshake or idle deadline; `serve_mux` refuses new connections at the cap instead of evicting (`main.c:6455-6470`). With `v2transport=1` the v2 peek phase has an 8 s deadline only for a peer that sends *nothing*; after the 16-byte v1 prefix (or any complete v1 `version`) the child blocks in `read(2)` forever.
- Failure scenario: an attacker opens `CFG_INBOUND_LIMIT` TCP connections, sends a v1 `version` on each and then idles. Every child sits in `fd_read_full` indefinitely; the parent logs "inbound at capacity" and refuses every honest peer until the attacker closes. Cost to the attacker: ~189 idle sockets.
- Core reference: `CConnman::InactivityCheck` (20-minute `TIMEOUT_INTERVAL`, 60 s if no `version`), ping timeouts, and `AttemptToEvictConnection` which frees a slot for a new inbound by evicting the least valuable peer while protecting long-lived, low-latency and per-netgroup peers.
- Suggested fix: `SO_RCVTIMEO` (or poll-with-deadline) on accepted sockets, a handshake deadline in the child, a ping/pong-based inactivity check in `node_serve_loop`, and an eviction pass in the parent when at capacity.
- Verdict: CONFIRMED.
- Test coverage: `tests/test_net_timeouts.c` covers outbound `tcp_connect_ip` timeouts; nothing pins inbound idle behaviour.

##### NET-4 (HIGH) — boot header fetch verifies neither PoW nor length
- Location: `main.c:2951-3034` (`dlc_fetch_headers`), `main.c:2892-2898`, `main.c:2829-2860` (`dlc_span`), `main.c:2790-2830` (`DLC_HDR_SANE_MAX` comment: "How many headers FOLLOW is not limited").
- Description: each received header page is checked for attachment to a locator point, identical overlap, prev-hash linkage and `txn_count == 0`, then `hst_append`ed. `pow_check` is never called (grep confirms no `pow_check` reference in `main.c`'s header path or in `bitcoind.asm`), nBits is not compared with the schedule, cumulative work is not computed, and `minimumchainwork` is consulted only in `reorg.c:597-602`. The store then drives `dlc_span` (index pre-sizing to `hdr_len`) and 16 `dlc_worker`s.
- Failure scenario: whichever probed peer answers the boot `getheaders` first (`dlc_headers`, `main.c:3094-3160`; candidates come from the address book, which NET-10 shows is attacker-influenceable) sends pages of headers whose `prev` chains from our tip but whose nBits/hash are arbitrary. 2000 headers per page, 1000 rounds → up to 2 M zero-work headers accepted in one boot. `dlc_span` grows `index.dat` by 48 bytes per header and the workers spend the run requesting blocks nobody has, banning honest peers as "dead weight" (`main.c:3300-3316`). This is exactly the 09-01 incident with hostile intent replacing an honest peer's genesis answer; the linkage/overlap guard does not stop it. Recovery relies on the next boot's `archive_trim_derived_tails`.
- Core reference: `AcceptBlockHeader` → `CheckBlockHeader` (PoW) → `ContextualCheckBlockHeader` (nBits, timestamp), plus `HeadersSyncState` pre-sync with commitments and the `nMinimumChainWork` gate before storing any header.
- Suggested fix: `pow_check` every header before appending; run `pow_check_bits` (the shared rule engine) per header once its height is known; accumulate work and refuse to extend `index.dat` past a header chain whose work does not exceed ours (and `minimumchainwork`); bound headers per session unless work-justified.
- Verdict: CONFIRMED.
- Test coverage: `tests/test_dialhelper.c` §5/§6 pin continuation/genesis-refusal/overlap/fork; none feeds a header failing PoW.

##### NET-5 (HIGH) — inbound block push lands in the archive without contextual checks
- Location: `asm/bitcoin_serve.asm:672-812`; `asm/bitcoin_cons.asm:6,48` (`cons_verify` = `pow_check` + parse + coinbase + merkle); `asm/bitcoin_idxscan.asm:274-321` (`idxscan_append_locked`).
- Description: any inbound peer may send `block`; the loop runs `cons_verify`, rejects duplicates via `idx_get`, requires `store_validates_prevhash` (block's prev == our tip) and then `idxscan_append_locked` writes it at tip+1 in the durable archive and `index.dat`. Nothing checks nBits against the schedule, the timestamp against MTP/2 h, block weight, or the witness commitment at this layer (the serve-side comment at `:703-709` acknowledges deliberately not *scoring* invalid blocks, but the block is still *stored*). `pow_check` only compares the hash against the header's own target (NET-6), so an attacker sets nBits to `0x207fffff` and mines the block in microseconds.
- Failure scenario: a peer pushes a syntactically valid block with prev = our tip, nBits = `0x207fffff`, one coinbase. It is appended as tip+1. `utxo_live` later rejects it with `bad-diffbits` (`utxo_live.c:1139-1144`), so UTXO application stops at that height; the legs' real tip+1 (whose prev is the *old* tip) is refused by `idxscan_append_locked`'s "tip+1 must link to the tip" rule (`bitcoin_idxscan.asm:291-300`) — the node stalls until the reorg probe (`main.c:5252-5280`) recognises the honest chain as heavier and reorgs out a block that was never applied. Meanwhile `getblock`/`getdata` serve the bogus block by hash, and `node_announce_tip` (`bitcoin_serve.asm:1571-1589`) announces it to every inbound peer, whose Core nodes will reject it and score us. The stall/reorg path was not traced end to end (PLAUSIBLE); the archive append is CONFIRMED.
- Core reference: `ProcessNewBlock` → `AcceptBlockHeader` (`ContextualCheckBlockHeader`: `bad-diffbits`, `time-too-old`, `time-too-new`) before `AcceptBlock` stores anything; unsolicited blocks with unknown parents are ignored.
- Suggested fix: run `pow_check_bits` and the timestamp checks (the same rule engine `utxo_live` and `reorg_analyze` use) in `.do_block` before `idxscan_append_locked`, or route inbound blocks through the download worker's validation path instead of appending from the serve child.
- Verdict: CONFIRMED (append) / PLAUSIBLE (downstream stall).
- Test coverage: `tests/test_serve.c` pushes valid blocks only.

##### NET-6 (MEDIUM) — `pow_check` accepts nBits Core rejects; OOB stack write for large exponents
- Location: `asm/bitcoin_hash.asm:110-175` (`diff_target`), `:196-250` (`pow_check`).
- Description: `diff_target` builds `mantissa << 8*(exp-3)` into a 32-byte big-endian buffer. It does not check the mantissa sign bit (comment at `:120` says "-> 0 (invalid)" but no code does it), does not detect overflow, and `pow_check` never compares against `powLimit`. For `exp-3 >= 30` the 3-byte write at `target[31-(exp-3)]` and the two bytes below it land before the buffer (`:150-165`); for `exp = 0xff` the write is ~220 bytes below `rsp`.
- Failure scenario: nBits `0x1d80ffff` (negative in Core) or `0x21ffffff` (overflow in Core) yields a huge positive target here and any hash passes. Paths that do not run the schedule (NET-4 header fetch, NET-5 `.do_block`, `reorg.c:418-431 headers_chain_valid`) accept such headers; paths that do (`utxo_live`, `reorg_analyze`) reject them as `bad-diffbits`. The below-buffer write is in this function's own frame for exponents 32-34 and below `rsp` beyond that — harmless today (no call follows), but undefined.
- Core reference: `CheckProofOfWork`: `fNegative || bnTarget == 0 || fOverflow || bnTarget > powLimit` → false.
- Suggested fix: implement Core's four checks in `diff_target`/`pow_check`; clamp `exp` before writing.
- Verdict: CONFIRMED.
- Test coverage: none for negative/overflow nBits.

##### NET-7 (MEDIUM) — `getdata` count parsed as one byte, unbounded walk
- Location: `asm/bitcoin_serve.asm:831-850`; contrast `.do_inv` at `:489-501` which calls `serve_inv_bounds`.
- Description: `movzx rax, byte [pl_buf]` is the count; the loop walks `pl_buf+1+i*36` for `count` entries after checking only `plen >= 37`. `serve_inv_bounds` (`serve_invbounds.c`) is only wired to `inv`. The audit response of 2026-09-02 ("inv/getdata above MAX_INV_SZ … scored") is therefore inaccurate for getdata.
- Failure scenario: (a) Core requests 253+ transactions in one getdata (`MAX_GETDATA_SZ` = 1000): the 0xfd byte is read as count 253 and entries are misaligned by two bytes → 50 `notfound`s for garbage hashes and no transactions served. (b) A 37-byte getdata with count byte 0xff serves up to 255 entries assembled from whatever earlier messages left in `pl_buf` — the exact "peer-steered nonsense" `serve_invbounds.c:11-14` describes. No memory-safety impact (`pl_buf` is 8 MB).
- Core reference: `ProcessMessage("getdata")`: `vRecv >> vInv`, `if (vInv.size() > MAX_INV_SZ) Misbehaving`.
- Suggested fix: call `serve_inv_bounds` in `.maybe_getdata` exactly as `.do_inv` does; score `-1`.
- Verdict: CONFIRMED.
- Test coverage: `tests/test_serve.c:158-175` sends a multi-entry getdata with a one-byte count only.

##### NET-8 (MEDIUM) — `getheaders` answers from genesis when the first locator hash is unknown
- Location: `asm/bitcoin_serve.asm:1085-1111`.
- Description: only `pl_buf+5` (the first locator hash) is looked up; a miss sets `from = 0`. The remaining locator entries and the stop hash are ignored; `plen` is only checked to be ≥ 5, so a 5-byte message reads a stale hash.
- Failure scenario: every peer that is one block ahead of us (its locator starts with a hash we do not have — the incident report calls this "common, not rare") receives 2000 headers from genesis (162 KB) on each `getheaders`, instead of the headers after the last common block. A Core peer discards them as already known. This is pure waste plus a fingerprint; it also means `node_announce_tip`-triggered `getheaders` from Core peers get useless replies.
- Core reference: `FindForkInGlobalIndex` walks every locator entry and serves from the first one on the active chain; only when none matches does it start at genesis; `hashStop` honoured.
- Suggested fix: loop over `count` locator hashes (bounded by `plen`), take the first known, honour stop.
- Verdict: CONFIRMED.
- Test coverage: `tests/test_headers.c` single-hash locators only.

##### NET-9 (MEDIUM) — compact blocks: serve side < 253 txs only, no receive path
- Location: `asm/bitcoin_cmpct.asm:510-538` (`block_txcount`: "only single-byte tx count supported"), `:565-570` (`block_tx_at` reads `[r12+80]` as the count), `:679-683` (`cmpctblock_build` same); `asm/bitcoin_serve.asm:383-411` (dispatch has no `cmpctblock`/`blocktxn` case); grep of `cmpctblock_shorttxids_count` shows no caller in `daemon/`.
- Description: for any block with ≥ 253 transactions the count byte is 0xfd, `block_tx_at` starts parsing at offset 81 (inside the 3-byte varint), `tx_parse` fails, and `cmpctblock_build`/`getblocktxn` return nothing (`.gd_miss` → `notfound`, `.gbkt_done` → silence). Virtually every mainnet block has more than 253 transactions. Inbound `cmpctblock` is not handled at all. README ("BIP152 compact blocks in both directions") and `docs/FEATURE_GAPS.md:1020-1021` ("both directions … full message handling") overstate this.
- Failure scenario: a Core peer that negotiated `sendcmpct` v2 and requests `MSG_CMPCT_BLOCK` for a current block gets `notfound`; a `getblocktxn` gets no reply and the peer waits out its timeout before asking for the full block elsewhere.
- Core reference: BIP152; `CBlockHeaderAndShortTxIDs` covers any tx count.
- Suggested fix: parse the CompactSize tx count in `block_tx_at`/`cmpctblock_build`/`block_txcount`; correct the documentation; either implement the receive side or state that it is absent.
- Verdict: CONFIRMED.
- Test coverage: `tests/test_bip152*.c` use tiny synthetic blocks.

##### NET-10 (MEDIUM) — address manager has no bucketed structure
- Location: `asm/daemon/addrbook.c:399-422` (`ab2_add`: full book → evict the record with the smallest `last_seen`), `addr_ingest.c:82-103` (per-response quotas, per-netgroup 16, per-response 256, 5-day-old timestamp sanitisation), `tx_relay.c:796-838` (0.1 addr/s token bucket per leg), `main.c:6189-6210` (`dl_pool_from_book` chooses dial candidates from the book).
- Description: Core's addrman keeps separate tried/new tables, buckets `new` by (source group, address group) with 64 entries per bucket and 1024 buckets so any single source can fill at most a bounded fraction, marks entries "terrible", and resolves collisions by test-before-evict. Here the book is one 65536-entry array; a new address evicts whichever entry has the oldest `last_seen`; gossip timestamps up to `now+600` are accepted verbatim. `net_policy.c:219-224` documents the flat design.
- Failure scenario: an attacker with many source addresses (or one source over time at 0.1/s per leg × legs, ≈ 70 k/day across 8 legs) fills the book with fresh-timestamped addresses it controls; each insertion evicts the oldest honest record. The next boot's `dl_pool_from_book` and the header phase (NET-4) then draw candidates from an attacker-dominated pool. `asmap` improves the group key but not the structure.
- Core reference: `AddrMan::AddSingle`/`Good`/`Attempt`, `ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP` (64), `ADDRMAN_BUCKET_SIZE` (64), `IsTerrible`.
- Suggested fix: at minimum, cap the number of live entries attributable to one source netgroup across the whole book, keep a "tried" flag that eviction never touches, and evict by (tried, terrible, age) rather than by peer-supplied timestamp.
- Verdict: CONFIRMED (design). Not listed in `docs/FEATURE_GAPS.md`.
- Test coverage: `tests/test_addr_ingest.c`, `test_addrbook.c` cover quotas and encoding, not eviction under adversarial timestamps.

##### NET-11 (LOW) — checksum never verified
- Location: `asm/bitcoin_net.asm:552-595`; `tests/test_p2p_msgsize.c:37` ("checksum: unchecked on this path").
- Description: the header's `checksum[4]` at `[rbp-0x44]` is read into the frame but never compared with `sha256d(payload)[0:4]`.
- Failure scenario: a corrupted or deliberately mis-checksummed message is processed; Core would disconnect the peer (`V1Transport::GetMessage`: "Checksum mismatch").
- Suggested fix: compute `cksum4` over the received payload when `announced <= cap` and treat mismatch like a bad magic.
- Verdict: CONFIRMED.
- Test coverage: none.

##### NET-12 (LOW) — decoy in `RECV_VERSION` promoted to version packet
- Location: `asm/crypto_bip324_transport.c:327-339`.
- Description: the first packet after the terminator is decrypted with the garbage as AAD (correct) and then unconditionally moves the state to `RECV_APP`. Core (`V2Transport::ProcessReceivedPacketBytes`) clears the AAD after the first packet but only transitions on a non-decoy packet. Today the real version packet is empty and lands in `RECV_APP` as an "empty packet" that is dropped (`:340-343`), so behaviour matches; a future non-empty version packet would be delivered to the caller as an application message with `plain[0]` interpreted as a short id.
- Suggested fix: transition only when `!ignore`.
- Verdict: CONFIRMED divergence, benign.
- Test coverage: `tests/test_bip324_transport.c` covers garbage/terminator/AAD; no decoy-before-version case.

##### NET-13 (LOW) — version messages over 256 bytes fail the handshake
- Location: `asm/bitcoind.asm:296-303` (`node_accept_handshake`, cap 256 → `p2p_read` returns −2 → `.fail`), `:150-160` (`node_handshake`, same).
- Description: `MAX_SUBVERSION_LENGTH` is 256 in Core, so a legal version message is up to ≈ 350 bytes. Peers with a long `-uacomment` cannot connect in either direction.
- Suggested fix: raise the capture buffer to 512 (the comment at `:101-104` already sized `node_make_version` for 81+255+5).
- Verdict: CONFIRMED.
- Test coverage: none.

##### NET-14 (LOW) — fixed compact-block nonce
- Location: `asm/bitcoin_serve.asm:899-905`.
- Description: `s_cmpct_nonce` is `0x0123456789abcdef` for every block served. Core draws a fresh random nonce per `CBlockHeaderAndShortTxIDs` so an adversary cannot precompute wtxids whose SipHash short ids collide for a given block.
- Failure scenario: an attacker who can predict the nonce mines transactions colliding with a block's short ids in receivers' mempools, forcing reconstruction failure and full-block fallback for every peer we serve compact blocks to (moot while NET-9 stands).
- Suggested fix: 8 bytes from `/dev/urandom` per block.
- Verdict: CONFIRMED.

##### NET-15 (LOW) — mainnet magic hardcoded in the worker's store frames
- Location: `asm/daemon/main.c:3196` (`*(int*)((char*)st+36)=0xd9b4bef9; /* magic */`).
- Description: every other writer uses `net_magic`; on testnet4/signet/regtest the `dlc_worker` frames carry mainnet's magic. Per the comment at `main.c:1813-1830` the frame magic is never read back, so today it is only an inconsistency that any future frame-magic check or external reindex tool would trip over.
- Suggested fix: use `net_magic`.
- Verdict: CONFIRMED.

##### NET-16 (INFO) — impersonated user agents
- `net_policy.c:293` sends `/Satoshi:25.0.0/` on feeler and block-relay-only handshakes; `addr_ingest.c:180` sends `/Satoshi:0.18.0/` with `start_height 789000` on the seednode/getaddr path. Both misrepresent the node to peers and to network crawlers, and differ from the daemon's own `node_ua_buf`.

##### NET-17 (INFO) — onion/I2P inbound violations pollute the ban list
- `main.c:6366-6380` sets `g_cur_peer_ip` from `peerdesc`, which is `"onion-inbound"` or `"<b32>"` for those listeners; `serve_violation_report` → `peer_misbehaving` → `ctl_ban_add("onion-inbound/32")`. `subnet_parse` rejects it on lookup, so nothing is enforced, but a slot of the fixed-size ban list is consumed per event (`ctl_ban_add` returns 0 silently when full).

#### Verified-correct controls

- Framer: announced length compared with `P2P_MAX_MSG` (4,000,000) before any read or drain, distinct `-3` code (`bitcoin_net.asm:567-568, 643-645`); truncated messages drained in 64-byte chunks (`:597-626`); magic checked per message (`:541-543`); v2 dispatch keyed by fd with explicit 16-byte alignment before calling C (`:404-410, 508-514`). BIP324 path enforces the same 4,000,000 on decrypted length (`crypto_bip324_transport.c:315`).
- Misbehaviour: hook wired for oversize announcement, inv > `MAX_INV_SZ`, unparseable tx, block shorter than a header (`bitcoin_serve.asm:1602-1650`) and malformed/oversized addr on legs (`tx_relay.c:798-801, 826-828`); scoring goes to the shared table under a pid-owning lock with dead-owner recovery (`main.c:1031-1056`); `noban` respected before scoring (`main.c:1231-1240`); bans enforced on dial and on v4 accept (`main.c:6392-6400`).
- BIP324 cipher: salt `"bitcoin_v2_shared_secret" || magic`, HKDF-extract then expand with labels `initiator_L/P`, `responder_L/P`, `garbage_terminators`, `session_id` in Core's order and role mapping (`crypto_bip324.c:95-128`); ECDH tagged hash `bip324_ellswift_xonly_ecdh` over initiator‖responder‖x with role-fixed order (`crypto_ellswift_ecdh.c:134-148, 204-205`); scalar range check without mod-p reduction (`:84-108`); FSChaCha20 keeps the partial keystream block, rekeys every 224 chunks with nonce `(0, ++rekey)` (`crypto_bip324_fs.c:290-324`); FSChaCha20Poly1305 rekeys from nonce `(0xFFFFFFFF, rekey)` block 1 and advances counters on failed decrypt (`:339-372`); garbage bounded at 4095+16 (`crypto_bip324_transport.c:282-305`); version packet AAD = peer garbage (`:325-329`); responder silent until v2 is proven (`:209-213`); ephemeral key zeroised after ECDH and on free (`:275, 219`; `v2transport.c:183`).
- ElligatorSwift: wire bytes reduced mod p (`crypto_ellswift.c:494-506`), decode order x3, x2, x1 (`:349-391`), encoding uses hashed uniform candidates with an attempt counter (`crypto_ellswift_enc.c:247-271`), outbound v2 only to peers advertising `NODE_P2P_V2` with v1 redial (`main.c:1737-1752`).
- v1 fallback: responder peeks (`MSG_PEEK`) and leaves a v1 peer's bytes untouched (`v2transport.c:205-235`), pinned by `tests/test_v2transport.c:150-181`; initiator never falls back in place.
- Inbound message parsers with bounds: `inv` via `serve_inv_bounds` (canonical CompactSize, ≤ 50,000, fits in `plen`, `serve_invbounds.c:36-68`); `sendcmpct` requires 9 bytes and version 2 (`bitcoin_serve.asm:1403-1409`); `feefilter` 8 bytes (`:1434-1438`); `ping` echoes 8 bytes only when present (`:459-473`); `getaddr` answered once (`:820-822`); leg-side `inv`/`getdata`/`notfound` entries bounded by `plen` (`tx_relay.c:1061-1195`); `addr`/`addrv2` count ≤ 1000, per-entry bounds, canonical decode, unknown networks skipped (`addr_ingest.c:104-145`, `netaddr.c:457-475`); user-agent parse bounded at 200 and non-printables scrubbed (`main.c:1913-1935`); `fRelay` parse bounded (`relay_policy.c:32-45`).
- Boot header fetch (post-incident): exponential locator, attachment must be a held header, overlap must be identical, links checked, `txn_count == 0`, attach depth ≤ 100,000, rollback on refusal (`main.c:2951-3034`), pinned by `tests/test_dialhelper.c` §5/§6; header mirror topped up from the archive before asking peers (`main.c:3077-3092`).
- Block download: every downloaded block is `cons_verify`'d and its hash compared with the stored header hash before `store_append` (`bitcoind.asm:1651-1672`); appends serialised under `append.lock` with per-process fds; `idxscan_append_locked` refuses a block that does not link to the on-disk tip (`bitcoin_idxscan.asm:287-314`); chunk workers bounded by `DLC_CHUNK_BUDGET_SECS` alarm and parent-side dead-weight signal with amnesty floor (`main.c:3265-3318`).
- Peer policy: `netperm` parses Core's token set, `noban` implies `download`, `forcerelay` implies `relay`, unsupported `bloomfilter`/`out` refused loudly (`netperm.c:166-191`); whitebind permissions come from the accepting socket (`main.c:6340-6349`); relay gates match Core's `RejectIncomingTxs`/`inboundrelaypercent` (`relay_policy.c`, `main.c:1104-1135`); `mempool` message requires the permission or `noban` (`main.c:1137-1155`); block-relay-only legs never gossiped (`net_policy.c:310-312`).
- SOCKS5: hostname handed to the proxy (ATYP 3), 255-byte host cap, RFC 1929 auth, reply bound-address length bounded (`socks5.c:373-424`); random per-connection isolation credentials from `/dev/urandom`, failing closed without entropy (`dialer.c:349-361, 437-441`); clearnet and IPv6 also proxied when `-proxy` is set (`dialer.c:453-479`); DNS seeds skipped behind a proxy or with `dns=0` (`main.c:2545-2551`).
- Tor control: `PROTOCOLINFO` → cookie (32 bytes, hex) or hashed password or NULL auth, `ADD_ONION` with persisted `ED25519-V3` key written 0600, ServiceID re-validated as a v3 onion with checksum (`torcontrol.c:201-253`, `netaddr.c:304-311`). I2P: SAM 3.1 hello, persistent key 0600, b32 derived by SHA-256 (`i2psam.c:34-42, 83-113`). Onion inbound identified by socket, not source address (`main.c:6375-6390`).
- Self-advertisement: clearnet address requires two independent peers to agree, unroutable views ignored, onion address never sent to clearnet peers and vice versa, addrv2 used only for peers that negotiated it (`addr_self.c:98-122, 191-233`).
- Upload cap: parent meters each child's `/proc/<pid>/io` `wchar`, refuses new inbound over target unless `download` permission, 24 h window (`upload_cap.c`, `main.c:6440-6449`).
- Erlay: BIP330 negotiation rules and `Tx Relay Salting` tagged hash in ascending salt order match Core; reconciliation deliberately not built (`txrecon.c`, documented in FEATURE_GAPS).
- Private broadcast: Core's `PickTxForSend` ordering, dedicated helper child per connection, `fRelay=0`/`NODE_NONE` version, exact-getdata check (`private_broadcast.c:73-92, 176-226`).

#### Coverage and limits

- Not verified: constant-time Poly1305 tag comparison in `crypto_chacha20.c`/`crypto_poly1305.c`; `bitcoin_chainwork.asm` work arithmetic for out-of-range nBits (relevant to NET-6 on the reorg path); `reorg_probe_peer` end to end (the PLAUSIBLE half of NET-5); `serve_cfilters.c` parsers (`getcfilters`/`getcfheaders`/`getcfcheckpt` bounds) — worth a dedicated pass; `asmap.c` bytecode interpreter bounds (only the header comment was read); the `mux_next_peer` / `dl_pool_from_book` netgroup diversity of outbound peer selection.
- Not run: no test binaries were executed; all findings are from reading.
- Next steps I would take: fuzz `node_serve_loop` with a corpus of malformed `getblocktxn`/`getdata`/`getheaders`/`cmpctblock` messages against a real-sized block; add an inbound-idle and partial-prefix test around `serve_mux`'s child; feed `dlc_fetch_headers` a zero-work chain from the fake header peer in `test_dialhelper`; and reconcile README/FEATURE_GAPS with NET-9 and NET-10.


---

### 6.7 Mempool, policy, relay, fee estimation, notifications — review

**Scope:**
- Fully read: `asm/bitcoin_mempool.asm`, `asm/bitcoin_mempool_policy.c`, `asm/mempool_entry.h`, `asm/daemon/tx_accept.c`, `asm/daemon/tx_relay.c`, `asm/daemon/relay_policy.c`, `asm/daemon/mempool_cfg.c`, `asm/daemon/mempool_persist.c`, `asm/daemon/mempool_compact.c`, `asm/daemon/fee_estimator.c`, `asm/daemon/fee_hooks.c`, `asm/daemon/tx_submit.c`, `asm/daemon/zmq_pub.c`, `asm/daemon/zmq_notify.c`, `asm/daemon/notify.c`, `asm/daemon/reorg.c` §5 (mempool reconcile, lines 845-1010).
- Skimmed (targeted reads/greps only): `asm/daemon/tx_verify.c` (`txv_parse`, `txv_connect_body`, `tx_verify_mempool`), `asm/rpc_chain.c` getblocktemplate (875-1130), `asm/rpc_node.c` prioritisetransaction (1482-1545), `asm/bitcoin_serve.asm` (`.inv_txann`, `.do_tx`, getdata tx arm), `asm/daemon/main.c` (ZMQ wiring, tip updates, helper kill sites, expiry timer), `asm/daemon/node_config.c` (zmq keys), test files under `asm/tests/` by string survey.
- Not read: `asm/daemon/main.c` private-broadcast helper internals (`pb_exchange`), `asm/daemon/txrecon.c`, the RPC renderers for `getrawmempool`/`getmempoolentry`.

**Summary:** The policy layer is a genuine, readable port of Core's `MemPoolAccept`/`txmempool` rules with Core's reason strings, and the bounded parsers, ZMTP publisher and notify-hook sanitisation are sound. The serious problems are structural rather than in the checks themselves: (1) **no nLockTime finality or BIP68 sequence-lock check exists anywhere in mempool admission** (and, by grep, not in block connection either — a consensus-class gap that I am flagging cross-module), so non-final transactions enter the pool and the block template; (2) the shared policy state silently loses conflict claims, parent links and eviction atomicity under realistic load (claims table full, >24 in-pool parents, RBF eviction before a "mempool full" reject, TrimToSize evicting a parent under an incoming child), each of which leaves the mempool holding transactions whose inputs are not spendable, and `getblocktemplate` includes such entries without re-validation — an invalid block for any miner using this node; (3) `worst_chunk` gives up above 65,536 entries while the pool is sized for ~1M, so a byte-full pool with more than 64K transactions rejects every new transaction ("mempool full") and never evicts, compacts or raises `mempoolminfee` — a liveness wedge reachable by organic congestion or by a ~0.3 BTC fill at the 0.1 sat/vB floor; (4) RBF lacks Core's rule 6 / feerate-diagram check and uses a stricter-than-Core "new unconfirmed input" rule. Relay has an O(n) inv-processing path that lets an outbound peer stall the single-threaded worker, and inbound peers can force unbounded re-fetch/re-verify of a rejected transaction. Confidence: high on the policy/data-structure findings (traced end to end); medium on the exact Core v31 RBF semantics (noted where uncertain).

#### Findings

| ID | Severity | Location | Title | Verdict |
|---|---|---|---|---|
| MEM-1 | HIGH (CRITICAL cross-module) | tx_accept.c / tx_verify.c / bitcoin_mempool_policy.c | No nLockTime finality (IsFinalTx) and no BIP68 sequence-lock check in mempool admission; none found in block connect either | CONFIRMED |
| MEM-2 | HIGH | bitcoin_mempool_policy.c:857-862, 1440-1443 | `worst_chunk` refuses pools > 65,536 entries: byte-full pool wedges (every tx "mempool full", no eviction/compaction/floor bump) | CONFIRMED |
| MEM-3 | HIGH | bitcoin_mempool_policy.c:83, 1147, 1409, 1465 | `MPOL_MAX_PARENTS` (24) silently truncates parent links; a 25th+ parent's eviction/replacement leaves a child spending a non-existent output, which GBT includes | CONFIRMED |
| MEM-4 | HIGH | bitcoin_mempool_policy.c:1511-1522, 1500-1506; mempool_cfg.c:114,161 | Claims/outreg tables share the node cap and drop entries silently when full: double-spend detection stops, conflicting txs coexist in the pool | CONFIRMED |
| MEM-5 | HIGH | bitcoin_mempool_policy.c:1435-1470 | TrimToSize evicts the incoming tx's own parent chunk and then stores the child unlinked (Core adds first, trims, then checks presence) | CONFIRMED |
| MEM-6 | MEDIUM | bitcoin_mempool_policy.c:1394-1400, 1440-1447 | Commit is not atomic: RBF/sibling evictions are applied before the "mempool full" reject in 1b; conflicts are lost for a replacement that never enters | CONFIRMED |
| MEM-7 | MEDIUM | bitcoin_mempool_policy.c:1085-1135 | RBF has no rule-6 (`PaysMoreThanConflicts`) / feerate-diagram check: a lower-feerate replacement is accepted if it pays absolute fee + incremental | CONFIRMED (Core-version note) |
| MEM-8 | MEDIUM | daemon/reorg.c:930-1000 | Reorg reconcile caps at 8,192 txs / 16 MB: excess entries stay in the structural pool as unregistered ghosts (never expire, unclaimed inputs) | CONFIRMED |
| MEM-9 | MEDIUM | daemon/tx_relay.c:1076-1094, 915-935, 109-117 | O(n·4096) inv processing: one 58K-entry inv costs seconds in the single-threaded worker; 64 per poll | CONFIRMED |
| MEM-10 | MEDIUM | bitcoin_serve.asm:539-560, 627-670 | Inbound peers have no recent-rejects memory: a rejected tx can be re-announced and re-fetched/re-verified without bound | CONFIRMED |
| MEM-11 | MEDIUM | bitcoin_mempool_policy.c:434-441 | P2A (`SPK_ANCHOR`) dust threshold uses the non-witness spend cost (483 sat vs Core's 240): a 240-sat anchor is "dust" and, with any fee, rejected | CONFIRMED |
| MEM-12 | MEDIUM | bitcoin_mempool_policy.c (linear scans throughout), 616-668, 1600-1650 | All registry lookups are O(n); with a 300 MB pool block-connect and each accept cost seconds under `mp_lock` | CONFIRMED (complexity) / PLAUSIBLE (timings) |
| MEM-13 | MEDIUM | bitcoin_mempool_policy.c:1435-1447; mempool_compact.c | Blob `fill` is never reclaimed outside the trim path: dead bytes trigger a spurious eviction and `mempoolminfee` bump before compaction | CONFIRMED |
| MEM-14 | LOW | bitcoin_mempool_policy.c:1117-1123 | Rule 2 is stricter than Core's `HasNoNewUnconfirmed`: an unconfirmed input from a *parent of a conflict* is refused unless the exact outpoint is already claimed | CONFIRMED |
| MEM-15 | LOW | bitcoin_mempool_policy.c:404-431 | Standardness solver is looser than Core's `Solver`: v0 witness programs of odd length, malformed bare multisig (m>n, non-pubkey pushes), P2PK with invalid key prefix all classified standard | CONFIRMED |
| MEM-16 | LOW | bitcoin_mempool_policy.c:1044 | Min-relay check compares `fee*1000 < vsize*rate` (ceil) where Core uses `GetFee` (floor, min 1): rejects at the boundary | CONFIRMED |
| MEM-17 | LOW | bitcoin_mempool_policy.c:616-668 (remove_node) | Children's `anc_cnt`/`anc_bytes` are never decremented when a parent confirms; TRUC ancestor limit then misfires | CONFIRMED |
| MEM-18 | LOW | rpc_node.c:1482-1545, rpc_chain.c:1035-1041, bitcoin_mempool_policy.c | `prioritisetransaction` deltas affect only `getmempoolentry` output — not eviction, RBF, fee floors or the block template | CONFIRMED |
| MEM-19 | LOW | daemon/mempool_persist.c:106-108 | `mempool.dat` written with `fflush`+`rename` but no `fsync`: torn/empty file possible across power loss, contrary to header claim | CONFIRMED |
| MEM-20 | LOW | daemon/mempool_cfg.c:76-81; tx_accept.c:862 etc. | Non-robust process-shared mutex: a serve child crashing inside `mpool_policy_add` wedges every process's mempool (accepted risk, restated) | CONFIRMED |
| MEM-21 | LOW | tx_accept.c:397-455, 655-661 | Mempool parent bytes are read (`mpool_get`) without `mp_lock` on the verification path; concurrent compaction/backward-shift delete can hand the verifier garbage | PLAUSIBLE |
| MEM-22 | INFO | tx_relay.c:1-41; node_config.c:750-765 vs FEATURE_GAPS.md:1405; zmq_pub.c:26-33 vs 471 | Stale/contradictory documentation: tx_relay header says no BIP339/no re-announce (both exist); FEATURE_GAPS says `zmqpubsequence` implemented while config refuses it; ZMQ "drops the message" but actually closes the subscriber | CONFIRMED |
| MEM-23 | INFO | tx_accept.c:655-661 | `IsWitnessStandard`/legacy-sigop prechecks run even under `acceptnonstdtxn`; `tx-size-small` skipped under it (Core: the opposite) | CONFIRMED |
| MEM-24 | INFO | tx_relay.c:1195-1200 | `getdata(MSG_TX)` is answered with the witness serialization (Core strips for non-witness requests) | CONFIRMED |

##### MEM-1 (HIGH; CRITICAL if the block-connect side is confirmed by the consensus reviewer) — no nLockTime / BIP68 finality in admission
- Location: `asm/daemon/tx_accept.c:845-990` (all three accept entries: prechecks → `txacc_script_verify` → `mpool_policy_add`); `asm/daemon/tx_verify.c:747-800` (`txv_connect_body`: resolves prevouts, coinbase maturity, script verify — nothing else); `asm/bitcoin_mempool_policy.c:907-1390` (`mpol_add_core`: standardness, fees, RBF, limits, TRUC — no locktime). `grep -rn -i 'IsFinal\|non-final\|BIP68\|SequenceLock' asm/daemon/*.c asm/*.c asm/*.asm` finds only the script-interpreter CLTV/CSV opcodes (`bitcoin_interp.asm:2325-2348`) and miniscript/wallet code; nothing at the transaction level, and nothing in `utxo_live.c`/`bitcoin_cons.asm`.
- Description: Core's `PreChecks` rejects `!CheckFinalTxAtTip(tip, tx)` ("non-final") and `!CheckSequenceLocks(tip, view, tx, &lp)` ("non-BIP68-final") using `STANDARD_LOCKTIME_VERIFY_FLAGS` (MTP-based). `parse_tx` reads sequences (`seq[]`) but uses them only for BIP125 signalling; the 4-byte nLockTime is never decoded on the admission path at all.
- Failure scenario: a transaction with `nLockTime = tip+500` (or nLockTime = a time 1 day ahead, or nVersion=2 with an nSequence relative lock of 100 blocks on a freshly confirmed input) passes every check, enters the shared pool, is announced to all legs (Core peers reject it as `non-final` and keep it in recent-rejects), and is selected by `cmd_getblocktemplate` (`rpc_chain.c:1035-1060`, which only checks registry ancestors). A miner on this template produces a block Core rejects with `bad-txns-nonfinal`. Since the grep finds no `IsFinalTx`/`SequenceLocks` in block connection either, the node would also *accept* such a block from the network — that half belongs to the consensus reviewer but is the highest-severity consequence.
- Core reference: `validation.cpp` `MemPoolAccept::PreChecks` (`CheckFinalTxAtTip`, `CheckSequenceLocks`), `consensus/tx_verify.cpp` `IsFinalTx`, `SequenceLocks` (BIP68), BIP113 (MTP locktime).
- Suggested fix: decode nLockTime in `parse_tx`; in `mpol_add_core` implement `IsFinalTx(tx, next_height, MTP(tip))` (height if < 500,000,000 else time; all inputs `0xffffffff` bypasses) and, for nVersion ≥ 2, BIP68 over each input's prevout height/MTP (mempool parents at `next_height`). The resolver already returns prevout height; MTP is computed in `main.c:5005-5014` for headers and can be exposed like `tx_accept_set_tip_time`.
- Verdict: CONFIRMED (admission); the block-connect half is CONFIRMED absent by grep but not traced.
- Test coverage: none. `asm/tests/` has no locktime/sequence-lock mempool test (`grep -l locktime asm/tests/*.c` hits only sighash/script tests).

##### MEM-2 (HIGH) — pool with >65,536 entries cannot evict: "mempool full" wedge
- Location: `asm/bitcoin_mempool_policy.c:857-862` (`worst_chunk`: `static ... child_head[65536] ...; if (n > 65536) return 0;`), consumed at `:1440-1447` (`while (put == 2){ if (!worst_chunk(st,&wc) || wc.n == 0){ reason="mempool full"; return 0; }`). Capacity: `daemon/mempool_cfg.c:114` sizes slots to `blob_cap/512` rounded up (1,048,576 for the default 300 MB) and `:161` sizes the policy state to the same `slots`. Also `decr_ancestors` `:592` (`seen[1u<<20]`, `if (n > (1u<<20)) return;`) silently stops maintaining descendant aggregates for `maxmempool` > ~500 MB.
- Description: the structural pool and policy graph are sized for ~1M entries, but the cluster-chunk evictor hard-fails above 64K. `mpool_put` returns 2 when `fill + txlen > blob_cap` (`bitcoin_mempool.asm` `.found_empty`), and `fill` only ever grows except in `mpool_compact`, which is called only *after* a successful eviction in this same loop (`:1455`).
- Failure scenario: mainnet backlog: at ~400 raw bytes per tx the pool holds >64K entries at ~26 MB, long before the 300 MB blob is full. When `fill` reaches the cap (organic congestion, or an attacker paying the 0.1 sat/vB floor: 300 MB ≈ 30M sat, since the floor never rises until an eviction occurs), `worst_chunk` returns 0 and *every* subsequent accept — any feerate — fails "mempool full". No eviction, no compaction, no `floor_bump`, so `getmempoolinfo` reports `mempoolminfee` 0 while rejecting everything. Recovery needs `n` to drop to ≤65,536 via confirmations/expiry (336 h); low-fee filler never confirms, so the wedge lasts up to two weeks. Bytes freed by block-confirmed removals do not help because `fill` is not reclaimed (MEM-13).
- Core reference: `CTxMemPool::TrimToSize` operates on DynamicMemoryUsage of live entries with no entry-count ceiling; `GetMinFee` rises on every trim.
- Suggested fix: size `child_head/child_next/mark` from the state cap (or allocate in the state region); on `put == 2` call `mpool_compact` *before* deciding; when `worst_chunk` cannot run, fall back to `worst_package` (already present, marked unused) instead of rejecting.
- Verdict: CONFIRMED.
- Test coverage: `tests/test_mempool_chunks.c`, `test_mempool_evict.c` use tiny pools (<10 entries); nothing exercises >64K entries.

##### MEM-3 (HIGH) — 24-parent cap silently drops parent links; child survives its parent's eviction/replacement
- Location: `asm/bitcoin_mempool_policy.c:83` (`MPOL_MAX_PARENTS 24`), `:1145-1150` (`if (n_par >= MPOL_MAX_PARENTS) break;`), repeated at `:1409` and `:1465`; node stores `parent[24]` at `:1532-1537`; descendants are discovered only via `parent[]` (`collect_descendant_txids` `:560-586`, cluster walk `:1180-1225`, `remove_node` `:616-668`).
- Description: the comment assumes Core's 25-ancestor limit bounds direct parents; but `anc_cnt` (`:1170`) is computed from the *truncated* `par_idx`, so a tx with 30 in-pool parents reports 25 ancestors and passes both the ancestor limit and the 64-node cluster limit. Parents 25..30 get no `parent[]` link and their `desc_*` aggregates are not bumped.
- Failure scenario: attacker (or any user with many unconfirmed UTXOs) broadcasts 30 low-feerate parents P1..P30 and a child C spending all 30. C is accepted linked only to P1..P24. Attacker RBF-replaces P30 (its own coin): `collect_descendant_txids(P30)` finds no child, P30 is removed, C stays in the pool spending P30:0, which is now conflicted. `cmd_getblocktemplate` (`rpc_chain.c:1052-1058`) marks C usable (all *registered* ancestors present) and includes C — an invalid block (C's input is spent by P30'). The same happens if P30 is evicted by TrimToSize or expires (`mpool_policy_expire_one` → `remove_package` uses the same link walk). C is also re-announced to peers.
- Core reference: `CTxMemPoolEntry` parents are a set (unbounded, limited only by policy); `removeRecursive`/`removeForBlock` walk `GetMemPoolChildren`; `BlockAssembler` only selects entries whose ancestors are in the block.
- Suggested fix: reject when a tx has more in-pool parents than can be recorded (Core's pre-v31 `too-long-mempool-chain` would fire at 25 anyway), or store parents out-of-line; have GBT verify each input resolves to the block-so-far or the confirmed set.
- Verdict: CONFIRMED.
- Test coverage: `test_mempool_policy.c` "child C joins them: cluster of exactly 64 accepted" builds 64-wide clusters through *one* child of many parents? (it checks the count limit, not the link truncation); nothing pins that the 25th parent's eviction removes the child.

##### MEM-4 (HIGH) — claims/outreg tables overflow silently; double-spends undetected
- Location: `asm/bitcoin_mempool_policy.c:1511-1522` (`if (nc < cap_){ ...record claim... }` — else nothing), `:1500-1506` (outreg likewise); `find_claim` `:540-546` is what RBF/conflict detection and block-conflict removal rely on. Cap = node cap (`mempool_cfg.c:161`, `pn = slots`).
- Description: the claims table has one slot per *node*, but holds one entry per *input*. With the pool sized at 1M nodes, the claims table fills once the pool holds ~1M inputs (≈400-500K typical txs, well within a 300 MB raw pool; Core's 300 MB is DynamicMemoryUsage ≈ 3× serialized, so this pool holds ~3× Core's count). After that every new tx's inputs are unclaimed.
- Failure scenario: pool near capacity; tx A spending O arrives (claim dropped); tx B spending O arrives: `find_claim` misses → no conflict → B accepted. Both A and B are in the pool, both relayed, both eligible for the template (GBT does not check conflicts) → invalid block. Outreg overflow is the conservative direction (children rejected as missing inputs) but silently breaks CPFP.
- Core reference: `CTxMemPool::mapNextTx` is unbounded; `MemPoolAccept::PreChecks` "txn-mempool-conflict".
- Suggested fix: size claims/outreg from the input/output budget (e.g. cap × average or a separate configurable count) and, when full, *reject* the tx ("mempool full") rather than admit it unregistered.
- Verdict: CONFIRMED (silent drop); block-template impact PLAUSIBLE (not executed).
- Test coverage: none for table exhaustion.

##### MEM-5 (HIGH) — TrimToSize can evict the incoming tx's parent, then store the child unlinked
- Location: `asm/bitcoin_mempool_policy.c:1435-1470`: on `put == 2`, `worst_chunk` is scored over the *existing* graph (the incoming tx is not yet in it), the chunk is removed via `mpool_policy_remove_package`, then "trimming may have shifted node indices: recompute parent/ancestor lists" re-derives `par_idx` from whatever is left.
- Failure scenario: pool byte-full; parent P (1 sat/vB, a leaf, the worst chunk) is in the pool; child C (50 sat/vB) spending P:0 arrives. C's feerate beats the chunk, so P is evicted; `par_idx` is recomputed and P is gone; C is stored with `n_parents = 0`, fee computed from P's output value, ancestors empty. C now sits in the pool spending an output that exists neither in the UTXO set nor the mempool; GBT includes it (registry ancestors all "present"); it is announced to peers who orphan it. Core adds C first, trims by chunk with C included (so {P,C} is scored together), then rejects C with "mempool full" if it was itself trimmed.
- Core reference: `MemPoolAccept::Finalize` → `LimitMempoolSize` after `addNewTransaction`, then `if (!m_pool.exists(GenTxid::Txid(hash))) return "mempool full"`.
- Suggested fix: add the node to the graph before trimming (or exclude chunks containing any of `par_idx` from eviction candidates and reject the incoming tx if its own chunk would be the worst).
- Verdict: CONFIRMED.
- Test coverage: `test_mempool_chunks.c` covers "C went with its parent: the chunk is evicted whole" for *resident* chains only.

##### MEM-6 (MEDIUM) — commit is not atomic: RBF/sibling evictions precede a possible "mempool full" reject
- Location: `asm/bitcoin_mempool_policy.c:1394-1400` (1a: `remove_node` for every `evict_set` entry, `_mpol_replaced` recorded), then `:1440-1447` (1b: `mpool_put` may return 2; if the incoming loses to the worst chunk the function returns 0 with "mempool full", and `:1457` "mempool store failed"). The file header (`:56-58`) claims "Accept is atomic: on any policy failure both the structural mempool and this state are untouched."
- Failure scenario: pool byte-full; a replacement R for tx T passes RBF (fee ≥ T + incremental) but has a lower feerate than the worst chunk (possible because of MEM-7, e.g. a 100 kvB replacement). T (and its descendants) are removed; R is rejected; nothing is stored. The same applies to a TRUC sibling evicted at `:1320-1330`. Because RBF requires signing authority over T's inputs, the practical victim is a two-party construction (an LN counterparty's commitment tx dropped from bmc nodes while Core nodes keep it) or the user's own transactions; `submitpackage`'s `replaced-transactions` (`mpol_last_replaced`) also reports evictions that did not accompany an accept.
- Core reference: `MemPoolAccept::Finalize` removes conflicts only after `PreChecks`/`PolicyScriptChecks`/`ConsensusScriptChecks` succeed and inserts the replacement before trimming.
- Suggested fix: attempt `mpool_put` (with compaction) before applying 1a, or snapshot/restore; at minimum compare the incoming feerate against the worst chunk *before* evicting conflicts.
- Verdict: CONFIRMED.
- Test coverage: none (evict tests never combine RBF with a full pool).

##### MEM-7 (MEDIUM) — RBF accepts lower-feerate replacements (no rule 6 / feerate-diagram check)
- Location: `asm/bitcoin_mempool_policy.c:1085-1135`: rules 1 (signalling), evict-set build, disjointness, rule 2, rules 3+4 (`fee >= removed_fees`, increment ≥ `incremental_fee*vsize/1000`). No comparison of the replacement's feerate with any conflict's feerate or package.
- Failure scenario: T = 200 vB paying 2,000 sat (10 sat/vB). R = 100,000 vB (max standard) paying 2,000 + 100,000 sat = 1.02 sat/vB. bmc: rules 3+4 pass → accepted, T evicted, 100 kvB relayed. Core (every version): rejected — pre-v31 `PaysMoreThanConflicts` ("insufficient fee", replacement feerate ≤ original), v31 cluster-mempool `ImprovesFeerateDiagram` (the new diagram is strictly worse). Consequence: miner-incentive-incompatible replacements; repeated churn of a 200 vB tx into 100 kvB relay traffic at 1 sat/vB.
- Core reference: `policy/rbf.cpp` `PaysMoreThanConflicts` (v22-v30); `ImprovesFeerateDiagram` / `CheckConflictTopology` (v28 package RBF, v31 general). I am not certain which of the two v31 applies to single-tx RBF, but bmc has neither.
- Suggested fix: add `PaysMoreThanConflicts` over `conf_claimers` using `fee/vsize` vs each conflict's `fee/size` (cross-multiplied), or the diagram check over the post-replacement cluster the code already computes.
- Verdict: CONFIRMED.
- Test coverage: `test_mempool_core_parity.c` §4 pins absolute-fee rules only ("equal-fee replacement refused", "850 pays P+C but not the replacement's own vsize").

##### MEM-8 (MEDIUM) — reorg reconcile leaves ghosts above 8,192 txs / 16 MB
- Location: `asm/daemon/reorg.c:930-931` (`REORG_MEMPOOL_MAX_TX 8192`, `REORG_MEMPOOL_ARENA 16 MB`), `:958-966` (`mempool_snapshot` stops at max; the copy loop truncates `ncand` when the arena fills), `:977-978` (only `from_mempool` entries are `mpool_del`'d, then `mpool_policy_state_init` wipes the whole graph).
- Failure scenario: a 1-block reorg with 20,000 txs (or >16 MB) in the pool: 8,192 are snapshotted and re-offered; the other ~12,000 remain in the structural pool with no registry node, no outreg, no claims and (because `mempool_forget` is only reached via the registry) their arrival-time entries are cleared by `mempool_expire_now` (`mempool_cfg.c:248-249`, `else e->used = 0`). They are served to `getdata`, counted by `mpool_count`, never expire, never evict, and their inputs are unclaimed, so a later double-spend is admitted alongside them. GBT skips them (`have_inf` = 0) so the template stays valid.
- Core reference: `DisconnectedBlockTransactions` + `MaybeUpdateMempoolForReorg` operate on the whole pool.
- Suggested fix: size the snapshot from `mpool_count`/`fill` (they are known), or walk-and-delete all live slots before rebuilding.
- Verdict: CONFIRMED.
- Test coverage: `test_reorg*` (not read) — nothing found exercising >8,192 entries.

##### MEM-9 (MEDIUM) — O(n·4096) inv processing in the worker
- Location: `asm/daemon/tx_relay.c:1076-1094`: for every inv entry (up to ~58K in a 2 MB payload) the loop calls `txr_want_note` (`:924-945`, linear scan of `TXR_WANT_MAX` 4096 × 32-byte memcmp plus oldest-slot eviction) and `txr_ring_has` (`:109-117`, 4096 × 8-byte memcmp) *before* the `want < 32` cap has any effect, because known/duplicate entries `continue` without counting.
- Failure scenario: an outbound peer (one of the 8 legs, or anyone who gets us to dial them) sends invs of 58K arbitrary txids. Each costs ~10^8 byte-compares (order of seconds); `TXR_MAX_MSGS` allows 64 per poll and the drain runs in the single-threaded download worker between block-sync passes, so tip-following stalls for minutes per poll. As a side effect every legitimate `txr_want_tab` entry (in-flight requests, orphan parent fetches) is evicted by `txr_want_note`'s oldest-slot replacement.
- Core reference: `TxRequestTracker` is indexed; `MAX_INV_SZ` 50,000 with `Misbehaving` on excess; `MAX_PEER_TX_ANNOUNCEMENTS` 5,000.
- Suggested fix: hash-index `txr_want_tab`/`txr_ring`; cap announcements per peer (5,000 in flight) and stop calling `txr_want_note` for entries already in the pool.
- Verdict: CONFIRMED.
- Test coverage: `test_tx_relay.c` uses small invs only.

##### MEM-10 (MEDIUM) — inbound peers can force unbounded re-fetch and re-verification
- Location: `asm/bitcoin_serve.asm:539-560` (`.inv_txann`: checks `node_relay_flag`, `tx_dv_ok`, `mpool_get`, then sends `getdata` — no recent-reject or recently-requested memory), `:627-670` (`.do_tx` → `tx_accept_validate`, full prechecks + script verification + policy).
- Failure scenario: inbound peer announces txid X of a valid-signature, policy-rejected tx (e.g. 100 kvB, thousands of inputs, fee just below the floor) once per second; each announcement is fetched and fully verified (thousands of ECDSA/Schnorr checks) by that connection's serve child, which also takes `mp_lock` for the policy pass. Core's `AlreadyHaveTx` (recent rejects / reconsiderable filters) answers the second announcement without a fetch. The worker's drain has the 60 s request ring and the reconsiderable bypass budget; the inbound path has neither.
- Suggested fix: share the recently-rejected (and `-28` reconsiderable) memory with serve children (a small MAP_SHARED prefix filter beside the mempool) and consult it in `.inv_txann`/`.do_tx`.
- Verdict: CONFIRMED (asm read; the absence of any filter is structural).
- Test coverage: none.

##### MEM-11 (MEDIUM) — P2A outputs get the non-witness dust threshold
- Location: `asm/bitcoin_mempool_policy.c:434-441`: `witness` includes V0 key/script, V1 taproot and `SPK_WITNESS_UNKNOWN` but **not** `SPK_ANCHOR`; `mpol_dust_outputs` `:456-475` and the ephemeral-dust rules `:990-1030`.
- Failure scenario: an LN/anchor-style tx with one P2A output of 240 sat and a normal fee. Core: `GetDustThreshold` = 3000 sat/kvB × (8+1+4 + 32+4+1+26+4 = 80 B) = 240 sat → not dust (`value < threshold` is false). bmc: 3000 × (13 + 148 = 161) = 483 → dust; one dust output is tolerated at standardness but the ephemeral rule then fires ("dust": fee ≠ 0). The tx is rejected here and accepted by Core. Anything between 240 and 482 sat on a P2A output is affected. (Core's `IsWitnessProgram` returns true for P2A: version 1, 2-byte program.)
- Core reference: `policy.cpp` `GetDustThreshold`, `CScript::IsWitnessProgram`.
- Suggested fix: add `SPK_ANCHOR` to the witness set.
- Verdict: CONFIRMED.
- Test coverage: `test_ephemeral_dust.c` uses P2WPKH-style dust; no P2A case.

##### MEM-12 (MEDIUM) — linear registry scans make a large pool a DoS amplifier
- Location: `find_node` `:531-536`, `find_outreg` `:537-544`, `find_claim` `:545-551` (linear over up to 1M entries, called per input per accept), `remove_node` `:616-668` (three linear passes per removal: children relink, claims, outreg), `collect_descendant_txids` `:560-586` (scan of all nodes per pop), `mpool_policy_block_connect` `:1605-1640` (per block input: `find_claim` over all claims, plus `remove_confirmed`).
- Failure scenario: with a few hundred thousand entries (see MEM-2/4 for how easily that happens), each accept costs tens of ms and each block connect — 3,000 removals × O(n) — tens of seconds to minutes, all under `mp_lock`, in the download worker, blocking every accept in every process and delaying tip processing. Attacker cost is the relay floor. Core's structures are indexed (boost multi-index / `TxGraph`).
- Suggested fix: hash-index the three tables (the FNV open-addressing already used by `bitcoin_mempool.asm` is the obvious model) and keep child lists.
- Verdict: CONFIRMED for complexity; timings PLAUSIBLE (not measured).
- Test coverage: none at scale.

##### MEM-13 (MEDIUM) — dead blob bytes cause a spurious eviction and `mempoolminfee` bump
- Location: `asm/bitcoin_mempool.asm` `mpool_del` (blob bytes left in place, `fill` untouched); `daemon/mempool_compact.c` is invoked only at `bitcoin_mempool_policy.c:1455`, after an eviction. `remove_confirmed`/expiry/RBF removals never compact.
- Failure scenario: the pool once reaches `fill == blob_cap`; blocks then confirm 50 MB of entries. `fill` stays at cap, so the next accept sees `put == 2`, computes the worst chunk, evicts it (or rejects the newcomer) and calls `floor_bump(chunk_feerate + incremental)` — raising `mempoolminfee` for 12+ hours — before compaction reclaims the 50 MB that was actually free. Under MEM-2's condition (n > 64K) this becomes the permanent wedge.
- Suggested fix: compact when `put == 2` before scoring, and/or account live bytes (`st+64`) against the cap.
- Verdict: CONFIRMED.
- Test coverage: `test_mempool_evict.c` observes the floor bump but only in the genuinely-full case.

##### MEM-14 (LOW) — rule 2 stricter than Core's `HasNoNewUnconfirmed`
- Location: `asm/bitcoin_mempool_policy.c:1117-1123`: every unconfirmed input must be *claimed by a conflict* (same outpoint).
- Failure scenario: original A spends unconfirmed P:0 and confirmed C:0; replacement B spends P:1 and C:0. Core: `parents_of_conflicts` = {P, C}; P is a parent of a conflict, so P:1 is allowed. bmc: P:1 unclaimed → "replacement-adds-unconfirmed". Wallet `bumpfee` that re-selects a sibling output of the same unconfirmed parent is refused here and accepted by Core. (`test_mempool_core_parity.c` "new-unconfirmed-input replacement refused" pins only the clearly-new case.)
- Core reference: `policy/rbf.cpp` `HasNoNewUnconfirmed`.
- Verdict: CONFIRMED.

##### MEM-15 (LOW) — output solver looser than Core's `Solver`
- Location: `asm/bitcoin_mempool_policy.c:404-431`. (a) `SPK_WITNESS_UNKNOWN` accepts `s[0]==0x00` with program length 2..40 other than 20/32: Core's `Solver` returns `NONSTANDARD` for version-0 programs of other lengths (consensus-unspendable, BIP141). (b) bare multisig is matched by first/last opcodes only: `OP_3 <key> OP_1 OP_CHECKMULTISIG` (m>n) and pushes that are not 33/65-byte keys are `MULTISIG` here, `NONSTANDARD` in Core (`MatchMultisig`, `IsStandard` `m<1||m>n`). (c) `P2PK` accepts any 33/65-byte push without `CPubKey::ValidSize` prefix checks. Effect: relays outputs Core will not, i.e. unprunable/unspendable UTXO bloat and wasted relay. No consensus impact.
- Verdict: CONFIRMED.
- Test coverage: `test_mempool_policy.c` covers `permitbaremultisig` on a well-formed multisig only.

##### MEM-16 (LOW) — min-relay fee comparison rounds the other way from Core
- Location: `asm/bitcoin_mempool_policy.c:1044`: `eff_fee*1000 < eff_vsize*rate` ⇔ fee < rate·vsize/1000 exactly (ceil). Core: `CFeeRate::GetFee` = `rate*vsize/1000` truncated (min 1) — with `minrelaytxfee` 100 sat/kvB and vsize 115, Core needs 11 sat, bmc needs 12. The mempool-floor path (`:1050-1052`) uses Core's rounding, so the two floors are inconsistent with each other. Also `test_mempool_policy.c` "200 sat over the adjusted 400 vB is under the 1 sat/vB floor" pins the 1 sat/vB unit, not this boundary.
- Verdict: CONFIRMED.

##### MEM-17 (LOW) — stale `anc_cnt`/`anc_bytes` after a parent confirms
- Location: `remove_node` `:616-668` clears children's `parent[k]` to 0xFFFFFFFF but never decrements their `anc_cnt`/`anc_bytes`; `decr_ancestors` fixes only the *ancestors'* `desc_*`. `anc_cnt` is read for TRUC at `:1288` (`pn->anc_cnt + n_pkg_par + 1 > TRUC_ANCESTOR_LIMIT`).
- Failure scenario: v3 parent P confirms; its v3 child C (anc_cnt still 2) is now a TRUC tx with no unconfirmed ancestors; C's own v3 child G is rejected "TRUC-violation" (Core accepts: C has 0 mempool ancestors). RPC readers walk links so `getmempoolentry` is unaffected.
- Core reference: `CTxMemPool::UpdateForRemoveFromMempool` / `UpdateAncestorsOf`.
- Verdict: CONFIRMED.

##### MEM-18 (LOW) — `prioritisetransaction` deltas are display-only
- Location: `asm/rpc_node.c:1482-1545` (parent-local table consulted by `getmempoolentry` `fees.modified` only); `rpc_chain.c:1035-1041` (template uses `infs[i].fee`, the base fee); the policy layer has no delta concept. Core applies `GetModifiedFee` to block assembly, eviction, RBF and the fee floors (`m_modified_fees`). An operator prioritising a tx changes nothing in this node's template or eviction. FEATURE_GAPS records prioritisetransaction as closed without this caveat; the code comment (`rpc_node.c:1484-1486`) states "entry/template views" which is half true.
- Verdict: CONFIRMED.

##### MEM-19 (LOW) — `mempool.dat` writer has no fsync
- Location: `asm/daemon/mempool_persist.c:106-108`: `fflush` → `fclose` → `rename`; no `fsync` on the file or directory (compare `fee_estimator.c:fest_write_file`, which does). Core's `DumpMempool` uses `FileCommit` before `RenameOver`. On a power loss shortly after `savemempool`/shutdown the renamed file can be empty or torn on ext4/xfs; the reader then reports a parse error and the pool starts empty. Contradicts the header's "a torn mempool.dat should never be loadable".
- Verdict: CONFIRMED.

##### MEM-20 (LOW) — non-robust cross-process mutex (accepted risk, restated)
- Location: `asm/daemon/mempool_cfg.c:76-81, 140-155` (PTHREAD_PROCESS_SHARED, not `PTHREAD_MUTEX_ROBUST`). Every accept in every inbound serve child holds it across `mpool_policy_add` (`tx_accept.c:862-866`), and the worker holds it across block connect. Any crash bug reachable in those regions (in *any* process) leaves the lock held forever: the whole node's mempool stops accepting, and RPC readers that lock (`rpc_chain.c` GBT `g_gbt_mph.lock`) hang. The helper `SIGKILL` sites in `main.c` (privbcast/dial helpers, catch-up kids) do not take the lock, so those are safe. Prior audit (08-29) accepted this; I note that MEM-12's long critical sections increase the window.
- Suggested fix: `PTHREAD_MUTEX_ROBUST` + `pthread_mutex_consistent` in `mp_lock` (state is rebuildable — `reorg_mempool_reconcile` already knows how).
- Verdict: CONFIRMED.

##### MEM-21 (LOW) — unlocked reads of mempool parents on the verification path
- Location: `asm/daemon/tx_accept.c:397-455` (`txacc_resolve_verify` → `mpool_get` → `txacc_tx_output`), called from `txacc_prechecks` `:655-661` and `txacc_script_verify` before `mp_lock` is taken at `:862/:929`. `mempool_cfg.c:66-70` documents only the getdata `mpool_get` as unlocked. A concurrent `mpool_compact` (memmove of the blob) or backward-shift `mpool_del` in another process can hand this reader a slot whose `len`/`blob_off` are from different entries or bytes mid-move; reads stay inside the blob mapping (both fields are < cap), so the outcome is a wrong prevout script/value and a false reject or a wrong sigop count — not memory corruption.
- Verdict: PLAUSIBLE (race window exists; I did not reproduce).

##### MEM-22 (INFO) — documentation contradicting code
- `tx_relay.c:15-31`: "no re-announcement", "no BIP339 wtxidrelay" — both are implemented in the same file (`txrelay_announce`, `TXR_MSG_WTX`). `docs/FEATURE_GAPS.md:1405-1406` lists `zmqpubsequence` as implemented; `node_config.c:750-765` refuses it and `zmq_pub.c` never publishes "sequence" (only 4 topics are added at `main.c:4153-4156`). `zmq_pub.c:26-33` says a slow subscriber "has the message DROPPED"; `:471` closes the subscriber instead (libzmq keeps the connection). `bitcoin_mempool_policy.c:56-58` claims atomic accept (see MEM-6).
- Verdict: CONFIRMED.

##### MEM-23 (INFO) — `acceptnonstdtxn` gating differs from Core
- `tx_accept.c:655-661` runs legacy-sigop, `bad-txns-too-many-sigops` and `IsWitnessStandard` unconditionally; Core gates `IsWitnessStandard` on `require_standard` and runs `tx-size-small` unconditionally, whereas `standard_checks` `:481` returns before `tx-size-small` when `accept_nonstd`. Test-network only.
- Verdict: CONFIRMED.

##### MEM-24 (INFO) — `getdata(MSG_TX)` answered with witness bytes
- `tx_relay.c:1195-1200` and `bitcoin_serve.asm` getdata tx arm mask the witness flag and serve the stored (witness) serialization for a bare `MSG_TX`. Core serializes `TX_NO_WITNESS` for non-witness requests. Only pre-segwit peers are affected (they would fail to parse); the serve path's own comment acknowledges the block case.
- Verdict: CONFIRMED.

#### Verified-correct controls

- `bitcoin_mempool.asm`: `mpool_put`/`get`/`del` bound every probe by slot count, wrap correctly, check `fill + txlen <= blob_cap` before copying, and `mpool_del` uses correct backward-shift deletion (the (i-k)&mask < (j-k)&mask rule) — pinned by `tests/test_mempool.c` ("tid1/tid2 survives after delete of another"). Stack alignment in `mpool_put` is 16 at every call.
- `parse_tx` (`bitcoin_mempool_policy.c:339-395`), `txacc_varint`/`txacc_tx_output`/`txacc_sigop_cost` (`tx_accept.c:355-470`), `txr_tx_parents`/`txr_varint` (`tx_relay.c:520-549`), `txv_parse` (`tx_verify.c:459-515`): every compactsize read is bounded by `end`, length checks use the subtraction form (`sl > end - p`), witness item loops consume ≥1 byte per iteration; `txacc_sigop_cost` caps inputs at 512 (returns -1 → no stamp) and `nin > 100000` is refused.
- Standardness matches Core where it is implemented: version 1..3 (`:483`), `MAX_STANDARD_TX_WEIGHT` 400,000 (`:484`), scriptSig ≤ 1650 and push-only (`:488-494`), OP_RETURN budget (`:508-511`), `permitbaremultisig` (`:506`), dust counting after the output loop with `MAX_DUST_OUTPUTS_PER_TX` 1 (`:517-521`), `MIN_STANDARD_TX_NONWITNESS_SIZE` 65 (`:525`), coinbase refused (`:479-481`). Dust threshold arithmetic for the recognised witness/non-witness types matches `GetDustThreshold` + `GetFee` (min 1).
- `txacc_witness_standard` (`tx_accept.c:583-652`) reproduces `IsWitnessStandard`: P2WSH script ≤ 3600, ≤ 100 stack items, items ≤ 80 bytes; taproot annex refused, empty control block refused, tapscript (0xc0) stack items ≤ 80 excluding script+control; P2SH-wrapped P2WSH via the last scriptSig push. `MAX_STANDARD_TX_SIGOPS_COST` 16,000 and `MAX_TX_LEGACY_SIGOPS` 2,500 enforced (`:655-661`). Pinned by `tests/test_policy_v31.c`.
- `bytespersigop`: `vsize = ceil(max(weight, sigops×bps)/4)` computed once and consumed/cleared on every path (`:940-950`); pinned by `test_mempool_policy.c` ("the NEXT tx is judged on its own sigops, not the dead one's").
- RBF rules 1 (signal on the *replaced* tx, skipped under fullrbf), 3, 4, 5 (≤100 evictions incl. descendants), disjointness (`bad-txns-spends-conflicting-tx`) (`:1085-1135`); pinned by `test_mempool_core_parity.c` §4/4b.
- Cluster limit 64 tx / 101 kvB measured on the post-replacement diagram (`:1177-1228`), ancestor/descendant limits (`:1229-1237`); pinned by `test_mempool_policy.c`.
- TRUC (BIP431): inheritance both ways incl. in-package parents, 10 kvB / 1 kvB caps on the sigop-adjusted vsize, 2-ancestor/2-descendant limits, sibling eviction only in Core's exact 1p1c shape and never in a package (`:1257-1370`); pinned by `test_truc_policy.c` and the regtest differential per FEATURE_GAPS 2026-09-03.
- Ephemeral dust rules 1 and 2 (`:990-1030`); pinned by `test_ephemeral_dust.c`.
- Rolling `mempoolminfee`: half-life 12 h, ÷4/÷2 speed-ups below ¼/½ capacity, zero below `incrementalrelayfee/2`, decay gated on a block since the last bump (`:680-735`); pinned by `test_mempool_core_parity.c` ("floor decayed after the block").
- Block-connect reconciliation removes confirmed txs alone and conflicting txs with descendants, and refuses to act on a tx whose txid it could not compute (`:1605-1645`); `tx_txid`'s int return is checked (the header notes the earlier void-declaration bug).
- `mempool_cfg.c`: regions are MAP_SHARED and initialised once pre-fork; `mpool_init` skipped in the asm when `mp_ext_inited`; fallback to per-process pools if the shared lock cannot be created rather than running unlocked; expiry with descendants under the lock every 60 s (`main.c:6311`). Pinned by `tests/test_mempool_shared.c` (cross-fork visibility, init-once).
- `mempool_persist.c` reader: every offset check is `pos + tl + 16 > fsz` style, single `malloc(fsz)`, v2 XOR key indexed by whole-file offset with the vector-serialised key prefix (verified both directions against Core per FEATURE_GAPS).
- `fee_estimator.c`: constants, bucket construction (iterative ×1.05 in the same FP order), `EstimateMedianVal` control flow, `removeTx` failure booking, `processBlock` early-outs, `validForFeeEstimation` = current tip ∧ no in-pool parents ∧ not in a package (`tx_accept.c:txacc_fee_note`), 60 h stale-file cut-off, atomic tmp+fsync+rename write; the tracked-tx map is bounded (Core's is not) and degrades to "untracked". Pinned by `tests/test_fee_estimator.c` and `validation/feeest_core_diff.sh` (byte-identical to Core).
- `notify.c`: substituted value filtered to `[A-Za-z0-9._:/-]` and truncated to 256 before `%s` expansion; only `%s` is expanded (other `%` sequences pass literally); over-long commands are refused rather than truncated; double-fork with signal reset. A 64-hex hash passes unchanged; no injection path.
- `zmq_pub.c`: `*` bind refused; subscriber servicing on its own thread under `g_lock` with a snapshotted poll set; frame length capped at `sizeof inbuf − 16`; subscription name bounds (`nl + 1 <= len`); non-blocking sends never stall the publisher; per-topic u32 LE sequence appended; hashes reversed to display order (`zmq_notify.c`). `zmq_notify.c` ring: atomic slot claim, `ready == seq+1` publish gate, overrun counted and logged. Pinned by `tests/test_zmq_ring.c`, `test_zmq_thread.c`, `test_zmq_bind.c`, `zmq_interop.py`.
- `tx_relay.c`: orphan pool bounded (2048 / 8 MB / 5 min TTL, one tx ≤ 2 MB), oldest-evicted; per-peer `notfound` memory; request TTL 60 s (Core `GETDATA_TX_INTERVAL`); 100 in-flight cap per peer; addr token bucket 1000/0.1 s with `> MAX_ADDR_TO_SEND` scored; 1p1c package path shares `mpol_package_well_formed`/overlay/fee context with `submitpackage` and clears all three contexts on every exit; Poisson per-leg announce timer; `-blocksonly` violations disconnect. Pinned by `tests/test_tx_relay.c` (868 lines), `test_relay_policy.c`, `test_net_policy.c`.
- `tx_submit.c`: announcement via the same per-leg inv schedule (no unsolicited `tx` push).

#### Coverage and limits

- I did not execute any test binary; all findings are from reading. Timings in MEM-9/MEM-12 are estimates from the loop bounds.
- Not traced: the block-connect side of nLockTime/BIP68 (MEM-1) beyond a repository-wide grep — the consensus reviewer should confirm `apply_block_inner` has no `IsFinalTx`/`SequenceLocks` equivalent; if so it is a CRITICAL consensus divergence (accepts blocks Core rejects with `bad-txns-nonfinal`).
- Not read: `pb_exchange` (private broadcast wire exchange), `txrecon.c`, `getrawmempool`/`getmempoolentry` renderers, `rpc_chain.c` template tail (weight/sigop budget accounting after chunk ordering), `bitcoin_serve.asm` beyond the three tx arms, `mempool_reload` (importmempool) wiring in `main.c`.
- Next: (1) write a regtest differential that submits a locktime-future tx and a BIP68-locked tx to both nodes; (2) a scale test that fills a small `maxmempool` with >65,536 tiny txs and then offers a high-fee tx (MEM-2); (3) a 30-parent child followed by RBF of parent 30 with `getblocktemplate` checked for the dangling child (MEM-3); (4) a claims-table exhaustion test with a 4-slot policy state (MEM-4); (5) verify Core v31's exact single-tx RBF rule set to settle whether MEM-7 should cite rule 6 or the diagram check.


---

### 6.8 Daemon orchestration, process model, configuration, logging, CLI tools, deployment — review

**Scope**
- Fully read: `asm/daemon/main.c` (all 7380 lines), `asm/daemon/node_config.c`, `asm/daemon/node_config.h`, `asm/daemon/wallet_pass.c/.h`, `asm/daemon/rpc_acl.c/.h`, `asm/daemon/notify.c/.h`, `asm/daemon/bitcoin_rpcd.c`, `asm/daemon/cli.c`, `asm/daemon/cli_conf.c/.h`, `asm/daemon/bitcoin_cli.c`, `asm/daemon/log_ts.h`, `asm/daemon/log_phase.h`, `asm/bmc_thread.h`, `asm/version.inc`, `asm/version_gen.h`, `asm/bitcoind.asm` (all 2194 lines), `asm/node_log.asm`, `scripts/start.sh`, `scripts/stop.sh`, `scripts/status.sh`, `scripts/worklog.sh`, `config/logrotate-bmc.conf`, the systemd units `/etc/systemd/system/bmc-bitcoind.service` + its four drop-ins, `bmc-logrotate.service/.timer` + drop-in (all readable), `docs/devlog/INCIDENT_2026-09-01_header_sync_genesis_answer.md`.
- Skimmed: `asm/bitcoin_cli.asm` (header + per-command cap handling), `asm/bitcoin_serve.asm` (only the serve-loop read model and setsockopt/timeout search), `asm/bitcoin_net.asm` lines 215-262, `asm/daemon/utxo_live.c` lines 250-370 and 2395-2415 (compaction fork / close path), `asm/rpc_server.c` cookie + auth section, `asm/rpc_chain.c` `cmd_stop`, `asm/rpc_node.c` `rpc_node_mempool_save`, `asm/daemon/chainctl.c` lines 55-86, `config/bitcoin.sample.conf` (all-comment; key list), `scripts/*.sh` (grep for dangerous ops), `scripts/*.py` (docstrings only), `asm/Makefile` bitcoind rule, test headers of the 14 daemon-related tests under `asm/tests/`.
- Not read: `asm/rpc_node.h` beyond the size macros and `node_status_t` field list; the storage/LSM asm the shutdown path touches (other reviewer).
- Two cheap live checks in a scratch datadir (never touching `data/` or the live node): `bitcoind -datadir=<dir> serve` exit status, and two `bitcoind serve <dir> <port>` instances against one datadir.

**Summary**
The orchestration layer is far more careful than a typical C daemon: every signal handler is async-signal-safe (flag set, `shutdown(2)`, `waitpid`), the SIGALRM budgets around every blocking network call are correct, shared-memory tables are published with `__sync_synchronize` and a pid-owning reclaimable spinlock, the notify hooks sanitise the substituted value before `sh -c`, the RPC ACL fails closed, and every 2026-09-01 incident fix is present in source and pinned by tests. The headline defects are in the process model rather than the hot loop: there is **no single-instance guard on the datadir** (two full daemons — two UTXO writers — boot side by side; verified empirically), inbound serve children have **no inactivity timeout** while `-peertimeout` is parsed and consumed nowhere (FEATURE_GAPS says "implemented"), the boot header fetch accepts up to 2M **zero-work headers** from the first peer that answers (the incident's root cause #4 was re-opened on 09-02), the config parser has **no `[section]` / `noX=` semantics** so a Core-shared `bitcoin.conf` can silently widen the mainnet RPC bind, and the worker's shutdown path never calls `utxo_live_close()` (pending checkpoint and background compaction child are abandoned). No consensus divergence lives in this module. Confidence: high on everything marked CONFIRMED; the report was written from the code, and the two behavioural claims that were cheap to test were tested.

#### Findings

| ID | Severity | Location | Title | Verdict |
|---|---|---|---|---|
| DMN-1 | HIGH | `main.c:6853-7126`, `7330` | No single-instance lock on the datadir; a second daemon (or an orphaned worker/serve child of the previous one) boots fully and becomes a second archive/UTXO writer | CONFIRMED (reproduced) |
| DMN-2 | MEDIUM | `main.c:2951-3015`, `3596-3647` | Boot header fetch accepts up to 2M headers with no PoW / nBits / min-chain-work check; index.dat is pre-extended and 16 workers dispatched on a single peer's say-so | CONFIRMED |
| DMN-3 | MEDIUM | `main.c:6400-6485`, `node_config.c:474`, `bitcoin_serve.asm` | Inbound serve children have no inactivity timeout and no eviction; `-peertimeout` is parsed, logged, and used by nothing (FEATURE_GAPS: "implemented") | CONFIRMED |
| DMN-4 | MEDIUM | `node_config.c:437-447`, `main.c:5665-5684`, `cli_conf.c:16-40` | No `[main]/[test]/[regtest]/[signet]` section semantics and no `noX=` negation; sectioned keys apply globally (fail-open for `rpcallowip`/`rpcbind`) | CONFIRMED |
| DMN-5 | MEDIUM | `main.c:5075-5087`, `utxo_live.c:2406-2411` | Worker shutdown `_exit(0)`s without `utxo_live_close()`: pending checkpoint not landed, background compaction child orphaned past the parent's exit | CONFIRMED (orphan/next-boot interaction PLAUSIBLE) |
| DMN-6 | MEDIUM | `main.c:6428-6480`, `6535`, `bitcoin_serve.asm:377` | Serve children ignore SIGTERM (flag-only handler, SA_RESTART read) and inherit the RPC listening socket; a stop outside systemd leaves them squatting the RPC port | CONFIRMED |
| DMN-7 | LOW | `main.c:6497`, `5186` | `clock()` (CPU time) used as the wall-clock for re-dial backoff; the blocksonly-violation redial also regresses to the DNS-seed list | CONFIRMED |
| DMN-8 | LOW | `main.c:3200-3211` | Predictable, never-unlinked `/tmp/dlc_hdr_<pid>.dat` opened without `O_EXCL` in every catch-up worker | CONFIRMED |
| DMN-9 | LOW | `node_config.c:449`, `568`, `437`, `670`; `main.c:1281`, `4809` | Integer parsing wraps before clamping; `bantime` unbounded (overflow makes a ban expire instantly); 1024-byte line splitting; `key=` (empty) is false where Core reads true | CONFIRMED |
| DMN-10 | LOW | `main.c:6567-6585`, `7048` | `bitcoind -datadir=<dir> serve` is documented as equivalent to the positional form but is refused with exit 2 — after seeding genesis and creating mempool/fee files in the datadir | CONFIRMED (reproduced) |
| DMN-11 | LOW | `scripts/start.sh`, `stop.sh`, `status.sh` | The three operator scripts invoke `bitcoind -daemon` (no mode: usage error) and `bitcoin-cli` (Core's binary name); none can work against this tree | CONFIRMED |
| DMN-12 | LOW | `bitcoind.asm:155-172`, `292` | A peer whose `version` message exceeds 256 bytes fails the handshake (Core allows a 256-byte UA alone) | CONFIRMED |
| DMN-13 | LOW | `wallet_pass.c:58-70`, `main.c:5700-5702`, `5874-5875`, `6428` | Passphrase read through an un-zeroised stdio buffer and silently truncated; mnemonic + BIP39 passphrase + seed + cookie secret live in the parent and are inherited by every peer-facing serve child | CONFIRMED (INFO-grade) |
| DMN-14 | INFO | various | `startupnotify` intermediate child decrements `g_inbound_n`; rpcauth entries added after the server is listening; pidfile via `fopen("w")`; `banned` mmap never unmapped; `lsock()` does not check `socket()`; `docs/FEATURE_GAPS.md` config table wrong for `peertimeout` | CONFIRMED |

##### DMN-1 (HIGH) — No single-instance guard on the datadir
- Location: `asm/daemon/main.c:6853` (`archive_trim_derived_tails`), `6855` (`store_init`), `6862-6867` (genesis seeding), `6821-6848` (`-reindex`), `7118` (`append.lock` opened only as an flock fd for per-append use), `7126` (P2P bind — the only thing that can fail on a co-resident instance, and only when `listen=1` on the same port), `7220` (`archive_repair_duplicates`), `7251` (`dl_catchup`), `7330` (worker fork), `6026-6029` (RPC bind failure is non-fatal: `return` from `serve_start_rpc`, the node runs on).
- Description: Core takes an exclusive `fs::FileLock` on `<datadir>/.lock` in `LockDataDirectory()` (init.cpp) before touching anything and aborts with "Cannot obtain a lock on data directory ... is probably already running". This daemon has no equivalent. `append.lock` is flock'ed only around individual appends (`bitcoin_idxscan.asm:283`, `store_append_shared`), never held for the process lifetime. The boot sequence truncates derived files (`archive_trim_derived_tails` cuts `index.dat`/`headers.dat`/`chainwork.dat` tails), zeroes duplicate records, runs a 16-worker catch-up, and forks a download worker that owns the single-writer LSM UTXO set — all with no exclusion against another instance doing the same. `main.c:1017-1019` records that exactly this happened on 2026-08-31 ("a stale co-resident daemon was SIGKILLed and the survivor stopped applying blocks").
- Failure scenario (reproduced in a scratch datadir): `bitcoind serve D 18555` then, 4 s later, `bitcoind serve D 18556`. Both boot completely: both log `[serve] download worker pid`, both log `[dl] worker: live UTXO state loaded`; the second logs `[rpc] server start failed: bind() failed on port 18443` and continues. On a real archive, instance B's `archive_trim_derived_tails` runs while instance A's worker is appending: B computes the tip from an index/headers snapshot and `truncate()`s `headers.dat`/`chainwork.dat` under A's writer; both workers then apply blocks into the same `utxo.dat` WAL / `utxo.idx` checkpoint / run files (the LSM is single-writer by design, `main.c:4168-4170`). The same happens with an orphaned worker from a SIGKILLed parent (the worker has no parent-death check) or a lingering serve child (DMN-6) during a manual restart.
- Core reference: `LockDataDirectory` / `util::LockDirectory` (init.cpp, util/fs_helpers.cpp).
- Suggested fix: first thing after `chdir(effdir)`: `open(".lock", O_RDWR|O_CREAT, 0600)` + `flock(LOCK_EX|LOCK_NB)`; on `EWOULDBLOCK` print Core's message and exit 1; keep the fd open for the process lifetime (children inherit it, which is fine — the lock belongs to the open file description, so a stale child holds it and correctly blocks a premature restart). Optionally `prctl(PR_SET_PDEATHSIG, SIGTERM)` in the worker.
- Verdict: CONFIRMED.
- Test coverage: none (no test starts two daemons; `test_archive_trim` runs the trim on a quiescent directory).

##### DMN-2 (MEDIUM) — Boot header fetch trusts zero-work headers from one peer
- Location: `asm/daemon/main.c:2951-3015` (`dlc_fetch_headers`), `2875-2876` (`DLC_HDR_SANE_MAX` is an attach-DEPTH bound since 2026-09-02, not a count bound), `3118-3131` (the first peer with `added>0` wins), `3596-3612` (`dlc_span` then `ftruncate(index.dat, (end_h+1)*48)` and worker fork).
- Description: the post-incident C fetch checks that the first header extends a header we hold, that overlapping headers are identical, that each header links to the previous, that `txn_count==0`, and that the attach point is not more than 100,000 below our tip. It never checks proof of work (`pow_check` is only used by `build_fake_chain`), never checks nBits against the chain schedule, and never compares accumulated work against `minimumchainwork` (which is armed at `main.c:6738` for `reorg_*`, not for the boot fetch). The only quantity bound is `round < 1000` × `DLC_HDR_PAGE 2000` = 2,000,000 headers per peer per boot. The incident report's root cause #4 ("No sanity bound on the header count") is therefore open again: fix #2 was rewritten from a count cap to a depth cap on 09-02 because a fresh node legitimately takes the whole chain.
- Failure scenario: an attacker's node is one of the ~8 confirmed-live candidates at boot (they come from `peers.good`, addnode, and a random sample of the book; `dlc_headers` returns on the first peer that adds ≥1 header). It answers `getheaders` with 2,000,000 headers that link from our real tip with arbitrary nBits/nonces. All pass the checks; `headers.dat` grows by 224 MB, `dlc_span` reports a 2M-block gap, `index.dat` is `ftruncate`d to +96 MB, 16 workers are forked and spend the boot asking honest peers for non-existent blocks (each failure bans a real peer for the run, `main.c:3729-3736`). The RPC surface stays correct (tip comes from stored blocks) but the boot is stalled/degraded for the run and `[dlc]` progress reports a fake target; the next boot's `archive_trim_derived_tails` cuts the junk. The 09-01 collateral ("UTXO engine sizing against the index the catch-up had just polluted") is reachable again; how `utxo_live_init` sizes against `hdr_len` was not traced here (PLAUSIBLE only for that part).
- Core reference: `CheckBlockHeader` → `CheckProofOfWork`; headers pre-sync anti-DoS (PR #25717: no header is stored until the presented chain's work exceeds `nMinimumChainWork`); `ContextualCheckBlockHeader` nBits.
- Suggested fix: in `dlc_fetch_headers`, `pow_check(h)` on every header (cheap, already linked), compare nBits to the previous header's within the retarget rules already in `bitcoin_pow_rules.c`, and refuse (roll back, mark peer failed) a reply whose cumulative work over the appended range is below what `minimumchainwork` or a per-header floor implies. Cross-check the answer of a second live peer before extending `index.dat` by more than, say, 50k records.
- Verdict: CONFIRMED (missing checks; bound); downstream sizing effect PLAUSIBLE.
- Test coverage: `tests/test_dialhelper.c` §6 pins continuation / genesis-first refusal / overlap / fork refusal; nothing pins PoW or a work floor on the boot path.

##### DMN-3 (MEDIUM) — Inbound connections have no inactivity timeout or eviction
- Location: `asm/daemon/main.c:491-508` (`lsock`: no `SO_RCVTIMEO` on the listener, so accepted sockets inherit none), `6390` (`peer_sock_buffers` sets only buffer sizes), `6400-6415` (hard refuse at `CFG_INBOUND_LIMIT()` = 189 by default), `6428-6480` (child runs `node_serve_loop` until read returns ≤0); `asm/bitcoin_serve.asm` contains no `setsockopt`, `poll`, or alarm (grep); `asm/daemon/node_config.c:474-475` parses `peertimeout` into `g_cfg.peer_timeout_s`, which has zero readers outside `node_config.c` (grep over `*.c`/`*.asm`).
- Description: a serve child blocks in `p2p_read` forever on an idle peer. There is no ping-based liveness, no `-peertimeout` inactivity disconnect, and no eviction when the inbound budget is full; the parent's only response at capacity is accept-and-close.
- Failure scenario: one host opens 189 TCP connections, completes the version handshake (or not — the child holds the slot from fork), and sends nothing. Every real inbound peer is refused from then on ("inbound at capacity"), 189 processes each holding a COW copy of the 384 MB hash index and the parent's mappings sit idle indefinitely, and (DMN-6) they also prolong every stop. Outbound sync is unaffected, so the node still follows the chain; it just stops serving.
- Core reference: `-peertimeout` (`DEFAULT_PEER_CONNECT_TIMEOUT`, `CConnman::InactivityCheck`: 60 s handshake, 20 min idle), `AttemptToEvictConnection`, and `PING` every 2 min with `TIMEOUT_INTERVAL`.
- Suggested fix: `setsockopt(c, SO_RCVTIMEO, {peer_timeout_s})` on the accepted socket in the parent before `fork()`, plus a per-child deadline in `node_serve_loop` (return on the timeout path), and Core-style eviction (oldest/least useful) when `g_inbound_n >= CFG_INBOUND_LIMIT()`. Either wire `peer_timeout_s` or move `peertimeout` to the no-effect table and fix FEATURE_GAPS.
- Verdict: CONFIRMED.
- Test coverage: none (`test_node_config` only checks the value parses and clamps).

##### DMN-4 (MEDIUM) — Config file sections and negation are not implemented
- Location: `asm/daemon/node_config.c:437-447` (a `[section]` line has no `=` and is skipped; every following key is applied unconditionally), no `no` prefix handling anywhere in the 1069 lines; `asm/daemon/main.c:5665-5684` (`serve_rpc_read_creds` re-reads `rpcport`/`rpcuser`/`rpcpassword` with the same flat parser, plus `atoi`), `asm/daemon/cli_conf.c:16-19` (documents that sections are skipped).
- Description: Core's `ArgsManager::ReadConfigStream` scopes keys under `[main]`, `[test]`, `[testnet4]`, `[signet]`, `[regtest]` to that chain, applies `-noX`/`noX=1` negation, and on a non-main chain *ignores* network-specific options (`port`, `rpcport`, `bind`, `rpcbind`, `rpcallowip`, `addnode`, `connect`, ...) that appear outside a section, with a warning. This parser does none of that. FEATURE_GAPS claims the surface is "133/181 implemented, ... 0 not recognised"; `nolisten=1` and any sectioned key are both silently mis-applied.
- Failure scenario: an operator reuses a Core `bitcoin.conf` containing `[regtest]\nrpcallowip=0.0.0.0/0\nrpcbind=0.0.0.0` (a common dev block) while running mainnet. Core: those lines are inert on mainnet. Here: `rpc_acl_add("0.0.0.0/0")` succeeds, `rpcbind` is honoured because `rpc_acl_configured()>0` (`main.c:6001-6011`), and the mainnet RPC server binds every interface and accepts every source. A `[regtest] connect=127.0.0.1:18444` line likewise pins the mainnet node to a loopback peer.
- Core reference: `ArgsManager::ReadConfigStream`, `GetChainTypeString`, `ArgsManager::InterpretOption` (negation), `common/args.cpp` "-only-applies-to" warning for network-specific options in the base section.
- Suggested fix: track the current section while reading; apply keys only when the section matches the selected chain (which means deferring the chain choice: read `chain=`/`regtest=`/... first, or two passes); implement `no<key>` as `<key>=0`; ignore the network-specific set in the base section on non-main chains with Core's warning. Apply the same parser to `serve_rpc_read_creds` and `cli_conf.c` (three parsers of one file is the drift the file's own header warns about).
- Verdict: CONFIRMED.
- Test coverage: `tests/test_node_config.c` has no section or negation case.

##### DMN-5 (MEDIUM) — Worker shutdown skips `utxo_live_close()`
- Location: `asm/daemon/main.c:5075-5087` (worker: log, `fest_shutdown_flush()`, `_exit(0)`); `asm/daemon/utxo_live.c:2406-2411` (`utxo_live_close`: `ckpt_now()` if a batch is pending, `utxo_live_compact_shutdown()`, `utxo_lsm_close()`) has no caller in `main.c` (grep); `utxo_live.c:342-349` (the compaction child inherits the worker's signal dispositions, i.e. the flag-only SIGTERM handler).
- Description: the only shutdown-aware code in the UTXO path is inside `utxo_live_catchup` (`utxo_live.c:2158`, checkpoint on the flag at a block boundary — pinned by `test_utxo_catchup_shutdown`). If SIGTERM arrives while the worker is anywhere else in its rotation (leg sync, relay drain, txsub linger, heartbeat), the worker exits with `g_ckpt_since>0` blocks applied but un-checkpointed (safe — the WAL is the truth — but the next boot replays the tail, which `main.c:1474-1487` describes as minutes on a large tail) and with a background compaction child still running. That child keeps merging and writing `utxo_run_*.dat` / the child manifest after its parent is gone. Under systemd it receives the cgroup SIGTERM (ignored: flag only) and is SIGKILLed at `TimeoutStopSec=900` (the drop-in comment says this timeout is "headroom for a compaction already in progress" — that is this child). Outside systemd, or if the restart is fast, the orphan overlaps the next instance's boot (DMN-1) which then adopts or unlinks the same files (`utxo_live.c:250-266`).
- Failure scenario: `systemctl restart` during a compaction: stop takes up to 15 minutes; or a manual restart: the old compaction child and the new worker both own LSM run files.
- Core reference: `Shutdown()` → `FlushStateToDisk` + `CDBWrapper` close; leveldb compaction threads are joined before the process exits.
- Suggested fix: in the worker's shutdown branch call `utxo_live_close()` (or at least `utxo_live_compact_shutdown()` which SIGKILLs and reaps the child) before `_exit(0)`; give the compaction child `prctl(PR_SET_PDEATHSIG, SIGKILL)` right after `fork()` so a parent death can never leave it running.
- Verdict: CONFIRMED (missing call); PLAUSIBLE (the orphan/next-boot file interaction was not traced into the LSM asm).
- Test coverage: `test_utxo_catchup_shutdown` covers only the in-catch-up path.

##### DMN-6 (MEDIUM) — Serve children ignore SIGTERM and inherit the RPC listener
- Location: `asm/daemon/main.c:6535-6536` (`signal(SIGTERM, handle_shutdown_signal)` — glibc `signal()` sets `SA_RESTART`), `1489-1492` (handler sets a flag the serve asm never reads; `bitcoin_serve.asm` has no reference to any shutdown state), `6428-6480` (child closes `l`, `l6`, whitebind fds; never closes the RPC listening socket created at `rpc_server.c:745` before the fork, nor `lo`), `6270-6294` (parent forwards SIGTERM to the worker only, then `_exit(0)`).
- Description: a serve child is stopped only by its peer disconnecting or by SIGKILL. The RPC listening socket is held open by every child, so after the parent exits (e.g. `bitcoin-cli stop` outside systemd, or a crash), a new instance's `rpc_server_start` fails with `bind() failed` and — because that failure is non-fatal — the new node runs with no RPC and no cookie until the last old child dies.
- Failure scenario: (a) any stop while N inbound peers are connected waits for those N children (systemd: up to 900 s); (b) manual restart per the ENGINEERING §8 runbook → new daemon has no RPC → cannot be stopped with `stop`, monitoring blind. The live log shows the last three restarts had no inbound children, which is why this has not been observed.
- Core reference: single process; `StartShutdown` interrupts all net threads; sockets are `SOCK_CLOEXEC` and never inherited.
- Suggested fix: in the child, close every inherited listener (`rpc_server` should expose its fd or set `FD_CLOEXEC` + the child `exec`s nothing, so an explicit close list is needed: RPC listen fd, `lo`, `li2p`, `g_txoq_parent`), and make `node_serve_loop` exit on the flag (a `poll` with timeout before each `p2p_read`, or `SO_RCVTIMEO` per DMN-3 with a flag check on the timeout path). Have the parent `kill(0, SIGTERM)`/track child pids and SIGKILL stragglers after a grace period.
- Verdict: CONFIRMED.
- Test coverage: none.

##### DMN-7 (LOW) — CPU clock used as the wall clock for backoff
- Location: `asm/daemon/main.c:6497` (`now_ms = clock()*1000/CLOCKS_PER_SEC` in `serve_mux`), `5186` (same expression in the worker, where every other timestamp is `CLOCK_MONOTONIC`), `5185` (`mux_next_peer(i, peers, pool_len, ...)` — the DNS-seed list, not `srcpool`).
- Description: `clock()` is process CPU time. In the parent it advances at a small fraction of wall time, so `REDIAL_BACKOFF_MS` (30 s) becomes a 30-CPU-second gap; in the worker the mismatch against `now_ms` (monotonic, huge) makes `mux_out_nextretry[i]` already in the past, i.e. no backoff. The blocksonly-violation branch also re-dials from `peers` (the seed hostnames), the exact regression `main.c:4423-4443` documents fixing on 2026-08-23.
- Failure scenario: `-blocksonly` node: a peer that relays a tx is disconnected and the slot is immediately re-dialled onto a DNS seed hostname, repeatedly, with no rate limit.
- Suggested fix: use `dh_now_ms()` at both sites; pass `srcpool, nsrc` at 5185.
- Verdict: CONFIRMED. Test coverage: `test_redial` covers the POLLHUP path only.

##### DMN-8 (LOW) — Predictable `/tmp` file in the catch-up workers
- Location: `asm/daemon/main.c:3200` (`/tmp/dlc_hdr_%d.dat`, pid), `3211` (`open(O_RDWR|O_CREAT|O_TRUNC, 0644)`, no `O_EXCL`/`O_NOFOLLOW`), never unlinked (grep: no `unlink` of it).
- Description: classic symlink race in a world-writable directory; the file is the worker's per-chunk header scratch and is left behind on every boot. Mitigated on the live host by `PrivateTmp=yes` (drop-in 50-hardening.conf), not for the runbook's manual invocation or other hosts.
- Suggested fix: keep it in the datadir (e.g. `dlc_hdr_<pid>.dat` under cwd, or `O_TMPFILE`), unlink at worker exit.
- Verdict: CONFIRMED. Test coverage: none.

##### DMN-9 (LOW) — Config value parsing edge cases
- Location: `asm/daemon/node_config.c:449` (`int iv = atoi(val)` for every key; `atoi` truncates `strtol`'s long, so `maxconnections=4294967496` → 200 passes the clamp), `568` (`bantime`: `atol`, `bv > 0`, no upper bound), `437` (`fgets(line, 1024)`: a longer line continues as a new line and its tail is parsed as `key=value` if it contains `=`), `670`/`495`/... (`iv?1:0`: `listen=` reads as 0).
- Failure scenario: `bantime=9223372036854775807` → `main.c:1281` `time(NULL)+bantime` wraps negative → `until <= now` → every automatic ban expires on the next `ctl_is_banned` call (fail-open); `listen=` (empty) disables listening where Core's `InterpretBool("")` is true.
- Core reference: `LocaleIndependentAtoi` (returns 0 on overflow), `InterpretBool`.
- Suggested fix: `strtoll` with `errno`/end checks and a shared bounded-parse helper; clamp `bantime` (Core has no cap but stores `int64` seconds and adds to `GetTime()`; cap at e.g. 100 years); reject lines that hit the buffer limit.
- Verdict: CONFIRMED. Test coverage: `test_node_config` clamps in-range typos only.

##### DMN-10 (LOW) — `-datadir=` form of `serve` is refused after doing work
- Location: `asm/daemon/main.c:6563-6573` (flags stripped, comment promises `bitcoind -datadir=/x serve` == `bitcoind serve /x`), `6581` (usage check passes because `flag_datadir`), `7048` (`strcmp(mode,"serve")==0 && argc>=3` — `argc` is now 2, so the branch is skipped and `main` returns 2 at 7379).
- Description: reproduced: `bitcoind -datadir=<scratch> serve` prints the whole boot preamble, runs `mempool_configure` (creates the shared mempool/fee files), `store_init`, seeds the regtest genesis block into a fresh datadir, then exits 2 silently (no usage message, because the usage check had already passed). Side effects precede argument validation.
- Suggested fix: validate `mode`/arity before any filesystem work; make the `serve` branch use `argc>=2 && dir` (port defaults from config already).
- Verdict: CONFIRMED (reproduced). Test coverage: none.

##### DMN-11 (LOW) — Operator scripts are dead
- Location: `scripts/start.sh:11-15` (`bitcoind -daemon -conf= -datadir=` — `-daemon` is on the no-effect list and no mode is given → usage error exit 2; `bitcoind` is also not on PATH), `scripts/stop.sh:8` and `status.sh:11` (`bitcoin-cli` — Core's binary; this tree builds `bitcoin_cli`; the fallback `killall bitcoind` matches nothing named `bitcoind.live`).
- Description: the only working stop path is `systemctl`/`bitcoin_cli stop`; the scripts documented in ENGINEERING §1 as "start/stop/status helpers" cannot start or stop this node.
- Suggested fix: rewrite to the systemd unit's command line, or delete them.
- Verdict: CONFIRMED. Test coverage: none.

##### DMN-12 (LOW) — 256-byte cap on the peer's `version` message
- Location: `asm/bitcoind.asm:152-160` (outbound: `p2p_read(... cap 0x100)`; `-2` truncated → `.fail`), `288-296` (inbound: cap 256).
- Description: a `version` message is 85 bytes + CompactSize + UA + 5; Core permits `MAX_SUBVERSION_LENGTH` = 256, so legitimate peers with a long `-uacomment` list (~170+ chars) cannot handshake with this node in either direction. The 2026-08-25 comment records the cap being raised from 128 for the same reason; the same class remains.
- Core reference: `MAX_SUBVERSION_LENGTH` (net.h).
- Suggested fix: read into a 512-byte buffer (the local frames already reserve 0x538/0x600).
- Verdict: CONFIRMED. Test coverage: none for long UAs.

##### DMN-13 (LOW/INFO) — Secret handling details
- Location: `asm/daemon/wallet_pass.c:63-70` (`fopen`/`fgets`: the passphrase transits a heap stdio buffer that `fclose` frees without zeroing; `fgets(out, cap)` silently truncates a passphrase longer than 255), `main.c:5700-5702`, `5856`, `5874-5875` (plaintext-store path keeps `g_wallet_mnemonic` and `g_wallet_bip39pass` for the process lifetime), `6428` (every inbound serve child is forked from this process, so it carries seed, mnemonic, passphrase and the RPC cookie secret while parsing untrusted P2P input).
- Description: not worse than Core's single-process model, and the refusal rules for the passphrase file are correct and tested; noted because a cheap mitigation exists.
- Suggested fix: `read(2)` into the caller's buffer instead of stdio; refuse (not truncate) an over-long passphrase; in the serve child, `explicit_bzero` the seed/mnemonic/passphrase/cookie globals immediately after `fork()`.
- Verdict: CONFIRMED. Test coverage: `test_wallet_pass` (refusal rules, accepted modes).

##### DMN-14 (INFO) — Small items
- `main.c:1463-1473` + `notify.c:77-96`: the parent's SIGCHLD reaper counts every non-worker child as an inbound child, so `startupnotify`'s intermediate child decrements `g_inbound_n` (drifts low by one; comment acknowledges the fail-open direction).
- `main.c:6026` vs `6047`: `rpc_auth_add` runs after `rpc_server_start`; a request with rpcauth credentials in that window gets 401 (harmless).
- `main.c:6038-6043`: pidfile via `fopen("w")` — Core does the same.
- `main.c:3629`, `3814-3816`: the `banned` mapping is never `munmap`ed (one page per catch-up run).
- `main.c:492`: `lsock` does not check `socket()`; the subsequent `bind(-1)` fails with EBADF and is reported as "bind failed".
- `docs/FEATURE_GAPS.md:1326`: `peertimeout` marked "implemented" — wrong (DMN-3); the "0 not recognised" claim ignores `noX=` and sectioned keys (DMN-4).
- `asm/daemon/bitcoin_rpcd.c:199-200`: the standalone RPC daemon defaults to `bitcoin`/`bitcoin` credentials when the config has none — a dev tool, not the production path, but the audit-N4 lesson applies.

#### Verified-correct controls
- Signal handlers are async-signal-safe: `handle_shutdown_signal` (`main.c:1489-1492`) sets a `sig_atomic_t` and `_exit`s only inside the UTXO reload window whose safety argument (`1474-1487`) is sound; `reap_children` (`1463-1473`) uses only `waitpid`; `mux_budget_alarm` (`1523-1528`) uses `shutdown(2)` to break a blocked read — the fix for the 08-31 "EINTR swallowed by retry" wedge; `SA_RESTART` is deliberately clear on the SIGALRM handlers (`1695-1697`).
- Every blocking network call in the worker is inside a wall-clock budget: `outbound_connect` (`1692-1738`, 20 s), `do_outbound_sync` (`5222-5229`, 60 s), reorg probe (`5254-5261`), catch-up chunk (`3289-3295`, 120 s + SIGUSR1 early-kill), `bmc_v2_handshake` 5 s; anonymity dials are moved to helper children with a 120 s reaper (`2096-2160`, `2302-2333`), `SCM_RIGHTS` transfer is correct. `tcp_connect_ip` sets `SO_SNDTIMEO` so a blackholed `connect()` fails in 10 s (`bitcoin_net.asm:245-258`).
- 2026-09-01 incident fixes are all present: linkage/overlap/fork/`txn_count` checks and rollback (`main.c:2974-3010`), header mirror topped up from the archive before any peer is asked (`3077-3097`, buffer sized 4 MB and tip read from `store+24`, the two crash causes of builds q/r), boot self-heal `archive_trim_derived_tails` before `store_init` (`6853`), catch-up worker-wait honours SIGTERM (`3662-3671`), boot exits on a stop seen after the catch-up (`7255-7263`), the asm `node_ibd_headers` is no longer called at boot (`3060`). Pinned by `test_dialhelper` §5/§6 and `test_archive_trim`.
- Shared-memory publication is ordered: ban entries write `subnet`/`created` then `__sync_synchronize()` then `until` (`1211-1214`, `4806-4809`); ctl/txsub/blksub acks are written after a full barrier (`4833-4836`, `4938-4941`, `5070-5073`); peer slots publish `used` last (`1966`); inbound slot claim uses CAS with dead-pid reclaim (`1162-1176`). The misbehaviour spinlock holds the owner pid and reclaims from a dead holder (`1031-1052`); `_Static_assert` keeps the local and shared table sizes equal (`993`).
- gettxout IPC refuses rather than guesses: bounded reads with deadline, echo of the outpoint to discard stale replies, `spklen` bounded both sides, serviced only at the worker's quiescent point (`1365-1458`, `5426`).
- Notify hooks: substituted value filtered to `[A-Za-z0-9._:/-]` and length-capped before `sh -c`; double-fork so the hook is never counted as an inbound child; `SIGPIPE`/`SIGCHLD` reset in the grandchild (`notify.c:36-97`). `bmc_alert_deliver` goes through the same sanitiser.
- No format-string injection: every `fprintf` in `main.c` uses a literal format; peer-derived strings (`ua`, `subver`, hosts, `reason`) are `%s` arguments, and the UA is reduced to printable ASCII before logging (`1913-1934`, `1949-1963`). `log_ts.h` formats into a fixed 8 KB buffer with `vsnprintf` and truncates, one `fwrite` per line (atomic across the forked processes).
- No secrets in logs: cookie and passphrase are never printed; the RPC start line prints `user=` only; `wallet_pass_load` messages print the path, not the content; `boot_pass` is `memset` after use (`5851`).
- RPC ACL fails closed: base list is `127.0.0.0/8` + `::1`, an unparsable `rpcallowip` is fatal (`main.c:5994-6000`), `rpcbind` without `rpcallowip` is ignored with Core's message (`6002-6007`), `rpc_acl_allows` re-initialises an empty list rather than allowing (`rpc_acl.c:31`). Pinned by `test_rpc_acl`.
- Cookie: 32 bytes from `/dev/urandom` (short read refused), created with the configured mode from the outset (no chmod window), removed at shutdown, constant-time compare (`rpc_server.c:220-249`, `205-216`); server starts on cookie alone (`test_rpc_start_policy`).
- Wallet passphrase file: must be absolute, outside the datadir (cwd prefix check), a regular file, not world-accessible, not group-writable; refusals are loud (`wallet_pass.c:52-60`, `84-114`); `test_wallet_pass` pins both refusal and acceptance.
- Chain/datadir mismatch refused by comparing block 0's hash (`1813-1840`); `-reindex`/`-reindex-chainstate` are one-shot via marker files (`4188-4204`, `6821-6848`); prune refuses across holes (`7186-7190`).
- `bmc_thread.h`: explicit 64 MB stacks for every thread (the incident-#13 TLS-in-stack overflow), used for the mempool-reload and I2P-accept threads.
- `bmc_tcp_info` mirror (`4639-4647`) matches the kernel `struct tcp_info` layout up to `tcpi_bytes_received` (7 u8 + pad, 24 u32, then u64s at offset 104) and guards each field by returned length.
- Struct/offset agreement between C and asm: `store_buf` offsets used in C (`+8` idx_fd, `+16` idx_len, `+24` tip, `+28` cur_file_no, `+36` magic, `+40` lock fd, `+48` prune) are the ones `bitcoin_store.asm` publishes; `g_peer_version_payload[256]`/`g_peer_version_len` match `bitcoind.asm:2171-2172`; `node_ua_buf` is 256 bytes with a one-byte varstr length and `main.c:6635` clamps to 255; `node_relay_flag`/`node_services` sizes match; `node_status_t.mis_lock` is `volatile int`, matched by the `int` CAS in `mis_lock_acquire`. `node_handshake`'s frame (0x538) and `node_accept_handshake`'s (0x600) hold the 512-byte version payload, 256-byte receive buffer, `cmd` and `plen` without overlap; the alignment arithmetic in the comments is right.
- `node_log.asm` buffers (96/128 bytes) are only ever fed literal strings ≤ 42 bytes from `main.c`; the save-area-above-rbp layout is correct.
- Deployment: the unit runs unprivileged with `LimitCORE=0`, `NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome=read-only`, `PrivateTmp`, address-family and kernel restrictions (audit N5 remediation verified in the drop-in); logrotate reads a root-owned copy and rotates as the service user (N6 verified); `-Werror`, `-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, full RELRO/`BIND_NOW` on the daemon link (`Makefile:31,39,2560-2563`).
- Time: all timestamps are `long long`/`time_t`; only `ab2_add`'s `last_seen` is `unsigned` (2106); block-time-too-new uses system time, matching Core ≥ v26 (no network time adjustment).

#### Coverage and limits
- Not traced: how `utxo_live_init` sizes against `hdr_len`/index length (DMN-2's downstream effect), the LSM's handling of an orphan child manifest at the next boot (DMN-5), and `bitcoin_serve.asm`'s internals beyond confirming no timeout/shutdown handling (the serve loop is the P2P reviewer's).
- `asm/bitcoin_cli.asm` was only skimmed for output-cap discipline (each `cmd_*` takes and checks `cap`); its argument parsers were not audited.
- Not run: any test binary (the daemon tests need loopback peers and take minutes); the two scratch-datadir runs above were the only executions.
- Next: add the `.lock` guard and a two-instance test; wire `peertimeout` + eviction and add a 190-idle-connection test; PoW + work-floor in `dlc_fetch_headers` with a hostile-peer case in `test_dialhelper`; section/negation support in one shared parser with `test_node_config` cases; `utxo_live_close()` on the worker's exit path with a compaction-in-flight shutdown test; close inherited listeners in serve children and make them honour the shutdown flag.


---

### 6.9 RPC transport, JSON, server, node/network RPCs, signer — review

**Scope:**
- Fully read: `asm/rpc_server.c`, `asm/rpc_server.h`, `asm/rpc_json.c`, `asm/rpc_json.h`, `asm/rpc_net.c`, `asm/rpc_net.h`, `asm/rpc_node.c`, `asm/rpc_node.h`, `asm/rpc_signer.c`, `asm/rpc_signer.h`.
- Skimmed (only the parts the module calls into or that write what it reads): `asm/rpc_commands.c` (`rpc_dispatch`, `rpc_param_str`, `cmd_getrpcinfo/logging/getmemoryinfo`), `asm/rpc_chain.c` (`cmd_stop/uptime`), `asm/daemon/main.c` (RPC start-up 5940-6070, ctl channel worker 4700-4835, peer-slot writers 1160-1175 / 1940-1967, ban matcher 955-980, shutdown 6280-6296), `asm/daemon/rpc_acl.c`, `asm/daemon/subnet.c`, `asm/daemon/bitcoin_rpcd.c` (240-280), `asm/bmc_thread.h`, `asm/bitcoin_tx.asm` (`tx_txid` contract only), `asm/tests/test_rpc_server.c`, `asm/tests/test_rpc_transport.c` (assertion list), `asm/tests/test_rpc_node.c` (grep for the RPCs reviewed), `docs/FEATURE_GAPS.md` (RPC sections), `docs/RPC_LIVE_NODE.md` (grep only), both prior audits (RPC sections).
- Not read: the rest of `rpc_commands.c` / `rpc_chain.c` / `rpc_wallet_ops.c` (sibling reviewer), `daemon/dialer.c`, the inbound-accept ban check, `mempool_dump.c`.

**Summary:**
The HTTP/JSON-RPC layer is small, readable and has had real hardening (constant-time auth with every credential arm evaluated, 512-deep JSON limit matching UniValue, 9 MiB request cap, sized reply buffers, per-connection ACL, 503 on queue depth). The prior-audit fixes in this area (depth counter, `ct_eq`, request cap, signer quoting, rpcbind gating) are all present as claimed. What the 2026-09-01 move from a serial accept loop to a 16-thread worker pool left behind is the main new risk: a global `g_last_auth_user` that is now shared between concurrently authenticating threads (an `rpcwhitelist` authorization race), a leak of the client fd plus the response body on any failed header write (an authenticated client can exhaust the serve parent's descriptors, which then busy-loops in `accept`), and blocking per-read socket timeouts that let an unauthenticated loopback client pin every worker. On the method side, `disconnectnode <nodeid>` uses a different numbering than the `id` `getpeerinfo` reports, so it disconnects the wrong peer. JSON-RPC batch requests are rejected with a message the code attributes to Core although Core executes them. No consensus-relevant path lives in this module. Confidence: high for the transport findings (all traced end to end); Core parser/escaper semantics are cited from memory of `univalue_read.cpp` / `univalue_escapes.h` and are flagged where that matters.

#### Findings

| ID | Severity | Location | Title | Verdict |
|---|---|---|---|---|
| RPC-1 | MEDIUM | rpc_server.c:587, 791-792 | Client fd + response body leaked on failed header write; `accept()` EMFILE busy-loop | CONFIRMED |
| RPC-2 | MEDIUM | rpc_server.c:351-355, 394-395, 753-754 | `g_last_auth_user` shared across 16 workers: rpcwhitelist authorization race | CONFIRMED |
| RPC-3 | MEDIUM | rpc_node.c:193-199; daemon/main.c:4713-4725 | `disconnectnode` nodeid numbering differs from `getpeerinfo` id: wrong peer disconnected | CONFIRMED |
| RPC-4 | MEDIUM | rpc_server.c:678-714, 821-831 | Per-read timeout only: unauthenticated slow client pins all worker threads (slowloris) | CONFIRMED |
| RPC-5 | LOW | rpc_server.c:760-780, 636-651 | Longpoll path: substring match spawns unbounded detached threads outside the pool/queue limits | CONFIRMED |
| RPC-6 | LOW | rpc_server.c:512-517; tests/test_rpc_server.c:274-280 | JSON-RPC batch (array) requests rejected; comment and test attribute this to Core, which executes batches | CONFIRMED |
| RPC-7 | LOW | rpc_json.c:275-355 | Parser accepts what UniValue rejects (raw control chars, lone surrogates, `01`, `-`, `1.`); surrogate pairs encoded as CESU-8; `` truncates | CONFIRMED (Core side from memory) |
| RPC-8 | LOW | rpc_node.c:860-866; daemon/main.c:4787-4793 | `setban` stores unparseable subnets silently; prefix restricted to /8-/32 multiples of 8 for no reason; bantime overflow | CONFIRMED |
| RPC-9 | LOW | rpc_node.c:142-152 | `getnetworkinfo`: the three known proxy bugs confirmed; `relayfee`/`incrementalfee` hardcoded while `getmempoolinfo` reports the configured floors | CONFIRMED |
| RPC-10 | LOW | rpc_server.c:580-594, 724 | HTTP: no `Connection: close` yet connection closed; no trailing `\n` in body; request path ignored (`/wallet/<name>` routing, 404 for other paths absent) | CONFIRMED |
| RPC-11 | LOW | rpc_json.c:103-134 | Writer does not escape 0x7f (Core emits ``) | PLAUSIBLE |
| RPC-12 | LOW | rpc_server.c:619, 646-648, 781-783; rpc_node.c:1413-1456, 1577, 1834-1851; rpc_signer.c:80-85 | Single `g_exec_lock` serialises every RPC behind 90 s waits, importmempool, and the signer's popen (including `stop`) | CONFIRMED |
| RPC-13 | LOW | daemon/main.c:1163-1171, 1943, 1966 | Inbound peer-slot claim: CAS then `memset` clears `used`, two children can claim one slot | PLAUSIBLE |
| RPC-14 | INFO | rpc_server.c:180-190, 487-501 | rpcwhitelist edge semantics differ from Core (`rpcwhitelistdefault=1` with no entries; 403 only after a parseable body) | CONFIRMED |
| RPC-15 | INFO | daemon/main.c:6026 vs 6048-6055 | Server starts before rpcauth entries and cookie are registered (fail-closed window; unsynchronised `g_n_rpcauth`) | CONFIRMED |
| RPC-16 | INFO | rpc_server.c:412-418, 438 | `rj_dup` 64 KiB cap echoes a large `id` as `null`; `rj_clone` exists | CONFIRMED |
| RPC-17 | INFO | rpc_signer.c:85-91 | Signer exit status reported as raw `wait` status; stderr/env inherited | CONFIRMED |
| RPC-18 | INFO | rpc_server.c:843-862, 797-798; rpc_acl.c:18 | IPv4-only listener: `rpcbind=::1` fatal, `::1` ACL entry and IPv6 `rpcallowip` entries dead | CONFIRMED |
| RPC-19 | INFO | rpc_node.c:572-583, 236-250; rpc_server.h:1-27 | Stale comments contradict code (ban list, ping, "loopback-only") | CONFIRMED |
| RPC-20 | INFO | rpc_node.c:1873-1875 | `sendrawtransaction` txid scratch (162 KB) smaller than the 404 KB stage: an oversized non-standard tx gets -22 instead of a policy reject | CONFIRMED |

##### RPC-1 (MEDIUM) — Client fd + response body leaked on failed header write; `accept()` busy-loop on EMFILE
- Location: `asm/rpc_server.c:587` (`if (write_all(cfd, hdr, (size_t)hl) != 0) return;`), `asm/rpc_server.c:572-594`, `asm/rpc_server.c:791-792`.
- Description: `handle_request` allocates `respbody` (line 575) and then, if the header write fails, returns without `free(respbody)` and without `close(cfd)`. Every other exit path in `service_conn`/`handle_request` closes the fd. The failure is reachable by any authenticated client: send a request, then reset the connection (or simply do not read a multi-MB reply so the 30 s `SO_SNDTIMEO` fires). Both the descriptor and the serialized reply (which for `getblock` verbosity 2 is many MB) are leaked per occurrence. Once the parent's descriptor table is full, `server_thread` does `accept()` → EMFILE → `continue` with no sleep (line 791-792), spinning one core, and the same process's P2P inbound `accept` fails too.
- Failure scenario: loop {open TCP, POST `getblock <big>` with cookie auth, close with `SO_LINGER {1,0}`} from loopback. Each iteration leaks one fd and one reply buffer; at `RLIMIT_NOFILE` (1024 default) the RPC listener and the inbound P2P listener both stop accepting, and the RPC accept thread spins. `stop` cannot be delivered over RPC any more.
- Core reference: libevent's `evhttp` owns the connection; a failed write frees the request and connection (`evhttp_connection_free`). No leak, no spin.
- Suggested fix: `if (write_all(...) != 0) { free(respbody); close(cfd); return; }`; in `server_thread`, on `accept()` failure with EMFILE/ENFILE sleep briefly (Core/libevent backs off 1 s).
- Verdict: CONFIRMED (path traced; not executed against the live node per the brief).
- Test coverage: none (`test_rpc_server.c` only exercises well-behaved clients).

##### RPC-2 (MEDIUM) — `g_last_auth_user` shared across worker threads: rpcwhitelist authorization race
- Location: `asm/rpc_server.c:351` (static global), `:354` (cleared at entry of `auth_ok`), `:394-395` (written on success), `:753-754` (copied by the caller for `wl_forbidden`), `:821-831` (16 `worker_thread`s call `service_conn` concurrently; `g_exec_lock` is taken only at `:781`).
- Description: The comment says "one connection at a time per worker" but the variable is process-global, not per-worker, and since 2026-09-01 up to 16 workers run `service_conn` → `auth_ok` → `snprintf(user, ..., g_last_auth_user)` concurrently with nothing between the write in `auth_ok` and the read at line 753 except the return. Thread A authenticates as `alice` (whitelist: `getblockcount`), thread B authenticates as `admin` in the same window; A's line 753 copies `admin` (or an empty string from B's line 354) and A's `wl_forbidden` is evaluated for the wrong principal.
- Failure scenario: an operator deploys `rpcwhitelist=alice:getblockcount` for a monitoring user and keeps `admin` for themselves. `alice` sends a continuous stream of concurrent `sendtoaddress` requests; whenever an admin request is being authenticated at the same instant, one of alice's requests is checked as `admin` and is executed. The reverse (admin denied as alice) is also possible. `rpcwhitelist` is the only authorization boundary between RPC users; this defeats it with timing alone.
- Core reference: `HTTPReq_JSONRPC` keeps `jreq.authUser` per request (`RPCAuthorized(..., jreq.authUser)`), never in a global.
- Suggested fix: make `auth_ok` return the user in a caller-supplied buffer (it already has `decoded`/`ulen` in hand); delete the global.
- Verdict: CONFIRMED (race is unconditional in the code; the exploit window is a few instructions wide but attacker-drivable by volume).
- Test coverage: `test_rpc_whitelist.c` is single-connection; no concurrent test.

##### RPC-3 (MEDIUM) — `disconnectnode <nodeid>` and `getpeerinfo.id` use different numbering
- Location: `asm/rpc_node.c:193-199` (`id` is a counter incremented only for slots that pass the `used`/dead-child filter), `asm/daemon/main.c:4713-4725` (worker matches `num == (long long)i` against the raw outbound leg index `i`, outbound legs only).
- Description: `getpeerinfo` reports `id` as the position among live entries; the worker interprets the nodeid as the raw leg slot. The two agree only while every slot below is occupied and no inbound slot precedes. After any leg churn (slot 1 free, slots 0,2,3 live) `getpeerinfo` shows ids 0,1,2 for legs 0,2,3; `disconnectnode "" 1` closes leg 1 (nothing) or, after further churn, a different peer than the operator selected. Inbound peers (slots 64..127) are listed with ids but cannot be disconnected by id at all (loop is `i < mux_n_out`), nor by address (only outbound hosts are compared). Ids are also reused, unlike Core's monotonically increasing `NodeId`.
- Failure scenario: operator sees a misbehaving peer as `id: 5` in `getpeerinfo`, runs `disconnectnode "" 5`, a healthy peer is dropped and the target stays connected; RPC returns success.
- Core reference: `CConnman::DisconnectNode(NodeId)` keys on the unique `CNode::GetId()` that `getpeerinfo` reports.
- Suggested fix: publish the slot index (or a monotonic id stored in `rpc_peer_t`) as `id`, and have the worker match on that; extend disconnect to inbound children (they have `pid`, so `kill(pid, SIGTERM)` is available).
- Verdict: CONFIRMED.
- Test coverage: `test_rpc_node.c:208-235` pins `id` 0/1 for two contiguous fake slots — it pins the numbering that diverges, not the mapping.

##### RPC-4 (MEDIUM) — Blocking per-read timeout: slow clients pin every worker (unauthenticated)
- Location: `asm/rpc_server.c:678-680` (`SO_RCVTIMEO = -rpcservertimeout`, applies per `read()`), `:686-714` (blocking read loop before authentication), `:821-831` (fixed pool of 16 workers, each blocked in `service_conn`).
- Description: The timeout is reset by every byte received, so a client that sends one byte every 29 s holds a worker forever; authentication happens only after the full body has arrived, so no credential is needed. 16 such connections (default `rpcthreads`) occupy the pool; the next 64 connections sit in the queue unanswered; everything after that gets 503. The operator's own `bitcoin-cli stop` is queued behind them.
- Failure scenario: any process on loopback (or any host in `rpcallowip`) opens 16 sockets, sends `POST / HTTP/1.1\r\nContent-Length: 1000000\r\n\r\n` then trickles bytes. All RPC is dark until the client stops.
- Core reference: libevent reads requests non-blockingly on the event thread; worker threads (`-rpcthreads`) only receive complete requests, so slow senders cost memory (bounded by `MAX_SIZE`) not threads. Core's `-rpcservertimeout` is likewise per-activity, so the *timeout* semantics match; the *thread pinning* does not.
- Suggested fix: read requests on the accept thread with `poll()` and a per-connection deadline, hand only complete requests to the pool; or at least enforce a total per-request deadline in `service_conn`.
- Verdict: CONFIRMED.
- Test coverage: none.

##### RPC-5 (LOW) — Longpoll path spawns unbounded detached threads on a substring match
- Location: `asm/rpc_server.c:760-780` (`"longpollid"` and `getblocktemplate` searched as raw substrings of the body, before JSON parsing), `:768-776` (a new detached 64 MiB-stack thread per request, `bmc_pthread_create`), `:636-651` (`lp_waiter` holds the request buffer up to 60 s).
- Description: The check is on the raw body, so `{"method":"getrawtransaction","params":["...longpollid...getblocktemplate..."]}` (or any value containing both tokens) takes the longpoll path. The path returns before the worker slot is released, so the `rpcthreads`/`rpcworkqueue` bounds do not apply; each request costs a thread, an fd, and up to 9 MiB of buffer for up to 60 s. Also, `rpc_server_stop` does not join these threads, so a waiter can call `handle_request` → `rpc_dispatch(..., g_wallet, ...)` after the caller has torn down the wallet (PLAUSIBLE; `main.c` never calls `rpc_server_stop`, `bitcoin_rpcd` does).
- Failure scenario: authenticated client sends thousands of such requests; thread/pid limit (`ulimit -u`) is reached in the serve parent, so `fork()` for inbound P2P connections fails.
- Core reference: Core's longpoll waits inside the handler on a condition variable (`g_best_block_cv`), bounded by `-rpcthreads`.
- Suggested fix: parse first, decide on `method == "getblocktemplate"` with a `longpollid` member; cap concurrent waiters; join or cancel them in `rpc_server_stop`.
- Verdict: CONFIRMED (spawn), PLAUSIBLE (post-stop use).
- Test coverage: none.

##### RPC-6 (LOW) — JSON-RPC batch requests rejected; attributed to Core incorrectly
- Location: `asm/rpc_server.c:512-517` ("parseable but not an object (e.g. array/string): Core throws RPC_PARSE_ERROR 'Top-level object parse error' -> HTTP 500"), `asm/tests/test_rpc_server.c:274-280` (pins `[1,2,3]` → 500).
- Description: Core (`httprpc.cpp` `HTTPReq_JSONRPC`) handles `valRequest.isArray()` via `JSONRPCExecBatch`, returning HTTP 200 with an array of replies (and per-element whitelist checks). Only a non-object, non-array top level gets "Top-level object parse error". This server answers every array with -32700/HTTP 500. Batch is used by real tooling (electrs, python-bitcoinrpc `batch_`, some explorers). Not listed in `docs/FEATURE_GAPS.md` (grep `batch` finds only unrelated uses), and the code comment states the opposite of Core's behaviour, so the divergence is invisible to the parity docs.
- Failure scenario: `[{"method":"getblockcount","id":1},{"method":"getbestblockhash","id":2}]` → 500 with a parse error; clients treat the node as broken.
- Core reference: `JSONRPCExecBatch` in `src/rpc/server.cpp`; `httprpc.cpp` array branch.
- Suggested fix: iterate array elements through the single-request path and return an array; document until then.
- Verdict: CONFIRMED.
- Test coverage: the divergence itself is pinned as intended behaviour.

##### RPC-7 (LOW) — JSON parser laxer than UniValue
- Location: `asm/rpc_json.c:275-332` (strings), `:342-355` (numbers), `:296-318` (`\u`).
- Description: (a) raw bytes < 0x20 inside a string are accepted (UniValue `getJsonToken` returns `JTOK_ERR` for them); (b) `😀` is encoded as two 3-byte sequences (CESU-8) and a lone surrogate is encoded as-is — UniValue's `JSONUTF8StringFilter` combines pairs into 4-byte UTF-8 and rejects lone surrogates; (c) `` produces an embedded NUL that `xstrdup` truncates at; (d) numbers: `01`, `-`, `1.`, `1e` are accepted verbatim (UniValue enforces the JSON number grammar). The resulting strings are re-emitted raw by the writer (only < 0x20, `"` and `\` are escaped), so a wallet label set with an escaped emoji is stored and returned as invalid UTF-8.
- Failure scenario: `setlabel <addr> "😀"` stores 6 bytes of CESU-8; `getaddressinfo` returns invalid UTF-8; Core would store/return the 4-byte code point. Error-code fidelity: bodies Core rejects with -32700 are dispatched here and produce method-level errors.
- Core reference: `src/univalue/lib/univalue_read.cpp`, `JSONUTF8StringFilter` (`univalue_utffilter.h`).
- Suggested fix: reject control chars, implement surrogate pairing, enforce the number grammar.
- Verdict: CONFIRMED for this parser; Core semantics cited from memory.
- Test coverage: `test_rpc_json.c` (197 lines) and `test_rpc_json_depth.c` cover escapes it does handle and the depth bound; none of the above.

##### RPC-8 (LOW) — `setban` argument handling
- Location: `asm/rpc_node.c:860-866` (bantime), `asm/daemon/main.c:4787-4793` (prefix rule), `:4805-4809` (stored verbatim), `asm/daemon/subnet.c:78-82` (`subnet_covers_str` returns 0 for an unparseable entry).
- Description: (a) The subnet string is never parsed before storage: `setban "not-an-ip" add` succeeds, appears in `listbanned`, and never matches — Core raises -30 "Error: Invalid IP/Subnet". (b) The worker refuses any `/n` not in {8,16,24,32} claiming the matcher cannot enforce it, but `subnet_covers` masks arbitrary prefixes including IPv6; so `setban 2001:db8::/32` is accepted while `2001:db8::/64` and `::1/128` are refused. (c) `bantime` is `atoll`'d and added to `time(NULL)`; a saturated value wraps `until` negative, which `listbanned`/`ctl_is_banned` treat as expired (Core has the same overflow, so INFO-grade). (d) `absolute=true` with `bantime<=0` silently becomes a 24 h relative ban.
- Core reference: `setban` in `src/rpc/net.cpp` (`LookupSubNet` → RPC_CLIENT_INVALID_IP_OR_SUBNET).
- Suggested fix: call `subnet_parse` in `cmd_setban` and return -30; drop the /8-multiple rule.
- Verdict: CONFIRMED.
- Test coverage: `test_rpc_node.c:1127-1160` pins add/duplicate/remove/expiry on valid IPv4 only.

##### RPC-9 (LOW) — `getnetworkinfo` fields
- Location: `asm/rpc_node.c:142-152`.
- Description: The three defects the 699e244 diff review found are present in current source, one line each: (1) `:143-147` echo the raw `-proxy`/`-onion` strings, so `-onion=0` reports proxy `"0"`; (2) `:149` reports cjdns with no proxy although the dialer routes cjdns through the proxy; (3) `:146` reports `proxy_randomize_credentials` for ipv6 from `-proxyrandomize` although the ipv6 dial passes NULL credentials. Beyond those: `relayfee` and `incrementalfee` (`:151-152`) are the literal `0.00001000` while `getmempoolinfo` (`:597-602`) reports the configured `-minrelaytxfee`/`-incrementalrelayfee`; with a non-default floor the two RPCs disagree. `timeoffset` is always 0 (no time-offset tracking exists; documented style elsewhere, but not here).
- Core reference: `getnetworkinfo` in `src/rpc/net.cpp` (`relayfee` = `minRelayTxFee`, `incrementalfee` = `incrementalRelayFee`).
- Suggested fix: use `g_minrelay_satkvb`/`g_incremental_satkvb`.
- Verdict: CONFIRMED.
- Test coverage: `test_rpc_node.c` checks field presence; values not pinned.

##### RPC-10 (LOW) — HTTP framing details
- Location: `asm/rpc_server.c:580-586` (reply header), `:594` (`close(cfd)` after every reply), `:724` (`(void)path`).
- Description: The reply carries no `Connection: close`, but the server always closes; HTTP/1.1 clients that keep connections alive (`http.client`, `requests`) see an unexpected EOF on their next request. Core appends `"\n"` to every reply body (`req->WriteReply(HTTP_OK, reply.write() + "\n")`); this server does not, so "Core-bit-exact" is off by one byte. The request path is ignored: Core serves only `/` and `/wallet/<name>` (404 otherwise); here `/wallet/foo` is accepted and silently ignores the wallet selector — with `loadwallet` switching a single active wallet, a client that addresses wallet A through the URI may operate on wallet B.
- Core reference: `httprpc.cpp` (`RegisterHTTPHandler("/", true, ...)`, `"/wallet/"` prefix handler), `JSONErrorReply`.
- Suggested fix: emit `Connection: close`, append `\n`, 404 unknown paths, reject or honour `/wallet/<name>`.
- Verdict: CONFIRMED.
- Test coverage: `test_rpc_server.c` checks body prefixes only.

##### RPC-11 (LOW) — Writer does not escape DEL
- Location: `asm/rpc_json.c:103-127`.
- Description: `rj_append_escaped` escapes `"`, `\`, `\b\f\n\r\t` and bytes < 0x20. UniValue's escape table (`univalue_escapes.h`, generated by `gen.cpp`: `escapes['\x7f'] = "\\u007f"`) also escapes 0x7f. Peer user agents are sanitised at ingest (`main.c:1959` maps > 0x7e to `.`) so this is reachable only through operator-supplied strings (labels, wallet names) — cosmetic bit-exactness.
- Verdict: PLAUSIBLE (Core table cited from memory).
- Test coverage: none.

##### RPC-12 (LOW) — One execution lock behind long waits
- Location: `asm/rpc_server.c:619, 646-648, 781-783`; waits held under it: `rpc_node.c:1413-1456` (`submitblock` up to 90 s), `:1577`/`:1909-1918` (`sendrawtransaction` 90 s), `:1834-1851` with `:1766` (`importmempool`: 90 s per entry, unbounded entries), `:737-770` (`ctl_send` 3 s), `rpc_signer.c:80-85` (`popen` of HWI, which waits for a human to press a button).
- Description: All handlers run under `g_exec_lock`, so any of the above blocks every other RPC, including `stop` and `getblockcount`. The serial model is documented for the longpoll design, but the consequence that one `walletdisplayaddress` on a hardware wallet freezes the whole RPC surface (and that a wedged worker turns every RPC into a 90 s timeout) is not in `FEATURE_GAPS.md`.
- Core reference: Core handlers run concurrently on `-rpcthreads`; long operations take specific locks.
- Suggested fix: at minimum run the signer and the channel waits outside `g_exec_lock` (the channel already has its own `g_submit_lock`), and let `stop` bypass it.
- Verdict: CONFIRMED.

##### RPC-13 (LOW) — Inbound peer-slot claim race
- Location: `asm/daemon/main.c:1163-1171` (CAS `used` 0→1, then `rpc_fill_peer_slot`), `:1943` (`memset(pr, 0, ...)` clears `used`), `:1966` (`used = 1` at the end).
- Description: Between the `memset` and the final `used = 1`, the slot reads as free; a sibling child forked for another inbound connection can CAS it and fill the same slot. `getpeerinfo`/`getconnectioncount` then under-report, and the losing child's later `used = 0` frees the winner's entry. Display-only.
- Suggested fix: do not `memset` the `used` word in `rpc_fill_peer_slot` when called from the claim path, or claim with a separate `claimed` flag.
- Verdict: PLAUSIBLE (window is microseconds; not reproduced).

##### RPC-14 (INFO) — rpcwhitelist edge semantics
- `asm/rpc_server.c:181`: with `rpcwhitelistdefault=1` and no `rpcwhitelist` entries Core denies every user (`!user_has_whitelist && g_rpc_whitelist_default`); here `g_wl_n == 0` allows everyone. `asm/rpc_server.c:492-494`: Core returns 403 for a user without a whitelist before parsing; here an unparseable body or non-string `method` from such a user falls through to the dispatcher and gets a parse/-32600 error instead of 403. Fail-open only in the first (misconfiguration) case.
- Verdict: CONFIRMED.

##### RPC-15 (INFO) — Start-up ordering
- `asm/daemon/main.c:6026` starts the listener; `rpcauth` entries are registered at `:6048` and the cookie written at `:6055`. During the gap only `rpcuser/rpcpassword` authenticates (fail-closed). `g_n_rpcauth`/`g_rpcauth[]` are written while workers may read them without synchronisation; a torn read can only reject. Reordering the three calls removes both.
- Verdict: CONFIRMED.

##### RPC-16 (INFO) — `rj_dup` 64 KiB cap
- `asm/rpc_server.c:412-418`: the id is round-tripped through a 64 KiB stack buffer; a larger `id` (allowed by the 9 MiB request cap) is echoed as `null`. `rj_clone` (`rpc_json.c:66`) does this without a cap.
- Verdict: CONFIRMED.

##### RPC-17 (INFO) — Signer process details
- `asm/rpc_signer.c:85-91`: `pclose` returns a `wait` status; the message prints it raw (exit 1 shows as 256). The child inherits the daemon's environment and stderr. Quoting (`sq`, `:49-65`) is correct: every descriptor/fingerprint byte is inside single quotes with `'\''` for quotes; the operator's command is intentionally unquoted (Core does the same via `RunCommandParseJSON`). Bounds: descriptor ≤ ~1000 bytes, fingerprint ≤ ~130, command ≤ 2048 — all checked before `popen`.
- Verdict: CONFIRMED.

##### RPC-18 (INFO) — IPv4-only RPC listener
- `asm/rpc_server.c:843, 857-861`: `AF_INET` socket, `inet_pton(AF_INET)` for `rpcbind`; `rpcbind=::1` is fatal ("not a valid IPv4 address"). `rpc_acl.c:18` seeds `::1` and any IPv6 `rpcallowip` entries are dead because `server_thread` (`:797-798`) only ever formats `AF_INET` peers. `FEATURE_GAPS.md:1344` lists `rpcbind` as "implemented" without the IPv4 qualifier.
- Verdict: CONFIRMED.

##### RPC-19 (INFO) — Stale comments
- `asm/rpc_node.c:572-583` says the node keeps no ban list and has no RPC-triggered ping path; both exist (`cmd_listbanned`, `RPC_CTL_PING`). `rpc_server.h:1-27` describes a loopback-only server (rpcbind/allowip exist). `rpc_server.c:512-514` misstates Core's array handling (RPC-6). `rpc_server.c:607-618` says the accept loop is serial (it is a pool since 09-01; only execution is serial).
- Verdict: CONFIRMED.

##### RPC-20 (INFO) — `sendrawtransaction` txid scratch
- `asm/rpc_node.c:1873-1875`: `tx_txid` needs `buflen >= unwitnessed length` (`bitcoin_tx.asm:442-449`); the scratch is 162 008 bytes while the stage accepts 404 000. A transaction whose stripped size exceeds 162 KB gets -22 "TX decode failed" instead of the worker's policy reject. Only non-standard sizes are affected (`submitpackage` uses a 1 MiB scratch).
- Verdict: CONFIRMED.

#### Verified-correct controls
- Constant-time credential comparison with length folded in and every arm (`by_pass`, `by_cookie`, all `rpcauth` entries) evaluated regardless of outcome: `rpc_server.c:305-315`, `:372-393`. Empty configured password can never authenticate: `:378`. (Re-verifies 2026-09-02 audit item 1.)
- Cookie: 32 random bytes from `/dev/urandom` with a full-read check, file created with the final mode from the outset (no chmod window), removed on shutdown and its memory zeroed: `rpc_server.c:318-348`, `main.c:6291`.
- `rpcauth` = hex(HMAC-SHA256(key=salt, msg=password)) compared constant-time, exactly Core's `share/rpcauth` scheme: `rpc_server.c:276-293`, `:383-391`.
- Base64 decoder output bound: `out_cap = (inlen/4)*3+3` (+1) is ≥ the maximum 3 bytes per 4-char group including a trailing partial group; invalid symbols in the first two positions abort: `rpc_server.c:206-223`.
- Request buffer: heap, doubled on demand, hard cap `RPC_REQ_MAX` 9 MiB, oversize dropped, header-end scan resumes at `scanned-3`, `Content-Length` via `strtol` saturates safely, `hdrend` re-based across `realloc`: `rpc_server.c:681-714`. (Re-verifies the 9 MiB cap.)
- Reply body sized by `rj_write_alloc`, header written with `write_all`, short writes on the body handled: `rpc_server.c:572-593`.
- JSON depth: `RJ_MAX_DEPTH 512` counted before recursion, decremented on close, so 512 accepted and 513 rejected exactly like `MAX_JSON_DEPTH`: `rpc_json.c:269`, `:368`, `:373/:389/:396/:404`; pinned by `tests/test_rpc_json_depth.c`. (Re-verifies the prior-audit fix.) Worker stacks are 64 MiB (`bmc_thread.h`), so the bounded recursion is safe.
- Trailing garbage after the document rejected: `rpc_json.c:420-421`. Duplicate keys: first wins (`rj_obj_get`), matching UniValue's `find_value`.
- Writer escapes `"`, `\`, and all bytes < 0x20 (with lowercase `\u00xx`) for every string including object keys, and grows buffers with the `len+n+1` invariant: `rpc_json.c:103-134`, `:138-145`. Peer-controlled `subver` is additionally sanitised and NUL-terminated at ingest (≤ 90 bytes into a 96-byte field): `main.c:1955-1959`; peer `addr` is `strncpy`'d into an 80-byte zeroed field: `main.c:1943-1944`.
- ACL is evaluated on every accepted connection, fails closed on an empty list, `127.0.0.0/8` seeded, `rpcbind` without `rpcallowip` ignored with Core's message, malformed `rpcallowip` fatal: `rpc_acl.c:13-35`, `main.c:5995-6009`.
- Work queue: bounded, 503 "Work queue depth exceeded" past `-rpcworkqueue`, threads clamped to 256, queued connections closed on stop: `rpc_server.c:806-817`, `:877-879`, `:906`.
- Envelope semantics match `httprpc.cpp`/`JSONErrorReply`: V2 errors → HTTP 200; V1 -32600 → 400, -32601 → 404, else 500; V2 notification → 204 with no body regardless of outcome; parse error → V1 envelope, 500; unsupported `jsonrpc` → -32600 "JSON-RPC version not supported": `rpc_server.c:502-566`; pinned by `tests/test_rpc_server.c` cases 3-12.
- Unknown method → -32601 "Method not found": `rpc_commands.c:4585`; live-node handlers all check `params` type/NULL before indexing (`rpc_node.c` throughout), and `rpc_param_str` refuses NULL/non-array params (`rpc_commands.c:213-218`).
- `SIGPIPE` ignored so a client reset cannot kill the node: `rpc_server.c:841`.
- Channel staging: hex length bounded by `RPC_TXSUBMIT_MAX`/`RPC_BLKSUBMIT_MAX` before decoding into shared memory, sequence published after a full barrier, results copied out under `g_submit_lock`, package count ≤ 25: `rpc_node.c:1418-1456`, `:1853-1928`, `:2036-2054` (package), `:2151-2180` (testmempoolaccept).
- `getpeerinfo` skips inbound slots whose serving child is dead (`kill(pid,0)` → ESRCH): `rpc_node.c:197`; `listbanned` filters expired bans: `:892-894`.
- Signer: only `enumerate` and `displayaddress` are ever invoked, arguments single-quoted, output bounded to 64 KiB and parsed with the same strict parser: `rpc_signer.c:49-101`. (Re-verifies 2026-09-02 audit item 7.)
- 2026-08-29 finding on `rj_parse` depth: fixed as claimed; 2026-09-02 N10 (`rpcbind` gating): present as described at `main.c:6004-6009`.

#### Coverage and limits
- Nothing was executed; findings rest on source tracing. RPC-1 and RPC-2 are deterministic from the code; RPC-4 depends only on kernel socket semantics. RPC-13 was not reproduced.
- Core behaviour for the UniValue parser/escaper (RPC-7, RPC-11) and `httprpc.cpp` batch handling (RPC-6) is cited from memory of Core source; no Core checkout is in the tree to grep. The batch claim is high-confidence (it is the documented JSON-RPC 1.0 batch feature Core has shipped for years); the DEL-escape claim is medium.
- Not reviewed: the worker-side implementations behind the ctl channel beyond what is cited (ban enforcement on inbound accept, addnode dialing), `mempool_dump.c` (importmempool file parsing of an operator-supplied path — worth a bounds review since it parses untrusted bytes in the parent), `rpc_chain.c`'s `getblocktemplate` longpoll handler that `lp_waiter` re-enters, and the sibling files.
- Next steps I would take: a concurrency test for `rpcwhitelist` (two users, 64 concurrent requests, assert no cross-authorisation); an fd-count test that resets connections mid-reply; a `disconnectnode`-by-id test with a hole in the slot table; and a decision on batch support with a `FEATURE_GAPS.md` entry either way.


---

### 6.10 Blockchain / raw-tx / util / mining RPC (rpc_commands.c, rpc_chain.c) — review

**Scope:**
- Fully read: `asm/rpc_chain.c` (4071 lines), `asm/rpc_commands.c` (4587 lines),
  `asm/rpc_chain.h`, `asm/rpc_commands.h`.
- Skimmed (peripheral / ownership only): `asm/rpc_server.c` (request buffering +
  `RPC_REQ_MAX`), `asm/rpc_node.c` (method-table ownership of the mempool/mining
  live methods, which are a sibling reviewer's module), `asm/tests/test_rpc_chain.c`,
  `asm/tests/test_txoutproof.c`, `docs/FEATURE_GAPS.md`, `docs/RPC_LIVE_NODE.md`.
- Not read in depth: rpc_wallet_ops.c, rpc_json.c (other reviewers).

**Summary:** The two files are large, careful ports of Core's blockchain/rawtx/util/
mining RPC surface, with an unusually honest "refuse rather than fabricate" discipline
and good differential-test coverage for the pure paths (decodescript, createmultisig,
descriptor engine, PSBT v0/v2, BIP37 proofs). Parameter validation and error codes are
generally faithful (ParseHashV messages, -8/-5/-3/-22/-28 usage). I found **one
confirmed remote heap-overflow** in `verifytxoutproof` (attacker-controlled nHashes
written past a fixed buffer because the `nTx > PMT_MAX_TX` bound is checked *after* the
copy loop) — the headline finding. The rest are correctness/parity divergences of
LOW–MEDIUM severity: getrawtransaction verbosity 2 never emits `prevout`/`fee`;
gettxout emits empty `asm`/`desc` and hardcoded `bestblock`/`confirmations`;
getaddressinfo emits `pubkey:""`+`iscompressed:true` for un-owned P2PKH (prior finding,
still present); createrawtransaction rejects >80-byte OP_RETURN data and duplicate
addresses differently from Core; a non-Core `coinbase_tx` field in getblock. No
consensus-affecting divergence found in the read paths themselves. Confidence high on
the traced items.

#### Findings

| ID | Severity | Location | Title | Verdict |
|----|----------|----------|-------|---------|
| RPX-1 | HIGH | rpc_chain.c:2027-2038 | `verifytxoutproof` heap overflow: nHashes bound checked after copy | CONFIRMED |
| RPX-2 | LOW | rpc_chain.c:1815-1848 | getrawtransaction verbosity 2 never emits `prevout`/`fee`/`vsize` distinction | CONFIRMED |
| RPX-3 | MEDIUM | rpc_commands.c:336-347 | getaddressinfo emits `pubkey:""` + `iscompressed:true` for un-owned P2PKH | CONFIRMED |
| RPX-4 | LOW-MED | rpc_commands.c:706-720 | gettxout emits empty `asm`/`desc`, hardcoded `bestblock`/`confirmations` | CONFIRMED |
| RPX-5 | LOW | rpc_commands.c:784-787 | createrawtransaction rejects >80-byte OP_RETURN data Core accepts | CONFIRMED |
| RPX-6 | LOW | rpc_commands.c:770-799 | createrawtransaction accepts duplicate addresses / no locktime range check | CONFIRMED |
| RPX-7 | LOW | rpc_chain.c:1350-1353 | getblock emits non-Core `coinbase_tx` field | CONFIRMED |
| RPX-8 | INFO | rpc_chain.c:1951-1976 | gettxoutproof (no blockhash) omits Core's UTXO-set fallback; duplicated error block | CONFIRMED |
| RPX-9 | INFO | rpc_commands.c:589-591 | decoderawtransaction rejects tx > 200000 bytes | CONFIRMED |

##### RPX-1 (HIGH) — `verifytxoutproof` heap overflow: nHashes bound checked after the copy loop
- Location: `asm/rpc_chain.c:2027-2038` (`cmd_verifytxoutproof`)
- Description: The partial-merkle-tree proof is parsed straight from the caller's hex.
  `ntx = rd32(p)` is read with **no upper bound**. `nhash` is then rejected only if
  `nhash > ntx + 64` (line 2028). The hashes are copied into a fixed static buffer
  `hashes = malloc(sizeof(*hashes)*(PMT_MAX_TX+64))` — 100064 entries — by
  `for (u64 i=0;i<nhash;i++){ memcpy(hashes[i], p, 32); ... }` (line 2031). The only
  guard on the loop count is `if (p + nhash*32 > end)` (line 2029), i.e. the *input
  length*, not the buffer size. The `if (ntx == 0 || ntx > PMT_MAX_TX)` check that
  would cap ntx (and therefore the `ntx+64` slack on nhash) is on **line 2038 — after
  the copy loop**.
- Failure scenario: An RPC caller submits a proof whose header field ntx = 100001 (any
  value > PMT_MAX_TX=100000) and supplies nHashes = 100065 real 32-byte hashes
  (~3.2 MB of hex, well under `RPC_REQ_MAX` = 9 MiB, rpc_server.c:507). `nhash > ntx+64`
  is false, `p + nhash*32 > end` is false, so the loop writes 100065 entries into a
  100064-entry heap buffer. With ntx≈140000 and a ~9 MB request the overflow reaches
  ~40000 entries (~1.28 MB) of attacker-controlled bytes past the allocation → heap
  corruption / crash (remote DoS, post-auth). The `bits`/`matched` buffers are correctly
  bounded before use, so only `hashes` is affected.
- Core reference: `CPartialMerkleTree` deserialization rejects `nHashes > nTransactions`
  and caps `nTransactions`; `blockencodings`/`merkleblock.cpp` never sizes a buffer to
  the untrusted count.
- Suggested fix: Move the `ntx == 0 || ntx > PMT_MAX_TX` check to *immediately after*
  `ntx = rd32(p)` (before nhash is read), and additionally reject `nhash > ntx` (Core's
  invariant) rather than `nhash > ntx + 64`.
- Verdict: CONFIRMED (traced end to end; single-threaded server means the static buffer
  is the live target).
- Test coverage: `tests/test_txoutproof.c` exercises only well-formed round-trips via
  the internal `pmt_test_*` hooks and a KAT; **no test feeds an oversized nTx/nHashes
  proof to `cmd_verifytxoutproof`**. The overflow path is unpinned.

##### RPX-2 (LOW) — getrawtransaction verbosity 2 does not add `prevout`/`fee`
- Location: `asm/rpc_chain.c:1815-1848` (blockhash + mempool branches both call
  `tx_to_json(..., -1)` regardless of verbosity)
- Description: Core's getrawtransaction verbosity 2 adds `fee` and a `prevout`
  sub-object per input (value, scriptPubKey, from the UTXO/undo set). This node's
  verbosity 2 is identical to verbosity 1 — `in_total` is always passed as `-1`.
- Failure scenario: A caller requesting verbosity 2 for fee/prevout data silently gets
  the verbosity-1 shape.
- Core reference: `rawtransaction.cpp` TxToJSON with `TxVerbosity::SHOW_DETAILS`.
- Suggested fix: Document explicitly in RPC_LIVE_NODE.md (it is currently only implied
  by "no txindex/undo reachable"), or reject verbosity 2 with the reason.
- Verdict: CONFIRMED. Honest omission, not wrong data.
- Test coverage: none for verbosity 2 prevout.

##### RPX-3 (MEDIUM) — getaddressinfo `pubkey`/`iscompressed` for un-owned P2PKH
- Location: `asm/rpc_commands.c:336-347`
- Description: For any valid P2PKH address, the code emits `pubkey` = hex of the wallet
  pubkey **or "" when the wallet does not hold it** (`has_pub==0`), and unconditionally
  `iscompressed: true`. Core only emits `pubkey`/`iscompressed` when the key is in the
  keystore (ismine), and never emits an empty pubkey or a fabricated `iscompressed`.
  This confirms the diff-review finding from commit 699e244 — it is still present. The
  `ismine`/`iswatchonly`/`ischange` fields *were* fixed to use real ownership lookup;
  the `pubkey`/`iscompressed` pair was not.
- Failure scenario: `getaddressinfo <a-P2PKH-address-not-in-wallet>` returns
  `"pubkey":"", "iscompressed":true` — a caller reads a compressed-key claim about a key
  the node does not have.
- Core reference: `rpc/util.cpp DescribeAddress` / wallet `getaddressinfo` — pubkey only
  under `ismine` with a real `KeyOriginInfo`.
- Suggested fix: Emit `pubkey`/`iscompressed` only when `has_pub` is true; derive
  `iscompressed` from the actual pubkey length (33 vs 65), not a constant.
- Verdict: CONFIRMED.
- Test coverage: none exercising an un-owned P2PKH through getaddressinfo.

##### RPX-4 (LOW-MEDIUM) — gettxout empty `asm`/`desc`, hardcoded `bestblock`/`confirmations`
- Location: `asm/rpc_commands.c:706-720` (`cmd_gettxout_w`)
- Description: On a found outpoint the result sets `scriptPubKey.asm = ""` and
  `desc = ""`, `bestblock = 0000…0000`, and `confirmations = 0`, with a comment marking
  these as out-of-scope. The `script`/`asm` renderer (`rpc_chain_script_asm`,
  `desc_inner_of`) is available and used elsewhere, so `asm`/`desc` could be filled;
  `height` is already returned by the UTXO query but discarded (`(void)height;`).
- Failure scenario: A caller relying on `gettxout(...).scriptPubKey.asm`, `desc`,
  `confirmations`, or `bestblock` gets empty/zero placeholders. `value`/`hex`/`address`/
  `type`/`coinbase` are correct (proven against Core in bumpfee_regtest_e2e.sh, which
  only checks those three).
- Core reference: `rpc/blockchain.cpp gettxout` fills all of them.
- Suggested fix: Compute `asm` via `rpc_chain_script_asm`, `desc` via `desc_inner_of`+
  checksum, and confirmations from the returned `height` vs `rpc_chain_tip_height()`.
- Verdict: CONFIRMED.
- Test coverage: `validation/bumpfee_regtest_e2e.sh` (value/hex/coinbase only).

##### RPX-5 (LOW) — createrawtransaction rejects >80-byte OP_RETURN data
- Location: `asm/rpc_commands.c:784-787` (`db>80` → "Data too long for OP_RETURN")
- Description: Core's createrawtransaction builds `OP_RETURN <data>` for any data size
  (the 80-byte relay policy is enforced at accept time, not by the builder). This node
  rejects >80 bytes at construction, so a raw tx Core would happily *build* (to be
  signed/inspected offline) is refused.
- Core reference: `rpc/rawtransaction.cpp` AddOutputs "data" branch — no size cap.
- Suggested fix: Drop the 80-byte cap; only require even-length hex.
- Verdict: CONFIRMED.
- Test coverage: none (KATs use small/no data outputs).

##### RPX-6 (LOW) — createrawtransaction: duplicate addresses accepted, no locktime range check
- Location: `asm/rpc_commands.c:770-799` (`crt_build_unsigned`)
- Description: (a) When outputs are supplied as an *array* of single-key objects, a
  repeated address is emitted twice; Core rejects duplicates ("Invalid parameter,
  duplicated address"). (b) `locktime = strtol(...)` with no bounds; Core errors on
  locktime outside [0, 0xffffffff]; here an out-of-range value is silently truncated to
  32 bits (and negative wraps).
- Failure scenario: divergent acceptance vs Core for duplicate-address or oversized-
  locktime requests.
- Core reference: `rpc/rawtransaction.cpp CreateRawTransaction`.
- Suggested fix: Track seen destination scripts and reject duplicates; range-check
  locktime.
- Verdict: CONFIRMED.
- Test coverage: none for these edge inputs.

##### RPX-7 (LOW) — getblock emits a non-Core `coinbase_tx` object
- Location: `asm/rpc_chain.c:1339-1353` (builds `cb`), pinned by
  `tests/test_rpc_chain.c:454-458`.
- Description: getblock verbosity ≥1 adds a `coinbase_tx` object (version/locktime/
  sequence/coinbase/witness). Bitcoin Core's `blockToJSON` has no such field — the
  coinbase appears only inside the `tx` array. This is an additive divergence a strict
  field-set diff against Core would flag.
- Core reference: `rpc/blockchain.cpp blockToJSON`.
- Suggested fix: Drop `coinbase_tx`, or document it as a deliberate extension in
  RPC_LIVE_NODE.md (it is currently undocumented and pinned by a test as if canonical).
- Verdict: CONFIRMED.
- Test coverage: `tests/test_rpc_chain.c:454-458` pins the (non-Core) field.

##### RPX-8 (INFO) — gettxoutproof (no blockhash) omits Core's UTXO-set fallback; duplicated error block
- Location: `asm/rpc_chain.c:1951-1976`
- Description: Confirms the diff-review note. The no-blockhash path now *does* try the
  txid index (an improvement over the old flat -5), but it (a) still lacks Core's
  coinsview fallback (Core locates the containing block when every requested txid is
  unspent, even without txindex) and (b) reproduces getrawtransaction's index-coverage
  error text nearly verbatim (lines 1965-1975 vs 1904-1918) — a maintenance hazard if
  one drifts.
- Core reference: `rpc/rawtransaction.cpp gettxoutproof` (GetUTXOStats / coinsview path).
- Suggested fix: Factor the shared "which heights does the index cover" message into one
  helper; note the missing UTXO fallback in RPC_LIVE_NODE.md.
- Verdict: CONFIRMED (behavioural gap is documented in spirit; the duplication is the
  concrete risk).
- Test coverage: none for the no-blockhash-with-index gettxoutproof path.

##### RPX-9 (INFO) — decoderawtransaction/converttopsbt reject tx > 200000 bytes
- Location: `asm/rpc_commands.c:589-591` (and converttopsbt:868, simulaterawtransaction).
- Description: `hl/2 > 200000` → "TX decode failed". Core decodes up to the block
  serialized-size limit (~4 MB). A valid but large transaction Core decodes is refused.
  Very unlikely to be hit for standard txs.
- Verdict: CONFIRMED. INFO only.
- Test coverage: none at the boundary.

#### Verified-correct controls
- `parse_hash_param` reproduces Core `ParseHashV` messages exactly, including the
  length-and-value error text and -8 code (`rpc_chain.c:170-186`).
- `tx_walk` input loop uses the split overflow-safe bound
  `avail < sl || avail - sl < 4` (rpc_chain.c:456) — the incident-#38 fix; no wrap.
- `crt_amount_to_sat` bounds `whole` *during* accumulation against `CRT_MAX_WHOLE`
  before it can overflow, and rejects >8 fractional digits and > MAX_MONEY
  (rpc_commands.c:735-760) — matches Core `ParseFixedPoint` reject-not-saturate.
- `rpc_amounts` / `amount_json` render satoshis as `q.%08llu` exactly (Core
  ValueFromAmount), with correct negative handling via the `-(x+1)+1` two's-complement
  dance (rpc_commands.c:222-229).
- BIP37 proof *builder* (`cmd_gettxoutproof`) is bounded by `pmt_block_txids`'
  `ntx > cap` reject and `PMT_MAX_TX`; the extract-side duplicate-right-hash check
  (`if (!memcmp(left,right,32)) e->bad=1`, rpc_chain.c:1749) and the
  all-hashes/all-bits-consumed validity test (line 2043) reproduce Core's
  CVE-2012-2459 defenses — correct *except* for the RPX-1 pre-copy bound.
- createmultisig validates pubkeys before count checks (Core order), forces legacy on
  uncompressed keys, refuses bech32m, enforces the 520-byte redeemScript limit and the
  20-key cap with Core's exact messages (rpc_chain.c:2456-2560).
- PSBT v2 normalize enforces per-key value sizes, required-field presence, the
  "not allowed in v0/v2" matrix, locktime-conflict detection and BIP370 fold, with
  Core's `TX decode failed …` message prefixes (rpc_commands.c:1046-1145).
- getblockhash range check `h < 0 || h > tip` → -8 "Block height out of range";
  getblockcount/getbestblockhash/getdifficulty all gate on `tip<0` → -28
  "Loading block index..." (rpc_chain.c).
- getblock pruned handling returns -1 "Block not available (pruned data)"
  (rpc_chain.c:1319); read_block maps hole/short reads to -3.
- versionHex via `%08x`, chainwork zero-padded to 64 hex, nTx from the tx-count varint,
  previousblockhash suppressed at height 0, nextblockhash suppressed at tip
  (header_json, rpc_chain.c:757-778) — all Core-faithful.
- decodescript `can_wrap` / `can_wrap_P2WSH` gating (uncompressed-key and
  OP_CHECKSIGADD/OP_SUCCESSx exclusions) matches Core; verified against
  `validation/decodescript_diff.py` (37/37, per FEATURE_GAPS).
- ScriptToAsmStr small-int rendering: pushes ≤4 bytes as CScriptNum decimal, OP_1..OP_16/
  OP_1NEGATE via names, sighash decoration only for valid DER sigs on spendable scripts
  (script_asm, rpc_chain.c:520-556) — matches Core.

#### Coverage and limits
- I did not dynamically build/run `tests/test_rpc_chain` or `test_txoutproof` to
  reproduce RPX-1 (would require a link with the full RPCLIBS set; the overflow is
  clear from static reading and the test harness does not cover the oversized-proof
  input). A 3-line PoC feeding a crafted proof hex to `cmd_verifytxoutproof` would
  confirm the crash under ASan.
- The getblocktemplate cluster-linearization selection (rpc_chain.c:900-1260) is large;
  I verified its bounds (`GBT_MAX_TX` caps, union-find, chunk buffers) and the witness-
  commitment/coinbasevalue construction but did not exhaustively diff its fee-ordering
  against Core's BlockAssembler — a fee-ordering divergence there is a template-quality
  issue, not consensus, and the code documents it as such.
- The MuSig2 / taproot PSBT signer paths (rpc_commands.c:3349-4269) are extensive; I
  traced buffer bounds (FIN_MAXIO/FIN_MAXKV/MU_EXTRA caps, per-input static arrays) and
  found them guarded, but did not audit the cryptographic correctness (out of scope;
  covered by test_musig2_psbt / test_rpc_psbt_taproot).
- Next I would: (1) write the verifytxoutproof PoC and confirm the fix; (2) diff
  getrawtransaction verbosity-2 and gettxout field sets against a live Core; (3) review
  the getblocktemplate sigop/weight budget arithmetic against Core's reservation.


---

### 6.11 Wallet, keys, descriptors, miniscript, PSBT, encryption, wallet RPCs — review

**Scope:**
- Fully read: `asm/wallet_core.c`, `asm/wallet_scan.c/.h`, `asm/wallet_store.c`, `asm/wallet_msgsign.c`, `asm/wallet_txlog.c`, `asm/wallet_book.c`, `asm/wallet_labels.c`, `asm/wallet_bnb.c`, `asm/rpc_wallet_ops.c` (all 4093 lines), `asm/descriptor.c`, `asm/miniscript.c`, `asm/miniscript_sign.c/.h`, `asm/psbt_update.c/.h`, `asm/bip32_ckdpub.c`, `asm/bitcoin_bip32.asm`, `asm/bitcoin_bip39.asm`, `asm/bech32.asm`, `asm/base32.c`, `asm/bitcoin_aes.c`, `asm/daemon/wallet_cli.c`, `asm/daemon/wallet_crypter.c`, `asm/daemon/wallet_enc_state.c`, `asm/daemon/wallet_pass.c`.
- Skimmed (only the parts my paths call into): `asm/daemon/main.c` 5695-5900 (seed installer, mnemonic provider, boot load), `asm/rpc_commands.c` 2604-2730 (`signrawtransactionwithwallet` prevtx precedence), 932-960 and 1171-1180 (`psbt_parse_map`, `psbt_load`), `asm/rpc_chain.c` 2382-2412 (`rpc_desc_normalize`), `asm/rpc_server.c` 585-625, `asm/descriptor.h`, `asm/rpc_wallet_ops.h`, the test files listed under coverage (grep-level).
- Not read: `asm/wordlist.inc` (table only), `asm/miniscript.h` beyond the type-bit names, `validation/*` oracles.

**Summary:** The cryptographic kernels in scope (BIP32 CKDpriv/CKDpub, BIP39, bech32/bech32m checksum math, base58check, AES-256-CBC, Core's `BytesToKeySHA512AES`, ECDSA signing with low-S, pubkey recovery, descriptor checksum, the miniscript type algebra and satisfier) are faithful to their references and mostly pinned by vector tests. The problems are at the edges. The one HIGH is a classic: `bech32_decode` (asm) has no length bound on the data part, and `wallet_validate_address` decodes into a 256-byte stack array, so any RPC that takes an address (`validateaddress`, `sendtoaddress`, `setlabel`, `signmessage`, ...) crashes the serve parent with a 300-character bech32-charset string. Two MEDIUMs are wallet-correctness: the spend/bump path hands the signer a P2WPKH scriptPubKey for every selected coin (wrong for coins received on the legacy/p2sh-segwit/bech32m descriptors that `createwalletdescriptor` activates, and an explicit prevtx beats the wallet's own synthesized one), and a "locked" encrypted wallet keeps its mnemonic, BIP39 passphrase and derived seed in static buffers that are never wiped (no `explicit_bzero` anywhere in the tree). Two more MEDIUMs are data-integrity: `wallet_store.c` writes the (only) wallet file without `fsync` and the CLI `init` truncates an existing store. The three `rpc_wops_address_ownership` items from the earlier diff review are confirmed present. Audit N4 (weak `BMCWAL v2`) is verified fixed in code: v3/wcrypt is the only writer, v2 is read-and-upgraded. Confidence: high on the CONFIRMED items (each traced caller to callee); the PSBT-map bounds item is PLAUSIBLE because the upstream normaliser was outside my scope.

#### Findings

| ID | Severity | Location | Title | Verdict |
|---|---|---|---|---|
| WAL-1 | HIGH | `asm/bech32.asm:557-600`, `asm/wallet_core.c:495-497` | bech32 decoder has no data-length bound; 256-byte stack buffer overflows on any RPC address argument | CONFIRMED |
| WAL-2 | MEDIUM | `asm/rpc_wallet_ops.c:2822-2825, 3042-3044, 3729-3732` | Spend/sweep/bump paths give the signer `00 14 <h160>` for every coin regardless of its output type; wrong for legacy/p2sh-segwit/bech32m coins | CONFIRMED |
| WAL-3 | MEDIUM | `asm/daemon/main.c:5700-5702,5874-5875`, `asm/bitcoin_bip39.asm` (`m39_acc/m39_prev/m39_cur`), `asm/daemon/wallet_crypter.c:393-398` | Locked wallet retains mnemonic, BIP39 passphrase, seed and wallet passphrase in never-wiped statics; all wipes are plain `memset` | CONFIRMED |
| WAL-4 | MEDIUM | `asm/wallet_store.c:65-74, 181-192, 269` | Wallet store written without fsync; legacy auto-upgrade rewrites the only copy in place; v1 plaintext path non-atomic with a perms window | CONFIRMED |
| WAL-5 | MEDIUM | `asm/wallet_store.c:181`, `asm/daemon/wallet_cli.c:702` | `wallet_cli init` silently truncates and replaces an existing wallet store | CONFIRMED |
| WAL-6 | LOW | `asm/rpc_wallet_ops.c:1878-1918, 1630` | The three `rpc_wops_address_ownership` defects from the 699e244 diff review are still present | CONFIRMED |
| WAL-7 | LOW | `asm/daemon/wallet_crypter.c:396-397` | Wallet passphrase silently truncated to 96 bytes before the KDF | CONFIRMED |
| WAL-8 | LOW | `asm/rpc_wallet_ops.c:1450-1451`, `asm/daemon/wallet_enc_state.c:174-175` | `walletpassphrase` timeout: 0 refused, no clamp, signed overflow on huge values makes the unlock expire immediately while reporting success | CONFIRMED |
| WAL-9 | LOW | `asm/bech32.asm:99-113`, `asm/wallet_core.c:503-530` | Address validation diverges from Core: mixed case accepted, no 90-char limit, witness v2..v16 rejected | CONFIRMED |
| WAL-10 | LOW | `asm/wallet_msgsign.c:63-66, 508-520`, `asm/rpc_wallet_ops.c:962-964` | Message signing: uncompressed-key compact signatures never verify, messages >65535 bytes refused, `signmessage` only searches the m/84' branch | CONFIRMED |
| WAL-11 | LOW | `asm/bitcoin_bip39.asm:262-263, 370-375, 655-670` | BIP39 `.bss` buffers (`m39_idx` 24 words, `m39_salt` 512 bytes) written without bounds; overflowable from `wallet_cli` argv and from the decrypted store payload | CONFIRMED |
| WAL-12 | LOW | `asm/rpc_wallet_ops.c:1514-1540, 749-755` | `backupwallet`/`restorewallet` cannot handle an encrypted wallet (`bmcwallet.enc`) or `walletkeys.dat`; error text misleading | CONFIRMED |
| WAL-13 | LOW | `asm/wallet_scan.c:146-167`, `asm/rpc_wallet_ops.c:2359` | Scan records carry heights but no block hashes; a reorg after the last manual rescan is invisible, `listsinceblock.removed` is always empty | CONFIRMED |
| WAL-14 | LOW | `asm/psbt_update.c:69-75, 95-104, 106-116` | PSBT map/tx walkers read key/value lengths without bounding them by the buffer; safety rests entirely on the upstream normaliser | PLAUSIBLE |
| WAL-15 | LOW | `asm/rpc_wallet_ops.c:1742-1782`, `asm/descriptor.c:299-323, 455` | `importdescriptors` ignores `timestamp`/`internal`/`active`/range start; descriptors accept tpub/testnet WIF on any chain; multi/multi_a capped at 32 keys, 64 per descriptor | CONFIRMED |
| WAL-16 | LOW | `asm/daemon/wallet_crypter.c:464-482` | Container trusts on-disk `iters` and carries no MAC over the seed ciphertext: a tampered file can make unlock spin for hours or "succeed" with a wrong seed | CONFIRMED |
| WAL-17 | LOW | `asm/rpc_wallet_ops.c:2656, 2789-2800, 3017, 2695` | Tx construction: locktime 0 (no anti-fee-sniping), change always last, no `-maxtxfee` check on sends, `sendall` silently caps at 64 inputs, coin set capped at 4096 | CONFIRMED |
| WAL-18 | LOW | `asm/wallet_core.c:834-837` | Legacy CLI `wallet_createrawtx` writes `locktime` into the version field (version 0 tx: non-standard in Core) | CONFIRMED |
| WAL-19 | INFO | `asm/bitcoin_bip32.asm:76-96`, `asm/wallet_core.c:203-207`, `asm/rpc_wallet_ops.c:248-262` | Minor spec gaps: master key not checked `< n`; nonce is `sha256d(z||d)` not RFC6979; `addhdkey` xprv scalar not range-checked | CONFIRMED |
| WAL-20 | INFO | `asm/wallet_store.c:55-58, 188, 243-273` | Audit N4 (weak BMCWAL v2) re-verified: only v3/wcrypt is written; v2 is read-only and rewritten in place on open | CONFIRMED |

##### WAL-1 (HIGH) — bech32 decoder has no data-length bound; stack overflow from any RPC address argument
- Location: `asm/bech32.asm:557-600` (`bech32_decode` `.data_conv` / final `rep movsb`), `asm/wallet_core.c:495-497` (`unsigned char d5[256]` passed as `out5`).
- Description: `bech32_decode` splits at the last `'1'`, bounds the HRP against `hrp_cap` (`cmp r15, r13; jae .err`), then converts every remaining character through `CHAR2IDX` into the module scratch `WS+300` (212 bytes left of a 512-byte `.bss` area) and finally copies `r9` (the data count, unbounded) bytes into the caller's `out5`. Neither BIP173's 90-character limit nor the caller's capacity is checked. `wallet_validate_address` passes a 256-byte stack array. The RPC request buffer allows 9 MB (`rpc_server.c:507`), so an address string of a few hundred to a few million charset characters is deliverable.
- Failure scenario: `validateaddress "bc1" + "q"*300` → 300 bytes written past `WS` in `.bss` and 300 bytes copied into `d5[256]` → the `-fstack-protector-strong` canary fires → `abort()` of the process hosting the RPC server (the serve parent, per `wallet_enc_state.c` header and `main.c`), taking the node down. A longer string corrupts the `.bss` of whatever objects follow `bech32.o` before the abort. Reachable through every caller of `wallet_validate_address` on RPC input: `validateaddress`/`getaddressinfo` (`rpc_commands.c:163,279`), `setlabel`, `signmessage`, `getreceivedbyaddress`, `getreceivedbylabel` (labels file), `sendtoaddress`/`sendmany`/`send`/`sendall` (`wf_addr_spk`), `walletdisplayaddress`, and the `rpc_chain.c` users. (`addr()` in `descriptor.c:515` is safe: it caps at 160 chars first.)
- Core reference: `bech32::Decode` rejects strings longer than 90 (`CharLimit::BECH32`) and mixed case before touching the data.
- Suggested fix: in `bech32_decode`, fail when `strlen(in) > 90` (or when the data count would exceed a caller-supplied `out5_cap` argument) before the conversion loop; also fail on mixed case. Add a test with a 91-char and a 4096-char string to `tests/test_bech32.c`.
- Verdict: CONFIRMED (traced RPC string → `wallet_validate_address` → `bech32_decode` → unbounded writes).
- Test coverage: none. `tests/test_bech32.c:121` has the BIP173 84-character-HRP vector, which fails on the HRP cap, not on total length; no over-long data vector exists.

##### WAL-2 (MEDIUM) — spend/sweep/bump paths tell the signer every coin is P2WPKH
- Location: `asm/rpc_wallet_ops.c:2822-2825` (`wf_fund` prevtxs), `3042-3044` (`sendall`), `3729-3732` (`bumpfee`), `2480-2517` (`wf_coins` takes every receive record regardless of `WOT_TYPE(branch)`), size model `2455-2457`.
- Description: Since 2026-09-01 the wallet has four output types; `rpc_wops_type_spk` (`3995-4013`) stores in `wscan_key.h160` the *key hash* for pkh/wpkh, the *script hash* for sh(wpkh), and the first 20 bytes of Q for tr. `wf_coins` selects coins of every type, but the prevtxs sent to `signrawtransactionwithwallet` are hard-coded as `00 14 <h160>`, and the fee model charges 68 vB per input. `signrawtransactionwithwallet` (`rpc_commands.c:2690-2695`) explicitly lets a caller-supplied prevtx win over the correct one it would synthesise via `rpc_wops_own_coin_spk`. The comment at 2452-2454 ("every output this wallet spends is P2WPKH") is stale.
- Failure scenario: operator runs `createwalletdescriptor legacy`, receives 1 BTC on the `1...` address, rescans, then `sendtoaddress`. `wf_select` picks that coin; the signer is told the prevout is `wpkh(h160)`; it produces a BIP143 witness against a P2PKH prevout. `wf_send` → `sendrawtransaction` → mempool script check fails → RPC error after a confusing path, or with `-walletbroadcast=0` (`2864-2877`) the RPC returns a txid for a transaction the network will never accept. For sh(wpkh) and tr coins the signer finds no key for the (script-hash / Q-prefix) h160 and reports "could not sign every input". `bumpfee` has the same defect for `in_h160` and only recognises P2WPKH change (`3591-3594`). No funds are lost, but every non-bech32 coin is unspendable through the wallet RPCs while `listunspent` (`rpc_wops_wallet_coins`, which *does* build the right spk) reports it spendable.
- Core reference: `CWallet::CreateTransactionInternal` / `DummySignTx` size the inputs per script type and the signer uses the wallet's own `SigningProvider` for the scriptPubKey.
- Suggested fix: carry `spk`/`spklen`/`redeem` in `wf_coin` (as `rpc_wops_coin` already does), emit them in the prevtxs (plus `redeemScript` for sh(wpkh)), and use per-type input weights (P2PKH 148 vB, P2SH-P2WPKH 91 vB, P2TR 57.5 vB). Simplest safe interim: filter `wf_coins` to `WOT_BECH32` and say so.
- Verdict: CONFIRMED.
- Test coverage: `tests/test_rpc_wallet_ops.c` pins `getnewaddress`/`getaddressinfo` for the three extra types (480-560) but every spend test uses bech32 coins (853-858). No test spends a legacy/p2sh/tr coin.

##### WAL-3 (MEDIUM) — a locked wallet still holds its secrets in memory
- Location: `asm/daemon/main.c:5700-5702` (`static char g_wallet_mnemonic[768], g_wallet_bip39pass[256]`) filled at `5874-5875` and never cleared; `asm/daemon/wallet_enc_state.c:180-184` (`wenc_lock` wipes `g_seed` only); `asm/bitcoin_bip39.asm` `m39_acc`/`m39_prev`/`m39_cur` (the final PBKDF2 accumulator *is* the seed, copied out at `.se` and never zeroed) and `m39_salt`/`m39_msg` (hold the BIP39 passphrase); `asm/daemon/wallet_crypter.c:393-398` (`static u8 buf[128]` keeps `pass||salt` after `wcrypt_derive`).
- Description: `walletlock` / timer expiry zero `g_seed` and `g_wallet_seed`, giving the appearance of Core's locked state, but (a) the mnemonic and its BIP39 passphrase stay in `main.c` statics for the life of the process — even after `encryptwallet` sealed and unlinked the plaintext store, the provider still serves them; (b) every `wallet_mnemonic_seed` call leaves the 64-byte seed in `m39_acc`; (c) every KDF call leaves the wallet passphrase in `wcrypt_derive`'s static scratch. Additionally, every wipe in the tree is a plain `memset` on a buffer that is dead afterwards (e.g. `wallet_store.c:102`, `wallet_enc_state.c:95,105`, `rpc_wallet_ops.c:624-626`, `wallet_crypter.c:444`), which `-O2` may legally elide; `grep explicit_bzero|memset_s|volatile` finds nothing, and there is no `mlock`/`MADV_DONTDUMP`.
- Failure scenario: an attacker with read access to `/proc/<pid>/mem` (same uid), a swap partition, or a hibernation image recovers the whole wallet from a node whose operator believes it is locked. The 09-02 host hardening (`LimitCORE=0`) removes the core-dump route only.
- Core reference: `CWallet::Lock` clears `vMasterKey`; `SecureString`/`secure_allocator` (`support/lockedpool`) keep key material in mlocked pages and `memory_cleanse` uses a compiler barrier.
- Suggested fix: after `encryptwallet` succeeds, zero `g_wallet_mnemonic`/`g_wallet_bip39pass` (the encrypted container is now the source; `wenc_unlock` already re-derives from it); add a `bip39_wipe()` (or zero `m39_*` at the end of `bip39_mnemonic_to_seed`) and a wipe of `buf` in `wcrypt_derive`; introduce one `secure_zero()` with an `asm volatile("" ::: "memory")` barrier and use it for every secret; `mlock` the seed/mnemonic buffers and mark them `MADV_DONTDUMP`.
- Verdict: CONFIRMED.
- Test coverage: none (memory-retention is not testable by the existing harnesses).

##### WAL-4 (MEDIUM) — wallet store rewrite is not durable
- Location: `asm/wallet_store.c:65-74` (`store_write_atomic`: `fputs`+`fflush`, `chmod`, `rename`, **no `fsync`** of file or directory), `269` (legacy v2 → v3 upgrade rewrites the store in place on every successful open), `181-192` (v1 plaintext: direct `fopen("w")` on the final path, `chmod 0600` only after the mnemonic has been written).
- Description: Every other store in this module (`wallet_enc_state.c:642,726`, `wallet_scan.c:535-538`, `wallet_labels.c:107-108`, `wallet_txlog.c:87`) fsyncs before rename; `wallet_store.c` does not. The upgrade path runs unattended at daemon boot (`main.c:5868`) and replaces the only copy of the wallet.
- Failure scenario: node boots with a legacy v2 store; `wallet_store_load` rewrites it as v3 and `rename`s; power fails before the page cache reaches disk. On filesystems without ext4's rename-triggered flush (xfs, btrfs, ext4 with `noauto_da_alloc`, most network filesystems) the directory entry points at a zero-length or partial file and the previous v2 file is gone. The mnemonic was also just printed on the CLI at `init`, so an operator who did not write it down has nothing. Separately, `wallet_store_create` for a plaintext wallet exposes the mnemonic with umask permissions between `fopen` and `chmod`.
- Core reference: `BerkeleyDatabase`/`SQLiteDatabase` commit with fsync; `wallet.cpp` `BackupWallet` never replaces the live file.
- Suggested fix: `fflush` + `fsync(fileno(f))` before `fclose`, then `fsync` the directory after `rename`; write plaintext v1 through the same tmp+rename path with `open(O_CREAT|O_EXCL, 0600)`; keep the v2 file as `<path>.v2.bak` until the v3 file has been re-opened successfully (the same verify-before-destroy discipline `wenc_encrypt` already documents).
- Verdict: CONFIRMED for the missing fsync and the in-place rewrite; the data-loss outcome depends on filesystem semantics.
- Test coverage: `tests/test_wallet_store.c` covers the format upgrade on fixtures, not durability.

##### WAL-5 (MEDIUM) — `wallet_cli init` overwrites an existing wallet without asking
- Location: `asm/daemon/wallet_cli.c:678-717` (`cmd_init`: no existence check), `asm/wallet_store.c:181` (`fopen(path, "w")` on the destination even on the encrypted branch, then `remove(path)` at 187 before the sealed write).
- Description: `init` generates a fresh mnemonic and truncates `data/bmcwallet.dat` unconditionally. On the encrypted branch the existing file is truncated and unlinked *before* `store_write_sealed` runs, so a failure there (e.g. `/dev/urandom` unavailable, disk full) leaves no wallet at all.
- Failure scenario: an operator re-runs `wallet_cli init` (muscle memory, a script, or to "re-encrypt") on a machine that already holds a funded wallet; the old mnemonic is gone. `createwallet` over RPC checks for existence (`rpc_wallet_ops.c:689-693`), the CLI does not.
- Core reference: `createwallet` → "Wallet file verification failed. Failed to create database path ... Database already exists."
- Suggested fix: `stat` the destination in `cmd_init` and refuse unless `--force`; open the destination with `O_EXCL`; never truncate before the replacement is fully written.
- Verdict: CONFIRMED.
- Test coverage: none (`tests/test_wallet_store.c` has no create-over-existing case).

##### WAL-6 (LOW) — the three `rpc_wops_address_ownership` items from the 699e244 diff review
- Location: `asm/rpc_wallet_ops.c:1873-1919`.
- (a) CONFIRMED: the byte-for-byte scriptPubKey re-derivation (`1899-1908`) runs only when `spending && keys[i].hdkey == 0`; watch-only entries and `addhdkey` entries are accepted on the bare 20-byte `h160` match, so the P2PKH rendering of a bech32-only key reports `ismine`/`iswatchonly` true.
- (b) CONFIRMED: `wop_watch_keyset` stores the descriptor slot in `branch` (`1630`), and `*is_change_out = WOT_CHAIN(keys[i].branch)` (`1912`) turns that into import-order parity.
- (c) CONFIRMED: with the seed locked and no watch-only wallet, `wop_keyset_cached` returns 0 and the function returns success with every output zero (`1880`); `getaddressinfo` then reports `ismine:false` for the wallet's own address instead of an error or a "locked" hint.
- Suggested fix: as in the diff review — carry and compare the script type for every keyset entry, store slot separately from branch/chain for watch-only keys, and return 0 / a distinct code when no keyset is available.
- Test coverage: `tests/test_rpc_wallet_ops.c:543-560` pins the positive `ismine` cases only.

##### WAL-7 (LOW) — passphrase truncated to 96 bytes
- Location: `asm/daemon/wallet_crypter.c:396-398` (`if (n > 96) n = 96;`).
- Failure scenario: `encryptwallet "<96 x 'a'>secret"` and `walletpassphrase "<96 x 'a'>wrong" 60` both unlock. A diceware or hex passphrase longer than 96 bytes has its tail ignored silently; entropy is capped and the operator is not told.
- Core reference: `CCrypter::BytesToKeySHA512AES` hashes the whole `SecureString`.
- Suggested fix: hash `pass||salt` with a length-agnostic path (feed `sha512_full` a heap/stack buffer sized to `passlen + 8`, or use the incremental SHA-512), and wipe it.
- Verdict: CONFIRMED. Test coverage: `tests/test_wallet_crypter.c` uses short passphrases only.

##### WAL-8 (LOW) — `walletpassphrase` timeout semantics
- Location: `asm/rpc_wallet_ops.c:1450-1451`, `asm/daemon/wallet_enc_state.c:174-175`.
- Description: `secs <= 0` is refused with a non-Core message; Core accepts 0 (relock immediately) and clamps at `MAX_SLEEP_TIME = 100000000`. `atol` of a large value saturates to `LONG_MAX`; `time(NULL) + seconds` overflows (UB, wraps negative in practice) so `wenc_seed()` treats the wallet as expired on the next access while the RPC returned success. Core's error strings ("Timeout cannot be negative.", "Error: running with an unencrypted wallet, ..." is correct here) differ.
- Suggested fix: reject negatives with Core's text, clamp at 100000000, allow 0.
- Verdict: CONFIRMED. Test coverage: `tests/test_rpc_wallet_ops.c` exercises `walletpassphrase` with a normal timeout only.

##### WAL-9 (LOW) — bech32 validation divergences
- Location: `asm/bech32.asm:99-113` (`bech32_init` maps upper-case letters to the same values, so mixed case decodes), no 90-char check anywhere; `asm/wallet_core.c:503-530` accepts only witness v0 (20/32) and v1 (32).
- Failure scenario: `validateaddress "bc1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"` (mixed case) → `isvalid:true` (Core: false); `validateaddress` of a v2 bech32m program → `isvalid:false` (Core: true, `witness_version:2`). `sendtoaddress` to a future-version address is refused with -5 where Core pays it.
- Core reference: `bech32::Decode` (case + 90 limit), `DecodeDestination` (`WitnessUnknown` for v1..16 with 2..40-byte programs, bech32m required for v>=1).
- Suggested fix: enforce case/length in the decoder (WAL-1's fix), add a `WAL_ADDR_WITNESS_UNKNOWN` type for v2..16 and render `OP_n PUSH<prog>` in `wf_addr_spk`.
- Verdict: CONFIRMED. Test coverage: `tests/test_bech32.c` has BIP173/350 vectors for checksums and program sizes; no mixed-case or v2+ case.

##### WAL-10 (LOW) — message signing divergences
- Location: `asm/wallet_msgsign.c:508-520` (`msg_verify_core` accepts headers 27..34 but always serialises the recovered key compressed), `63-66` (`mlen > 65535` refused), `asm/rpc_wallet_ops.c:962-964` (`wop_key_for_p2pkh` hard-codes purpose 84').
- Failure scenario: a signature produced by an uncompressed-key legacy wallet (header 27-30) verifies in Core and returns `false` here; `signmessage` of the wallet's own `1...` address after `createwalletdescriptor legacy` → "Private key not available" because the key lives under m/44'.
- Core reference: `MessageVerify` → `CPubKey::RecoverCompact` (`fComp = (vchSig[0]-27) & 4`), `PKHash(pubkey)` on the *recovered form*.
- Suggested fix: serialise uncompressed when `(hdr-27)&4 == 0`; search every active type's path in `wop_key_for_p2pkh` (or derive the type from `rpc_wops_active_types`).
- Verdict: CONFIRMED. Test coverage: `test_msg_sign` round-trips compressed keys only.

##### WAL-11 (LOW) — BIP39 scratch buffers written without bounds
- Location: `asm/bitcoin_bip39.asm:370-375` (`mov [m39_idx + rcx*4], eax` for every token before the 12/15/18/21/24 count check; `m39_idx` is 96 bytes), `655-670` (`m39_salt` 512 bytes receives `"mnemonic"||passphrase` for any `passlen`; `m39_msg` 520 bytes likewise).
- Failure scenario: `wallet_cli seed "<400 valid words>"` writes 1.6 KB over `m39_salt/m39_msg/...` and into the next object's `.bss`; `wallet_cli seed "<12 words>" <600-byte passphrase>` overflows `m39_salt`. From the daemon the mnemonic comes from the store (`WENC_MNMAX*2 = 1536` bytes → at most ~190 words, which stays inside this module's own `.bss`) and the passphrase is capped at 256, so the RPC path cannot reach the overflow; the CLI and a hand-edited store can.
- Suggested fix: count tokens first and fail above 24; bound `passlen` (or size the salt buffer to the caller's cap) in `bip39_mnemonic_to_seed`.
- Verdict: CONFIRMED (bounds absent; local reachability only). Test coverage: `tests/test_bip39.c` has an "unknown word" and a checksum case, no over-long input.

##### WAL-12 (LOW) — encrypted wallets cannot be backed up or restored over RPC
- Location: `asm/rpc_wallet_ops.c:1514-1540` (`backupwallet` copies `bmcwallet.dat` only; `wop_exists` fails once `encryptwallet` unlinked it → "No wallet file to back up"), `749-755` (`restorewallet` proves the backup with `wallet_store_load`, which does not understand `BMCWENC1`), and neither touches `walletkeys.dat` (the `addhdkey` xprvs).
- Failure scenario: `encryptwallet x; backupwallet /mnt/usb/w.bak` → -4 "No wallet file to back up" on a wallet that exists; a backup of a wallet with added HD keys silently omits them.
- Core reference: `backupwallet` copies the whole database (every key).
- Suggested fix: back up `bmcwallet.enc` when present (and `walletkeys.dat`, `wallet.types`, `descriptors.dat`), teach `restorewallet` the container.
- Verdict: CONFIRMED. Test coverage: none for the encrypted case.

##### WAL-13 (LOW) — no reorg awareness in wallet state
- Location: `asm/wallet_scan.c:146-167` (record = height + txid, no block hash), `asm/rpc_wallet_ops.c:2359` (`removed: []`), `2036-2070` (rescan is manual and synchronous).
- Failure scenario: rescan at height H; a 2-block reorg replaces the block that paid the wallet; until the operator rescans, `getbalance`/`listunspent` report the orphaned coin as confirmed with growing confirmations, and a spend of it fails at broadcast. Also, `rescanblockchain` walks the whole archive on the single RPC thread (hours on mainnet), blocking every other RPC.
- Core reference: `CWallet::blockDisconnected` marks conflicted/abandoned; `listsinceblock.removed`.
- Suggested fix: store the block hash per record and, on read, drop records whose (height, hash) no longer match the header chain; consider an incremental scan from the last tip on `getbalance`-class calls.
- Verdict: CONFIRMED as a design gap (documented in spirit by the "run rescanblockchain" warnings, not by name).

##### WAL-14 (LOW, PLAUSIBLE) — PSBT map walkers are unbounded
- Location: `asm/psbt_update.c:69-75` (`parse_map`: `kl`/`vl` from `rd_varint` never compared to `blen`; `p += kl` can run past the buffer and the loop condition only checks the start), `95-104` (`walk_tx`: reads `tx[5]` and each varint one byte past the checked bound), `106-116`.
- Description: `psbt_update_bytes_from_descs` is called from `rpc_commands.c:3322` (on a buffer this code serialised) and `3590` (on `psbt_load` output, i.e. after `psbt_v2_normalize`). `rpc_commands.c:932-938` `psbt_parse_map` has the identical shape. Whether `psbt_v2_normalize` fully validates every key/value length was outside my scope; if it does not, a PSBT with a 0xff-varint key length makes `ser_map`/`has_key` read far out of bounds (crash) on `utxoupdatepsbt`/`walletprocesspsbt`/`descriptorprocesspsbt`.
- Suggested fix: bound `kl`, `vl` and every varint read by `blen` in both parsers; cap `PU_MAXKV`-overflowing maps explicitly (today entries beyond 160 per map are silently dropped on re-serialisation — unknown/proprietary fields are lost on a very large map).
- Verdict: PLAUSIBLE (the bound is genuinely absent; reachability depends on the normaliser, which the RPC reviewer should confirm).
- Test coverage: `tests/test_psbt_update.c` (40 checks) uses well-formed PSBTs.

##### WAL-15 (LOW) — importdescriptors / descriptor parsing divergences
- Location: `asm/rpc_wallet_ops.c:1742-1782` (`timestamp` never read — Core: "Missing required timestamp"; `internal`/`active` ignored — slot 0 always serves `getnewaddress` (`1798`), so an `internal:true` import first becomes the receive descriptor; `range` `[begin,end]` uses only `end`), `asm/descriptor.c:299-323` (tpub/tprv and 0xef WIF accepted with no chain check — Core rejects testnet keys on mainnet), `455` (`multi_a` capped at `DESCR_NODE_KEYS = 32`, Core 999; `DESCR_MAX_KEYS 64` per descriptor).
- Verdict: CONFIRMED divergences, none consensus-relevant. `rpc_desc_normalize` does refuse private-key descriptors and over-long (>340) results explicitly (`rpc_chain.c:2385-2392`), which is correct behaviour.

##### WAL-16 (LOW) — container trusts `iters` and has no MAC over the seed ciphertext
- Location: `asm/daemon/wallet_crypter.c:464-482` (`iters` read from the file and passed straight to `wcrypt_derive`; integrity is a plain `sha256` over the file that anyone can recompute; wrong-passphrase detection is the PKCS#7 pad of the 48-byte wrapped master key, which is sound — 2^-128 false accept — but the seed ciphertext is only pad-checked).
- Failure scenario: an attacker with write access to `bmcwallet.enc` sets `iters = 0xffffffff` → the next `walletpassphrase` spins ~4·10^9 SHA-512 rounds (hours) on the RPC thread; or flips bits in the seed ciphertext → `wcrypt_open` returns garbage (valid pad with probability ~1/256 per attempt... or exactly when the last block is untouched), `wenc_unlock` derives a seed from it, and the wallet reports "unlocked" while serving foreign addresses.
- Core reference: Core's `CMasterKey` also stores `nDeriveIterations` unchecked, so the DoS is shared; Core's `DecryptKey` verifies the decrypted private key reproduces the stored pubkey, which is the analogue of a seed check.
- Suggested fix: cap `iters` (e.g. 10^7), and after unlock verify the mnemonic's BIP39 checksum (`bip39_validate`) before installing the seed; better, HMAC the container under a key derived from the master key.
- Verdict: CONFIRMED.

##### WAL-17 (LOW) — tx construction policy gaps
- Location: `asm/rpc_wallet_ops.c:2656` (locktime 0), `2789-2800` (change appended last), `wf_fund` has no `-maxtxfee`/`maxfeerate` guard (`BF_MAXTXFEE_SAT` exists only for bumpfee), `3017` (`sendall` truncates to 64 inputs and still reports `complete:true`), `2695` (`coins[4096]`).
- Core reference: `DiscourageFeeSniping` (locktime = tip height), `ChangePosition` randomised, `m_default_max_tx_fee`.
- Verdict: CONFIRMED (fingerprinting and fee-safety divergences; BnB, dust threshold 294, the `wf_select` fee iteration and `wallet_bnb.c`'s pruning are otherwise faithful).

##### WAL-18 (LOW) — legacy CLI tx builder writes locktime into the version field
- Location: `asm/wallet_core.c:834-837` (`t[pos++] = locktime & 0xff` under the comment `/* version */`).
- Failure scenario: `wallet_cli send ...` (locktime 0) produces a version-0 transaction; Core's `IsStandardTx` rejects `nVersion < 1` ("version"), so it never relays through Core peers. Only the explicitly legacy CLI path and `tests/test_wrpc_sign.c` use it; the RPC wallet builds its own (`wf_build_unsigned`, version 2).
- Suggested fix: write a constant version (1 or 2).
- Verdict: CONFIRMED. Test coverage: `test_wrpc_sign.c` builds with this function and never checks the version bytes.

##### WAL-19 (INFO) — minor spec gaps in key handling
- `asm/bitcoin_bip32.asm:76-96`: `bip32_master` returns 1 for any non-zero `IL`, without `IL < n` (BIP32 says invalid; probability 2^-128). `bip32_ckd_priv` does check both `IL` and the child (`scalar_small_nonzero`).
- `asm/wallet_core.c:203-207`: ECDSA nonce is `sha256d(z||d)` (deterministic, key- and message-bound; not RFC6979, so not cross-checkable against Core's signatures, but not weak).
- `asm/rpc_wallet_ops.c:248-262`: `wop_hdk_parse` accepts an xprv whose 32-byte scalar is 0 or ≥ n (Core: `CExtKey` → `key.IsValid()`).
- `asm/wallet_store.c:251` and `wallet_store.c:296-301`: the legacy v2 read path leaves `K[64]` unwiped (moot once v2 is gone).

##### WAL-20 (INFO) — audit N4 re-verification
- `asm/wallet_store.c:55-58` marks v2 legacy/read-only; `wallet_store_create` (188) and `wallet_secret_write` (300) write only through `store_write_sealed` → `wcrypt_seal` (100000 iterations, random salt, AES-256-CBC, wrapped master key); `wallet_store_load` (243-273) and `wallet_secret_read` (329-348) decrypt v2 and immediately rewrite it as v3 with a stderr line. Status: fixed in code as claimed, subject to WAL-4 (the rewrite is not fsynced).

#### Verified-correct controls
- BIP32 CKDpriv (`asm/bitcoin_bip32.asm:118-320`): hardened input `0x00||k||i`, normal `ser33(K)||i`, HMAC keyed by the parent chain code, `0 < IL < n` and `0 < child < n` both enforced, 257-bit carry handled in the `mod n` reduction; in-place derivation safe because parents are snapshotted. Pinned by `tests/test_bip32_chain`, `test_bip32_master`, `test_bip32_extkey` (vector 1..3).
- CKDpub (`asm/bip32_ckdpub.c:181-207`): hardened index refused, `IL` range check, point-at-infinity check, parent point decompressed with `x < p` and on-curve verification; xpub parse checks version, prefix byte and point validity (`151-166`). Pinned by `tests/test_bip32_ckdpub` against Core's `deriveaddresses`.
- BIP39 (`asm/bitcoin_bip39.asm`): checksum bits verified against `SHA256(entropy)`, PBKDF2-HMAC-SHA512 with exactly 2048 rounds (U1 + 2047), salt `"mnemonic"||passphrase`. Pinned by `tests/test_bip39` (`bip39_vec.h`).
- bech32/bech32m checksum (`asm/bech32.asm:100-113, 231-341`): BIP173 generator constants, HRP expansion, constant `1` vs `0x2bc830a3`; `wallet_validate_address` requires bech32 for v0 and bech32m for v1, program sizes 20/32 for v0 and 32 for v1, and `convert_bits` with `pad=0` rejects non-zero padding.
- base58check decode (`asm/wallet_core.c:315-350`): leading-`1` zero preservation, 128-char cap on a 128-byte accumulator, sha256d checksum compared before use.
- Wallet encryption (`asm/daemon/wallet_crypter.c`, `bitcoin_aes.c`): Core's `BytesToKeySHA512AES` (SHA512(pass||salt) then iters-1 rehashes, key=[0:32], iv=[32:48]), random 8-byte salt and 32-byte master key from `/dev/urandom` with short-read handling, two-layer wrap so `walletpassphrasechange` never re-encrypts the seed, PKCS#7 pad validated with correct bounds, and `wenc_encrypt` verifies the written container round-trips *before* unlinking the plaintext store (`wallet_enc_state.c:104-136`). `wenc_seed()` re-checks the expiry on every access, and both RPC and the multi-wallet code install seeds through the same single installer (`main.c:5828-5833`).
- Passphrase source (`asm/daemon/wallet_pass.c`): refuses world-accessible, group-writable, relative, or in-datadir files and warns on a legacy `<store>.pass`.
- Descriptor engine (`asm/descriptor.c`): BIP380 checksum charset and polymod constants match Core; nesting rules (`sh` top only, `wsh` top/sh, no `wpkh`/`wsh`/`sh` in `wsh`, `tr`/`rawtr` top only, `multi_a` only in `tr`, bare multi ≤ 3 keys, `sh` redeem ≤ 520, uncompressed keys only at top/sh and never in `wpkh`), hybrid keys refused, path elements bounded to 2^31-1 with `h`/`H`/`'` and `*` last, BIP389 `<a;b>` rules, `DESCR_MAX_NODES 96` bounds the recursive tree parse, miniscript sanity ladder mirrors Core's `ParseScript` messages, hardened derivation from an xpub refused. 720 checks in `tests/test_descriptor_vectors` against Core's `descriptor_tests.cpp`.
- Miniscript (`asm/miniscript.c`): type algebra spot-checked against `miniscript.h::ComputeType` for every fragment listed (pk/pkh/older/after/hashes/wrappers/and_v/and_b/or_*/andor/thresh/multi/multi_a); ops/stack/witness-size accounting, `MAX_OPS_PER_SCRIPT 201`, P2WSH stack 100 / tapscript 1000, 3600-byte P2WSH script limit, minimal-push enforcement and `OP_x OP_VERIFY` rejection in the decoder, the satisfier's malleability/non-canonical marking and the final `nonmalleable && (malleable || !has_sig)` rule all follow `ProduceInput`/`Satisfy`. Pinned by `tests/test_miniscript` (`miniscript_vectors.h`) and the 436-case Core differential recorded in FEATURE_GAPS.
- Miniscript signer (`asm/miniscript_sign.c:432-443`): BIP68 type-flag mismatch and disabled-bit rules, BIP65 threshold-class and `nSequence != 0xffffffff` rule match the interpreter.
- Scan file durability (`asm/wallet_scan.c:529-547`, `614-656`): tmp file, fsync, header written last, fsync, rename; spends matched by `(prev_txid, vout)`; malformed blocks abort the scan rather than skip.
- Labels/txlog (`asm/wallet_labels.c`, `wallet_txlog.c`): 255-byte, no-newline label cap, tmp+fsync+rename, FNV checksum rejects torn journal records.
- `lockunspent` validates the whole list before mutating (`rpc_wallet_ops.c:903-919`); wallet names are restricted to a safe charset with no leading dot (`105-112`); `listdescriptors true` refuses to export private keys (`1074-1078`); `dumpprivkey`/`dumpwallet` are not served at all.
- Coin selection (`asm/wallet_bnb.c`): Core's BnB search in effective values with the `[target, target+cost_of_change]` window, waste metric and 100000-try cap; the fallback selector recomputes the fee per input count with and without change and folds sub-dust change into the fee.
- `rpc_wops_address_ownership`'s spending path does re-derive and compare the full scriptPubKey (`1899-1908`), so the taproot 20-byte-prefix collision noted in `wscan_spk_h160` is closed for the wallet's own keys.

#### Coverage and limits
- I did not review `rpc_commands.c`'s wallet-query methods (`getnewaddress`, `listunspent`, `getbalances`, `gettransaction`, `walletprocesspsbt`, the PSBT parser/normaliser, `signrawtransactionwithkey`) beyond the two spots quoted; `docs/RPC_LIVE_NODE.md:247` documents that `getnewaddress`/`getrawchangeaddress` always derive index 0 (address reuse by design), which I therefore did not file.
- WAL-14 needs the RPC reviewer to confirm whether `psbt_v2_normalize` bounds every map entry; if it does not, WAL-14 becomes a CONFIRMED crash on RPC input.
- I did not run any test binary; coverage statements come from reading the test sources.
- The miniscript type table was checked fragment by fragment against my recollection of `miniscript.h`; the two places I was least certain of (`and_v` lacking `d`, `or_d`'s `e` rule) agree with the spec table and are covered by the Core vector run.
- Not examined: the CUDA tier, `musig2.h`/musig key aggregation called from `descriptor.c:621-623`, the HWI external-signer path (`rpc_signer_*`), and `wallet_pass.c`'s interaction with `chdir` when `walletdir` is outside the datadir.
- Next: fuzz `bech32_decode`, `wallet_validate_address`, `descr_parse`, `ms_parse`/`ms_decode` and `psbt_update_bytes_from_descs` with ASan (the asm modules need a C harness); add a spend test for each activated output type; add a "locked wallet has no secrets in memory" harness that scans the process image after `walletlock`.


---

### 6.12 Build system, test suite, differential harness, CUDA tier, documentation — review

**Scope**
- Fully read: `asm/Makefile` (lines 1–1030 and 1780–3071 line by line; 1030–1780 by targeted grep for `-O0/-O1/-O3/fsanitize/NASM/MANUAL/gate`), `docs/ABI_STACK_ALIGNMENT.md`, `docs/PARITY_ATTESTATION.md`, `README.md`, `.gitignore`, `asm/daemon/rpc_acl.c`, `asm/build.sh`, `scripts/start.sh`, `scripts/stop.sh`, `scripts/status.sh`, `scripts/worklog.sh`, `scripts/utxo_progress.sh`, `validation/signer_core_diff.sh`, `validation/gen_script_flags.py` (head + regenerated to scratch), `asm/cuda/Makefile` (head), `asm/tests/test_elf_hardening.c` (checks), `asm/tests/txacc_bidx_stub.c`.
- Skimmed: `docs/ENGINEERING.md` (§1, §2, §2.3d, §5–7), `docs/FEATURE_GAPS.md` (§Summary, lines 232–300, 458–482, 1960–2091 and the heading index), `docs/PARITY_PLAN.md` (first 90 lines), `docs/OPERATIONS.md` (upgrade/deploy section), `asm/cuda/WORKING.md` (first 80 lines + grep), `scripts/bench_tier3.sh`, `scripts/bench_vs_core.sh`, `scripts/live_*.sh` and `validation/*.sh` (pattern grep only), the 13 flagged `validation/gen_*.py` / `asm/validation/gen_*.py` generators (oracle-source lines only), vector-header preambles.
- Not read: the 853 files under `asm/tests/` individually (characterised through the Makefile, `runlist-check`, and header comments), `docs/RPC_LIVE_NODE.md`, `docs/devlog/*`, the Python audit scripts' internals (`scripts/*.py`), `asm/cuda/*.cu`.
- Ran (read-only): `make -C asm abi-check`, `make -C asm callee-saved-check`, `scripts/abi_stack_audit.py --format summary`, `scripts/makefile_runlist_audit.py`, `make -C asm -n gate|test|clean`, `make -C asm -q daemon/bitcoind`, `git ls-files | xargs du`, `git worktree list`, a copy of `gen_script_flags.py` executed into the scratchpad.

**Summary**
The build/test machinery is unusually self-policing for a project of this shape: `make test` is preceded by five static audits (abi-check, callee-saved-check, prereq-check, runlist-check, link-check) plus a gate-log auditor, every test source is either gated or declared manual (313 gated / 11 manual, `runlist-check` OK), the daemon and every harness link the *same* assembled `.o` objects, and the two ABI audits pass on the current tree. The prior audit's N1 (optimiser pins around wrong block parses) is genuinely closed: every `-O0`/`-O1` pin is gone, the root cause is attributed to specific ABI defects (LOG.md incidents #27/#31) and mechanically enforced. No circular vectors (ENGINEERING 2.3d) were found: every committed expected value traces to Bitcoin Core, libsecp256k1, a Core-linked oracle, or an independent Python model. The CUDA tier is not linked into the daemon and is never consulted for consensus.

The defects found are all in the build/ops/documentation layer, none consensus-relevant: `make clean` deletes a tracked source file; the gate is not reproducible off this host because four gated tests hard-fail without `/storage/bitcoin-core-source/.../block413567.raw`; a Core-oracle RPC credential is committed in two validation scripts; `asm/build.sh` and two Makefile rules bypass the `-Werror` nasm flags; and a cluster of documentation claims (README, FEATURE_GAPS, ENGINEERING, Makefile comments, PARITY_ATTESTATION) are stale or contradict the code. Confidence: high for everything marked CONFIRMED (each was executed or grepped, not inferred).

#### Findings

| ID | Severity | Location | Title | Verdict |
|---|---|---|---|---|
| BLD-1 | MEDIUM | `asm/Makefile` `clean:` rule (line 2896) | `make clean` deletes the tracked source `daemon/rpc_acl.c` | CONFIRMED |
| BLD-2 | MEDIUM | `asm/Makefile:3061-3064`, `asm/tests/test_txv_parse_diff.c:190-192` (+3 siblings) | The gate hard-fails on any host without `/storage/bitcoin-core-source/src/bench/data/block413567.raw` | CONFIRMED |
| BLD-3 | LOW | `validation/corpus_diff.py:62`, `validation/fullchain_diff.py:110` | Committed RPC credential fallback for the Core oracle | CONFIRMED |
| BLD-4 | LOW | `asm/build.sh:8`, `asm/Makefile:281`, `asm/Makefile:1781` | Assembly `-Werror`/`-I.` (NASMFLAGS) bypassed for the whole tree by build.sh and for `bitcoin_sigops.o` (a consensus object) by its own rule | CONFIRMED |
| BLD-5 | LOW | README.md, docs/FEATURE_GAPS.md, docs/ENGINEERING.md, docs/PARITY_ATTESTATION.md, Makefile comments | Documentation claims that are false, stale, or contradict the code (nine items) | CONFIRMED |
| BLD-6 | INFO | `asm/Makefile:2743-3064` | Gate structure: no `gate` target; one 321-line recipe under `make -k` stops at the first failing line | CONFIRMED |
| BLD-7 | INFO | `asm/Makefile` (no sanitizer target) | ASan/UBSan runs exist only as devlog notes; nothing repeatable | CONFIRMED |
| BLD-8 | INFO | `validation/gen_*.py`, `asm/validation/gen_*.py`, `asm/tests/taproot_scriptpath_vec.h` | Five generators are independent Python models, not Core; one of them produced wrong vectors that the verifier shared (2.3d instance, since corrected) | CONFIRMED |
| BLD-9 | INFO | scripts/, validation/*.sh | Ops-script observations (Core-tool wrappers, `killall`, sudo `/proc/pid/mem`, `eval` of a make line) | CONFIRMED |
| BLD-10 | INFO | repo hygiene | Prior N11 re-verified: deploy snapshots 69 → 8 (243 MB), worktrees gone, `config/bitcoin.conf.bak-*` grew 5 → 7 | CONFIRMED |

##### BLD-1 (MEDIUM) — `make clean` deletes a tracked source file
- Location: `asm/Makefile:2896` (the `clean:` recipe). The `rm -f` list contains `rpc_json.o rpc_net.o rpc_commands.o rpc_server.o daemon/rpc_acl.c daemon/bitcoin_cli ...`. `daemon/rpc_acl.c` is a tracked source (`git ls-files asm/daemon/rpc_acl.c`), the RPC allow-list implementation (`rpc_acl_allows`, the "never fail open" check). It is referenced as a *source* in `DAEMON_RPCOBJS` (`Makefile:168`), which is presumably how a `.c` ended up in a list of build products.
- Failure scenario: developer runs `make clean` (documented in ENGINEERING §2.2 as a normal step) → `daemon/rpc_acl.c` is unlinked → `make daemon/bitcoind` fails with "No rule to make target 'daemon/rpc_acl.c'"; any uncommitted edit to the ACL code is destroyed. Confirmed with `make -C asm -n clean | grep -o daemon/rpc_acl.c`.
- Core reference: n/a (build hygiene).
- Suggested fix: remove `daemon/rpc_acl.c` from the `clean` list; add a guard to `prereq-check` (or a one-line `clean-check`) that fails if any `rm -f` operand is a `git ls-files` path.
- Test coverage: none (`prereq-check` audits recipes' inputs, not `clean`'s outputs).

##### BLD-2 (MEDIUM) — The gate is not reproducible off this host
- Location: `asm/Makefile:3061-3064` runs `./tests/test_txv_parse_diff`, `test_txvb_parse_diff`, `test_strip_witness_diff`, `test_bip143_diff` with the literal argument `/storage/bitcoin-core-source/src/bench/data/block413567.raw`. Each harness does `fopen(argv[1])` and `return 1` on failure (`test_txv_parse_diff.c:190-192`; identical pattern in the other three). The file is not a prerequisite of any rule and is not in the repo (999,887 bytes, root-owned, under a Core checkout). By contrast the ABI audit's block is optional (`ABI_AUDIT_BLOCK := $(wildcard ...)`, `Makefile:2657`).
- Failure scenario: fresh clone on a CI box or a second machine → `make test` reaches the recipe, the four `_diff` tests exit 1 with `perror`, make aborts the recipe (see BLD-6), the remaining ~60 tests in the recipe never run. README §Build presents `make test` as "the full gate" with no mention of the external dependency. The same host-coupling exists in the differential tooling: `validation/gen_bip152_vectors.py:29`, `gen_signet_*.py`, `asm/validation/gen_segwit_txout_vectors.py:57` hard-code `/storage/bitcoin-core-source/build/bin/bitcoin-cli` and `/storage/core-oracle`; `corpus_diff.py:56` hard-codes `/storage/bitcoin/data/.cookie`.
- Core reference: n/a.
- Suggested fix: commit `block413567.raw` under `asm/tests/fixtures/` (it is Core's own public bench fixture and is smaller than the already-tracked `fe_vec.h`), or make it `$(wildcard)`-optional with a loud SKIP the way `test_taproot_block_diff` does, and list the requirement in README §Requirements.
- Test coverage: `gate-log-check` would report the never-run tests, but only after the failure.

##### BLD-3 (LOW) — Committed RPC credential fallback
- Location: `validation/corpus_diff.py:59-63` and `validation/fullchain_diff.py:107-111`: `except Exception: cookie = 'bitcoinrpc:<REDACTED-IN-AUDIT>'` used as HTTP Basic auth to `127.0.0.1:8332` when the cookie file cannot be read. Present since commit `404ea5d` (2026-08-16); the string appears nowhere else in the tree.
- Failure scenario: the credential for the operator's Core oracle node is in git history for anyone with repo access; if that node is ever exposed beyond loopback, the RPC password is public. It is not this node's credential and the oracle binds loopback, so impact is confined to the development host.
- Core reference: Core's own guidance is cookie-only or `rpcauth` (salted), never plaintext in source.
- Suggested fix: delete the fallback (fail loudly when the cookie is unreadable), rotate the oracle's credential, and note the rotation in `docs/audits/`.
- Test coverage: none. Related observation (INFO): `config/bitcoin.regtest.conf` and `config/bitcoin.testnet4.conf` are mode 0644 with plaintext `rpcpassword=` (trivial values, loopback, gitignored) while `config/bitcoin.conf` is 0600; make them 0600 for consistency.

##### BLD-4 (LOW) — NASMFLAGS (`-Werror -I.`) bypassed
- Location: `asm/build.sh:8` loops `nasm -f elf64 -o "$obj" "$src"` over every `.asm`; `asm/Makefile:1781` assembles `bitcoin_sigops.o` with `$(NASM) -f elf64` and `:281` assembles `tests/point_ref.o` the same way, while `NASMFLAGS := -f elf64 -I. -Werror` (`:18`) is documented (`:14-17`) as the fix for "signed dword value exceeds bounds" warnings that hid three real bugs.
- Failure scenario: `./build.sh` is the step-1 build in ENGINEERING §2.2. It rewrites every `.o` with fresh mtimes without `-Werror`, so the subsequent `make test` sees nothing to rebuild and the warning-as-error gate never runs on that tree. `bitcoin_sigops.o` is in `DAEMONOBJS` (sigop counting, consensus) and is *never* assembled with `-Werror` even by `make`. The Makefile's own comment at `:37-38` ("nasm warnings are NOT yet errors, six kinds remain") contradicts `:18`.
- Suggested fix: `build.sh` should call `make asm`; both special rules should use `$(NASMFLAGS)`; delete the stale comment.
- Test coverage: none.

##### BLD-5 (LOW) — Documentation claims that are false, stale, or contradict the code
Spot-checked 20+ concrete claims; the following are wrong today:
1. **README §Differences "Sibling eviction is not implemented."** — False: TRUC sibling eviction landed 2026-09-03 (`asm/bitcoin_mempool_policy.c:1312`, header comment `:45`), and FEATURE_GAPS records it as "proven against real Core on regtest" (`FEATURE_GAPS.md:1733`).
2. **FEATURE_GAPS.md:464 and :476 — `whitebind` "is a Bitcoin Core option this node does not implement" / "still genuinely unimplemented".** — False: `daemon/node_config.c:583-586` parses it and calls `netperm_whitebind_add`; the unsupported-option table (`node_config.c:137-140`) no longer lists it; README lists it as supported. The same passage claims "a test asserts the list and the implementation move together", which is why the prose drifted without failing anything.
3. **README:118 "155 methods; only `rpc.discover` is absent".** — Inaccurate: `rpc_commands.c:4543` refuses *both* `getopenrpcinfo` and `rpc.discover` via `ctl_unsupported`. The four dispatch tables carry 162 names (36+41+38+47); PARITY_PLAN says "~157"; RPC_LIVE_NODE says "155/155". The number is unverifiable from the code and the three documents disagree.
4. **ENGINEERING.md §2.2 "146 harness invocations"** — the recipe has 321 `./tests/...` lines (313 gated sources); README says "about 290". **§2.2 "several harnesses are built at `-O0` ... do not fix these to `-O2`"** and **§5.3 "the daemon is `-O0`-linked"** — false since 2026-08-23 (`Makefile:2528-2545`, all recipes `-O2`). **§6.2** stops at the 08-15/16 internal passes and omits `docs/audits/` (08-29, 09-02). **§1** cites HEAD `62a8225`, `PLAN.md`/`LOG.md`/`PLAN_SCRIPT_VERIFY.md`/`BENCHMARKS.md` at the repo root (all moved to `docs/devlog/`), `soak/ soak-store/ .worktrees/` (purged per `.gitignore`), and a `utxo.dat`/`utxo.idx` WAL layout that the LSM store replaced.
5. **Makefile comments at :975-978, :983-984, :1015 ("Built at -O0 ...") and :2638 ("every C file on that path is pinned to -O0 below")** describe recipes that are `-O2`; a reader auditing N1 from the comments would conclude the pins are still there.
6. **README §Build table says `link-check` runs "in the first seconds"** — it is deliberately *last* in `test:`'s prerequisites (`Makefile:2703-2716`), after every binary is built.
7. **docs/PARITY_ATTESTATION.md "produced after every deploy"** — last entry is deploy `ak` (2026-09-02 07:04). `worklog/2026-09-02.md` records muhash-identical for `an`, `ao`, `ap`, `aq` (not copied into the file); for `ar`–`av` (2026-09-03, five deploys, `av` is `bitcoind.live`) neither the file nor `worklog/2026-09-03.md` records a muhash comparison — only "at the oracle's height". The audit-08-29 recommendation 8 this file exists to satisfy is not being followed.
8. **docs/ABI_STACK_ALIGNMENT.md summary table** (339 functions, 1,121 sites, 262 latent) vs today's run: 1,223 reachable sites, 246 latent, 0 leaving asm; callee-saved audit covers 432 functions. Stale but harmless (the document says it is a branch snapshot).
9. **FEATURE_GAPS.md:284-299 "`assumevalid` — parsed and then IGNORED ... this node verifies every script in every block"** — false since 2026-09-01; the 09-03 re-audit at the end of the file says so explicitly but the passage itself is uncorrected, so a reader of the "REMAINING gaps, precisely (this is the real backlog)" section is misled.
- Suggested fix: correct items 1–3, 7 and 9 now (they affect what an operator believes about relay policy, permissions, RPC coverage, the attestation cadence and the trust boundary); sweep the rest with the next doc re-audit.

##### BLD-6 (INFO) — Gate structure
- `make -C asm -n gate` → "No rule to make target 'gate'". The gate is `make test` (`all: test`, `Makefile:180`); OPERATIONS.md documents `make -k test` + `gate-log-check`. `make -n test` parses cleanly (rc 0) and `make -q daemon/bitcoind` reports the tree binary up to date and byte-identical to `bitcoind.live` (deploy `av`).
- The whole gate is one recipe with 321 command lines. A recipe stops at its first failing line even under `-k`, so an early failure silently skips every later test in the same run; `gate-log-check` exists precisely to detect that, and the audits are ordered so `link-check` cannot mask a link failure as a clean log (`Makefile:2703-2716`).
- Tests share the daemon's assembled objects (`DAEMONOBJS`, `REORGOBJS`, `TXVBWPSOBJS`) but C sources are recompiled per target with the same `-no-pie -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Werror`; only shipped binaries add `-Wl,-z,relro,-z,now` (`HARDENFLAGS`, `:2560`), and `tests/test_elf_hardening` inspects the built daemon for PT_GNU_STACK non-exec, PT_GNU_RELRO and BIND_NOW. Substitutions are explicit and documented: `tests/txacc_bidx_stub.c` (unconditional miss for the in-block index in mempool-admission harnesses) and the `TXVBWPSOBJS` filter that swaps the real LSM for an adversarial `utxo_lsm_get`.
- Manual (ungated) tests: 11, each with a stated reason (`fuzz_verify_diff`, `fuzz_script_diff`, `test_ibd_scale`, `test_addr_ingest`, `test_taproot_block_diff` SKIPs without fetched fixtures, benches). No test is marked flaky; `test_ripemd160_thread_stress`, `test_utxo_prefetch_race`, `test_schnorr_thread_stress`, `soak_lsm_mm` are gated with fixed iteration counts.

##### BLD-7 (INFO) — No sanitizer target
- `grep fsanitize` finds only prose in `docs/devlog/LOG.md:3302,3765,5437,5629,5899` ("the same corpus under -fsanitize=address,undefined gives byte-identical …"). There is no `make test-asan`/`CFLAGS_SAN` knob, so those runs cannot be repeated by anyone else. Given the C P2P/RPC parsers are exactly the code `HARDEN_CC` was added for, a repeatable `SAN=1` build of the C-only harnesses (`test_rpc_json`, `test_rpc_json_depth`, `test_p2p_msgsize`, `test_addr_ingest_parse`, `test_v2transport`, `test_node_config`) would be cheap.

##### BLD-8 (INFO) — Vector provenance (ENGINEERING 2.3d)
- No committed vector header cites the code under test as its source (grep for "generated by tests/|the asm|this node|our"). Generators trace to: Core's `bitcoin-cli` (`gen_bip152_vectors.py`, `gen_signet_*`, `gen_segwit_txout_vectors.py`), `core_script_oracle`/`core_verify_oracle` (built from Core's tree by `validation/build_core_oracle.sh`), libsecp256k1 (`gen_schnorr_diff_vectors.py`, `gen_ecdsa_inverse_vectors.py`), a MuHash oracle compiled against `libbitcoin_crypto.a` (`asm/validation/gen_muhash_vectors.py:30-46`), Core's source text (`gen_script_flags.py`, `gen_bip30_consts.py`, `gen_script_error_defines.py`), or the i2pd router (`i2p_vec.h`).
- Five generators are independent Python models rather than Core: `validation/gen_cmpct_expected.py` (via `bip152_ref.py`), `validation/gen_p2sh_vectors.py`, `asm/validation/gen_taproot_scriptpath_vectors.py`, `asm/validation/gen_multi_p2wpkh.py`, `validation/gen_fe_sqrt_vectors.py`. These are not circular (a different implementation), but the weaker of the two; `taproot_scriptpath_vec.h`'s preamble records the consequence: three vectors carried a wrong control-byte parity and passed because the verifier ignored the bit — the 2.3d failure mode — fixed 2026-08-26 with `tests/test_taproot_parity` against Core.
- `gen_script_flags.py`: source of truth is `/storage/bitcoin-core-source/src/kernel/chainparams.cpp` + `script/interpreter.h` (Core v31.99 master, `CMakeLists.txt`). Re-running a copy into the scratchpad reproduced `asm/script_flags_consts.inc` and `.h` byte-for-byte, so the committed table is current. It is not a Makefile rule (manual after a Core upgrade) and nothing asserts the header matches the Core tree on disk; `test_chainparams` and `test_script_flags` pin the *values*, which is the right invariant for consensus.
- The differential tools (`validation/consensus_diff.py`, `fullchain_diff.py`, `corpus_diff.py`, `p2sh_diff.py`, `sigops_diff.py`, `spend_corpus_diff.py`, `synth_corpus_diff.py`, `mempool_policy_diff.py`, `asm/tests/fuzz_script_diff`, `fuzz_verify_diff`) are manual, need the scratch Core oracle, and compare verdicts (accept/reject + error string) and hashes; their JSON/TXT reports are committed. Distilled corpora are gated (`test_verify_core_vectors`, `test_interp_core_vectors`, `test_schnorr_diff`, `test_bip143_diff`, `test_bip341_diff`, `test_core_parity`, `test_mempool_core_parity`).

##### BLD-9 (INFO) — Ops scripts
- `scripts/start.sh`, `stop.sh`, `status.sh` invoke a *system* `bitcoind`/`bitcoin-cli` (Bitcoin Core), not `asm/daemon/bitcoind`; ENGINEERING §3.7 says so. `stop.sh` falls back to `killall bitcoind`, which would also SIGTERM a tree-built bmc daemon of that name (the systemd unit runs `bitcoind.live` → `bitcoind.deploy-…`, whose comm differs). Consider deleting or repointing them; they do not match README's quick start.
- `scripts/utxo_progress.sh` has no `set -e`, runs `sudo dd if=/proc/<pid>/mem` and `sudo nm` (root read of live process memory; acceptable for a dev box, should be documented).
- `validation/signer_core_diff.sh:20` `eval "$CMD2"` on a link line derived from `make -n`; `:36` `rm -rf $TMP` unquoted (mktemp path, no spaces). `validation/bfi_closing_pass.sh:83,101` stops/starts the production service via sudo. All other `rm -rf` operands are quoted mktemp paths; no `curl | sh`, no `wget | sh`. 25 of 26 shell scripts set `-e`/`-u`.

##### BLD-10 (INFO) — Repo hygiene (prior N11 re-verified)
- Deploy snapshots: 69 (2.1 GB) → 8 (`bitcoind.deploy-20260902ao`…`20260903av`, 243 MB), all gitignored (`asm/daemon/bitcoind.deploy-*`); `git worktree list` shows only `main`; `.worktrees/` is gone and `.claude/worktrees/` is empty; `config/bitcoin.conf.bak-*` grew from 5 to 7 (0600, gitignored, comments only per the prior audit). Ignored build output in-tree: `asm/tests` 684 MB, `asm/daemon` 336 MB.
- Tracked tree: 997 files, 22 MB; nothing over 5 MB (largest: `validation/corpus_diff_report.json` 2.8 MB, `asm/tests/fe_vec.h` 1.0 MB); the three `asm/tests/fixtures/blk_*.bin` are small force-added fixtures under an otherwise ignored directory. `.gitignore` covers `data/`, `logs/`, `soak/`, `soak-store/`, `*.dat`, `*.pass`, `bmcwallet.dat`, `*.mnemonic`, `config/bitcoin.conf`, `config/bitcoin.{testnet4,regtest}.conf`, `bench-results/`, `validation/fullchain_state/`; `git status` is clean with no untracked non-ignored files. No key/passphrase/cookie material found in tracked files outside `data/` other than BLD-3.

#### Verified-correct controls
- `make -C asm abi-check` → "ABI CHECK OK: every call site that leaves assembly has RSP == 0 mod 16 (1223 reachable sites; 246 asm→asm latent)"; `make -C asm callee-saved-check` → "432 functions, no register left unrestored at any ret". Runtime halves gated: `tests/test_abi_stack_align` (checksig_fn callback parity + a printf in the callback), `tests/bench_abi_audit` (sentinel registers, exits non-zero on any violation) — `Makefile:2743-2746`.
- Prior N1 closed: `tests/test_sigops` (`:1783-1786`), `daemon/pverify` (`:2566-2578`), `tests/test_bitcoind_sync`/`test_log`/`test_ibd_*` (`:979-1022`) and `daemon/bitcoind` (`:2528-2545`) are all `-O2`; root cause recorded as LOG.md incident #27 (`docs/devlog/LOG.md:4375`), #31 and the base58check save-area overrun, with the two ABI audits as the standing guard and `fullchain_diff.py` prescribed on every toolchain bump.
- Hardening is uniform: `CFLAGS := -no-pie -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wall -Werror` (`:31-46`) on every C compile; `HARDENFLAGS := -Wl,-z,relro,-z,now` on the daemon and every shipped tool (`:711,717,724,727,2562,2578`); `tests/test_elf_hardening` depends on `daemon/bitcoind` so it cannot pass against a stale binary (`:2575-2576`); `.note.GNU-stack` presence is checked via PT_GNU_STACK.
- `NASMFLAGS := -f elf64 -I. -Werror` (`:18`) for the generic `%.o: %.asm` rule; `bitcoind.o bitcoin_p2p.o: $(VERSION_INC)` (`:190`) so a version bump re-assembles the wire identity; `version_gen.h` generated from the single `version.inc` (`:57-58`).
- Build-integrity audits are prerequisites of `test` (`:2743`): `prereq-check` (recipe uses only declared inputs), `link-check` (every rule links the definer of every symbol; runs last, after `$(VERSION_GEN_H)`), `runlist-check` (313 gated / 11 manual / 0 orphans), `gate-log-selftest` and `link-audit-selftest` (the auditors audit themselves).
- Test isolation: every storage-touching harness calls `tt_isolate()` from `tests/test_tmpdir.h` (mkdtemp + chdir + cleanup on all exits) and lists `$(TEST_TMPDIR_H)` as a prerequisite; no gated test uses the network, sudo, or the live datadir (grep of the recipe for `sudo|8333|seed` is empty; `test_addr_ingest` and the live probes are manual).
- Group variables (`SIGNETSRCS`, `DAEMONOBJS`, `DAEMON_RPCOBJS`, `REORGOBJS`) are defined above first use, with the parse-time-expansion trap documented (`:83-94, :431-442, :961-969`).
- `gen_script_flags.py` regenerated from Core v31.99 source is byte-identical to the committed `asm/script_flags_consts.inc`/`.h`; the assumevalid hash in `daemon/chainparams.c:141` is Core v31.99's `defaultAssumeValid` (height 938343) as README states; BIP94 retarget base is implemented (`bitcoin_pow_rules.c:120-122`); every README configuration key spot-checked (`asmap`, `maxuploadtarget`, `blocksonly`, `bantime`, `minimumchainwork`, `checkblocks`, `checklevel`, `signer`, `whitelist`, `whitebind`, `v2transport`, `bytespersigop`, `persistmempool`, `walletpassfile`) is parsed in `daemon/node_config.c`; `dumptxoutset` dispatches and `loadtxoutset` refuses (`rpc_chain.c:4062-4063`); the `sequence` ZMQ topic is refused by config (`node_config.c:750`); `waitfor*` dispatch (`rpc_chain.c:4056-4058`); wire identity `/BitcoinMachineCode:0.0.1/`, protocol 70016 in `asm/version.inc`.
- The three "real bugs" the 09-03 FEATURE_GAPS re-audit found are fixed in `699e244`: `getnetworkinfo` reports real `proxy_randomize_credentials` (`rpc_node.c:113`), `getaddressinfo` computes `ismine` (`rpc_commands.c:345`), the `gettxoutproof` reason text was restated (`rpc_chain.c:1948`).
- CUDA tier: no reference to cuda/`libbmc_cuda`/`dlopen` in `asm/Makefile` or `asm/daemon/*.c` (the only hit is a comment in `asm/utxo_lsm_mm.c:34`); `asm/cuda/WORKING.md:7-9,127-128,178-179` states it is not wired in and must not serve consensus without a permanent CI harness; `cuda_verify` compares against the asm SHA-256 oracle bit-for-bit.
- Deploy discipline (`docs/OPERATIONS.md:300-335`): gate → `cp -a daemon/bitcoind daemon/bitcoind.deploy-<date><letter>` → relink `bitcoind.live` → restart; verified today that `asm/daemon/bitcoind` is up to date and `cmp`-identical to `bitcoind.live`.
- `docs/README.md` index: every linked document exists.

#### Coverage and limits
- I did not run `make test` (brief forbids full builds) and did not read the 853 test sources; the per-test claims above come from the Makefile, `runlist-check`, and file headers. A reviewer with time should sample ten gated `_diff` harnesses for the strength of their assertions (verdict + error code vs verdict only).
- I did not verify the *content* of the committed differential reports (`validation/*_report.json`) against a fresh oracle run; they are dated artifacts and the 09-03 worklog notes the false-accept oracle was "silently dead for over a day", so a re-run before the next attestation is warranted.
- The `scripts/*.py` auditors (`abi_stack_audit.py`, `makefile_link_audit.py`, `gate_log_audit.py`) were executed but their internals were not reviewed; their self-tests are gated.
- Next: fix BLD-1/BLD-2 (both are one-line Makefile changes plus a 1 MB fixture), rotate the BLD-3 credential, add `$(NASMFLAGS)` to the two bypassing rules and make `build.sh` call `make asm`, and correct README/FEATURE_GAPS items 1–3, 7 and 9 of BLD-5 in the same commit that records the `ar`–`av` muhash attestations.


---

### 6.13 Wire-format parsing / serialization / hashing / address-encoding — review
**Prefix:** SER

**Scope:**
- *Fully read:* `asm/bitcoin_tx.asm`, `asm/bitcoin_txv_parse.asm`, `asm/bitcoin_hash.asm`,
  `asm/bitcoin_addr.asm`, `asm/bech32.asm`, `asm/base32.c`, `asm/bitcoin_scriptcodec.asm`,
  `asm/bitcoin_headers.asm`, `asm/bitcoin_strip_witness.asm`, `asm/bitcoin_cons.asm`,
  `asm/daemon/block_witness.c`, `asm/daemon/serve_invbounds.c`, the CompactSize readers in
  `asm/bitcoin_segwit.c`, `asm/bitcoin_taproot_sighash.c`, `asm/daemon/tx_verify.c`
  (`txv_rd_cs`), `asm/daemon/block_strip.c` (bs_varint), the scriptPubKey classifier in
  `asm/rpc_chain.c` (`script_type`), the bech32/base58 decode path in `asm/wallet_core.c`.
- *Read relevant sections:* `asm/bitcoin_cmpct.asm` (block enumeration + wtxid + cmpctblock
  build), the tx-message P2P entrypoints in `asm/bitcoin_serve.asm`, `asm/daemon/tx_relay.c`,
  `asm/daemon/tx_submit.c`, `asm/rpc_node.c`, `asm/rpc_wallet_ops.c`, `asm/rpc_commands.c`
  (validateaddress), `asm/daemon/blk_submit.c`.
- *Skimmed:* `asm/rpc_json.c` (no varint/CompactSize helpers; only JSON \u hex, out of scope),
  the SipHash body of `bitcoin_cmpct.asm`.

**Summary.** The tree has TWO parser lineages. The C-side readers used on the hot
consensus/mempool path (`tx_verify.c::txv_rd_cs`, `bitcoin_segwit.c::read_cs`,
`bitcoin_taproot_sighash.c::read_cs`, and their asm twin `bitcoin_txv_parse.asm`) are
carefully bounded, cap `nin`/witness-items, and — for segwit/taproot/strip — reject
non-canonical CompactSize exactly like Core. Those are in good shape and well fuzzed
(`test_segwit_bounds_fuzz`, `test_taproot_bounds_fuzz`, `test_txv_parse_diff`). The
weaknesses are (1) the *hand-written asm* `bitcoin_tx.asm` (`tx_parse`/`tx_txid`), which is
the block-consensus and P2P-`tx` parser and still does unbounded pre-check reads and
enforces neither canonical CompactSize nor `MAX_SIZE`; and (2) `bech32_decode`, which has no
input-length cap at all and overflows both a `.bss` scratch and the caller's stack buffer
from the `validateaddress`/`getaddressinfo` RPC. One HIGH memory-safety finding
(bech32), plus consensus-divergence and interop findings. Confidence high; the bech32
overflow and the tx_parse over-reads were traced end-to-end.

#### Findings

| ID | Severity | Location | Title | Verdict |
|----|----------|----------|-------|---------|
| SER-1 | HIGH | bech32.asm:537-615 / wallet_core.c:497 | `bech32_decode` has no length cap → stack + .bss OOB write from RPC | CONFIRMED |
| SER-2 | MEDIUM | bitcoin_tx.asm:93,216,512,539,613 | `tx_parse`/`tx_txid` unbounded pre-check reads (OOB read) | CONFIRMED |
| SER-3 | MEDIUM | bitcoin_tx.asm (tx_parse) | Consensus parser accepts non-canonical CompactSize / no `MAX_SIZE` (accept-where-Core-rejects) | CONFIRMED |
| SER-4 | MEDIUM | bitcoin_cmpct.asm:513,567,680 | BIP152 serving only handles single-byte tx count (<253 tx) — misparses every modern block | CONFIRMED |
| SER-5 | LOW | bech32.asm (decode) | Accepts mixed-case and >90-char strings (BIP173/350 violations) | CONFIRMED |
| SER-6 | LOW | bitcoin_hash.asm:492 / bitcoin_cons.asm | `merkle_root`/`cons_verify` have no CVE-2012-2459 mutation or duplicate-txid guard | PLAUSIBLE |

##### SER-1 (HIGH) — `bech32_decode` unbounded data length overflows both a .bss scratch and the caller's stack buffer
- Location: `asm/bech32.asm:537-615` (decode); reached via `asm/wallet_core.c:497`
  (`wallet_validate_address`) from `asm/rpc_commands.c:276` (`cmd_validate`,
  `validateaddress`/`getaddressinfo`).
- Description: `bech32_decode` scans for the separator, validates HRP length against
  `hrp_cap` (`bech32.asm:572`, good), then in `.data_conv` (`:597-607`) converts *every*
  charset character after the separator into `[WS+300]` with the running index `r9`
  **never bounded**, and finally `rep movsb` copies `r9` bytes into the caller's `out5`
  (`:610-613`). There is no maximum-string-length check anywhere in the function (BIP173/350
  cap the whole string at 90). `WS` is a 512-byte `.bss` buffer (`bech32.asm:64-65`) written
  from offset +300, so any data section longer than ~212 chars overruns `WS` into adjacent
  `.bss`; the caller `wallet_validate_address` passes `unsigned char d5[256]` on its stack
  (`wallet_core.c:494`), so a data section longer than 256 chars smashes that stack frame
  with attacker-controlled bytes.
- Failure scenario: an RPC client calls `validateaddress` with
  `"bc1" + <~300 charset chars>`. `wallet_base58check_decode` rejects it (`slen>128`,
  `wallet_core.c:317`) and control falls to `bech32_decode`. The separator is at index 2
  (HRP `"bc"`, within `hrp_cap`), the ~300 following characters are all in the charset, so
  `.data_conv` writes ~300 bytes into `WS[512]` (from +300 → ~88 bytes past the buffer) and
  `rep movsb`'s ~300 bytes into `d5[256]` → ~44-byte stack overwrite past `d5`. The overflow
  happens during decode, *before* any checksum/length validation, so an invalid address still
  triggers it. Result: memory corruption / crash (DoS), potentially controllable.
- Core reference: `bech32::Decode` rejects `in.size() > 90` up front and rejects mixed case;
  `DecodeDestination`/`CTxDestination` never call the codec on an unbounded string.
- Suggested fix: cap the input length (reject `strlen(in) > 90`) at the top of
  `bech32_decode` and bound the `.data_conv`/copy loop against a fixed maximum
  (e.g. 90) and against the real `out5` capacity (pass a cap parameter). Independently, give
  `wallet_validate_address` an early `strlen(str) > 90` reject.
- Verdict: CONFIRMED.
- Test coverage: `tests/test_bech32.c` exercises the BIP173/350 vectors including an
  over-length string (line 121) but only asserts accept/reject, not buffer bounds; no
  guard-page / oversized-input fuzz of `bech32_decode`. None for the overflow.

##### SER-2 (MEDIUM) — `bitcoin_tx.asm` reads CompactSize/length bytes before bounding the cursor (OOB read)
- Location: `asm/bitcoin_tx.asm:93` (`.read_nin: mov eax,[r9]`), `:216` (n_out `mov eax,[r9]`),
  and in `tx_txid` `:512` (`movzx ecx,byte[r8]`), `:539` (`movzx eax,byte[r8+36]`),
  `:613` (`movzx eax,byte[r8+8]`).
- Description: unlike the C readers (which do `if (p>=end)` first) and the asm `RDCS` macro
  (`bitcoin_txv_parse.asm:91`, `cmp rbx,r12; jae fail` before the byte load), `tx_parse`/
  `tx_txid` load the first varint/length byte (a 4-byte `mov` in two spots) with **no prior
  `cmp r9,end`**. After the segwit-marker branch, `r9` can equal `end`
  (the marker check at `:78-80` jumps to `.read_nin` when `r9+2 > end`), and the per-input
  scriptlen peek `byte[r8+36]` in `tx_txid` is read before the `rbx<=end` check that follows.
- Failure scenario: `tx_txid` is called on a tightly-sized heap buffer at
  `asm/rpc_wallet_ops.c:2872` (`raw = malloc(hl/2+1)`), and on any short/odd input it reads
  `raw[36…]` and up to 3 bytes past the varint word before the bound check fails and it
  returns 0. On the block path (`cons_verify`→`tx_parse`) the reads are within the multi-MB
  block buffer and PoW-gated, so not remotely triggerable; but on a heap buffer sized exactly
  to the tx the over-read could fault if the tx ends at a page boundary. Effect is a
  read-only over-read (crash risk), not a logic error — the masked-off high bytes don't change
  the decode.
- Core reference: `CDataStream`/`ReadCompactSize` never reads past the buffer; the difference
  is defensive-read hygiene, not a semantic Core rule.
- Suggested fix: add `cmp r9,r11 / jae .fail` before every first-byte load in `tx_parse`,
  and bound `r8+36`/`r8+8` before the peeks in `tx_txid` (or route both through an
  `RDCS`-style bounded read as `txv_parse_asm` already does).
- Verdict: CONFIRMED (over-read reachable; fault probability low because principal callers use
  oversized `.bss`/static buffers).
- Test coverage: `tests/test_tx.c`, `tests/test_txtxid.c` cover well-formed txs only; no
  PROT_NONE guard-page fuzz targets `bitcoin_tx.asm` (the guard-page fuzzers
  `test_segwit_bounds_fuzz`/`test_taproot_bounds_fuzz` exercise the *C* readers, not this asm).

##### SER-3 (MEDIUM) — block/consensus parser enforces neither canonical CompactSize nor `MAX_SIZE`
- Location: `asm/bitcoin_tx.asm` `tx_parse` (all four CompactSize decoders) — the parser
  `cons_verify` (`bitcoin_cons.asm:117`) uses for block acceptance and that the P2P `tx`
  path reaches via `tx_txid`.
- Description: `tx_parse` accepts an 0xfd/0xfe/0xff CompactSize regardless of whether the
  value is below the width's minimum (non-canonical) and applies no `MAX_SIZE`
  (`0x02000000`) bound to any count or length. Core's `ReadCompactSize` throws
  "non-canonical ReadCompactSize()" and range-checks against `MAX_SIZE`, so a transaction
  carrying a padded CompactSize (or a vector length > `MAX_SIZE`) cannot deserialize in Core
  and cannot appear in any block Core accepts. The codebase itself documents this gap:
  `bitcoin_segwit.c` (read_cs header) — *"nothing else in this codebase enforces minimality —
  bitcoin_tx.asm's readers do not — so a peer's non-canonical transaction is still mis-parsed
  elsewhere. Pre-existing divergence, separate fix."* `tests/test_txv_cs_maxsize.c` pins the
  analogous over-`MAX_SIZE` accept on the mempool twin.
- Failure scenario: `tx_txid` reconstructs the unwitnessed txid by copying bytes verbatim
  (`bitcoin_tx.asm:663-698`), not by re-encoding varints, so a miner can build a block whose
  txs use non-canonical CompactSize, compute a self-consistent merkle root the same way, and
  mine valid PoW. `cons_verify` recomputes the same merkle root and accepts; Core rejects the
  block → chain split. Requires hashpower, so practical exploitability is low, but it is a
  genuine accept-where-Core-rejects divergence.
- Core reference: `ReadCompactSize(range_check=true)` (serialize.h) — non-canonical + `MAX_SIZE`.
- Suggested fix: make `tx_parse`'s CompactSize decoders reject values below the width minimum
  and above `MAX_SIZE`, matching the already-correct `RDCSC` macro in
  `bitcoin_strip_witness.asm:265-305`. Not in `docs/FEATURE_GAPS.md`; add it there if it is
  to remain a deliberate divergence.
- Verdict: CONFIRMED (behaviour verified by reading the decoders; block-level exploit path is
  the merkle-consistent construction above).
- Test coverage: `tests/test_txv_cs_maxsize.c` pins the twin's accept; no test on
  `bitcoin_tx.asm`/`cons_verify` for either non-canonical or `MAX_SIZE`.

##### SER-4 (MEDIUM) — BIP152 block enumeration only handles a single-byte tx count
- Location: `asm/bitcoin_cmpct.asm:513-531` (`block_txcount` returns -1 for count ≥ 0xfd),
  `:567` (`block_tx_at`: `movzx rax,byte[r12+80]` then cursor `= block+81`),
  `:680` (`cmpctblock_build`: `movzx rax,byte[r13+80]`).
- Description: all three read the block's tx-count CompactSize as a single byte and start the
  tx walk at `block+81`. For any block with ≥253 transactions (a 3/5/9-byte varint) the count
  is taken as the marker byte (253/254/255) and the cursor is 2/4/8 bytes short, so every tx
  boundary is misparsed. `cons_verify` (the consensus path) reads the count correctly
  (`bitcoin_cons.asm:52-92`), so this affects only the BIP152 serving helpers.
- Failure scenario: a peer requests a `cmpctblock`/`getblocktxn` for a modern block. The walk
  desyncs, `tx_parse` bounds-fails, `block_tx_at` returns 0, `cmpctblock_build` returns −1, and
  `bitcoin_serve.asm` takes its `.gd_miss` path — so no crash, but the node effectively cannot
  serve compact blocks for realistic blocks. `docs/FEATURE_GAPS.md:1020` lists BIP152 "both
  directions … DONE", which overstates the serving side.
- Core reference: `PartiallyDownloadedBlock` / `CBlockHeaderAndShortTxIDs` use full
  `ReadCompactSize` for `nTransactions`.
- Suggested fix: decode the full CompactSize in `block_txcount`/`block_tx_at`/`cmpctblock_build`
  (reuse the bounded reader used elsewhere); or correct the FEATURE_GAPS entry to note the
  <253-tx limitation.
- Verdict: CONFIRMED (interop/serving correctness; not consensus, not memory-safety — the
  downstream bounds checks contain the misparse).
- Test coverage: none exercising ≥253-tx blocks through these helpers.

##### SER-5 (LOW) — `bech32_decode` accepts mixed case and over-length strings
- Location: `asm/bech32.asm:110-125` (`bech32_init` maps uppercase to the same values) and the
  absence of a 90-char cap (see SER-1).
- Description: BIP173/350 require rejecting a string that mixes upper and lower case and one
  longer than 90 chars. This decoder folds case in the lookup table and never checks total
  length, so it accepts both. Address standardness therefore diverges from Core's
  `bech32::Decode`. (Subsumed operationally by SER-1's overflow, but a distinct correctness
  divergence for shorter inputs.)
- Failure scenario: `validateaddress` reports `isvalid=true` for a mixed-case bech32 string
  that Core rejects; `wallet_validate_address` normalises case only *after* decoding.
- Core reference: `bech32::Decode` (lower/upper exclusivity + `size()>90`).
- Suggested fix: track a case flag during the separator scan and reject on mix; add the 90-char
  cap from SER-1.
- Verdict: CONFIRMED.
- Test coverage: `tests/test_bech32.c` includes the BIP173 invalid vectors but asserts on
  final valid/invalid classification (which the checksum happens to also reject in many cases),
  not on the case/length rule specifically.

##### SER-6 (LOW) — no CVE-2012-2459 merkle-mutation or duplicate-txid guard on the block path
- Location: `asm/bitcoin_hash.asm:492` (`merkle_root`, odd level duplicates the last node);
  `asm/bitcoin_cons.asm:161-182` (recompute + compare, no duplicate check).
- Description: `merkle_root` has no mutation-detection mode and `cons_verify` does not reject a
  block that repeats a transaction to forge an identical merkle root (Core's
  `BlockMerkleRoot(*mutated)` + `bad-txns-duplicate`). `docs/devlog/BENCHMARKS.md:311` already
  states `merkle_root` "has no mutation-detection mode at all". I could not locate a
  compensating duplicate-txid check on the acceptance path within this module's files.
- Failure scenario: classic CVE-2012-2459 — a peer relays a mutated (duplicated-subtree) copy
  of a valid block; if the node caches it as permanently invalid it can be tricked into
  rejecting the real block. Needs verification of the caching behaviour, which lives outside
  this module.
- Core reference: `CheckBlock` → `BlockMerkleRoot(block, &mutated)`; `bad-txns-duplicate`.
- Suggested fix: add duplicate-hash detection in `merkle_root` (or a duplicate-txid pass in
  `cons_verify`) and reject.
- Verdict: PLAUSIBLE — flagged for the consensus-semantics reviewer, who owns the
  invalid-block caching path; documented in devlog but not in FEATURE_GAPS.
- Test coverage: `tests/bench_checkblock.c`/`bench_merkle.c` mention the guard as a benchmark
  target but do not assert rejection.

#### Verified-correct controls
- `bitcoin_txv_parse.asm` (mempool/block twin): `RDCS` macro bounds every byte before reading
  (`:91-92`), caps `nin` at `TXV_MAX_INPUTS=20000` (`:180`) and witness items at
  `TXV_MAX_WIT_ITEMS=4000000` (`:243`), and uses the split scriptSig bound
  `avail<sl || avail-sl<4` that cannot wrap (`:199-204`) — pinned bug-for-bug against the C by
  `tests/test_txv_parse_diff.c`.
- Witness-pool realloc discipline: pointers are stored as offsets and re-resolved after growth
  (`bitcoin_txv_parse.asm:266-297`), so a `txv_witpool_reserve` realloc cannot dangle; pinned
  by `tests/test_tx_verify_bytepool_realloc.c`.
- `bitcoin_segwit.c::read_cs`, `bitcoin_taproot_sighash.c::read_cs`, and
  `bitcoin_strip_witness.asm::RDCSC` all reject non-canonical CompactSize AND are bounded;
  the `ts_avail`/`sw_avail` "remaining ≥ wanted" comparisons avoid pointer-overflow
  (`bitcoin_taproot_sighash.c:95-110`). Guard-page fuzzed by `test_segwit_bounds_fuzz` /
  `test_taproot_bounds_fuzz`.
- `serve_invbounds.c`: enforces canonical CompactSize (`:56-57`), `MAX_INV_SZ=50000`
  (`:61`), and overflow-safe vector-fit `(plen-o)/36 < c` (`:64`) — the fix for the
  2026-08-30 addendum finding, verified present.
- `block_witness.c::bw_walk_tx`: bounded walk with `v > (u64)(end-p)` length checks
  (`:44,56,72`), last-output-wins commitment index (`:57-60`), coinbase wtxid forced to
  `0x00..00` and nonce required to be exactly one 32-byte item (`:102-107`) — matches Core's
  merkle.cpp/validation.cpp citations in the comments.
- `cons_verify`: coinbase-first `n_in==1` (`bitcoin_cons.asm:127-131`), tx-count field must
  equal walked count (`:167-171`), full-consumption check `cursor==len` (`:162-164`),
  txid-slot cap check before writing scratch (`:133-135`) — the incident-#33 scratch-cap sizing
  is corrected at every caller.
- `base58check_encode`: refuses `paylen>78` before touching `data` (`bitcoin_addr.asm:157-167`),
  the fix for the extended-key frame overflow, with the frame layout documented.
- `base32.c::base32_decode`: rejects leftover non-zero padding bits like Core's `DecodeBase32`
  (`base32.c:333-335`).
- `der_sig_strict` (`bitcoin_scriptcodec.asm:537`) transcribes Core's `IsValidSignatureEncoding`
  check-for-check with an in-bounds argument for every load; `get_op` bounds every push
  (`:700-704`); `scriptnum_decode` minimal-encoding + size checks match `CScriptNum`.
- scriptPubKey classifier `rpc_chain.c::script_type` matches Core's Solver ordering: P2PK
  validates the pubkey shape (`:570`, invalid pubkey → nonstandard), bare multisig →
  `"multisig"` (`:584`), OP_RETURN → `"nulldata"`, `anchor`, witness v1/`witness_unknown`
  (`:562-587`).

#### Coverage and limits
- I did not dynamically run the parsers against guard pages for `bitcoin_tx.asm` — SER-2 is
  from reading; a `PROT_NONE`-page harness around `tx_parse`/`tx_txid` (mirroring
  `test_segwit_bounds_fuzz`) would confirm the fault and is the first thing I'd add.
- SER-6's real severity depends on the invalid-block caching behaviour, which is outside this
  module; handed to the consensus-semantics reviewer.
- I did not exhaustively trace every RPC that reaches `wallet_validate_address` — SER-1 is
  reachable via at least `validateaddress`/`getaddressinfo`; other address-taking RPCs
  (e.g. `deriveaddresses`, `getaddressinfo` in wallet ops) likely share the sink and would
  amplify reachability.
- PSBT byte-level decode (`psbt_update.c`, `rpc_commands.c` psbt readers) was only skimmed;
  a follow-up should audit its key/value length handling with the same lens as the tx parsers.
- Serialization round-trip for `createrawtransaction`→decode is pinned by
  `tests/test_rpc_rawtx.c` against Core known-answers; I read the harness header but did not
  re-derive the vectors.
