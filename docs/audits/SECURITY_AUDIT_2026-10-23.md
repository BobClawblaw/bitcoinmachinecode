# Security and code review — bmc @ f07b90bb (2026-10-23)

Static review of `asm/` at HEAD f07b90bb (branch `perf/2026-10-11-b15-lsm-reads-pread`), six areas
in parallel, weighted toward the ~1,060 commits since the 09-03 audit closed. Nothing in the repo
was modified, built or run; no traffic went to any node (bench run 50 in progress). The scratch
PoCs were not kept.

**Status (2026-10-24):** every finding below is fixed, with a revert-checked test, in PRs #424 to
#430; the formal-verification findings and follow-ups are in #431 to #435. The account of the
fixes, the proofs and the two validation syncs is
[docs/history/2026-10-23-the-review](../history/2026-10-23-the-review/). This report was held
back until the fixes were up, as SECURITY.md asks; it is published as written, apart from this
paragraph and local paths.

Verification column: **V** = re-read end to end by the lead reviewer against the code (and Core
v31.1's source); **A** = traced by the area reviewer, not re-read
by the lead; **P** = plausible, one link unverified (named).

## Summary

| Sev | ID | Area | One line | Ver |
|---|---|---|---|---|
| HIGH | CON-1 | consensus | Any peer can get a real block marked invalid by tampering its witness bytes (no PoW needed) | V |
| HIGH | P2P-1 | p2p | Keep-up pass stores the peer's block under the hash *we* asked for; a difficulty-1 block halts the applier | V (store) / P (permanence) |
| HIGH | CON-2 | consensus | Unknown witness versions skip Core's EVAL_FALSE check on the program push (`OP_2 0x0000` spendable) | V |
| HIGH | CON-3 | consensus | Zero-output transactions accepted on block connect (Core: bad-txns-vout-empty) | V |
| HIGH | CON-4 | consensus | VAL-10 incomplete: superfluous `00 01` marker accepted on non-coinbase txs | V |
| HIGH | CON-5 | consensus | Header nVersion compared unsigned; versions ≥ 0x80000000 accepted | V |
| HIGH | MPL-1 | mempool | Unsolicited `tx` skips the recent-rejects filter; scripts run before policy; no score → free repeated signature-verify DoS | V (filter) / A |
| HIGH | MPL-2 | mempool | Re-sending a low-fee parent re-verifies every parked orphan child; failed children never freed | A |
| HIGH | MPL-3 | mempool | Each eviction for room rebuilds and re-linearizes every cluster in the pool, under the pool lock | A (PoC timed) |
| MED | P2P-2 | p2p | Unsolicited `cmpctblock` triggers a full mempool short-id scan before any PoW check, never scored | A |
| MED | RPC-21 | rpc | Esplora per-connection threads leak ~24 MB of `__thread` buffers each (unauth memory exhaustion) | V |
| MED | RPC-22 | rpc | Esplora listener: no total read deadline; 16 slow sockets lock out all clients | A |
| MED | RPC-23 | rpc | Unauth Esplora routes with unbounded work (`max_txs`, batch txid lists, O(n²) parent dedup) + `ACAO: *` | A |
| MED | CON-6 | consensus | Fixed 4 MiB cap on spent scriptPubKeys in the taproot sighash (Core: none) | A |
| MED | CON-7 | consensus | Assumevalid skips scripts by height alone, not ancestry | P (reorg probe below AV height) |
| MED | CON-8 | consensus | BIP94 time-timewarp-attack rule missing (testnet4 only) | A |
| MED | CON-9 | consensus | Non-canonical tx-count CompactSize stored, then halts the applier instead of rejecting | P (recovery) |
| MED | MPL-4 | mempool | Cluster-limit BFS scans the whole pool per popped node (243 ms at 1M entries) | A |
| MED | MPL-5 | mempool | One peer can flush the global orphan pool (no per-peer reservation) | A |
| MED | MPL-6 | mempool | Replacement check rebuilds the whole-pool child index per candidate | A |
| MED | CFG-1 | config | RPC credentials parsed section-blind (`[regtest] rpcpassword=` works on mainnet); `rpcport` atoi wraps | V |
| MED | CFG-2 | config | All-rejected `rpcwhitelist` entries fail open to unrestricted | A |
| MED | CRY-1 | wallet | Legacy BMCWAL v2 cipher is a repeating 64-byte XOR; one known block decrypts the file | A (PoC) |
| MED | ST2-1 | storage | LSM asm ignores every fsync return before publishing manifests / unlinking inputs | V |
| MED | ST2-2 | storage | addr_hist merge can leave overlapping runs; readers double-count, next merge bakes it in | A |
| MED | ST2-3 | storage | `dumptxoutset` overwrites any file in the chain dir (relative path, no exists check) | A |
| MED | ST2-4 | storage | undo.idx / rev never fsynced; power loss can make WAL ops durable without their undo | P |
| LOW | CRY-2 | crypto | `neg_n` drops the borrow when a limb is all ones → BIP340 sign returns rc=1 with an invalid sig | V (PoC key) |
| LOW | P2P-3/4 | p2p | cmpctblock index forms Core rejects (memory-safe); eviction rounds differ from Core | A |
| LOW | RPC-24..27 | rpc | JSON-RPC intake slowloris residual; `bmc_cli` writes past its 32 KB body buffer (PoC); LF injection into exec-lock log; idle ZMQ subscribers fill 32 slots | A |
| LOW | CON-10..14 | consensus | 100-block reorg cap; 64-entry invalid set; unchecked arena growth; time-too-old floor skipped < h11; submitblock 16,384-tx cap | A |
| LOW | MPL-7/8 | mempool | Sibling orphans not retried; `strstr("missing")` misclasses missing-ephemeral-spends | A |
| LOW | CFG-3..6 | config | Unclosed `[section`; 1024-byte line split; IPv6 `bind=`; `chain=mainnet` drops base-section keys incl. `bind=` | A |
| LOW | HST-1..7 | host | SIGCHLD reaper vs popen; non-atomic `g_inbound_n`; signer child inherits fds; helpers without RELRO; wallet side-files created 0644 then chmod; Tor plain COOKIE (no SAFECOOKIE) | A |
| LOW | CRY-3..8 | crypto | Secret wipes optimized away / missing; BIP324 handover blob not wiped; rewrap iters unbounded; CLI passfile 0644 window; `init --force` uses "--force" as passphrase; no dir fsync before plaintext unlink | A |
| LOW | ST2-5..9 | storage | Rollover writes a dword -1 into a qword fd; journal capacity multiply wrap; addr_hist trusts on-disk counts; sparse_off unbounded; dead runs stay mapped | A |

No CRITICAL memory-safety finding on the remote surfaces. The new constant-time point code,
field/scalar kernels, safegcd, MuHash inversion, ChaCha20-AVX2, Poly1305 and ElligatorSwift all
matched references on edge-case differentials.

---

## HIGH findings in detail

### CON-1 — witness tampering gets a real block marked invalid (no PoW)
- `daemon/utxo_live.c:2345-2357` runs the weight/length phase before the witness-commitment phase
  at `:2427-2440`. A weight failure sets `g_last_reject` without `g_last_mutated`.
- `daemon/block_witness.c:125-127`: a coinbase that fails `bw_walk_tx` returns -1, which
  `utxo_live.c:2434-2440` files as a real refusal ("bad-witness-merkle-match"), not a mutation.
- `utxo_live.c:4114-4131`: a REJECT calls `g_reject_fn`, which invalidates the hash (invalid.dat,
  archive truncate, headers rollback). Only a *second* reject within 100 blocks is held back.
- IBD and inbound blocks are archived after `cons_verify` only (PoW, txids, merkle root), none of
  which cover witness bytes.
- Trigger: serve a real block with (a) junk witness items pushing weight over 4M, (b) a coinbase
  with the marker but an empty witness stack, or (c) a non-canonical nonce length.
- Core v31.1 runs `CheckWitnessMalleation` (validation.cpp:4217) before `bad-blk-weight` (:4228)
  and files these as BLOCK_MUTATED, never failed.
- Fix: commitment check before the weight phase; every witness-structure failure (incl. -1) is a
  mutation; ideally check commitment before archiving, as `cmpct_recv.c` already does.

### P2P-1 — keep-up pass stores the wrong block under the requested hash
- `bitcoind.asm` `node_sync_multi`: the requested hash (from the peer's own `headers`) is copied
  to `[rbp-0xa0]`; a `block` reply jumps to `.have_block`, runs `cons_verify`, then
  `idxscan_append_locked(st, [rbp-0xa0], raw, len)`. Nothing compares `block_hash(raw)` with
  the requested hash; `idxscan_append_locked` only checks `prev == tip`.
- `cons_verify` checks the block's PoW against its *own* nBits, so a powLimit block (~2^32
  sha256d) passes.
- The applier then sees index hash ≠ body hash and loops "archive not ready… retries"; `index.dat`
  is durable, so this survives restarts (permanence: P).
- Fix: require `block_hash(raw) == [rbp-0xa0]` at `.have_block` and score the peer; better, route
  pass blocks through `blk_submit_evaluate_ex` like the sweep path; make `cmpct_recv_blocktxn`
  take the wanted hash; give the applier an escalation for a persistent index/body mismatch.

### CON-2 — unknown witness versions skip EVAL_FALSE
- `daemon/tx_verify.c:941/1885` assign `TXV_SHAPE_WPASS`; `:667/:1481` return 1.
  `bitcoin_witness_v0.c:138` `sv_classify_segwit` never tests the program push for truth.
- Core `VerifyScript` evaluates scriptPubKey (or the P2SH redeemScript) first and fails
  EVAL_FALSE on a false top item, before the witness branch.
- Trigger: output `52 02 0000` (OP_2, push 0x0000, or negative zero) spent with an empty scriptSig;
  wrapped form via redeemScript `52020000`.
- Fix: CastToBool the program bytes before WPASS; separately refuse unknown-witness spends in
  mempool policy (Core's DISCOURAGE flag) so bmc does not relay or template them.

### CON-3 — zero-output transactions accepted on connect
- `utxo_live.c:2108` refuses `nin == 0` only; `val_read_tx` and `txvb_parse_tx`
  (`tx_verify.c:1395`) have no `nout == 0` check. The only checks are in `blk_submit.c:71` and
  `bitcoin_txval_modern.c:287`, neither on the connect path.
- Core: `bad-txns-vout-empty` (consensus/tx_check.cpp:17).
- Fix: reject `nout == 0` for every tx in Phase 0.15.

### CON-4 — superfluous witness on non-coinbase txs
- `block_witness.c:135-147`: with a commitment present, only the coinbase is walked; txs 1..n are
  hashed for wtxids. VAL-10's `if (!*has_witness) return 0` therefore never runs for them.
- Core throws "Superfluous witness record" at deserialization.
- Fix: walk every tx in the commitment branch, or check in Phase 0.15.

### CON-5 — nVersion compared unsigned
- `daemon/hdrrules.h:57` `unsigned int ver`; Core's `nVersion` is `int32_t` (primitives/block.h:30),
  so any version ≥ 0x80000000 is negative and fails `bad-version` (validation.cpp:4161).
- Fix: `int32_t ver`.

### MPL-1 — free repeated script verification of the same invalid tx
- `daemon/tx_relay.c:1390-1408` `txr_take_tx` checks only `mpool_get`; the recent-rejects filter
  (`serve_reject_has`) is consulted only before we send getdata (`bitcoin_serve.asm:617`) and in
  `txrelay_classify_missing`.
- `tx_accept.c:1108-1125`: `validate_p2p` runs scripts before fee/policy (RPC paths were reordered
  10-03, this one was not); no misbehaviour score on an invalid script.
- Trigger: push the same ~100 kvB taproot-heavy tx with one bad final signature, repeatedly.
- Fix: filter check in `.do_tx` and `txr_take_tx`; policy before scripts; score the source.

### MPL-2 — 1p1c re-verification amplification
- `tx_relay.c:870-889`: each arrival of a fee-rejected parent (-28, deliberately unfiltered) runs a
  full `tx_accept_test_reason` on every parked child; a failing child is not freed.
- Fix: free/filter a child failing for a non-fee reason; rate-limit per parent.

### MPL-3 — eviction re-linearizes the whole pool
- `bitcoin_mempool_policy.c:2150-2252` `worst_chunk_excl` rebuilds the child-edge index, finds
  every cluster and runs `mpc_linearize_optimal` on each, per call, under the pool lock; called in
  the `put == 2` loop (`:3129-3175`) and RBF (`:3026`).
- PoC: up to 486 µs per adversarial 64-member cluster → ~8 s per eviction in an adversarial pool;
  0.1-0.3 s per eviction in a 300k-singleton pool (estimate).
- Fix: per-cluster cached worst chunk, dirty on change (Core's design).

---

## Selected MEDIUMs (lead-verified)

- **RPC-21** `rpc_chain.c:1872-1874, 1889-1892, 1043-1044`: `static __thread` buffers malloc'd on
  first use (4.8 MB + 19.2 MB + 256 KB) in detached per-connection Esplora threads
  (`rpc_server.c:1457-1458`); the 10-07 `rd_lane_release` key destructor frees only the lane's
  store handle and block buffer. Unauthenticated `GET /block/<h>/txs` leaks per request.
  Fix: free all `__thread` heap state in the same destructor, or a fixed thread pool.
- **CFG-1** `daemon/main.c:11692-11712` `serve_rpc_read_creds`: flat parse, ignores `[section]`,
  `includeconf` and inline comments; last value wins; `atoi` port. DMN-4 was marked closed but this
  reader was not changed. Fix: read the three keys through `node_config_load`, clamp the port.
- **ST2-1** `bitcoin_utxo_lsm.asm` calls `mac_fsync2` at 3109, 3255, 3275, 5109, 5287, 5309 and goes
  straight to `close` without testing `rax`. An EIO/ENOSPC during writeback still publishes the
  manifest / adopts the compaction and unlinks inputs. Fix: test and fail the flush/compaction.

## Not covered / limits
- `tx_accept.c` policy internals beyond MPL-1/8, `bitcoin_serve.asm` beyond its parsers, the dial
  helpers' fork + SCM_RIGHTS path, every RPC lane handler against everything `irs_refresh` touches,
  `schnorr_verify` / GLV internals on the consensus side (crypto side did test them).
- Nothing was run against a live node; DoS cost figures are PoC timings of copied code or estimates.
- Per project rule, each fix needs a test that is watched to FAIL with the fix reverted.

## Controls verified sound (abridged)
- v1 framer: 4 MB cap before drain, checksum verified (NET-11). BIP324: garbage ≤ 4095, packet cap,
  decoys do not advance state (NET-12), handshake deadlines (NET-2), CT tag compare before decrypt.
- Compact receive: witness commitment checked before use; collisions → missing → full-block fallback.
- addr/addrv2: 1000 cap + score, token bucket, netgroup cap, tried never evicted (NET-10 holds).
- RPC auth: constant-time compare, all rpcauth HMACs computed, empty password never accepted,
  cookie 0600 urandom; ACL before auth and REST; bad `rpcallowip` fatal; defaults loopback;
  ZMQ refuses `*`; REST/Esplora off by default; JSON depth 512, strict numbers, escaping writer;
  no non-literal format strings; Esplora reaches only fixed method names.
- Consensus: merkle + CVE-2012-2459, MAX_MONEY per output and running, CVE-2018-17144 duplicates,
  maturity, BIP30/34 exceptions, BIP68 with no input cap, PoW retarget/clamp, activation flags,
  interpreter limits, tapscript rules, undo count pre-flight.
- Crypto: CT multiplies scan every table entry with masks; variable-time inverses only on public
  values; RNG getrandom/urandom fail-closed, no userspace CSPRNG state across fork; MuSig2 nonces
  erased on use under the exclusive lock.
- Storage: B15 pread path bounded and falls back safely on short read/EINTR; B16 drops are hints
  only and do not hide writeback errors from STO-11's fdatasync; append cursor invariant (09-17)
  holds; manifest publish tmp+fsync(checked)+rename+dirfsync.
- Build: daemon has NX stack, full RELRO + BIND_NOW, FORTIFY, stack-protector-strong; every asm
  object has `.note.GNU-stack`; no tracked secrets; 09-04 keys marked compromised.
