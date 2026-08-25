# Bitcoin Core feature-parity plan

Grounded in the actual registered method tables (`rpc_commands.c`, `rpc_node.c`,
`rpc_chain.c`) and the wallet surface (`daemon/wallet_cli.c`, `wallet_core.c`) as
of 2026-08-25 — not from memory. "Parity" here means **RPC-surface + behavior
parity**, method by method, verified where verifiable. It does NOT resolve the
separate, deeper open question of consensus correctness (LOG.md incidents).

## Verification bound (honest)
The scratch Core oracle (`/storage/core-oracle`, port 8335) is built **without
wallet support**, so wallet-state RPCs cannot be oracle-diffed. Verification
strategy per class:
- **Chain / UTXO / mining-info RPCs** → oracle-diff (byte/field parity).
- **Pure tx/message RPCs** (createrawtransaction, sign*, *message) → Core-shaped
  JSON + round-trip self-consistency (build→sign→decode→validate) + fixed-format
  cross-check (message signatures are Core-byte-compatible).
- **Wallet-state RPCs** (send*, balance, history, multiwallet) → round-trip and
  own-node consistency; oracle-diff not available. Stated as such, not claimed.

### gettxoutsetinfo — RPC WIRED 2026-08-25 (capstone-gated for live proof)
daemon/utxo_setinfo_rpc.c #includes the standalone parity TOOL's translation
unit (main renamed -- the test_dial_budget pattern), inheriting its
fingerprint/quiescence discipline, applied-height reading, and memtable
sizing VERBATIM: the tool -- the capstone's measuring instrument -- is
untouched, and the two readers cross-check each other. The RPC REFUSES
(busy) while the datadir is being written; there is no --force. DOCUMENTED
DIVERGENCES: our default hash_type is muhash (Core's hash_serialized_3 is
refused by name with a clear message); no coinstatsindex extras
(total_unspendable_amount/block_info); height = the UTXO APPLIED height.
Cross-check on the parked pre-rebuild state: RPC reader and tool agree
field-for-field. Live end-to-end proof lands with the capstone.

## Current surface (verified present)
Chain/util: getblock*, getrawtransaction, gettxoutproof/verify, decodescript,
createmultisig, getdescriptorinfo, deriveaddresses, getchaintips, uptime, stop.
Live-node: getconnectioncount, getnetworkinfo, getpeerinfo, getmempoolinfo,
getrawmempool (stub), sendrawtransaction.
Wallet (RPC): getnewaddress, getrawchangeaddress, validateaddress,
getaddressinfo, gettxout, listunspent, getbalance, decoderawtransaction.
Wallet (CLI only, primitives exist in wallet_core.c): sendtoaddress, send,
createrawtransaction, signrawtransactionwithkey, signmessage, verifymessage,
listtransactions, history, mnemonic/seed/HD.
UTXO: gettxoutsetinfo (daemon/utxo_setinfo.c).

## Tranches (ordered: verifiable value first)

### T1 — Pure tx/message wallet RPCs  [status: MOSTLY DONE]
Wire existing primitives onto JSON-RPC with Core shapes.
- [x] signmessagewithprivkey + verifymessage — cross-verified vs oracle BOTH
      ways; frozen as KAT in test_rpc_msg (commit 8cbfff0, merged)
- [x] createrawtransaction — byte-identical to oracle across all 5 output
      script types + multi-in/out + OP_RETURN + locktime + replaceable
      (test_rpc_rawtx, 11 KATs). Caught: modern Core defaults replaceable=true.
- [~] signrawtransactionwithkey — ECDSA single-sig DONE (P2PKH, P2WPKH,
      P2SH-P2WPKH) with a hand-built BIP143 sighash + segwit serializer. Every
      signature VALIDATED LIVE by Core's script engine (feed our signed tx back
      to the oracle with empty keys -> complete:true), frozen as deterministic
      KATs in test_rpc_signraw. STILL DEFERRED: P2WSH/P2SH multisig assembly and
      P2TR key-path (needs a BIP340 Schnorr SIGNER, which does not exist in the
      tree -- its own future "taproot signing" task).

### T2 — Chain/UTXO query completion  [oracle-verifiable]
- [x] getblockstats — 20 block-only fields diffed byte-for-byte vs oracle across
      5 blocks (pre/post-segwit); fee/feerate/utxo_size_inc need undo (omitted
      where absent, honest divergence) and are verified via synthetic undo in
      test_rpc_chain. Numeric-height + blockhash forms both work.
- [ ] scantxoutset — needs the COMPLETE UTXO set; BLOCKED on the rebuild.
- [ ] getmempoolentry / getmempoolancestors / getmempooldescendants (after T4)

### T3 — Mining-info RPCs  [oracle-verifiable, non-wallet]
- [x] getnetworkhashps + getmininginfo — getnetworkhashps diffed byte-for-byte
      vs oracle (incl. float formatting) at multiple heights/windows;
      getmininginfo = documented v31 field set. NOTE: this uncovered and FIXED
      incident #43 -- chainwork.dat corrupt for the whole post-segwit chain
      (getblock/getblockheader chainwork wrong); regenerated + verified + live.
- [x] getblocktemplate (BIP22/23) — the deterministic frame is FULLY
      oracle-verified: at our tip, previousblockhash and mintime (MTP+1)
      match the oracle's records exactly; bits/target/version/rules
      (csv, !segwit, taproot)/limits/mutable/noncerange/vbavailable/
      vbrequired/capabilities all diff clean; coinbasevalue = exact
      subsidy + our pool's fees. The 2016-block difficulty retarget
      (rpc_chain_retarget, arith_uint256-faithful incl the /4..x4 clamp,
      pow-limit cap, and GetCompact sign-bit shuffle) reproduces 8/8 REAL
      historical retargets from production headers (incl 481824).
      default_witness_commitment recomputed over the template's tx order
      (empty-template constant frozen as a KAT). Transactions come from
      the shared mempool via the same injected hooks (parents-before-
      children order, 1-based depends, fee from the policy registry,
      weight via tx_walk). DOCUMENTED GAPS: per-tx "sigops" is the legacy
      count x4 only (P2SH/witness sigops need prevout scripts this path
      does not resolve -- a lower bound); longpollid is emitted (prevhash+
      counter) but hanging longpoll is not honored; BIP23 proposal mode
      rejected as Invalid mode; tx order is valid but not fee-optimal
      (no package feerate sort).
- [x] prioritisetransaction + getprioritisedtransactions -- parent-local
      fee-delta map (like Core's: in-memory operator hints, cleared on
      restart); deltas ACCUMULATE, zero-sum entries erased, tx need not be
      in the mempool, fees.modified = base + delta in getmempoolentry,
      companion shows modified_fee (sats) only when in-mempool -- every
      semantic oracle-verified. Also fixed a latent bug: rpc_node.c never
      included stdlib.h, so atof/atol/atoll were implicitly declared (int
      returns) -- estimatesmartfee's conf_target parse worked only by ABI
      accident.
- [x] submitblock -- COMPLETE, including the connect step. What works now: the RPC transport accepts the
      ~8MB hex payload (the request buffer was a fixed 256KB stack array
      that silently truncated -- now heap-grown to 9MB with a linear header
      scan); a 4MB shared block channel (same seq/ack discipline as
      sendrawtransaction) carries it to the download worker, which runs
      daemon/blk_submit.c: duplicate check vs tip, PoW vs the header's own
      bits (high-hash), cons_verify (bad-txnmrklroot), the BIP141 witness-
      commitment check (bad-witness-merkle-match -- the stripped-archive
      lesson), tip-linkage. A consensus-clean, tip-extending block answers
      "inconclusive" -- BIP22's honest word -- because CONNECTING it needs a
      UTXO-level dry run of the apply path first: appending an un-dry-run
      block could wedge catch-up exactly like the witness-stripped archive
      did. That dry-run + append + apply + relay is the follow-up slice.
      Tests: the evaluator on the REAL genesis block with targeted
      corruptions pinning every reason string; the channel handshake
      against a fake worker; the 600KB transport round-trip on the real
      server.
      CONNECT STEP (second commit): utxo_live_dryrun_block runs the SAME
      verification phases (parse, witness commitment, BIP30, in-block dup,
      full script verify) a real apply runs and stops at the Phase 5
      boundary -- the first mutation -- with the reject reason captured
      (utxo_live_last_reject). The worker connects a submitted block ONLY
      when fully synced (applied == tip; otherwise "inconclusive"), after
      contextual checks (bits must equal the chain's required next work incl
      the 2016-block retarget -> "bad-diffbits"; timestamp > MTP(11) and
      <= now+2h -> "time-too-old"/"time-too-new"), then dry-run -> reason on
      reject -> else store_append + the NORMAL catch-up apply (same undo/
      checkpoint crash-safety as any network block; a dry-run pass makes the
      apply deterministic) + headers.dat append + inv(MSG_BLOCK) to the
      outbound legs -> RPC returns null. tests/test_blk_dryrun proves
      PURITY (clean dry run mutates nothing), REASONS, and COHERENCE
      (the dry-run-passed block then applies cleanly) on a real synthetic
      chain. UNTESTED-BY-SUITE: the worker-loop connect branch itself
      (bits/MTP wiring) -- exercised at the supervised deploy, not before.
      DRIVE-BY REAL BUG: hunting a "flaky" dry-run exposed a 65-byte
      hand-built coinbase written into u8[64] stack buffers across SEVEN
      test fixtures -- one byte of stack UB whose landing spot depended on
      each binary's layout (test_apply_block_rollback et al passed by
      luck). All widened to [80].

### T4 — Mempool coherence
- [x] mp_ext_area/blob/policy-state MAP_SHARED, init-once pre-fork
      (mp_ext_inited; serve.asm adopts, never re-inits), PROCESS_SHARED
      mp_lock over every C mutation site (accept, expiry, reorg reconcile).
      Proven hermetically: tests/test_mempool_shared (cross-fork visibility).
- [x] Real getrawmempool from the shared pool (txid array; verbose entries
      carry vsize/weight/time/fees.base -- full ancestor/descendant
      aggregates land with getmempoolentry) + getmempoolinfo real
      size/bytes/usage/total_fee/maxmempool. BUILD-SIDE ONLY so far: the live
      daemon still runs the MAP_PRIVATE build; deploy batched post-rebuild,
      then live-verify (inbound tx -> parent getrawmempool).
- [x] getmempoolentry -- full documented field set minus master's
      cluster-mempool extras (vsize_adjusted/chunkweight/fees.chunk;
      bip125-replaceable is gone in modern Core). Graph fields from a
      mp_lock'd snapshot of the shared policy registry
      (mpool_policy_entry_info): depends/spentby direct edges,
      ancestor/descendant transitive closures INCLUDING self, fees summed over
      the set, sizes as true BIP141 vsize sums (each member's bytes re-read
      from the pool). Semantics verified against a live oracle chain (child
      anccount=2, ancsize=sum of member vsizes, fees.anc=sum incl self,
      parent desccount incl self, spentby). wtxid = sha256d(full
      serialization). Error parity: -5 not-in-mempool, -8 with Core's exact
      bad-txid message. DOCUMENTED GAPS: height=0 (entry height untracked at
      accept), unbroadcast=false. Hermetic test drives a REAL parent->child
      chain through the REAL mpool_policy_add path. Deploy batched with the
      rest (build-side).
- [x] getmempoolancestors / getmempooldescendants -- same
      mpool_policy_entry_info snapshot; sets EXCLUDE the tx itself
      (oracle-verified), stale registry members filtered against the pool;
      non-verbose txid arrays, verbose = getmempoolentry-shaped member
      objects; -8/-5 error parity shared with getmempoolentry.

### T5 — Fee estimation
- [x] estimatesmartfee -- Core's CONTRACT (arg validation with Core-exact -8
      messages incl the conf_target [1,1008] range and estimate_mode list;
      blocks clamps to >= 2, oracle-verified; fresh node returns
      {"errors":["Insufficient data or no feerate found"],"blocks":N}) over
      OUR estimator: the tx-accept policy layer's EMA of accepted feerates
      (shared state, read under mp_lock), floored at min relay fee. The
      NUMBER is honestly ours -- Core's bucket tracker needs confirmed-block
      history we don't keep. economical/conservative accepted (case-insens.)
      but return the same EMA (one estimator). Deploy batched (build-side).
- [ ] estimaterawfee (hidden/debug RPC -- low value, deferred)

### T6 — Wallet-state RPCs on the RPC surface
- [ ] sendtoaddress, sendmany, listtransactions, gettransaction,
      getreceivedbyaddress, getunconfirmedbalance

### T7 — Wallet management (multiwallet)
- [ ] createwallet/loadwallet/unloadwallet/listwallets, backupwallet,
      walletpassphrase/encryptwallet, importdescriptors/importprivkey,
      fundrawtransaction, bumpfee

### T8 — PSBT (BIP174)
- [~] createpsbt (v0, Core-validated) + decodepsbt (byte-identical to Core) DONE.
      This also fixed incident #44: decoderawtransaction was minimal; now routes
      through rpc_chain's full tx_to_json (Core shape). converttopsbt + combinepsbt + joinpsbts +
      analyzepsbt DONE.
      joinpsbts: Core SHUFFLES inputs/outputs (privacy) so there is no byte-stable target; ours is
      deterministic (P1-first concat) and verified SEMANTICALLY vs Core (Core's decodepsbt reads our
      output as v0 / version 2 / locktime 0 with the identical input+output multiset). Remaining:
      finalizepsbt, walletprocesspsbt (wallet), utxoupdatepsbt (needs UTXO lookup).

### T9 — Indexes
- [x] getindexinfo — this node runs NONE of the optional indexes
      (txindex/coinstatsindex/blockfilterindex), so it returns {} exactly as
      Core does when none are enabled; verified live (Core is also lenient on a
      non-string arg -> {}). The remaining index BUILDS below are the real work.
- [ ] txindex (global) → getrawtransaction without blockhash
- [ ] blockfilterindex → getblockfilter (BIP157/158)

### T10 — Networks
- [ ] testnet3/testnet4 + signet chain params, net magic, DNS seeds, RPC ports

## Gating analysis (2026-08-25, autonomous session)
The safe + fully-oracle-verifiable-NOW RPC queue is exhausted after joinpsbts +
getindexinfo. Every remaining item is blocked on one of:
- **the UTXO rebuild** (in-daemon, ~79% and climbing): scantxoutset, and the
  gettxoutsetinfo parity capstone (txouts/total_amount/MuHash vs oracle at tip).
- **a supervised live-daemon deploy** (mp_ext_area → MAP_SHARED is a runtime
  memory-model change; must not be flipped unsupervised): verbose getrawmempool,
  getmempoolentry/ancestors/descendants, real getmempoolinfo bytes,
  estimatesmartfee. The formatter/iterator can be built + hermetically tested in
  a worktree first, but end-to-end verification needs the deploy.
- **the heavy verify/solver stack** (deliberately kept out of rpc_commands):
  analyzepsbt and verifychain. See the analyzepsbt note below.
- **a wallet / signer** (no oracle to diff against): send*, listtransactions,
  gettransaction, finalizepsbt, walletprocesspsbt, P2TR/multisig PSBT signing.
- **an index we don't build**: getchaintxstats needs cumulative nChainTx (we
  store per-block nTx only); getblockfilter needs blockfilterindex; scanblocks.
- **policy divergence we don't chase**: getdeploymentinfo (script_flags).

### analyzepsbt — LANDED 2026-08-25 (14-vector live diff vs oracle, all match)
Full role machine (updater<signer<finalizer<extractor, psbt next = min over
inputs), missing pubkeys/signatures/redeemscript/witnessscript, fee, and
estimated_vsize/feerate. Non-obvious Core behaviors replicated (each found by
live-diffing, then confirmed in Core source):
- witness_utxo-only + non-witness-resolving script: Core's require_witness_sig
  early-return in SignPSBTInput fires BEFORE out_sigdata is filled, so ALL
  "missing" info is dropped (next=updater, no missing) -- same script via
  non_witness_utxo DOES report missing.
- dummy sig for vsize estimation is 71 bytes (DummySignatureCreator(32,32):
  32+32+7), not 72 -- 2-input P2WPKH vsize is 180 (72 would give 181).
- P2SH-wrapped witness adds the redeem push to scriptSig (P2SH-P2WPKH: 136).
- estimated_feerate uses CFeeRate = floor-toward-neg-inf division (negative
  fee -50000/136vB -> -0.00367648, not truncation's -367647).
DOCUMENTED DIVERGENCE: is_final is presence-of-final-field based; Core re-runs
full script verification on final data (a deliberately corrupt final witness
reads final here, not in Core). Conformant PSBTs match. Taproot inputs and
inner-multisig missing-sets fall to next=updater with no missing (no schnorr
signer / CHECKMULTISIG solver in the RPC path yet).

## Process
One tranche at a time: worktree → implement → hermetic + oracle tests → full
`make test` → merge to main → next. Production deploy stays batched until the
UTXO rebuild completes; then the gettxoutsetinfo parity proof. Update the [ ]
boxes here as each lands.
