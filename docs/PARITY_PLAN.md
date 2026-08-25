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
- [ ] getblocktemplate (BIP22/23) — large; diff structure vs oracle
- [ ] submitblock, prioritisetransaction

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
- [ ] estimatesmartfee / estimaterawfee from mempool feerate buckets + recent blocks

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
