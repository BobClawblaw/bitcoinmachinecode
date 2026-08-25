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
- [ ] Flip mp_ext_area to MAP_SHARED + add bitcoin_mempool slot iterator
- [ ] Real getrawmempool (verbose object) from the shared mempool
- [ ] getmempoolinfo real size/bytes/usage

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
      through rpc_chain's full tx_to_json (Core shape). Remaining: combinepsbt,
      finalizepsbt, walletprocesspsbt (wallet), utxoupdatepsbt, joinpsbts.

### T9 — Indexes
- [ ] txindex (global) → getrawtransaction without blockhash; getindexinfo
- [ ] blockfilterindex → getblockfilter (BIP157/158)

### T10 — Networks
- [ ] testnet3/testnet4 + signet chain params, net magic, DNS seeds, RPC ports

## Process
One tranche at a time: worktree → implement → hermetic + oracle tests → full
`make test` → merge to main → next. Production deploy stays batched until the
UTXO rebuild completes; then the gettxoutsetinfo parity proof. Update the [ ]
boxes here as each lands.
