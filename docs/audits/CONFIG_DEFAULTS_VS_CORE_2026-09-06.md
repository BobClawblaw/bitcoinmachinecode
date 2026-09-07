# Config defaults vs Bitcoin Core v31.1 — every key, 2026-09-06

Every key this node accepts, compared against Core's default. Core's side comes
from `bitcoind -help-debug` and, where its help states no default, from the
`DEFAULT_*` constant in Core's source. Ours comes from `config/bitcoin.sample.conf`,
which is generated from a compiled `g_cfg` rather than transcribed.

**Rule this audit enforces:** a key named after a Core option carries Core's exact
semantics AND Core's default. Node-specific knobs take the `bmc.` prefix. Any
divergence is discussed before it ships.

## What was wrong (all found by this audit, all fixed)

| key | was | now (Core's) | why it mattered |
|---|---|---|---|
| `blockfilterindex` | 1 | 0 | we built the compact-filter index by default; Core makes it opt-in |
| `coinstatsindex` | 1 | 0 | same: disk and sync time a default Core node never pays |
| `limitancestorcount` | 64 | 25 | **enforced at acceptance here** (`tx_accept.c`), so we accepted chains Core's default refuses |
| `limitdescendantcount` | 64 | 25 | same |
| `debuglogfile` | `logs/bitcoind.log` | `debug.log` | **FIXED.** Core's `DEFAULT_DEBUGLOGFILE` (`logging.cpp:23`) is `debug.log`, resolved against the net-specific datadir. Every chain here has its own directory and the daemon chdir()s into it, so a bare `debug.log` lands in exactly the same place Core's does |
| `pid` | unset (no pid file) | `bitcoind.pid` | Core writes one by default |
| `par` (clamp) | uncapped | 15 workers + caller | Core clamps to `MAX_SCRIPTCHECK_THREADS`; `par=0` gave us 32 threads and Core 16 |

The `par` *semantics* were fixed separately the same day: it had been wired to the
download worker count and the verifier ignored it entirely.

## Every key

| key | ours | Core | verdict |
|---|---|---|---|
| `acceptnonstdtxn` | 0 | (none stated) | match (DEFAULT_ACCEPT_NON_STD_TXN false) |
| `acceptstalefeeestimates` | 0 | (none stated) | match (DEFAULT_ACCEPT_STALE_FEE_ESTIMATES false) |
| `addnode` | _unset_ | (none stated) | no stated Core default; unset here |
| `addresstype` | bech32 | (none stated) | match (DEFAULT_ADDRESS_TYPE BECH32) |
| `addrindex` | 0 | - | **ours only — no Core counterpart** |
| `alertnotify` | _unset_ | (none stated) | no stated Core default; unset here |
| `asmap` | _unset_ | (none stated) | no stated Core default; unset here |
| `assumevalid` | _unset_ | (none stated) | no stated Core default; unset here |
| `avoidpartialspends` | 0 | (none stated) | match (DEFAULT_AVOIDPARTIALSPENDS false) |
| `bantime` | 86400 | 86400 | match |
| `bind` | _unset_ | 0.0.0.0). Use [host]:port notation for I… | match (ours binds 0.0.0.0; Core states it in prose) |
| `blockfilterindex` | 0 | 0 | **FIXED** 1 -> 0 |
| `blockmaxweight` | 4000000 | 4000000 | match |
| `blockmintxfee` | 0.00000001 | 0.00000001 | match |
| `blocknotify` | _unset_ | (none stated) | no stated Core default; unset here |
| `blockreservedweight` | 8000 | 8000 | match |
| `blocksonly` | 0 | 0 | match |
| `blockversion` | 0 | (none stated) | no stated Core default; unset here |
| `bmc.addrmaxpernetgroup` | 16 | - | ours — node-specific, prefixed |
| `bmc.addrmaxperresponse` | 256 | - | ours — node-specific, prefixed |
| `bmc.blockrelayonly` | 2 | - | ours — node-specific, prefixed |
| `bmc.bootcatchup` | 1 | - | ours — node-specific, prefixed |
| `bmc.catchupworkers` | 16 | - | ours — node-specific, prefixed |
| `bmc.feelerinterval` | 120000 | - | ours — node-specific, prefixed |
| `bmc.feelers` | 1 | - | ours — node-specific, prefixed |
| `bmc.maxoutbound` | 8 | - | ours — node-specific, prefixed |
| `bmc.peerminbps` | 32768 | - | ours — node-specific, prefixed |
| `bmc.peerminticks` | 3 | - | ours — node-specific, prefixed |
| `bmc.peerminusable` | 8 | - | ours — node-specific, prefixed |
| `bmc.peerpool` | 2048 | - | ours — node-specific, prefixed |
| `bmc.utxobulkgapblocks` | 50000 | - | ours — node-specific, prefixed |
| `bmc.utxocompactthreshold` | 12 | - | ours — node-specific, prefixed |
| `bytespersigop` | 20 | 20 | match |
| `chain` | main | main | match |
| `changetype` | _unset_ | (none stated) | no stated Core default; unset here |
| `checkblocks` | 6 | 6 | match |
| `checklevel` | 3 | (none stated) | match (DEFAULT_CHECKLEVEL 3) |
| `cjdnsreachable` | 0 | 0 | match |
| `coinstatsindex` | 0 | 0 | **FIXED** 1 -> 0 |
| `connect` | _unset_ | (none stated) | no stated Core default; unset here |
| `consolidatefeerate` | 0.0001 | 0.0001 | match |
| `datacarrier` | 1 | 1 | match |
| `datacarriersize` | 100000 | 100000 | match |
| `dbcache` | 1024 | (none stated) | match (DEFAULT_DB_CACHE 1024; our devlog's "450" is stale) |
| `debuglogfile` | logs/bitcoind.log | debug.log | **FIXED** logs/bitcoind.log -> debug.log (chain dir, as Core) |
| `disablewallet` | 0 | (none stated) | match (DEFAULT_DISABLE_WALLET false) |
| `discardfee` | 0.0001 | 0.0001 | match |
| `discover` | 1 | 1 | match |
| `dns` | 1 | 1 | match |
| `dnsseed` | 1 | 1 | match |
| `dustrelayfee` | 0.00003 | 0.00003 | match |
| `externalip` | _unset_ | (none stated) | no stated Core default; unset here |
| `fallbackfee` | 0 | 0.00 | match (0 == 0.00) |
| `fixedseeds` | 1 | 1 | match |
| `forcednsseed` | 0 | 0 | match |
| `i2pacceptincoming` | 1 | 1 | match |
| `i2psam` | _unset_ | (none stated) | no stated Core default; unset here |
| `inboundrelaypercent` | 50 | (none stated) | match (help: 50) |
| `includeconf` | _unset_ | (none stated) | no stated Core default; unset here |
| `incrementalrelayfee` | 0.000001 | 0.000001 | match |
| `keypool` | 1000 | 1000 | match |
| `limitancestorcount` | 25 | 25 | **FIXED** 64 -> 25 |
| `limitancestorsize` | 101 | - | **ours only — no Core counterpart** |
| `limitclustercount` | 64 | 64 | match |
| `limitclustersize` | 101 | 101 | match |
| `limitdescendantcount` | 25 | 25 | **FIXED** 64 -> 25 |
| `limitdescendantsize` | 101 | - | **ours only — no Core counterpart** |
| `listen` | 1 | 1 | match |
| `listenonion` | 1 | 1 | match |
| `logsourcelocations` | 0 | 0 | match |
| `logthreadnames` | 0 | 0 | match |
| `logtimemicros` | 0 | 0 | match |
| `logtimestamps` | 1 | 1 | match |
| `maxapsfee` | 0 | 0.00 | match (0 == 0.00) |
| `maxconnections` | 200 | 200 | match (200) |
| `maxmempool` | 300 | 300 | match |
| `maxreceivebuffer` | 5000 | 5000 | match |
| `maxsendbuffer` | 1000 | 1000 | match |
| `maxtipage` | 86400 | 86400 | match |
| `maxuploadtarget` | 0 | 0M | match (0 == 0M) |
| `mempoolexpiry` | 336 | 336 | match |
| `mempoolfullrbf` | 1 | - | **ours only — no Core counterpart** |
| `minimumchainwork` | _unset_ | 0000000000000000000000000000000000000001… | match (unset = chain default; boot prints Core's hash) |
| `minrelaytxfee` | 0.000001 | 0.000001 | match |
| `mintxfee` | 0.00001 | 0.00001 | match |
| `networkactive` | 1 | 1 | match |
| `onion` | _unset_ | -proxy | match (unset = follow -proxy) |
| `onlynet` | _unset_ | (none stated) | no stated Core default; unset here |
| `par` | 0 | (none stated) | match (0); **the CLAMP was fixed**: now 15 workers + caller, as Core |
| `peerblockfilters` | 0 | 0 | match |
| `peertimeout` | 60 | (none stated) | match (DEFAULT_PEER_CONNECT_TIMEOUT 60) |
| `permitbaremultisig` | 1 | 1 | match |
| `persistmempool` | 1 | 1 | match |
| `pid` | _unset_ | bitcoind.pid | **FIXED** unset -> bitcoind.pid; then 2026-09-07 **DISCUSSED DIVERGENCE**: `bmcbitcoind.pid`, following the daemon's rename, so nothing we write carries Core's daemon name. Semantics of the key unchanged. |
| `port` | 8333 | 8333 | match |
| `printpriority` | 0 | 0 | match |
| `proxy` | _unset_ | disabled | match (unset = disabled) |
| `proxyrandomize` | 1 | 1 | match |
| `prune` | 0 | 0 | match |
| `regtest` | 0 | (none stated) | no stated Core default; unset here |
| `reindex` | 0 | (none stated) | no stated Core default; unset here |
| `rpcallowip` | _unset_ | (none stated) | no stated Core default; unset here |
| `rpcauth` | _unset_ | (none stated) | no stated Core default; unset here |
| `rpcbind` | _unset_ | 127.0.0.1 and ::1 i.e., localhost | match (unset = localhost) |
| `rpccookiefile` | _unset_ | data dir | match (unset = datadir) |
| `rpccookieperms` | owner | owner | match |
| `rpcpassword` | _unset_ | (none stated) | no stated Core default; unset here |
| `rpcport` | 8332 | 8332 | match |
| `rpcservertimeout` | 30 | 30 | match |
| `rpcthreads` | 16 | 16 | match |
| `rpcuser` | _unset_ | (none stated) | no stated Core default; unset here |
| `rpcwhitelist` | _unset_ | (none stated) | no stated Core default; unset here |
| `rpcwhitelistdefault` | 1 | (none stated) | no stated Core default; unset here |
| `rpcworkqueue` | 64 | 64 | match |
| `seednode` | _unset_ | (none stated) | no stated Core default; unset here |
| `shrinkdebugfile` | 1 | 1 | match |
| `shutdownnotify` | _unset_ | (none stated) | no stated Core default; unset here |
| `signer` | _unset_ | (none stated) | no stated Core default; unset here |
| `signet` | 0 | (none stated) | no stated Core default; unset here |
| `signetchallenge` | _unset_ | (none stated) | no stated Core default; unset here |
| `signetseednode` | _unset_ | (none stated) | no stated Core default; unset here |
| `spendzeroconfchange` | 1 | 1 | match |
| `startupnotify` | _unset_ | (none stated) | no stated Core default; unset here |
| `stopatheight` | 0 | 0 | match |
| `testnet4` | 0 | (none stated) | no stated Core default; unset here |
| `timeout` | 5000 | (none stated) | match (DEFAULT_CONNECT_TIMEOUT 5000) |
| `torcontrol` | 127.0.0.1:9051 | 127.0.0.1:9051 | match |
| `torpassword` | _unset_ | empty | match (unset = empty) |
| `txconfirmtarget` | 6 | 6 | match |
| `txindex` | 0 | 0 | match |
| `txreconciliation` | 0 | 0 | match |
| `uacomment` | _unset_ | (none stated) | no stated Core default; unset here |
| `v2transport` | 1 | 1 | match |
| `wallet` | _unset_ | (none stated) | no stated Core default; unset here |
| `walletbroadcast` | 1 | 1 | match |
| `walletdir` | _unset_ | <datadir>/wallets if it exists, otherwis… | match (unset = datadir) |
| `walletnotify` | _unset_ | (none stated) | no stated Core default; unset here |
| `walletpassfile` | _unset_ | - | **ours only — no Core counterpart** |
| `walletrbf` | 1 | 1 | match |
| `whitebind` | _unset_ | download,noban,mempool,relay | match (unset) |
| `whitelist` | _unset_ | incoming only | match (unset) |
| `whitelistforcerelay` | 0 | 0 | match |
| `whitelistrelay` | 1 | 1 | match |
| `zmqpubhashblock` | _unset_ | (none stated) | no stated Core default; unset here |
| `zmqpubhashblockhwm` | 1000 | 1000 | match |
| `zmqpubhashtx` | _unset_ | (none stated) | no stated Core default; unset here |
| `zmqpubhashtxhwm` | 1000 | 1000 | match |
| `zmqpubrawblock` | _unset_ | (none stated) | no stated Core default; unset here |
| `zmqpubrawblockhwm` | 1000 | 1000 | match |
| `zmqpubrawtx` | _unset_ | (none stated) | no stated Core default; unset here |
| `zmqpubrawtxhwm` | 1000 | 1000 | match |
| `zmqpubsequence` | _unset_ | (none stated) | no stated Core default; unset here |
| `zmqpubsequencehwm` | 1000 | 1000 | match |

## Ours only (no Core counterpart)

`addrindex` and `walletpassfile` are genuine extensions and should arguably carry
the `bmc.` prefix; renaming breaks existing configs, so it is left for a decision.
`limitancestorsize`, `limitdescendantsize` and `mempoolfullrbf` are names Core has
since retired.

## What this audit does NOT prove

It compares DEFAULTS and names. It does not prove that each key's *behaviour*
matches Core's — `par` was the example that started this: the name, the 0/negative
convention and the default all matched Core while the setting drove the wrong
subsystem entirely. A key is only really verified when a test asserts its READER.

## Two behavioural notes this audit turned up (NOT defaults)

- **`rpcwhitelistdefault`** — the sample config listed a default of `1`; the
  effective default is *unset*, and Core derives it: `GetBoolArg(
  "-rpcwhitelistdefault", !GetArgs("-rpcwhitelist").empty())`. Our runtime
  already does exactly that (`rpc_server.c`, `wl_default_effective`), so the
  behaviour matched and only the documentation was wrong. Fixed.
- **`blockversion`** — Core honours `-blockversion` **only on chains with
  `MineBlocksOnDemand()`** (regtest); `node/miner.cpp:148`. This node applies
  it wherever it is set (`rpc_chain.c`, `g_gbt_version`). A mainnet operator
  setting it would change the version this node puts in `getblocktemplate`
  where Core would ignore it. **FIXED 2026-09-06** (PR #57): same predicate as Core,
  read from `g_chainp->pow_no_retargeting`; `test_rpc_chain` pins it.
