/* rpc_chain.h -- blockchain-query / node-status JSON-RPC methods served
 * straight off the on-disk block archive (read-only).
 *
 * Why a separate module: bitcoin_rpcd (daemon/bitcoin_rpcd.c) is a STANDALONE
 * process -- it is not hosted inside `bitcoind serve`, so it has no in-memory
 * chain, peer table or mempool. What it CAN see is exactly what an inbound
 * serve child sees: the archive on disk (index.dat + blk*.dat, via
 * bitcoin_store.asm's read path), chainwork.dat, headers.dat. That is enough
 * for every blockchain-query RPC Core exposes, so those live here, opened
 * once from -datadir and re-synced (store_reload) on every request so they
 * track the live daemon's appends. Anything needing live node state
 * (getpeerinfo, getmempoolinfo, sendrawtransaction...) is NOT implemented
 * here and stays "Method not found" -- see FEATURE_GAPS.md.
 *
 * Shapes follow Core v31's src/rpc/blockchain.cpp / rawtransaction.cpp /
 * core_io.cpp field-for-field so a differential harness can diff this node
 * against a scratch bitcoind. Known divergences are listed in rpc_chain.c's
 * header comment.
 */
#ifndef RPC_CHAIN_H
#define RPC_CHAIN_H

#include "rpc_json.h"

/* Open the archive in `dir` (chdir there if non-NULL; pass NULL when the
 * caller already chdir'd, e.g. after bitcoin_rpcd's UTXO-store init). Builds
 * the hash->height index. Returns 1 ok / 0 failure (no index.dat etc.).
 * Until this succeeds every chain method answers -28 "Loading block index...". */
int rpc_chain_open(const char* dir);

/* Core -prune setting (MiB; 0 off, 1 manual) for getblockchaininfo's
 * pruned/automatic_pruning/prune_target_size fields. */
void rpc_chain_set_prune_mib(long mib);

/* What `stop` does after building its reply. Default: SIGTERM to self (the
 * rpcd main loop's handler shuts the server down). Tests install a no-op. */
void rpc_chain_set_stop_handler(void (*fn)(void));

/* Dispatch. Returns 1 handled+ok, 0 handled+error (ec/em filled),
 * -1 "not one of my methods" (caller keeps looking). */
int rpc_chain_dispatch(const char* method, const rj_val* params,
                       rj_val** result, long* ec, const char** em);

/* Is `method` one this module implements? (for rpc_known_method) */
int rpc_chain_known_method(const char* method);

/* Full-tx decoder (Core decoderawtransaction shape). Shared by
 * decoderawtransaction and decodepsbt so both use the getblock-verified
 * tx_to_json output. Returns 1, or 0 with *ec / *em. */
int rpc_chain_decode_rawtx(const unsigned char* tx, long txlen, rj_val** result, long* ec, const char** em);

/* getblocktemplate's view of the shared mempool: same injected hooks struct
 * rpc_node uses (rpc_node.h), plus the sigop-cost fn. All optional -- with
 * nothing injected the template is empty (valid, feeless). */
struct rpc_mempool_hooks_tag;   /* see rpc_node.h's rpc_mempool_hooks */
void rpc_chain_set_mempool(const void* hooks_rpc_mempool, long (*sigop_cost)(const unsigned char*, unsigned long));

/* Pure difficulty-retarget arithmetic (Core pow.cpp CalculateNextWorkRequired
 * incl the /4..x4 clamp and pow-limit cap); exported for hermetic KATs. */
unsigned int rpc_chain_retarget(unsigned int old_bits, long timespan);

#endif /* RPC_CHAIN_H */
