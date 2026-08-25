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

/* Archive access for the wallet rescan: read one block by height (returns
 * its length, or < 81 when unavailable) and the current tip. Same store
 * handle the chain RPCs use -- not a second one over the same files. */
long rpc_chain_read_block_at(long h, unsigned char* buf, long cap);
long rpc_chain_tip_height(void);

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

/* Core's descriptor checksum (the 8 chars after '#') over a descriptor's
 * inner span. Returns 1 and fills out[9] on success, 0 if the span contains
 * a character the checksum alphabet does not cover. Exposed because the
 * wallet-ops module renders descriptors too and must not carry a second,
 * separately-drifting copy of this. */
int rpc_chain_desc_checksum(const char* span, char out[9]);

/* Is `method` one this module implements? (for rpc_known_method) */
int rpc_chain_known_method(const char* method);

/* Enumerate the methods this module serves; NULL past the end. */
const char* rpc_chain_method_at(int i);

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

/* gettxoutsetinfo's injected reader (daemon/utxo_setinfo_rpc.c). The out
 * pointer is rpc_chain.c's rpc_usi_out_t; passed as void* so consumers of
 * this header need no extra types. */
void rpc_chain_set_utxosetinfo(long (*run)(int want_muhash, void* out,
                                           char* msg, unsigned long mcap));

/* scantxoutset's injected whole-set scanner (same reader TU). */
void rpc_chain_set_utxoscan(long (*run)(const unsigned char* spks, const unsigned int* spklens,
                                        int nspk, void* hits, long hits_cap, long* hits_n,
                                        long* out_height, unsigned long long* out_scanned,
                                        unsigned long long* out_total, int* out_overflow,
                                        char* msg, unsigned long mcap));

#endif /* RPC_CHAIN_H */
