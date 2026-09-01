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

/* Attach the undo-data reader (daemon/undo_log.c's undo_replay), so
 * getblockfilter can include the spent-prevout elements BIP158 requires.
 * Without it, filters are refused for every non-genesis block rather than
 * served missing elements. */
/* Attach the snapshot-dump runner (daemon/utxo_setinfo_rpc.c) behind
 * dumptxoutset. */
void rpc_chain_set_utxodump(long (*run)(const char* path,
        int (*hash_at)(long height, unsigned char out[32]),
        long* out_height, unsigned long long* out_coins,
        char* msg, unsigned long mcap));

void rpc_chain_set_undo(long (*replay)(long height,
        int (*cb)(void*, const unsigned char*, unsigned int, unsigned long long,
                  unsigned int, unsigned char, const unsigned char*, unsigned short),
        void*));

/* Core -prune setting (MiB; 0 off, 1 manual) for getblockchaininfo's
 * pruned/automatic_pruning/prune_target_size fields. */
void rpc_chain_set_prune_mib(long mib);

/* getblocktemplate BIP23 proposal evaluation (daemon injects rpc_node's
 * staging helper; NULL => refused as unavailable). fn returns 1 valid /
 * 0 reason filled / -2 decode / -3 timeout / -1 unavailable. */
void rpc_chain_set_proposal(long (*fn)(const char* hex, char* reason, unsigned long rcap));

/* Runtime chain selection (daemon/chainparams.c). Defaults are mainnet;
 * the daemon calls this once after chainparams_select(). `name` must point
 * at storage that outlives the RPC server (chainparams' names are static). */
void rpc_chain_set_chainparams(const char* name, long halving_interval, int pow_no_retargeting,
                               int allow_min_difficulty, unsigned int pow_limit_bits,
                               int enforce_bip94);

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

/* txo-spender index (Core's -txospenderindex): available when txospender.dat
 * exists; lookup answers a CONFIRMED spend of (txid, vout) with the spender's
 * wire txid, height and block hash, optionally copying the spending tx. */
int rpc_chain_txospender_available(void);
int rpc_chain_txospender_lookup(const unsigned char txid_wire[32], unsigned vout, unsigned char spender_wire[32],
                                long* height_out, unsigned char blockhash_wire[32], unsigned char* txout, long txcap, long* txlen_out);
/* ScriptToUniv(include_hex, include_address) + inferred desc, as decoderawtransaction renders a vout */
rj_val* rpc_chain_script_pubkey_json(const unsigned char* sc, unsigned long n);
rj_val* rpc_chain_script_json_noaddr(const unsigned char* sc, unsigned long n);
char* rpc_chain_script_asm(const unsigned char* sc, unsigned long n, int sighash);
/* BIP389 multipath: expansions of a descriptor as public form + checksum (1 when none); 0 with err on a parse error */
int rpc_desc_multipath_expand(const char* in, char (*out)[340], int cap, char* err, unsigned long errcap);
#endif /* RPC_CHAIN_H */
