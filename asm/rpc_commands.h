/* rpc_commands.h -- shared JSON-RPC command dispatch + Core-bit-exact rendering.
 *
 * Bridges the in-scope wallet-core command layer (asm/wallet_core.c, built +
 * green by cards t_wrpc_getaddr..t_wrpc_send) onto JSON-RPC. Given a parsed
 * request (method + params) and a wallet-state struct, produces a Core-shaped
 * `result` UniValue exactly as bitcoind would for that method.
 *
 * The child card (HTTP JSON-RPC server endpoint) dispatches through the same
 * rpc_dispatch() function, so the client-side rendering here and the server do
 * not diverge -- one render path, bit-identical on both ends.
 */
#ifndef RPC_COMMANDS_H
#define RPC_COMMANDS_H

#include "rpc_json.h"

/* Wallet state a request is resolved against. Not owned/freed here; the caller
 * (client harness or HTTP server) supplies it. */
typedef struct {
    const unsigned char* seed;      /* 64-byte BIP32 seed (deterministic wallet) */

    /* the wallet's own unspent outputs (for listunspent/getbalance/sendtoaddr) */
    const unsigned char (*utxo_txid)[32];
    const unsigned long* utxo_idx;
    const unsigned long long* utxo_val;
    const unsigned char* const* utxo_script; /* scriptPubKey hex strings */
    unsigned long utxo_n;
} rpc_wallet;

/* Amount (satoshis) -> Core ValueFromAmount string, exactly:
 *   sign? "-" then quotient "." 8-zero-padded remainder. Returns into a
 *   caller buffer at least 24 bytes. */
void rpc_amounts(long long sats, char* out, size_t outcap);

/* The inverse: a Core BTC amount string -> satoshis, or -1 if malformed.
 * Shared so the spend path cannot round differently from the renderer. */
long long rpc_amount_to_sat(const char* s);

/* Dispatch one JSON-RPC method with params. Builds a `result` value into
 * *result (heap; caller rj_free) on success (returns 1) or fills *err_code /
 * *err_msg (static string, no free) and returns 0 on an RPC error. */
int rpc_dispatch(const char* method, const rj_val* params,
                 const rpc_wallet* w,
                 rj_val** result, long* err_code, const char** err_msg);

/* Parse a JSON-RPC param array element as a string; on error sets err. */
const char* rpc_param_str(const rj_val* params, size_t i,
                          long* err_code, const char** err_msg);

/* Parse a JSON-RPC param array element as a 64-bit number (strict integer).
 * Core JSON numbers here are integral amounts (no floats). */
int rpc_param_i64(const rj_val* params, size_t i, long long* out,
                  long* err_code, const char** err_msg);

/* Human + machine model: is `method` a wallet command we dispatch? */
int rpc_known_method(const char* method);

/* Enumerate the wallet/util subset this module dispatches itself; NULL past
 * the end. `help` merges this with the other modules' tables. */
const char* rpc_wallet_method_at(int i);

/* Long-lived UTXO LSM store handle backing gettxout (real Bitcoin Core
 * semantics: any confirmed outpoint, not wallet-scoped) and, once the
 * address index lands, listunspent/getbalance. Deliberately a SEPARATE
 * handle from rpc_wallet, which stays scoped to the wallet's own known
 * outputs per its existing doc comment -- this isn't wallet data.
 * `lst`/`u` are opaque here (bitcoin_utxo_lsm.asm's struct lsm_state and
 * the in-memory UTXO table); only the caller that builds them (bitcoin_
 * rpcd.c) needs the concrete layout. Pass NULL/NULL to say "not
 * configured" (gettxout then reports every outpoint as not found, same
 * as an RPC server with no chain data). Safe with no locking: rpc_
 * server.c's server_thread is a single accept()->service_conn() loop,
 * never fork/thread-per-connection. */
void rpc_commands_set_utxo_store(void* lst, void* u);

/* Long-lived, read-only scriptPubKey(hash)->UTXO reverse index handle
 * backing listunspent/getbalance (asm/daemon/build_addr_index.c). `base`
 * should be an mmap()'d, read-only view of the whole index file (see that
 * tool's own header comment for the on-disk format); `size` its byte
 * length. Pass NULL/0 to say "not configured" (listunspent/getbalance
 * then behave as if the resolved address owns nothing). This is a
 * periodically-*rebuilt* index, not incrementally live-maintained, so it
 * only reflects whatever the index file held as of when the caller mmap'd
 * it -- restart/remap to pick up a freshly rebuilt file. */
void rpc_commands_set_addr_index(const void* base, unsigned long long size);

#endif /* RPC_COMMANDS_H */
