/* rpc_wallet_ops.h -- Core's Wallet RPC category beyond the query subset.
 *
 * Chained from rpc_dispatch() exactly like rpc_node/rpc_chain: dispatch
 * returns 1 on success, 0 with ec/em set on an RPC error, and -1 for
 * "not one of my methods, keep looking". See rpc_wallet_ops.c for what is
 * backed by real state, what reproduces Core's answer exactly, and what
 * refuses -- each is marked there.
 */
#ifndef RPC_WALLET_OPS_H
#define RPC_WALLET_OPS_H

#include "rpc_json.h"
#include "rpc_commands.h"

int rpc_wops_known_method(const char* method);

/* Enumerate the methods this module serves; NULL past the end. */
const char* rpc_wops_method_at(int i);
int rpc_wops_dispatch(const char* method, const rj_val* params, const rpc_wallet* w,
                      rj_val** result, long* err_code, const char** err_msg);

/* Output locks (lockunspent/listlockunspent). Process-lifetime, matching
 * Core, whose lock set is in memory and documented as lost on stop. Exposed
 * so a funding path can refuse to spend a locked output. */
int  rpc_wops_is_locked(const unsigned char txid[32], unsigned long vout);

/* Attach the block archive so the wallet rescan can run. BORROWED: the
 * reader, its scratch buffer and the tip function must outlive the RPC
 * server. Without this, rescanblockchain reports that no archive is
 * attached rather than silently scanning nothing. */
void rpc_wops_set_scanner(long (*read_block)(long h, unsigned char* buf, long cap),
                          unsigned char* blockbuf, long bufcap,
                          long (*tip)(void));

/* 1 if this txid was marked abandoned (gettransaction reports it). */
int  rpc_wops_is_abandoned(const char* txid_display);

/* Look one of the wallet's own outputs up by outpoint (from the rescan
 * records), for signrawtransactionwithwallet: BIP143 commits to each
 * input's value and scriptPubKey, and for the wallet's own coins the scan
 * carries both. Fills the value and the key's h160; 0 if unknown. */
int  rpc_wops_own_coin(const void* wallet_seed, const unsigned char txid_wire[32],
                       unsigned int vout, unsigned long long* value_out,
                       unsigned char h160_out[20]);
void rpc_wops_reset_locks(void);

/* ---- the wallet's own unspent outputs, from the rescan records ----------
 * getbalance/listunspent historically answered from the ADDRESS INDEX, an
 * extension that is OFF by default -- so on a default node a fully funded
 * wallet reported 0.00000000 and an empty list while walletscan.dat held
 * every receive. These enumerate the wallet's coins from the scan instead.
 *
 * Spent-ness comes from the scan's own SPEND records: a spend stores the
 * outpoint it consumed as (prev_txid, vout), so a receive is unspent when no
 * spend names it. The live UTXO set would also answer this, but the embedded
 * RPC server holds no handle on it (only the standalone rpcd does), and the
 * download worker writes that store from another process -- casual reads are
 * not safe there. The scan is self-contained and always available.
 *
 * Coinbase maturity uses the per-record flag, which only a format-3 scan
 * carries; wscan_flags_known() says whether the file could answer.
 *
 * Returns the number written (capped at cap), or -1 when no rescan has
 * completed -- which callers must report as an error, never as a zero
 * balance (they are not the same answer). */
typedef struct {
    unsigned char      txid[32];      /* WIRE order */
    unsigned int       vout;
    unsigned long long value;
    unsigned long      height;
    int                is_coinbase;
    unsigned char      h160[20];      /* the wallet key that owns it */
    unsigned char      branch;        /* 0 receive, 1 change */
} rpc_wops_coin;

int rpc_wops_wallet_coins(const void* wallet_seed, rpc_wops_coin* out, int cap);

#endif
