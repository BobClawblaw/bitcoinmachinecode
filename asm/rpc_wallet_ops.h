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
void rpc_wops_reset_locks(void);

#endif
