/* rpc_esplora.h -- the Esplora facade (2026-09-08): mempool.space's
 * BACKEND "esplora" contract, served from this node's own RPC handlers in
 * process. See rpc_esplora.c. */
#ifndef RPC_ESPLORA_H
#define RPC_ESPLORA_H
#include <stddef.h>
#include "rpc_commands.h"
/* Route one HTTP request. *out is heap (caller frees), *status the HTTP
 * status, *ctype the Content-Type. Always produces a response. */
int esplora_handle(const char* method, size_t mlen, const char* path, size_t plen,
                   const char* body, size_t blen, const rpc_wallet* w,
                   char** out, size_t* outlen, int* status, const char** ctype);
/* the execution lock, taken around each dispatch (rpc_server.c installs it) */
void esplora_set_exec_lock(void (*lock)(void), void (*unlock)(void));
/* the second listener (rpc_server.c): 0 ok, -1 with errmsg */
int rpc_esplora_start(const char* bind_addr, int port, char* errmsg, size_t errcap);
/* pure helpers, exported for tests */
long   esplora_sats_of_amount(const char* dec);                 /* "0.01000000" -> 1000000; -1 on garbage */
size_t esplora_asm_of_hex(const char* hex, char* out, size_t cap); /* mempool's convertScriptSigAsm */
const char* esplora_spk_type(const char* core_type);            /* Core scriptPubKey.type -> esplora */
int esplora_merkle_branch(const unsigned char (*txids)[32], long n, long pos,
                          unsigned char (*branch)[32], long cap);   /* sibling hashes leaf->root; count or -1 */
#endif
