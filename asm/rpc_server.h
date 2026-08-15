/* rpc_server.h -- HTTP JSON-RPC 2.0 server endpoint (daemon side).
 *
 * The production counterpart to the bitcoin-cli client card (t_8e5be37f).
 * Where the client POSTs JSON-RPC requests over a loopback socket, this module
 * LISTENS on a TCP port, authenticates (HTTP Basic rpcuser/rpcpassword per
 * Bitcoin Core), parses a JSON-RPC 2.0 request, routes it through the SAME
 * rpc_dispatch() used client-side, and writes back a Core-bit-exact JSON-RPC
 * reply envelope.
 *
 * Response behavior mirrors Bitcoin Core's src/httprpc.cpp exactly:
 *
 *   - non-POST method            -> 405, body "JSONRPC server handles only POST requests"
 *   - missing / wrong auth       -> 401 + WWW-Authenticate: Basic realm="jsonrpc"
 *   - body not parseable JSON    -> -32700 "Parse error", HTTP 500 (version unknown)
 *   - request not an object      -> -32600 "Invalid Request object"
 *   - invalid/missing method     -> -32600 "Method must be a string" etc.
 *     (all -32600 -> HTTP 400, -32601 -> HTTP 404 -- V1 mapping only)
 *   - JSON-RPC 2.0 request       -> errors are caught and returned as HTTP 200
 *                                   with the V2 envelope (jsonrpc field, only
 *                                   result OR error, id echoed)
 *   - V2 notification (no id)    -> executed but HTTP 204, no body
 *
 * V2 reply envelope (JSONRPCReplyObj V2):
 *   success: {"jsonrpc":"2.0","result":...,"id":<id>}
 *   error:   {"jsonrpc":"2.0","error":{"code":N,"message":"..."},"id":<id>}
 * V1/legacy reply (no jsonrpc field, both result and error present):
 *   success: {"result":...,"error":null,"id":<id>}
 */
#ifndef RPC_SERVER_H
#define RPC_SERVER_H

#include "rpc_commands.h"

/* Server configuration. */
typedef struct {
    int  port;                  /* listen port; 0 = ephemeral (fill actual) */
    const char* user;           /* rpcuser */
    const char* pass;           /* rpcpassword */
    const rpc_wallet* wallet;   /* wallet state the requests resolve against */
} rpc_server_cfg;

/* Start the HTTP JSON-RPC server: bind+listen on loopback, spawn an accept
 * thread, and serve connections until rpc_server_stop(). `wallet` must outlive
 * the server. On success returns 0 and sets *actual_port to the bound port
 * (useful when cfg->port==0). On bind failure returns -1 and fills errmsg. */
int rpc_server_start(const rpc_server_cfg* cfg, int* actual_port,
                     char* errmsg, size_t errcap);

/* Stop the server and join its accept thread. Safe to call once. */
void rpc_server_stop(void);

#endif /* RPC_SERVER_H */
