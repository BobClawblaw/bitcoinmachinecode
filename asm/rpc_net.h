/* rpc_net.h -- JSON-RPC 2.0 framing + HTTP POST transport (bitcoin-cli client)
 *              and a minimal HTTP/1.1 request parser (loopback server stub).
 *
 * This is the "JSON-RPC request/reply framing over a local socket" piece of the
 * bitcoin-cli network layer. It mirrors how Bitcoin Core's bitcoin-cli talks to
 * bitcoind's HTTP JSON-RPC endpoint:
 *
 *   POST / HTTP/1.1
 *   Host: 127.0.0.1:8332
 *   Authorization: Basic <base64(rpcuser:rpcpassword)>
 *   Content-Type: application/json
 *   Content-Length: <n>
 *
 * Request body is a JSON-RPC 2.0 object:
 *   {"jsonrpc":"2.0","id":<id>,"method":"<m>","params":[...]}
 * Reply body:
 *   {"result":...,"error":null,"id":<id>}          (success)
 *   {"result":null,"error":{"code":N,"message":"..."},"id":<id>} (error)
 */
#ifndef RPC_NET_H
#define RPC_NET_H

#include "rpc_json.h"
#include <stddef.h>

/* ---- JSON-RPC reply envelope ---- */
typedef struct {
    rj_val* result;        /* result value (may be null) */
    int     is_error;      /* 1 if "error" is non-null */
    long    error_code;    /* error.code when is_error */
    char*   error_message; /* error.message when is_error (heap) */
    int     has_id;
    long    id;            /* echoed request id */
} rpc_reply;

/* Parse a JSON-RPC 2.0 HTTP reply body. On success returns 1 and fills `r`
 * (caller rpc_reply_free). On malformed envelope returns 0. */
int rpc_reply_parse(const char* body, size_t len, rpc_reply* r);
void rpc_reply_free(rpc_reply* r);

/* ---- HTTP POST client over a TCP socket ----
 * Connect to 127.0.0.1:port, POST the JSON-RPC body with Basic auth
 * (user:pass), read the full HTTP reply, and return the reply BODY (without
 * HTTP headers) into out/outcap. Returns length >0 on success, 0 on transport
 * error (-1 fills errmsg with reason). */
long rpc_http_post(int port, const char* user, const char* pass,
                   const char* body, long bodylen,
                   char* out, long outcap, char* errmsg, size_t errcap);

/* Build a JSON-RPC 2.0 request object for method + params array.
 * Returns heap request value; caller rj_free. id = request sequence. */
rj_val* rpc_request_build(const char* method, rj_val* params, long id);

/* ---- minimal HTTP/1.1 request parser (loopback server stub) ----
 * Given raw bytes of one HTTP request, return 1 and fill method/path/body
 * (pointers into buf, not copies). Returns 0 if incomplete/malformed. */
int http_request_parse(const char* buf, size_t len,
                       const char** method, size_t* method_len,
                       const char** path, size_t* path_len,
                       const char** body, size_t* body_len);

#endif /* RPC_NET_H */
