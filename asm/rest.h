#ifndef BMC_REST_H
#define BMC_REST_H
/* Bitcoin Core's REST interface (rest=1): the /rest/ routes of src/rest.cpp,
 * served on the JSON-RPC listener without authentication, answered from
 * the node's own RPC handlers. See docs/RPC_LIVE_NODE.md. */
#include <stddef.h>
#include "rpc_commands.h"
int rest_handle(const char* method, size_t mlen, const char* path, size_t plen,
                const char* body, size_t blen, const rpc_wallet* w,
                char** out, size_t* outlen, int* status, const char** ctype);
void rest_set_exec_lock(void (*lock)(void), void (*unlock)(void));
int  rest_is_path(const char* path, size_t plen);           /* "/rest/..." */
#endif
