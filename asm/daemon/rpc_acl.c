/* daemon/rpc_acl.c -- see rpc_acl.h. */
#include <stdio.h>
#include <string.h>
#include "rpc_acl.h"
#include "subnet.h"

#define ACL_MAX 64

static subnet_t g_acl[ACL_MAX];
static int      g_n;            /* total entries, base included */
static int      g_configured;   /* entries from -rpcallowip only */

void rpc_acl_reset(void){
    g_n = 0; g_configured = 0;
    /* Core: "always allow IPv4 local subnet" -- note it is 127.0.0.0/8, not
     * /32, so a service bound to 127.0.0.2 still reaches it. Then ::1. */
    if (subnet_parse("127.0.0.0/8", &g_acl[g_n])) g_n++;
    if (subnet_parse("::1", &g_acl[g_n])) g_n++;
}

int rpc_acl_add(const char* spec){
    if (!spec || !*spec || g_n >= ACL_MAX) return 0;
    if (!subnet_parse(spec, &g_acl[g_n])) return 0;
    g_n++; g_configured++;
    return 1;
}

int rpc_acl_configured(void){ return g_configured; }

int rpc_acl_allows(const char* ip){
    if (g_n == 0) rpc_acl_reset();      /* never fail open on an unset list */
    for (int i = 0; i < g_n; i++)
        if (subnet_covers(&g_acl[i], ip)) return 1;
    return 0;
}
