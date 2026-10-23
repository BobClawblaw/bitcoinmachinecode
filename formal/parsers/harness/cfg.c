/* P-CFG: the line-level parsers of the configuration file
 * (daemon/node_config.c): cfg_classify (every line), cfg_split_host_port
 * (rpcbind / bind / proxy / onion values, CFG-5), cfg_port, cfg_addlist
 * (addnode / connect / seednode) and nodecfg_hex32_be (minimumchainwork,
 * assumevalid). The file is the operator's, but it may be a Core
 * bitcoin.conf copied in; lines are NUL-terminated strings of
 * nondeterministic bytes, length <= FP_N (FP_HEX: <= 70 for the hex reader).
 * Claims: memory safety; classify's key/value pointers lie inside the line and
 * are NUL-terminated there; split_host_port writes a NUL-terminated host of
 * < hcap bytes and a port in 1..65535 (or 0); addlist never exceeds
 * CFG_MAX_NODES entries or 63-byte hosts; hex32_be writes exactly 32 bytes. */
#include <stdlib.h>
#include <string.h>
#include "nd.h"
#include SRC
#ifndef FP_N
#define FP_N 8
#endif
static char* nd_str(size_t max){ size_t n = nondet_size(); ASSUME(n <= max); char* s = (char*)nd_buf(n + 1); s[n] = 0; return s; }
int main(void){
    int mode = nondet_int();
#ifdef FP_HEX
    char* s = nd_str(70); unsigned char out[32];
    int r = nodecfg_hex32_be(s, out);
    if (r){   /* Core's nMinimumChainWork is a uint256: at most 64 hex digits */
        const char* q = s; while (*q == ' ' || *q == '\t') q++;
        if (q[0] == '0' && (q[1] == 'x' || q[1] == 'X')) q += 2;
        size_t d = 0; while (q[d] && q[d] != ' ' && q[d] != '\t' && q[d] != '\r' && q[d] != '\n') d++;
        CHECK(d >= 1 && d <= 64, "an accepted value has 1..64 hex digits");
    }
    COVER(r && strlen(s) >= 64, "a 64-digit value");
    free(s); (void)mode; return 0;
#else
    char* s = nd_str(FP_N); size_t L = strlen(s);
    if (mode == 0){
        char *k = 0, *v = 0; int t = cfg_classify(s, &k, &v);
        if (t == CL_KV){ CHECK(k >= s && k <= s + L && v >= s && v <= s + L, "key and value inside the line"); CHECK(strlen(k) <= L && strlen(v) <= L, "terminated inside"); }
        if (t == CL_SECTION) CHECK(k >= s && k <= s + L, "section name inside");
        COVER(t == CL_KV && *k && *v, "a key=value line");
        COVER(t == CL_SECTION, "a section");
    } else if (mode == 1){
        size_t hcap = nondet_size(); ASSUME(hcap >= 1 && hcap <= 6);
        char* host = (char*)nd_buf(hcap); int port;
        int r = cfg_split_host_port(s, host, hcap, &port);
        if (r){ CHECK(memchr(host, 0, hcap) != 0, "host terminated within hcap"); CHECK(port == 0 || (port >= 1 && port <= 65535), "port range"); }
        COVER(r && port > 0, "host:port split");
        free(host);
    } else {
        static char list[CFG_MAX_NODES][64]; static unsigned short ports[CFG_MAX_NODES]; int n = nondet_int(), bad = 0;
        ASSUME(n >= CFG_MAX_NODES - 1 && n <= CFG_MAX_NODES);
        for (int i = 0; i < CFG_MAX_NODES; i++) list[i][0] = 0;
        int r = cfg_addlist(list, ports, &n, s, "addnode", &bad);
        CHECK(n <= CFG_MAX_NODES, "list within CFG_MAX_NODES");
        if (r) CHECK(memchr(list[n-1], 0, 64) != 0, "host terminated");
        COVER(r, "an entry added");
    }
    free(s);
    return 0;
#endif
}
