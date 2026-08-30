/* daemon/bitcoin_cli.c -- the bitcoin-cli network-layer client.
 *
 * Bit-for-bit behaves like Bitcoin Core's bitcoin-cli against a local
 * HTTP JSON-RPC endpoint:
 *
 *   usage:
 *     bitcoin_cli [-rpcport=<p>] [-rpcconnect=<host>] [-rpcuser=<u>]
 *                 [-rpcpassword=<p>] <method> [param...]
 *     bitcoin_cli getblockchaininfo | getnewaddress | getbalance | ...
 *
 * It frames a JSON-RPC 2.0 request, POSTs it over a local socket with HTTP
 * Basic auth, parses the reply and renders it exactly as bitcoin-cli does:
 *   - a string `result` is printed raw (no quotes),
 *   - anything else is printed with Core's write(2) pretty format,
 *   - an RPC error prints `error code: <n>` + `error message: <m>` to stderr
 *     and exits non-zero.
 *
 * Wrapper around rpc_net.c (wire/framing) + rpc_commands.c (dispatch/render),
 * which together are the client-side of the RPC-transport OPEN item.
 */
#include "../rpc_net.h"
#include "cli_conf.h"
#include "../rpc_commands.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Overrides win over anything discovered; 0/NULL means "not given". */
static const char* g_rpcuser  = 0;
static const char* g_rpcpass  = 0;
static int         g_rpcport  = 0;
static const char* g_datadir  = 0;
static const char* g_chain    = 0;

static int parse_args(int argc, char** argv, int* start) {
    int i = 1;
    while (i < argc && argv[i][0] == '-') {
        const char* a = argv[i];
        if (!strncmp(a, "-rpcport=", 9)) g_rpcport = atoi(a + 9);
        else if (!strncmp(a, "-rpcuser=", 9)) g_rpcuser = a + 9;
        else if (!strncmp(a, "-rpcpassword=", 13)) g_rpcpass = a + 13;
        else if (!strncmp(a, "-datadir=", 9)) g_datadir = a + 9;
        else if (!strncmp(a, "-chain=", 7)) g_chain = a + 7;
        else if (!strcmp(a, "-signet"))   g_chain = "signet";
        else if (!strcmp(a, "-testnet4")) g_chain = "testnet4";
        else if (!strcmp(a, "-regtest"))  g_chain = "regtest";
        else if (!strncmp(a, "-rpcconnect=", 12)) { /* only loopback supported; accept + ignore host */ }
        /* bitcoin-cli ignores unknown -flags with a warning; keep it lenient. */
        i++;
    }
    *start = i;
    return i;
}

int main(int argc, char** argv) {
    int argi;
    parse_args(argc, argv, &argi);
    if (argi >= argc) {
        fprintf(stderr,
            "Bitcoin Core RPC client\n\n"
            "usage: bitcoin_cli [-datadir=<dir>] [-chain=<c>|-signet|-testnet4|-regtest]\n"
            "                   [-rpcport=<n>] [-rpcuser=<u>] [-rpcpassword=<p>]\n"
            "                   <method> [params...]\n\n"
            "With -datadir the port and credentials come from that datadir's\n"
            "bitcoin.conf and .cookie, so no flags are usually needed.\n\n"
            "commands: getnewaddress getrawchangeaddress getaddressinfo validateaddress\n"
            "          listunspent gettxout getbalance decoderawtransaction\n");
        return 1;
    }
    /* Resolve the endpoint from the datadir's config and cookie, exactly the
     * way the daemon wrote them. Explicit flags still win. */
    cli_conf_t conf;
    const char* cerr = 0;
    int have = cli_conf_resolve(g_datadir, g_chain, &conf, &cerr);
    if (g_rpcport > 0) conf.port = g_rpcport;
    if (g_rpcuser) { snprintf(conf.user, sizeof conf.user, "%s", g_rpcuser); have = 1; }
    if (g_rpcpass) { snprintf(conf.pass, sizeof conf.pass, "%s", g_rpcpass); }
    if (!have && !(g_rpcuser && g_rpcpass)) {
        fprintf(stderr, "error: no credentials -- %s\n", cerr ? cerr : "?");
        if (conf.cookie_path[0])
            fprintf(stderr, "       looked for a cookie at %s\n", conf.cookie_path);
        fprintf(stderr, "       pass -datadir=<dir>, or -rpcuser=/-rpcpassword=\n");
        return 1;
    }
    g_rpcport = conf.port;
    g_rpcuser = conf.user;
    g_rpcpass = conf.pass;

    const char* method = argv[argi];

    /* Build params array from remaining args: strings stay strings, numeric-
     * looking args become JSON numbers (matching bitcoin-cli's RPCConvertValues
     * heuristic for the commands that take numbers on the wire). */
    rj_val* params = rj_arr();
    for (int i = argi + 1; i < argc; i++) {
        const char* s = argv[i];
        int numeric = (*s == '-' || (*s >= '0' && *s <= '9'));
        if (numeric) { for (const char* p = s + (s[0] == '-'); *p; p++) if (*p < '0' || *p > '9') { numeric = 0; break; } }
        rj_arr_push(params, numeric ? (rj_val*)rj_numf("%s", s) : (rj_val*)rj_str(s));
    }

    rj_val* req = rpc_request_build(method, params, 1);
    char body[32768];
    long bodylen = rj_write(body, sizeof body, req, 0);
    rj_free(req);

    char resp[65536];
    char errmsg[256];
    long blen = rpc_http_post(g_rpcport, g_rpcuser, g_rpcpass, body, bodylen,
                              resp, sizeof resp, errmsg, sizeof errmsg);
    if (blen < 0) {
        fprintf(stderr, "error: %s\n", errmsg);
        return 1;
    }

    rpc_reply r;
    if (!rpc_reply_parse(resp, (size_t)blen, &r)) {
        fprintf(stderr, "error: malformed JSON-RPC reply\n");
        return 1;
    }

    if (r.is_error) {
        fprintf(stderr, "error code: %ld\n", r.error_code);
        fprintf(stderr, "error message:\n%s\n", r.error_message ? r.error_message : "");
        rpc_reply_free(&r);
        return 1;
    }

    /* Render as bitcoin-cli does. */
    if (r.result && r.result->typ == RJ_STR) {
        printf("%s\n", r.result->str);
    } else if (r.result && r.result->typ == RJ_NULL) {
        /* null result -> bitcoin-cli prints nothing */
    } else if (r.result) {
        char out[65536];
        long n = rj_write(out, sizeof out, r.result, 2); /* Core write(2) */
        if (n >= 0) printf("%s\n", out);
    }
    rpc_reply_free(&r);
    return 0;
}
