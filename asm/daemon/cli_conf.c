/* daemon/cli_conf.c -- see cli_conf.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cli_conf.h"

int cli_conf_default_rpcport(const char* chain){
    if (!chain || !*chain || !strcmp(chain, "main") || !strcmp(chain, "mainnet"))
        return 8332;
    if (!strcmp(chain, "signet"))   return 38332;
    if (!strcmp(chain, "testnet4")) return 48332;
    if (!strcmp(chain, "regtest"))  return 18443;
    return 0;
}

/* One `key=value` line, trimmed. Comments and [sections] are skipped: a
 * chain-scoped [signet] section is not honoured here, and pretending
 * otherwise would be the same class of bug this file exists to fix. */
static int conf_get(const char* path, const char* key, char* out, long cap){
    FILE* f = fopen(path, "r");
    if (!f) return 0;
    char line[1024];
    int found = 0;
    size_t klen = strlen(key);
    while (fgets(line, sizeof line, f)){
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == ';' || *p == '[' || *p == '\n' || !*p) continue;
        if (strncmp(p, key, klen) != 0) continue;
        char* q = p + klen;
        while (*q == ' ' || *q == '\t') q++;
        if (*q != '=') continue;
        q++;
        while (*q == ' ' || *q == '\t') q++;
        char* e = q + strlen(q);
        while (e > q && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t')) e--;
        *e = 0;
        snprintf(out, (size_t)cap, "%s", q);
        found = 1;                 /* last wins, as the daemon's parser does */
    }
    fclose(f);
    return found;
}

/* The daemon looks in the datadir and then in ../config (node_config.c). */
static int conf_lookup(const char* datadir, const char* key, char* out, long cap){
    char p[512];
    if (!datadir || !*datadir) return 0;
    snprintf(p, sizeof p, "%s/bitcoin.conf", datadir);
    if (conf_get(p, key, out, cap)) return 1;
    snprintf(p, sizeof p, "%s/../config/bitcoin.conf", datadir);
    return conf_get(p, key, out, cap);
}

/* bounded string copy: strnlen+memcpy, so the compiler can see the bound
 * (snprintf("%s") from a larger scratch buffer trips -Wformat-truncation) */
static void cc_copy(char* dst, size_t cap, const char* src){
    size_t l = strnlen(src, cap - 1); memcpy(dst, src, l); dst[l] = 0;
}
static int read_cookie(const char* path, cli_conf_t* c){
    FILE* f = fopen(path, "r");
    if (!f) return 0;
    char buf[512];
    if (!fgets(buf, sizeof buf, f)){ fclose(f); return 0; }
    fclose(f);
    char* nl = strpbrk(buf, "\r\n"); if (nl) *nl = 0;
    char* colon = strchr(buf, ':');
    if (!colon) return 0;
    *colon = 0;
    cc_copy(c->user, sizeof c->user, buf);
    cc_copy(c->pass, sizeof c->pass, colon + 1);
    c->from_cookie = 1;
    return 1;
}

int cli_conf_resolve(const char* datadir, const char* chain_override,
                     cli_conf_t* out, const char** err){
    static const char* dummy;
    if (!err) err = &dummy;
    *err = 0;
    memset(out, 0, sizeof *out);

    char v[512];
    if (chain_override && *chain_override)
        cc_copy(out->chain, sizeof out->chain, chain_override);
    else if (conf_lookup(datadir, "chain", v, sizeof v))
        cc_copy(out->chain, sizeof out->chain, v);
    else
        snprintf(out->chain, sizeof out->chain, "main");

    /* Validate the chain BEFORE the port, and regardless of whether rpcport
     * is set. An unknown chain name still resolves fine when the port and
     * cookie are both explicit -- and reporting nothing there would let a
     * typo ("signett") look like it worked, which is how this whole class of
     * bug survives. */
    if (cli_conf_default_rpcport(out->chain) == 0){
        *err = "unknown chain";
        return 0;
    }
    if (conf_lookup(datadir, "rpcport", v, sizeof v)) out->port = atoi(v);
    if (out->port <= 0) out->port = cli_conf_default_rpcport(out->chain);

    /* A configured user/password wins, exactly as the daemon prefers it. */
    int have_user = conf_lookup(datadir, "rpcuser", v, sizeof v);
    if (have_user) cc_copy(out->user, sizeof out->user, v);
    int have_pass = conf_lookup(datadir, "rpcpassword", v, sizeof v);
    if (have_pass) cc_copy(out->pass, sizeof out->pass, v);
    if (have_user && have_pass) return 1;

    if (!datadir || !*datadir){
        *err = "no -datadir given, so the cookie cannot be found "
               "(pass -datadir=<dir>, or -rpcuser/-rpcpassword)";
        return 0;
    }
    if (conf_lookup(datadir, "rpccookiefile", v, sizeof v))
        snprintf(out->cookie_path, sizeof out->cookie_path, "%s", v);
    else
        snprintf(out->cookie_path, sizeof out->cookie_path, "%s/%s/.cookie", datadir,
                 !strcmp(out->chain, "mainnet") ? "main" : out->chain);   /* every chain in its own subdir, main included */

    if (read_cookie(out->cookie_path, out)) return 1;
    *err = "no rpcuser/rpcpassword and no readable cookie";
    return 0;
}
