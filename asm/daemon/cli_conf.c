/* daemon/cli_conf.c -- see cli_conf.h. */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "cli_conf.h"

int cli_conf_default_rpcport(const char* chain){
    /* CFG-6 (audit 2026-10-23): Core's chain names; "mainnet" is not one. */
    if (!chain || !strcmp(chain, "main")) return 8332;
    if (!strcmp(chain, "signet"))   return 38332;
    if (!strcmp(chain, "testnet4")) return 48332;
    if (!strcmp(chain, "regtest"))  return 18443;
    return 0;
}

/* ---- CFG-1 (audit 2026-10-23): read the file the way bitcoin-cli does ----
 * bitcoin-cli parses bitcoin.conf with the same ArgsManager as bitcoind
 * (common/config.cpp GetConfigOptions, common/settings.cpp GetSetting):
 * '#' starts a comment; a line is empty, a [section] or key=value, and
 * anything else is an error; a value under [<chain>] beats a base-section
 * one, the FIRST value at a rank wins, and a NETWORK_ONLY option (rpcport)
 * is not read from the base section off mainnet. This reader used to skip
 * [section] lines and keep the LAST value of a key wherever it appeared, so
 * a [regtest] rpcpassword became the mainnet one -- the same section
 * blindness the daemon's own reader had. (node_config.c is the daemon side;
 * bmc_cli does not link it.) */
typedef struct { char* sec; char* key; char* val; } cc_ent;
typedef struct { cc_ent* e; int n, cap; char err[160]; } cc_file;
static void cc_free(cc_file* cf){
    for (int i = 0; i < cf->n; i++){ free(cf->e[i].sec); free(cf->e[i].key); free(cf->e[i].val); }
    free(cf->e); cf->e = 0; cf->n = cf->cap = 0;
}
static int cc_ws(int c){ return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
/* 1 = read (an absent file reads as empty), 0 = a parse error (cf->err). */
static int cc_read(const char* path, cc_file* cf){
    memset(cf, 0, sizeof *cf);
    FILE* f = fopen(path, "r");
    if (!f) return 1;
    char* line = 0; size_t lcap = 0; long lineno = 0;
    char sec[64] = "";
    int ok = 1;
    while (getline(&line, &lcap, f) >= 0){
        lineno++;
        int used_hash = 0;
        char* h = strchr(line, '#'); if (h){ *h = 0; used_hash = 1; }
        char* p = line; while (*p && cc_ws((unsigned char)*p)) p++;
        size_t n = strlen(p); while (n && cc_ws((unsigned char)p[n-1])) p[--n] = 0;
        if (!n) continue;
        if (p[0] == '[' && p[n-1] == ']'){
            p[n-1] = 0;
            /* a name too long for any chain is kept as one that matches none */
            if (strlen(p + 1) >= sizeof sec) snprintf(sec, sizeof sec, "?");
            else snprintf(sec, sizeof sec, "%s", p + 1);
            continue;
        }
        char* eq = (p[0] == '-') ? 0 : strchr(p, '=');
        if (!eq){ snprintf(cf->err, sizeof cf->err, "parse error on line %ld", lineno); ok = 0; break; }
        *eq = 0;
        char* k = p; size_t kl = strlen(k); while (kl && cc_ws((unsigned char)k[kl-1])) k[--kl] = 0;
        char* v = eq + 1; while (*v && cc_ws((unsigned char)*v)) v++;
        if (used_hash && strstr(k, "rpcpassword")){
            snprintf(cf->err, sizeof cf->err,
                     "parse error on line %ld, using # in rpcpassword can be ambiguous and should be avoided", lineno);
            ok = 0; break;
        }
        if (cf->n == cf->cap){
            int nc = cf->cap ? cf->cap * 2 : 32;
            cc_ent* ne = realloc(cf->e, (size_t)nc * sizeof *ne);
            if (!ne){ snprintf(cf->err, sizeof cf->err, "out of memory"); ok = 0; break; }
            cf->e = ne; cf->cap = nc;
        }
        cc_ent* e = &cf->e[cf->n];
        e->sec = strdup(sec); e->key = strdup(k); e->val = strdup(v);
        if (!e->sec || !e->key || !e->val){
            free(e->sec); free(e->key); free(e->val);
            snprintf(cf->err, sizeof cf->err, "out of memory"); ok = 0; break;
        }
        cf->n++;
    }
    free(line);
    fclose(f);
    if (!ok) cc_free(cf);
    return ok;
}
/* Core GetSetting for one single-valued key: the [chain] section's first
 * value, else -- unless the option is NETWORK_ONLY and the chain is not
 * main -- the base section's first value. */
static const char* cc_get(const cc_file* cf, const char* chain, const char* key, int network_only){
    for (int i = 0; i < cf->n; i++)
        if (cf->e[i].sec[0] && !strcmp(cf->e[i].sec, chain) && !strcmp(cf->e[i].key, key)) return cf->e[i].val;
    if (network_only && strcmp(chain, "main")) return 0;
    for (int i = 0; i < cf->n; i++)
        if (!cf->e[i].sec[0] && !strcmp(cf->e[i].key, key)) return cf->e[i].val;
    return 0;
}
/* Core GetChainArg over the base section: the last value of each selector
 * wins, and more than one of them set is an error (NULL, *err set). */
static const char* cc_chain(const cc_file* cf, const char** err){
    const char* chain = 0; int rt = 0, sn = 0, tn = 0, t4 = 0;
    for (int i = 0; i < cf->n; i++){
        if (cf->e[i].sec[0]) continue;
        const char* k = cf->e[i].key; const char* v = cf->e[i].val;
        int neg = k[0] == 'n' && k[1] == 'o'; if (neg) k += 2;
        int b = (!*v || atoi(v) != 0); if (neg) b = !b;   /* Core InterpretBool */
        if (!neg && !strcmp(k, "chain")) chain = v;
        else if (!strcmp(k, "regtest"))  rt = b;
        else if (!strcmp(k, "signet"))   sn = b;
        else if (!strcmp(k, "testnet"))  tn = b;
        else if (!strcmp(k, "testnet4")) t4 = b;
    }
    if ((chain != 0) + rt + sn + tn + t4 > 1){
        *err = "Invalid combination of -regtest, -signet, -testnet, -testnet4 and -chain in the config file";
        return 0;
    }
    return chain ? chain : rt ? "regtest" : sn ? "signet" : tn ? "test" : t4 ? "testnet4" : "main";
}
/* Core ToIntegral<uint16_t>, nonzero: -1 when the value is not a port. */
static int cc_port(const char* v){
    if (!v || !*v) return -1;
    long r = 0;
    for (const char* c = v; *c; c++){
        if (*c < '0' || *c > '9') return -1;
        r = r * 10 + (*c - '0'); if (r > 65535) return -1;
    }
    return r >= 1 ? (int)r : -1;
}

/* Which config file the DAEMON would read for this datadir. It picks exactly
 * one -- $BITCOIN_CONF, else <datadir>/bitcoin.conf when readable, else
 * <datadir>/../config/bitcoin.conf -- and never merges them
 * (node_config.c, node_config_path). This must agree, key for key.
 *
 * It used not to. conf_lookup resolved PER KEY across both files, so a datadir
 * config that set `port` but not `rpcport` left the daemon on its own default
 * while the CLI still read rpcport from ../config. On the live node
 * (2026-09-05) that put the daemon's RPC on 8332 and bmc_cli on 8331, and the
 * CLI could not reach its own node without -rpcport=. Neither side was wrong
 * alone; they disagreed about what a second file means. The daemon matches
 * Core (defaults + one conf), so the CLI is the side that moves. */
static void conf_file_for(const char* datadir, char* out, long cap){
    const char* env = getenv("BITCOIN_CONF");
    if (env && *env){ snprintf(out, (size_t)cap, "%s", env); return; }
    snprintf(out, (size_t)cap, "%s/bitcoin.conf", datadir);
    if (access(out, R_OK) == 0) return;
    snprintf(out, (size_t)cap, "%s/../config/bitcoin.conf", datadir);
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
    static char errbuf[768];
    if (!err) err = &dummy;
    *err = 0;
    memset(out, 0, sizeof *out);

    cc_file cf; memset(&cf, 0, sizeof cf);
    if (datadir && *datadir){
        char p[512];
        conf_file_for(datadir, p, sizeof p);
        if (!cc_read(p, &cf)){
            snprintf(errbuf, sizeof errbuf, "error reading configuration file %s: %s", p, cf.err);
            *err = errbuf;
            return 0;
        }
    }
    int rc = 0;
    if (chain_override && *chain_override)
        cc_copy(out->chain, sizeof out->chain, chain_override);
    else {
        const char* ch = cc_chain(&cf, err);
        if (!ch) goto done;
        cc_copy(out->chain, sizeof out->chain, ch);
    }

    /* Validate the chain BEFORE the port, and regardless of whether rpcport
     * is set. An unknown chain name still resolves fine when the port and
     * cookie are both explicit -- and reporting nothing there would let a
     * typo ("signett") look like it worked, which is how this whole class of
     * bug survives. */
    if (cli_conf_default_rpcport(out->chain) == 0){
        *err = "unknown chain";
        goto done;
    }
    {   const char* v = cc_get(&cf, out->chain, "rpcport", 1);   /* NETWORK_ONLY in Core */
        if (v){
            out->port = cc_port(v);
            if (out->port < 0){ out->port = 0; *err = "Invalid port provided in -rpcport"; goto done; }
        }
        if (out->port <= 0) out->port = cli_conf_default_rpcport(out->chain); }

    /* A configured user/password wins, exactly as the daemon prefers it. */
    {   const char* u  = cc_get(&cf, out->chain, "rpcuser", 0);
        const char* pw = cc_get(&cf, out->chain, "rpcpassword", 0);
        if (u)  cc_copy(out->user, sizeof out->user, u);
        if (pw) cc_copy(out->pass, sizeof out->pass, pw);
        if (u && pw){ rc = 1; goto done; } }

    if (!datadir || !*datadir){
        *err = "no -datadir given, so the cookie cannot be found "
               "(pass -datadir=<dir>, or -rpcuser/-rpcpassword)";
        goto done;
    }
    {   const char* cp = cc_get(&cf, out->chain, "rpccookiefile", 0);
        if (cp) snprintf(out->cookie_path, sizeof out->cookie_path, "%s", cp);
        else    snprintf(out->cookie_path, sizeof out->cookie_path, "%s/%s/.cookie",
                         datadir, out->chain); }   /* every chain in its own subdir, main included */

    if (read_cookie(out->cookie_path, out)){ rc = 1; goto done; }
    *err = "no rpcuser/rpcpassword and no readable cookie";
done:
    cc_free(&cf);
    return rc;
}
