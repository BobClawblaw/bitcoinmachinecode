/* rpc_signer.c -- the external signer interface (Core's -signer / HWI).
 *
 * Core's model: the operator names a signing program with -signer=<cmd>
 * (in practice HWI), and the node shells out to it -- `<cmd> enumerate` to
 * list hardware signers, `<cmd> --fingerprint <fp> displayaddress --desc
 * <descriptor>` to show an address on the device. The program's stdout is
 * JSON. This module does exactly that and nothing more: the OPERATOR chose
 * the command in bitcoin.conf, the node never invents one, and with no
 * signer configured the methods answer with Core's exact error text.
 *
 * ARGUMENT QUOTING is the one sharp edge. The descriptor reaches a shell,
 * and descriptors legitimately contain (), ', # and *. Every argument is
 * therefore single-quoted with embedded single quotes rewritten as '\''
 * (the POSIX idiom), so no descriptor byte is ever interpreted by the
 * shell. The command string itself is the operator's own configuration and
 * is deliberately NOT quoted -- like Core, `signer=hwi --testnet` is a
 * command line, not a path. */

#include "rpc_signer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char g_signer_cmd[512];

void rpc_signer_set_cmd(const char* cmd){
    if (!cmd || !cmd[0]){ g_signer_cmd[0] = 0; return; }
    snprintf(g_signer_cmd, sizeof g_signer_cmd, "%s", cmd);
}
int rpc_signer_configured(void){ return g_signer_cmd[0] != 0; }

/* single-quote `in` for a POSIX shell into out; 0 if it does not fit */
static int sq(const char* in, char* out, unsigned long cap){
    unsigned long o = 0;
    if (o + 1 >= cap) return 0;
    out[o++] = '\'';
    for (const char* p = in; *p; p++){
        if (*p == '\''){
            if (o + 4 >= cap) return 0;
            out[o++]='\''; out[o++]='\\'; out[o++]='\''; out[o++]='\'';
        } else {
            if (o + 1 >= cap) return 0;
            out[o++] = *p;
        }
    }
    if (o + 2 >= cap) return 0;
    out[o++] = '\''; out[o] = 0;
    return 1;
}

/* Run the signer with `args` appended, capture stdout (bounded), parse as
 * JSON. Returns the parsed value (caller rj_free), or NULL with *em set.
 * stderr is left attached to the daemon's own stderr so a signer's
 * diagnostics land in the log rather than vanishing. */
static rj_val* signer_run(const char* args, long* ec, const char** em){
    static char errbuf[256];
    if (!g_signer_cmd[0]){
        *ec = -1; *em = "Error: restart bitcoind with -signer=<cmd>";
        return NULL;
    }
    char cmd[2048];
    if (snprintf(cmd, sizeof cmd, "%s %s", g_signer_cmd, args) >= (int)sizeof cmd){
        *ec = -1; *em = "signer command too long"; return NULL; }
    FILE* p = popen(cmd, "r");
    if (!p){ *ec = -1; *em = "could not run the configured signer"; return NULL; }
    static char out[65536];
    size_t n = fread(out, 1, sizeof out - 1, p);
    out[n] = 0;
    int rc = pclose(p);
    if (rc != 0){
        snprintf(errbuf, sizeof errbuf,
                 "the signer exited with status %d%s%.120s", rc,
                 n ? "; output: " : "", n ? out : "");
        *ec = -1; *em = errbuf;
        return NULL;
    }
    rj_val* v = rj_parse(out, n);
    if (!v){
        snprintf(errbuf, sizeof errbuf,
                 "the signer's output is not JSON: %.180s", out);
        *ec = -1; *em = errbuf;
        return NULL;
    }
    return v;
}

/* enumeratesigners -> {"signers":[{"fingerprint","name"}]}
 * HWI's enumerate emits [{"fingerprint": "...", "model": "...", ...}]. */
int rpc_signer_enumerate(rj_val** res, long* ec, const char** em){
    rj_val* v = signer_run("enumerate", ec, em);
    if (!v) return 0;
    if (v->typ != RJ_ARR){
        rj_free(v);
        *ec = -1; *em = "the signer's enumerate output is not a JSON array";
        return 0;
    }
    rj_val* arr = rj_arr();
    for (size_t i = 0; i < v->nitems; i++){
        rj_val* e = v->items[i];
        if (e->typ != RJ_OBJ) continue;
        rj_val* fp = rj_obj_get(e, "fingerprint");
        if (!fp || fp->typ != RJ_STR) continue;    /* Core requires it too */
        rj_val* o = rj_obj();
        rj_obj_set(o, "fingerprint", rj_str(fp->str));
        rj_val* model = rj_obj_get(e, "model");
        rj_obj_set(o, "name", rj_str(model && model->typ == RJ_STR ? model->str : ""));
        rj_arr_push(arr, o);
    }
    rj_free(v);
    rj_val* o = rj_obj();
    rj_obj_set(o, "signers", arr);
    *res = o;
    return 1;
}

/* walletdisplayaddress: ask the signer to display `desc`; echo the address
 * the SIGNER confirmed, not the one we asked about -- if the device shows a
 * different address than expected the caller must see that. */
int rpc_signer_display(const char* fingerprint, const char* desc,
                       rj_val** res, long* ec, const char** em){
    char qd[1024], qf[136], args[1400];
    if (!sq(desc, qd, sizeof qd)){ *ec = -8; *em = "descriptor too long"; return 0; }
    if (fingerprint && fingerprint[0]){
        if (!sq(fingerprint, qf, sizeof qf)){ *ec = -8; *em = "fingerprint too long"; return 0; }
        snprintf(args, sizeof args, "--fingerprint %s displayaddress --desc %s", qf, qd);
    } else {
        snprintf(args, sizeof args, "displayaddress --desc %s", qd);
    }
    rj_val* v = signer_run(args, ec, em);
    if (!v) return 0;
    rj_val* addr = (v->typ == RJ_OBJ) ? rj_obj_get(v, "address") : NULL;
    if (!addr || addr->typ != RJ_STR){
        rj_free(v);
        *ec = -1; *em = "the signer did not return an address";
        return 0;
    }
    rj_val* o = rj_obj();
    rj_obj_set(o, "address", rj_str(addr->str));
    rj_free(v);
    *res = o;
    return 1;
}
