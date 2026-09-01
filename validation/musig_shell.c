/* validation/musig_shell.c -- a line-driven RPC shell over rpc_dispatch() for
 * the MuSig2 Core differential (validation/musig_core_diff.py): one request
 * per stdin line, `METHOD<TAB>PARAMS_JSON`, one reply per stdout line,
 * `OK<TAB>RESULT_JSON` or `ERR<TAB>CODE<TAB>MESSAGE`. The process stays alive
 * across the rounds so the signer's in-memory MuSig2 sessions (secret
 * nonces) survive between the nonce and partial-signature calls, exactly
 * as they do inside the daemon. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../asm/rpc_commands.h"
#include "../asm/rpc_json.h"
int main(void){
    static char line[400000];
    while (fgets(line, sizeof line, stdin)){
        size_t n = strlen(line); while (n && (line[n-1]=='\n' || line[n-1]=='\r')) line[--n] = 0;
        char* tab = strchr(line, '\t'); if (!tab){ printf("ERR\t-32600\tno tab\n"); fflush(stdout); continue; }
        *tab = 0; const char* method = line; const char* pj = tab + 1;
        rj_val* p = rj_parse(pj, strlen(pj)); if (!p){ printf("ERR\t-32700\tparse\n"); fflush(stdout); continue; }
        rj_val* r = NULL; rpc_wallet w; memset(&w, 0, sizeof w); long ec = 0; const char* em = NULL;
        int ok = rpc_dispatch(method, p, &w, &r, &ec, &em);
        if (ok && r){ long len = 0; char* s = rj_write_alloc(r, 0, &len); printf("OK\t%s\n", s ? s : "null"); free(s); }
        else printf("ERR\t%ld\t%s\n", ec, em ? em : "");
        fflush(stdout);
        if (r) rj_free(r); rj_free(p);
    }
    return 0;
}
