#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "invalid_set.h"
/* CON-11 (audit 2026-10-23): the set GROWS. It was a fixed 64 entries, and
 * the 65th mark -- an operator's invalidateblock or the connect path's
 * automatic rejection (utxo_live's reject hook) -- was refused, leaving the
 * node halted below a block it knew to be invalid. Core's block index keeps
 * a failed flag on every block, without limit. Lookups stay linear: the set
 * holds operator marks and the rare invalid block a miner produces. */
static unsigned char (*g_h)[32] = 0; static long g_n = 0, g_cap = 0;
long invset_count(void){ return g_n; }
void invset_clear(void){ g_n = 0; }
int invset_has(const unsigned char h[32]){ for (long i = 0; i < g_n; i++) if (!memcmp(g_h[i], h, 32)) return 1; return 0; }
int invset_add(const unsigned char h[32]){
    if (invset_has(h)) return 0;
    if (g_n >= g_cap){
        long nc = g_cap ? g_cap * 2 : 64;
        unsigned char (*q)[32] = realloc(g_h, (size_t)nc * 32);
        if (!q) return -1;                                  /* out of memory: the only refusal left */
        g_h = q; g_cap = nc;
    }
    memcpy(g_h[g_n++], h, 32); return 1;
}
int invset_remove(const unsigned char h[32]){
    for (long i = 0; i < g_n; i++) if (!memcmp(g_h[i], h, 32)){ memmove(g_h[i], g_h[i+1], (size_t)(g_n - i - 1) * 32); g_n--; return 1; }
    return 0;
}
long invset_load(const char* path){
    g_n = 0; FILE* f = fopen(path, "rb"); if (!f) return 0;
    unsigned char rec[32]; size_t got;
    while ((got = fread(rec, 1, 32, f)) == 32){
        if (invset_add(rec) < 0){ fclose(f); g_n = 0; return -1; }
    }
    int bad = got != 0 || ferror(f);                        /* a trailing partial record: not ours */
    fclose(f);
    if (bad){ g_n = 0; return -1; }
    return g_n;
}
long invset_save(const char* path){
    char tmp[512]; snprintf(tmp, sizeof tmp, "%s.tmp", path);
    if (g_n == 0){ unlink(path); unlink(tmp); return 0; }
    FILE* f = fopen(tmp, "wb"); if (!f) return -1;
    long ok = fwrite(g_h, 32, (size_t)g_n, f) == (size_t)g_n; fclose(f);
    if (!ok || rename(tmp, path) != 0){ unlink(tmp); return -1; }
    return 0;
}
