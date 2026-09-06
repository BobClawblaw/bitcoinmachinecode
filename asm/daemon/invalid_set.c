#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "invalid_set.h"
static unsigned char g_h[INVSET_MAX][32]; static long g_n = 0;
long invset_count(void){ return g_n; }
void invset_clear(void){ g_n = 0; }
int invset_has(const unsigned char h[32]){ for (long i = 0; i < g_n; i++) if (!memcmp(g_h[i], h, 32)) return 1; return 0; }
int invset_add(const unsigned char h[32]){ if (invset_has(h)) return 0; if (g_n >= INVSET_MAX) return -1; memcpy(g_h[g_n++], h, 32); return 1; }
int invset_remove(const unsigned char h[32]){
    for (long i = 0; i < g_n; i++) if (!memcmp(g_h[i], h, 32)){ memmove(g_h[i], g_h[i+1], (size_t)(g_n - i - 1) * 32); g_n--; return 1; }
    return 0;
}
long invset_load(const char* path){
    g_n = 0; FILE* f = fopen(path, "rb"); if (!f) return 0;
    unsigned char buf[INVSET_MAX * 32 + 32]; long len = (long)fread(buf, 1, sizeof buf, f); fclose(f);
    if (len < 0 || len % 32 != 0 || len > INVSET_MAX * 32) return -1;
    for (long o = 0; o < len; o += 32) invset_add(buf + o);
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
