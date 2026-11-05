/* daemon/hdr_tree.c -- see hdr_tree.h */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "hdr_tree.h"
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern long chainwork_cmp(const unsigned char a[16], const unsigned char b[16]);
typedef struct { unsigned char hash[32], prev[32]; long height; unsigned bits; unsigned char work[16];
                 unsigned ntx, flags; unsigned char hdr[80]; } ent_t;
static ent_t* g_e; static long g_n, g_cap; static int g_loaded;
static void pack(unsigned char* r, const ent_t* e){
    memset(r, 0, HDRTREE_REC); memcpy(r, e->hash, 32); memcpy(r + 32, e->prev, 32); memcpy(r + HDRTREE_OFF_HEIGHT, &e->height, 8);
    memcpy(r + 72, &e->bits, 4); memcpy(r + HDRTREE_OFF_WORK, e->work, 16); memcpy(r + HDRTREE_OFF_NTX, &e->ntx, 4);
    memcpy(r + HDRTREE_OFF_FLAGS, &e->flags, 4); memcpy(r + HDRTREE_OFF_HDR, e->hdr, 80);
}
/* a version-1 record is the first 92 bytes of a version-2 one: no nTx, no header */
static void unpack(ent_t* e, const unsigned char* r, int v2){
    memset(e, 0, sizeof *e);
    memcpy(e->hash, r, 32); memcpy(e->prev, r + 32, 32); memcpy(&e->height, r + HDRTREE_OFF_HEIGHT, 8);
    memcpy(&e->bits, r + 72, 4); memcpy(e->work, r + HDRTREE_OFF_WORK, 16);
    if (v2){ memcpy(&e->ntx, r + HDRTREE_OFF_NTX, 4); memcpy(&e->flags, r + HDRTREE_OFF_FLAGS, 4); memcpy(e->hdr, r + HDRTREE_OFF_HDR, 80); }
}
static int reserve(long n){ if (n <= g_cap) return 1; long c = g_cap ? g_cap * 2 : 256; while (c < n) c *= 2; ent_t* p = realloc(g_e, (size_t)c * sizeof *p); if (!p) return 0; g_e = p; g_cap = c; return 1; }
static long find(const unsigned char hash[32]){ for (long i = 0; i < g_n; i++) if (!memcmp(g_e[i].hash, hash, 32)) return i; return -1; }
static int rewrite(void){
    char tmp[64]; snprintf(tmp, sizeof tmp, "%s.tmp", HDRTREE_FILE);
    FILE* f = fopen(tmp, "wb"); if (!f) return 0;
    unsigned char r[HDRTREE_REC]; for (long i = 0; i < g_n; i++){ pack(r, &g_e[i]); if (fwrite(r, 1, HDRTREE_REC, f) != HDRTREE_REC){ fclose(f); return 0; } }
    fflush(f); fsync(fileno(f)); fclose(f); return rename(tmp, HDRTREE_FILE) == 0;
}
/* -1 when the file does not exist */
static long load(const char* path, int v2){
    FILE* f = fopen(path, "rb"); if (!f) return -1;
    size_t rs = v2 ? HDRTREE_REC : HDRTREE_REC_V1;
    unsigned char r[HDRTREE_REC];
    while (fread(r, 1, rs, f) == rs && g_n < HDRTREE_MAX){ if (!reserve(g_n + 1)) break; unpack(&g_e[g_n], r, v2); g_n++; }
    fclose(f); return g_n;
}
int hdrtree_open(void){
    g_n = 0; g_loaded = 1;
    if (load(HDRTREE_FILE, 1) >= 0) return 1;
    /* a version-1 file: read once, rewrite as version 2, keep the old one aside */
    if (load(HDRTREE_FILE_V1, 0) >= 0 && rewrite()){
        char aside[64]; snprintf(aside, sizeof aside, "%s.v1", HDRTREE_FILE_V1);
        if (rename(HDRTREE_FILE_V1, aside) != 0) fprintf(stderr, "[hdrtree] could not move %s aside\n", HDRTREE_FILE_V1);
        fprintf(stderr, "[hdrtree] %ld version-1 entr%s rewritten to %s (no headers to serve for those)\n", g_n, g_n == 1 ? "y" : "ies", HDRTREE_FILE);
    }
    return 1;
}
long hdrtree_count(void){ return g_n; }
int hdrtree_has(const unsigned char hash[32]){ return find(hash) >= 0; }
int hdrtree_get(const unsigned char hash[32], unsigned char prev[32], long* height, unsigned char work[16]){
    long i = find(hash); if (i < 0) return 0;
    if (prev) memcpy(prev, g_e[i].prev, 32);
    if (height) *height = g_e[i].height;
    if (work) memcpy(work, g_e[i].work, 16);
    return 1;
}
static int is_tip(long i){ for (long k = 0; k < g_n; k++) if (k != i && !memcmp(g_e[k].prev, g_e[i].hash, 32)) return 0; return 1; }
static void fill(ent_t* e, const unsigned char h[32], const unsigned char hdr80[80], long height, const unsigned char work[16], unsigned ntx){
    memset(e, 0, sizeof *e);
    memcpy(e->hash, h, 32); memcpy(e->prev, hdr80 + 4, 32); e->height = height; memcpy(&e->bits, hdr80 + 72, 4); memcpy(e->work, work, 16);
    e->ntx = ntx; e->flags = HDRTREE_HAVE_HDR; memcpy(e->hdr, hdr80, 80);
}
int hdrtree_add_ntx(const unsigned char hdr80[80], long height, const unsigned char work[16], unsigned ntx){
    if (!g_loaded) hdrtree_open();
    unsigned char h[32]; block_hash(h, hdr80);
    long at = find(h);
    if (at >= 0){
        /* known: fill in what the record lacked (a version-1 entry has no
         * header; a candidate's header was retained before its block) */
        ent_t* e = &g_e[at];
        if (!(e->flags & HDRTREE_HAVE_HDR) || (!e->ntx && ntx)){
            memcpy(e->hdr, hdr80, 80); e->flags |= HDRTREE_HAVE_HDR; if (ntx) e->ntx = ntx;
            rewrite();
        }
        return 0;
    }
    if (g_n >= HDRTREE_MAX){
        /* full: evict the lightest TIP (a branch's end, never its middle) */
        long victim = -1;
        for (long i = 0; i < g_n; i++) if (is_tip(i) && (victim < 0 || chainwork_cmp(g_e[i].work, g_e[victim].work) < 0)) victim = i;
        if (victim < 0 || chainwork_cmp(work, g_e[victim].work) <= 0) return -1;
        fill(&g_e[victim], h, hdr80, height, work, ntx);
        rewrite();                     /* an eviction is not an append: the victim must leave the file too */
        return 1;
    }
    if (!reserve(g_n + 1)) return -1;
    ent_t* e = &g_e[g_n]; fill(e, h, hdr80, height, work, ntx); g_n++;
    FILE* f = fopen(HDRTREE_FILE, "ab");
    if (f){ unsigned char r[HDRTREE_REC]; pack(r, e); fwrite(r, 1, HDRTREE_REC, f); fclose(f); }
    return 1;
}
int hdrtree_add(const unsigned char hdr80[80], long height, const unsigned char work[16]){
    return hdrtree_add_ntx(hdr80, height, work, 0);
}
int hdrtree_best(unsigned char hash[32], long* height, unsigned char work[16]){
    long best = -1;
    for (long i = 0; i < g_n; i++) if (is_tip(i) && (best < 0 || chainwork_cmp(g_e[i].work, g_e[best].work) > 0)) best = i;
    if (best < 0) return 0;
    if (hash) memcpy(hash, g_e[best].hash, 32);
    if (height) *height = g_e[best].height;
    if (work) memcpy(work, g_e[best].work, 16);
    return 1;
}
long hdrtree_prune_below(long height){
    long w = 0, dropped = 0;
    for (long i = 0; i < g_n; i++){ if (g_e[i].height < height){ dropped++; continue; } g_e[w++] = g_e[i]; }
    g_n = w; if (dropped) rewrite(); return dropped;
}
void hdrtree_reset(void){ g_n = 0; g_loaded = 1; unlink(HDRTREE_FILE); unlink(HDRTREE_FILE_V1); }
