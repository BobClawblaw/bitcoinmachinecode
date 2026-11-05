/* daemon/benchlog.c -- see benchlog.h (2026-10-04). Formatting only: no
 * clock, no I/O, no globals, so the daemon pays nothing it does not print. */
#include <stdio.h>
#include <string.h>
#include "benchlog.h"

int benchlog_fmt_index(char* out, size_t cap, long h, const unsigned long long ns[BL_IX_N]){
    return snprintf(out, cap, "[bench] index %ld: txindex %.2f | txospender %.2f | bfilter %.2f | addr %.2f | zmq %.2f ms",
                    h, (double)ns[BL_IX_TXINDEX] / 1e6, (double)ns[BL_IX_TXOSPENDER] / 1e6,
                    (double)ns[BL_IX_BFILTER] / 1e6, (double)ns[BL_IX_ADDR] / 1e6, (double)ns[BL_IX_ZMQ] / 1e6);
}

/* append "name" to one of the two lists, comma-separated */
static void ready_add(char* list, size_t cap, const char* name){
    size_t n = strlen(list);
    if (n + 2 >= cap) return;
    snprintf(list + n, cap - n, "%s%s", n ? ", " : "", name);
}

int benchlog_ready_eval(const benchlog_ready_t* r, char* out, size_t cap){
    if (!r->ibd_over){ snprintf(out, cap, "waiting: initial block download"); return 0; }
    if (r->tip < 0){ snprintf(out, cap, "waiting: no archive tip"); return 0; }
    /* the first unmet condition, in the order the stages finish on a sync */
    if (r->utxo_on && r->utxo_applied < r->tip){
        snprintf(out, cap, "waiting: utxo at %ld of %ld", r->utxo_applied, r->tip); return 0; }
    if (r->txindex_on && r->txindex_covered < r->tip){
        snprintf(out, cap, "waiting: txindex at %ld of %ld", r->txindex_covered, r->tip); return 0; }
    if (r->bfilter_on && r->bfilter_count - 1 < r->tip){
        snprintf(out, cap, "waiting: bfilter at %ld of %ld", r->bfilter_count - 1, r->tip); return 0; }
    if (r->coinstats_on && r->coinstats_height < r->tip){
        snprintf(out, cap, "waiting: coinstats at %ld of %ld", r->coinstats_height, r->tip); return 0; }
    if (r->coinstats_on && !r->coinstats_hist_ok){
        snprintf(out, cap, "waiting: coinstats history base"); return 0; }
    char on[96] = "", off[96] = "";
    ready_add(r->utxo_on ? on : off, sizeof on, "utxo");
    ready_add(r->txindex_on ? on : off, sizeof on, "txindex");
    ready_add(r->bfilter_on ? on : off, sizeof on, "bfilter");
    ready_add(r->coinstats_on ? on : off, sizeof on, "coinstats history");
    snprintf(out, cap, "[ready] all indexes at height %ld (%s%s%s) -- %.1fs",
             r->tip, on[0] ? on : "none enabled", off[0] ? "; skipped: " : "", off, r->secs);
    return 1;
}

/* ---- the [mem] line (plan M1, 2026-10-06) -- see benchlog.h --------------
 * The one function here that reads anything: /proc/self/smaps and
 * /proc/self/smaps_rollup, at the two MEM marks of a benchmark run. */
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define BLM_MAX   96            /* distinct mapping names tracked (the daemon has ~40) */
#define BLM_NAME  48
#define BLM_SMALL (16UL * 1024) /* kB: entries under this are summed as "other" */

typedef struct { char name[BLM_NAME]; unsigned long pss_kb; } blm_ent;

/* the name column of a maps/smaps header: "[anon:x]" -> x, "" -> anon,
 * "[heap]"/"[stack]"/"[vdso]" as they are, a path -> its basename */
static void blm_name_of(const char* hdr, char* out, size_t cap){
    /* addr perms offset dev inode [path...] */
    int f = 0; const char* p = hdr;
    while (*p && f < 5){ while (*p && *p != ' ') p++; while (*p == ' ') p++; f++; }
    const char* path = p; size_t n = strlen(path);
    while (n && (path[n-1] == '\n' || path[n-1] == ' ')) n--;
    if (n == 0){ snprintf(out, cap, "anon"); return; }
    if (n > 7 && memcmp(path, "[anon:", 6) == 0 && path[n-1] == ']'){ size_t m = n - 7; if (m >= cap) m = cap - 1; memcpy(out, path + 6, m); out[m] = 0; return; }
    if (path[0] == '['){ size_t m = n; if (m >= cap) m = cap - 1; memcpy(out, path, m); out[m] = 0; return; }
    const char* b = path + n; while (b > path && b[-1] != '/') b--;
    size_t m = (size_t)(path + n - b); if (m >= cap) m = cap - 1; memcpy(out, b, m); out[m] = 0;
    /* a deleted file's mapping reads "name (deleted)": keep the name */
    char* d = strstr(out, " (deleted)"); if (d) *d = 0;
}

static int blm_cmp(const void* a, const void* b){
    unsigned long x = ((const blm_ent*)a)->pss_kb, y = ((const blm_ent*)b)->pss_kb;
    return x < y ? 1 : x > y ? -1 : 0;
}

int benchlog_mem_line(char* out, size_t cap, const char* tag){
    unsigned long pss = 0, anon = 0, file = 0, shmem = 0;
    FILE* f = fopen("/proc/self/smaps_rollup", "r");
    if (f){
        char l[256];
        while (fgets(l, sizeof l, f)){
            unsigned long v;
            if (sscanf(l, "Pss: %lu", &v) == 1) pss = v;
            else if (sscanf(l, "Pss_Anon: %lu", &v) == 1) anon = v;
            else if (sscanf(l, "Pss_File: %lu", &v) == 1) file = v;
            else if (sscanf(l, "Pss_Shmem: %lu", &v) == 1) shmem = v;
        }
        fclose(f);
    }
    static blm_ent ents[BLM_MAX];      /* the two marks are seconds apart on one thread */
    int n = 0; unsigned long other = 0, cur_pss = 0; char cur[BLM_NAME] = "";
    int have = 0;
    f = fopen("/proc/self/smaps", "r");
    if (f){
        char l[512];
        /* a header line starts the next mapping; "Pss:" is its share */
        for (;;){
            int more = fgets(l, sizeof l, f) != NULL;
            int is_hdr = more && ((l[0] >= '0' && l[0] <= '9') || (l[0] >= 'a' && l[0] <= 'f')) && strchr(l, '-') && strchr(l, '-') < strchr(l, ' ');
            if (!more || is_hdr){
                if (have){
                    int i; for (i = 0; i < n; i++) if (strcmp(ents[i].name, cur) == 0) break;
                    if (i < n) ents[i].pss_kb += cur_pss;
                    else if (n < BLM_MAX){ snprintf(ents[n].name, BLM_NAME, "%s", cur); ents[n].pss_kb = cur_pss; n++; }
                    else other += cur_pss;
                }
                if (!more) break;
                blm_name_of(l, cur, sizeof cur); cur_pss = 0; have = 1;
                continue;
            }
            unsigned long v; if (sscanf(l, "Pss: %lu", &v) == 1) cur_pss += v;
        }
        fclose(f);
    } else {
        return snprintf(out, cap, "[mem] %s: /proc/self/smaps unreadable", tag);
    }
    qsort(ents, (size_t)n, sizeof ents[0], blm_cmp);
    int len = snprintf(out, cap, "[mem] %s: pss %lu MB (anon %lu, file %lu, shmem %lu)", tag, pss / 1024, anon / 1024, file / 1024, shmem / 1024);
    for (int i = 0; i < n; i++){
        if (ents[i].pss_kb < BLM_SMALL){ other += ents[i].pss_kb; continue; }
        if ((size_t)len >= cap) break;
        len += snprintf(out + len, cap - (size_t)len, " | %s %lu", ents[i].name, ents[i].pss_kb / 1024);
    }
    if ((size_t)len < cap) len += snprintf(out + len, cap - (size_t)len, " | other %lu", other / 1024);
    if ((size_t)len >= cap) len = (int)cap - 1;
    return len;
}

