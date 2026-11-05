/* daemon/addr_hist.c -- reader of the address history index (addr_hist_fmt.h).
 *
 * 2026-09-16: the index is a SET of runs (index_runs.h's idea, in this
 * format): the legacy addr_hist.dat base plus every addr_hist.r<from>-<to>.dat
 * the daemon's trailing builder writes behind the applied height, during the
 * sync and after it. Runs are disjoint by height and are kept in height
 * order, so a key's events are the concatenation of its group in each run --
 * still sorted by (height, txpos, kind, idx), which is what the consumers
 * assume. ah_lookup hands back one contiguous array (a reader-owned buffer,
 * valid until the next call); the single-mapping pointer it used to return
 * could not span files.
 *
 * Each file is mmap'd read-only and remapped when replaced (rename); a run
 * that vanished (merged away) is unmapped on the next scan. The scan is a
 * directory listing, at most once per second unless the directory changed.
 *
 * THREAD SAFETY (2026-09-26). The Esplora facade calls these from several
 * connection threads at once. With no lock, one thread's ah_lookup realloc'd
 * the shared result buffer while another was copying into it or reading its
 * result, and ah_scan rebuilt the run table and munmap'd replaced runs
 * under concurrent readers: test_rpc_esplora_stress crashed in ah_lookup's
 * memmove in 2 of 5 runs on the Mac ("4 threads on /address at once"; x86
 * passed by timing). Now g_ah_mu covers every access to the run table and
 * the mappings -- held across a whole lookup, which is a binary search and
 * a copy -- and the result buffer is PER THREAD, so "valid until the next
 * call" holds for each caller and no other thread can free what it holds. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <pthread.h>
#include "addr_hist_fmt.h"

#define AH_MAX_RUNS 64
typedef struct { char path[300]; const uint8_t* map; size_t len; ino_t ino; ah_header hdr; long from, to; } ah_run;
static ah_run g_runs[AH_MAX_RUNS]; static int g_n;
static time_t g_last_scan; static long g_dir_s = -1, g_dir_ns;
/* per-thread result buffer (see THREAD SAFETY), freed when its thread exits:
 * a connection thread per request must not leak its buffer */
typedef struct { uint8_t* p; size_t cap; } ah_tbuf;
static pthread_key_t g_tbuf_key; static pthread_once_t g_tbuf_once = PTHREAD_ONCE_INIT;
static void ah_tbuf_free(void* v){ ah_tbuf* b = v; if (b){ free(b->p); free(b); } }
static void ah_tbuf_init(void){ (void)pthread_key_create(&g_tbuf_key, ah_tbuf_free); }
static ah_tbuf* ah_tbuf_get(void){
    pthread_once(&g_tbuf_once, ah_tbuf_init);
    ah_tbuf* b = pthread_getspecific(g_tbuf_key);
    if (!b){ b = calloc(1, sizeof *b); if (b && pthread_setspecific(g_tbuf_key, b) != 0){ free(b); b = 0; } }
    return b;
}
static pthread_mutex_t g_ah_mu = PTHREAD_MUTEX_INITIALIZER;

/* ST2-7 (audit 2026-10-23): the header's regions must lie inside the file,
 * checked without wrapping -- a crafted body_off/body_len or sparse_n made
 * the unchecked sums small again and the lookups read past the mapping. */
static int ah_header_fits(const ah_header* h, uint64_t size){
    uint64_t end;
    if (h->body_off < AH_HDR_BYTES) return 0;
    if (__builtin_add_overflow(h->body_off, h->body_len, &end) || end > size) return 0;
    if (__builtin_mul_overflow(h->sparse_n, (uint64_t)AH_SPARSE_BYTES, &end)
        || __builtin_add_overflow(end, h->sparse_off, &end) || end > size) return 0;
    if (h->sparse_n && h->sparse_off < AH_HDR_BYTES) return 0;
    return 1;
}
static int ah_open_one(ah_run* r){
    struct stat sb;
    if (stat(r->path, &sb) != 0 || (size_t)sb.st_size < AH_HDR_BYTES) return 0;
    int fd = open(r->path, O_RDONLY); if (fd < 0) return 0;
    void* m = mmap(0, (size_t)sb.st_size, PROT_READ, MAP_SHARED, fd, 0); close(fd);
    if (m == MAP_FAILED) return 0;
    ah_header h; memcpy(&h, m, sizeof h);
    if (h.magic != AH_MAGIC || h.version != AH_VERSION || !ah_header_fits(&h, (uint64_t)sb.st_size)){ munmap(m, (size_t)sb.st_size); return 0; }
    r->map = m; r->len = (size_t)sb.st_size; r->ino = sb.st_ino; r->hdr = h;
    r->to = (long)h.to_height;
    r->from = (long)h.pad;               /* a run writes its from_height here; the legacy base has 0 */
    return 1;
}
static void ah_close_one(ah_run* r){ if (r->map) munmap((void*)r->map, r->len); r->map = 0; r->len = 0; }
static int is_ah_name(const char* f){
    size_t fl = strlen(f); const char* n = "addr_hist"; size_t nl = strlen(n);
    if (fl < nl + 4 || strncmp(f, n, nl) || strcmp(f + fl - 4, ".dat")) return 0;
    if (fl == nl + 4) return 1;
    return f[nl] == '.' && f[nl+1] == 'r';
}
static int cmp_run(const void* a, const void* b){
    const ah_run* x = a; const ah_run* y = b;
    if (x->from != y->from) return x->from < y->from ? -1 : 1;
    if (x->to != y->to) return x->to < y->to ? -1 : 1;
    return strcmp(x->path, y->path);
}
/* is run i's [from,to] inside another run's? (same range: the earlier one
 * in cmp_run order yields to the later) -- found[] is sorted by cmp_run */
static int ah_range_superseded(const ah_run* f, int n, int i){
    for (int j = 0; j < n; j++){
        if (j == i || f[j].from > f[i].from || f[j].to < f[i].to) continue;
        if (f[j].from == f[i].from && f[j].to == f[i].to && j < i) continue;
        return 1;
    }
    return 0;
}
static int ah_scan(void){
    time_t now = time(NULL); struct stat ds;
    if (stat(".", &ds) != 0) return g_n > 0;
    int dir_changed = g_dir_s != (long)ds.st_mtim.tv_sec || g_dir_ns != (long)ds.st_mtim.tv_nsec;
    if (g_last_scan && !dir_changed && now == g_last_scan) return g_n > 0;
    g_last_scan = now; g_dir_s = (long)ds.st_mtim.tv_sec; g_dir_ns = (long)ds.st_mtim.tv_nsec;
    DIR* d = opendir("."); if (!d) return g_n > 0;
    ah_run found[AH_MAX_RUNS]; int nf = 0; struct dirent* e;
    while ((e = readdir(d)) && nf < AH_MAX_RUNS){
        if (!is_ah_name(e->d_name)) continue;
        struct stat sb; if (stat(e->d_name, &sb) != 0) continue;
        int kept = 0;
        for (int i = 0; i < g_n; i++)
            if (g_runs[i].map && g_runs[i].ino == sb.st_ino && g_runs[i].len == (size_t)sb.st_size && !strcmp(g_runs[i].path, e->d_name)){
                found[nf++] = g_runs[i]; g_runs[i].map = 0; kept = 1; break; }
        if (kept) continue;
        ah_run r; memset(&r, 0, sizeof r); snprintf(r.path, sizeof r.path, "%s", e->d_name);
        if (ah_open_one(&r)) found[nf++] = r;
    }
    closedir(d);
    for (int i = 0; i < g_n; i++) if (g_runs[i].map) ah_close_one(&g_runs[i]);
    qsort(found, (size_t)nf, sizeof found[0], cmp_run);
    /* ST2-2 (audit 2026-10-23): a run whose range lies inside another run's
     * is that run's input left behind -- the merger renames its output into
     * place and only then unlinks the inputs, so a crash in between leaves
     * both. Concatenating them counted every event of the overlap twice.
     * Keep only the widest; of two with the same range, the later in name
     * order (the merged addr_hist.r* sorts after the legacy addr_hist.dat). */
    int keep = 0;
    for (int i = 0; i < nf; i++){
        if (ah_range_superseded(found, nf, i)){ ah_close_one(&found[i]); continue; }
        found[keep++] = found[i];
    }
    memcpy(g_runs, found, (size_t)keep * sizeof found[0]); g_n = keep;
    return g_n > 0;
}
int  ah_available(void){ pthread_mutex_lock(&g_ah_mu); int a = ah_scan(); pthread_mutex_unlock(&g_ah_mu); return a; }
long ah_to_height(void){
    pthread_mutex_lock(&g_ah_mu);
    long t = -1;
    if (ah_scan()) for (int i = 0; i < g_n; i++) if (g_runs[i].to > t) t = g_runs[i].to;
    pthread_mutex_unlock(&g_ah_mu);
    return t;
}
int  ah_run_count(void){ pthread_mutex_lock(&g_ah_mu); ah_scan(); int n = g_n; pthread_mutex_unlock(&g_ah_mu); return n; }

/* one run's group for the key: pointer to its events (in the mapping) and count */
static long ah_lookup_run(const ah_run* r, uint8_t type, const uint8_t hash[32], const uint8_t** events){
    *events = 0;
    if (r->hdr.sparse_n == 0) return 0;
    const uint8_t* sp = r->map + r->hdr.sparse_off;
    uint64_t lo = 0, hi = r->hdr.sparse_n;
    while (lo < hi){
        uint64_t mid = (lo + hi) / 2; const uint8_t* e = sp + mid * AH_SPARSE_BYTES;
        if (ah_key_cmp(e[0], e + 1, type, hash) <= 0) lo = mid + 1; else hi = mid;
    }
    if (lo == 0) return 0;
    /* ST2-7: every offset and count below comes from the file. Positions are
     * kept as offsets into the body (bounded by body_len, which the header
     * check holds inside the mapping) and compared by subtraction, so no
     * on-disk value can carry a pointer past the end. */
    uint64_t off; memcpy(&off, sp + (lo - 1) * AH_SPARSE_BYTES + 33, 8);
    const uint8_t* body = r->map + r->hdr.body_off; const uint64_t blen = r->hdr.body_len;
    if (off > blen) return 0;
    for (int k = 0; k < AH_SPARSE_STRIDE && blen - off >= AH_GROUP_HDR; k++){
        ah_group_hdr gh; memcpy(&gh, body + off, AH_GROUP_HDR);
        uint64_t room = (blen - off - AH_GROUP_HDR) / AH_EVENT_BYTES;
        if ((uint64_t)gh.n > room) return 0;                /* a group longer than the body: corrupt */
        int c = ah_key_cmp(gh.type, gh.hash, type, hash);
        if (c == 0){ *events = body + off + AH_GROUP_HDR; return (long)gh.n; }
        if (c > 0) return 0;
        off += AH_GROUP_HDR + (uint64_t)gh.n * AH_EVENT_BYTES;
    }
    return 0;
}
static long ah_lookup_locked(uint8_t type, const uint8_t hash[32], const ah_event** events){
    *events = 0;
    if (!ah_scan()) return -1;
    ah_tbuf* tb = ah_tbuf_get(); if (!tb) return -1;
    long total = 0;
    for (int i = 0; i < g_n; i++){
        const uint8_t* ev; long n = ah_lookup_run(&g_runs[i], type, hash, &ev);
        if (n <= 0) continue;
        size_t need = ((size_t)total + (size_t)n) * AH_EVENT_BYTES;
        if (need > tb->cap){
            size_t cap = tb->cap ? tb->cap : 1 << 16; while (cap < need) cap *= 2;
            uint8_t* nb = realloc(tb->p, cap); if (!nb) return -1;
            tb->p = nb; tb->cap = cap;
        }
        memcpy(tb->p + (size_t)total * AH_EVENT_BYTES, ev, (size_t)n * AH_EVENT_BYTES);
        total += n;
    }
    if (total) *events = (const ah_event*)tb->p;
    return total;
}
long ah_lookup(uint8_t type, const uint8_t hash[32], const ah_event** events){
    pthread_mutex_lock(&g_ah_mu);
    long n = ah_lookup_locked(type, hash, events);
    pthread_mutex_unlock(&g_ah_mu);
    return n;
}
/* test seam: forget every mapping */
void ah_reset_for_test(void){ pthread_mutex_lock(&g_ah_mu); for (int i = 0; i < g_n; i++) ah_close_one(&g_runs[i]); g_n = 0; g_last_scan = 0; g_dir_s = -1; pthread_mutex_unlock(&g_ah_mu); }
