/* daemon/lsm_manifest.c -- see lsm_manifest.h. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include "lsm_manifest.h"
#define MAGIC_MANIFEST  0x4E414D55u
#define MAGIC_MANIFEST2 0x324E4D55u

static int read_raw(const char* path, unsigned char** ents, uint64_t* n, uint64_t* live){
    FILE* f = fopen(path, "rb");
    if (!f) return -1;
    unsigned char h[20];
    if (fread(h, 1, 12, f) != 12){ fclose(f); return -1; }
    uint32_t magic; memcpy(&magic, h, 4);
    memcpy(n, h + 4, 8);
    *live = ~0ULL;
    if (magic == MAGIC_MANIFEST2){
        if (fread(h + 12, 1, 8, f) != 8){ fclose(f); return -1; }
        memcpy(live, h + 12, 8);
    } else if (magic != MAGIC_MANIFEST){ fclose(f); return -1; }
    if (*n > (1u << 20)){ fclose(f); return -1; }
    *ents = malloc((size_t)(*n * 16) + 16);
    if (!*ents){ fclose(f); return -1; }
    if (*n && fread(*ents, 16, (size_t)*n, f) != *n){ free(*ents); *ents = 0; fclose(f); return -1; }
    fclose(f);
    return 0;
}
static void advance_counters(struct lsm_state* lst){
    const unsigned char* e = (const unsigned char*)lst->manifest_buf;
    for (uint64_t i = 0; i < lst->manifest_n; i++){
        uint64_t g, r; memcpy(&g, e + i*16, 8); memcpy(&r, e + i*16 + 8, 8);
        if (g + 1 > lst->next_gen)    lst->next_gen    = g + 1;
        if (r + 1 > lst->next_run_no) lst->next_run_no = r + 1;
    }
}
int lsm_manifest_read_file(const char* path, struct lsm_state* lst, uint64_t* persisted_live){
    unsigned char* ents; uint64_t n, live;
    if (read_raw(path, &ents, &n, &live) != 0) return -1;
    if (n > lst->manifest_cap){ free(ents); return -1; }
    memcpy(lst->manifest_buf, ents, (size_t)n * 16);
    free(ents);
    lst->manifest_n = n;
    if (persisted_live) *persisted_live = live;
    advance_counters(lst);
    return 0;
}
int lsm_manifest_read(struct lsm_state* lst, uint64_t* persisted_live){
    return lsm_manifest_read_file(LSM_MANIFEST_FILE, lst, persisted_live);
}
uint64_t lsm_manifest_persisted_live_file(const char* path){
    FILE* f = fopen(path, "rb");
    if (!f) return ~0ULL;
    unsigned char h[20]; size_t got = fread(h, 1, 20, f); fclose(f);
    if (got != 20) return ~0ULL;
    uint32_t magic; memcpy(&magic, h, 4);
    if (magic != MAGIC_MANIFEST2) return ~0ULL;
    uint64_t live; memcpy(&live, h + 12, 8); return live;
}
uint64_t lsm_manifest_persisted_live(void){ return lsm_manifest_persisted_live_file(LSM_MANIFEST_FILE); }

int lsm_manifest_publish(const struct lsm_state* lst, uint64_t persisted_live){
    int fd = open(LSM_MANIFEST_PUB, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    unsigned char h[20]; size_t hl;
    uint32_t magic = persisted_live == ~0ULL ? MAGIC_MANIFEST : MAGIC_MANIFEST2;
    memcpy(h, &magic, 4); memcpy(h + 4, &lst->manifest_n, 8);
    if (persisted_live == ~0ULL) hl = 12; else { memcpy(h + 12, &persisted_live, 8); hl = 20; }
    size_t el = (size_t)lst->manifest_n * 16;
    if (write(fd, h, hl) != (ssize_t)hl || (el && write(fd, lst->manifest_buf, el) != (ssize_t)el) || fsync(fd) != 0){
        close(fd); unlink(LSM_MANIFEST_PUB); return -1;
    }
    close(fd);
    if (rename(LSM_MANIFEST_PUB, LSM_MANIFEST_FILE) != 0){ unlink(LSM_MANIFEST_PUB); return -1; }
    int dfd = open(".", O_RDONLY);
    if (dfd >= 0){ fsync(dfd); close(dfd); }
    return 0;
}

static int in_list(const unsigned char* ents, uint64_t n, uint64_t run_no){
    for (uint64_t i = 0; i < n; i++){ uint64_t r; memcpy(&r, ents + i*16 + 8, 8); if (r == run_no) return 1; }
    return 0;
}
static int in_inputs(const uint64_t* inputs, int k, uint64_t run_no){
    for (int i = 0; i < k; i++) if (inputs[i] == run_no) return 1;
    return 0;
}
int lsm_manifest_adopt_child(struct lsm_state* lst, const uint64_t* inputs, int k,
                             int is_full, uint64_t base_at_fork, uint64_t* new_persisted){
    unsigned char* c; uint64_t cn, cbase;
    if (read_raw(LSM_MANIFEST_CHILD, &c, &cn, &cbase) != 0) return -1;
    if (cn < 1){ free(c); return -1; }
    const unsigned char* cur = (const unsigned char*)lst->manifest_buf;
    /* the child's manifest = [merged] + the non-input runs it saw at fork:
     * the merged run is the one child entry we do not know; every other
     * entry must be ours, and none may be an input. (Leveled: the merged
     * run sits wherever the batch began, not necessarily at index 0.) */
    int unknown = 0, bad = 0; uint64_t merged = 0;
    for (uint64_t i = 0; i < cn && !bad; i++){
        uint64_t r; memcpy(&r, c + i*16 + 8, 8);
        if (in_inputs(inputs, k, r)) bad = 1;
        else if (!in_list(cur, lst->manifest_n, r)){ unknown++; merged = r; }
    }
    if (unknown != 1) bad = 1;
    (void)merged;
    for (int i = 0; i < k && !bad; i++) if (!in_list(cur, lst->manifest_n, inputs[i])) bad = 1;
    if (bad){ free(c); return -1; }
    /* union: child's list, then whatever we flushed since fork (in our order) */
    uint64_t total = cn;
    for (uint64_t i = 0; i < lst->manifest_n; i++){
        uint64_t r; memcpy(&r, cur + i*16 + 8, 8);
        if (!in_inputs(inputs, k, r) && !in_list(c, cn, r)) total++;
    }
    if (total > lst->manifest_cap){ free(c); return -1; }
    unsigned char* nb = malloc((size_t)total * 16);
    if (!nb){ free(c); return -1; }
    memcpy(nb, c, (size_t)cn * 16);
    uint64_t w = cn;
    for (uint64_t i = 0; i < lst->manifest_n; i++){
        uint64_t r; memcpy(&r, cur + i*16 + 8, 8);
        if (!in_inputs(inputs, k, r) && !in_list(c, cn, r)){ memcpy(nb + w*16, cur + i*16, 16); w++; }
    }
    /* live count. Flushes persist the running counter (runs-only at that
     * instant), so the on-disk base moved by exactly the net ops flushed
     * since fork. A full merge re-derived the merged runs' exact count
     * (cbase); a partial merge is count-neutral. */
    uint64_t base_now = lsm_manifest_persisted_live();
    uint64_t nbase; uint64_t heal = 0;
    if (!is_full) nbase = base_now;
    else if (cbase != ~0ULL && base_now != ~0ULL && base_at_fork != ~0ULL){
        nbase = cbase + (base_now - base_at_fork);
        heal  = cbase - base_at_fork;
    } else nbase = ~0ULL;                       /* unknown: OLD header, reload recounts */
    /* commit to memory, publish, then clean up */
    memcpy(lst->manifest_buf, nb, (size_t)total * 16);
    lst->manifest_n = total;
    lst->total_live += heal;
    advance_counters(lst);
    free(nb); free(c);
    if (lsm_manifest_publish(lst, nbase) != 0) return -1;   /* memory now ahead of disk; harmless: inputs still exist */
    unlink(LSM_MANIFEST_CHILD);
    if (new_persisted) *new_persisted = nbase;
    return 0;
}

int lsm_manifest_sweep_orphans(const struct lsm_state* lst){
    unsigned char* e; uint64_t n, live;
    if (access(LSM_MANIFEST_FILE, F_OK) != 0) return 0;      /* fresh store: nothing published yet, nothing to sweep */
    if (read_raw(LSM_MANIFEST_FILE, &e, &n, &live) != 0) return -1;
    int same = (n == lst->manifest_n) && (n == 0 || memcmp(e, lst->manifest_buf, (size_t)n * 16) == 0);
    free(e);
    if (!same) return -1;
    int gone = 0;
    if (unlink(LSM_MANIFEST_CHILD) == 0) gone++;
    if (unlink(LSM_MANIFEST_PUB) == 0) gone++;
    DIR* d = opendir(".");
    if (!d) return gone;
    struct dirent* de;
    while ((de = readdir(d))){
        unsigned run; char tail;
        if (sscanf(de->d_name, "utxo_run_%06u.dat%c", &run, &tail) != 1) continue;
        if (strlen(de->d_name) != strlen("utxo_run_000000.dat")) continue;
        if (in_list((const unsigned char*)lst->manifest_buf, lst->manifest_n, run)) continue;
        if (unlink(de->d_name) == 0) gone++;
    }
    closedir(d);
    return gone;
}

/* Byte budget (2026-09-01): the mapped run files must stay inside the page
 * cache next to the memtable, or every lookup faults from disk (the live
 * replay fell to 2-5 blocks/s at 10 runs / 30 GB on a 63 GB box while the
 * bulk count threshold sat at 48). When the runs' total exceeds `budget`
 * bytes the pick behaves as if the count threshold were 2: the newest
 * similar-size runs merge now, and repeated merges fold the set back under
 * the budget. budget = 0 disables the rule. */
long lsm_compact_pick_budget(const uint64_t* sizes, long n, long threshold, long max_k, uint64_t budget, long* lo){
    if (budget && n >= 2){
        uint64_t total = 0; for (long i = 0; i < n; i++) total += sizes[i];
        if (total > budget) threshold = 2;
    }
    return lsm_compact_pick(sizes, n, threshold, max_k, lo);
}
long lsm_compact_pick(const uint64_t* sizes, long n, long threshold, long max_k, long* lo){
    if (n < 2 || n < threshold) return 0;
    long l = n - 1; uint64_t acc = sizes[l];
    while (l > 0 && sizes[l-1] <= (uint64_t)LSM_COMPACT_RATIO * acc){ acc += sizes[l-1]; l--; }
    if (n - l > max_k) l = n - max_k;
    if (n - l < 2) return 0;
    *lo = l; return n - l;
}
