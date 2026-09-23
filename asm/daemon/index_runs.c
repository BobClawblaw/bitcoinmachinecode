/* daemon/index_runs.c -- see index_runs.h */
#include "index_runs.h"
#include <stdio.h>
#include "log_ts.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>

static unsigned long long rd64(const unsigned char* p){ unsigned long long v = 0; for (int i = 0; i < 8; i++) v |= (unsigned long long)p[i] << (8*i); return v; }
static unsigned long      rd32(const unsigned char* p){ unsigned long v = 0; for (int i = 0; i < 4; i++) v |= (unsigned long)p[i] << (8*i); return v; }

void irs_init(irunset_t* s, const char* name, const char* magic, int rec_bytes, int sparse_bytes){
    memset(s, 0, sizeof *s);
    snprintf(s->name, sizeof s->name, "%s", name);
    snprintf(s->magic, sizeof s->magic, "%s", magic);
    s->rec = rec_bytes; s->sparse = sparse_bytes;
    s->dir_mtime_s = -1;
}
void irs_dirty(irunset_t* s){ s->last_scan = 0; s->dir_mtime_s = -1; }

void irs_run_name(const char* name, long from, long to, char* out, size_t cap){
    snprintf(out, cap, "%s.r%09ld-%09ld.dat", name, from, to);
}

int irs_open_run(const irunset_t* s, irun_t* r){
    r->map = 0; r->len = 0;
    int fd = open(r->path, O_RDONLY); if (fd < 0) return 0;
    struct stat sb;
    if (fstat(fd, &sb) != 0 || sb.st_size < IRS_HDR){ close(fd); return 0; }
    void* m = mmap(NULL, (size_t)sb.st_size, PROT_READ, MAP_SHARED, fd, 0); close(fd);
    if (m == MAP_FAILED) return 0;
    const unsigned char* b = m;
    if (memcmp(b, s->magic, 8)){ munmap(m, (size_t)sb.st_size); return 0; }
    unsigned long long n = rd64(b + 8), so = rd64(b + 16), ns = rd64(b + 24);
    long from = (long)rd32(b + 32), to = (long)rd32(b + 36);
    /* a header that describes more than the file holds is a torn build */
    if (so + ns * (unsigned long long)s->sparse > (unsigned long long)sb.st_size
        || IRS_HDR + n * (unsigned long long)s->rec != so || to < from){
        munmap(m, (size_t)sb.st_size); return 0; }
    r->map = b; r->len = (size_t)sb.st_size; r->ino = sb.st_ino;
    r->n = n; r->sparse_off = so; r->nsparse = ns; r->from = from; r->to = to;
    return 1;
}
void irs_close_run(irun_t* r){ if (r->map) munmap((void*)r->map, r->len); r->map = 0; r->len = 0; }
void irs_close_all(irunset_t* s){ for (int i = 0; i < s->n; i++) irs_close_run(&s->r[i]); s->n = 0; irs_dirty(s); }

static int is_run_name(const irunset_t* s, const char* f){
    size_t nl = strlen(s->name), fl = strlen(f);
    if (fl < nl + 4 || strncmp(f, s->name, nl)) return 0;
    if (strcmp(f + fl - 4, ".dat")) return 0;                   /* not .tmp, not .tail */
    if (fl == nl + 4) return 1;                                  /* <name>.dat: the legacy base */
    return f[nl] == '.' && f[nl+1] == 'r' && fl > nl + 6;        /* <name>.r<from>-<to>.dat */
}
static int cmp_run(const void* a, const void* b){
    const irun_t* x = a; const irun_t* y = b;
    if (x->from != y->from) return x->from < y->from ? -1 : 1;
    if (x->to != y->to) return x->to < y->to ? -1 : 1;
    return strcmp(x->path, y->path);
}

int irs_refresh(irunset_t* s){
    time_t now = time(NULL);
    struct stat ds;
    if (stat(".", &ds) != 0) return -1;
    /* rescan when the directory changed (a run was created, renamed or
     * unlinked -- what builders and the merger do), and otherwise at most
     * once per second, so a file rewritten in place is still noticed. A
     * first draft gated on the wall-clock second alone and a run committed
     * in the same second as the previous scan was invisible until the next. */
    int dir_changed = s->dir_mtime_s != (long)ds.st_mtim.tv_sec || s->dir_mtime_ns != (long)ds.st_mtim.tv_nsec;
    if (s->last_scan && !dir_changed && now == s->last_scan) return 0;
    s->last_scan = now; s->dir_mtime_s = (long)ds.st_mtim.tv_sec; s->dir_mtime_ns = (long)ds.st_mtim.tv_nsec;

    DIR* d = opendir("."); if (!d) return -1;
    irun_t found[IRS_MAX_RUNS]; int nf = 0; int changed = 0;
    struct dirent* e;
    while ((e = readdir(d)) && nf < IRS_MAX_RUNS){
        if (!is_run_name(s, e->d_name)) continue;
        struct stat sb; if (stat(e->d_name, &sb) != 0) continue;
        /* already mapped and unchanged? keep the mapping */
        int kept = 0;
        for (int i = 0; i < s->n; i++){
            if (s->r[i].ino == sb.st_ino && s->r[i].len == (size_t)sb.st_size && !strcmp(s->r[i].path, e->d_name)){
                found[nf++] = s->r[i]; s->r[i].map = 0; kept = 1; break; }
        }
        if (kept) continue;
        irun_t r; memset(&r, 0, sizeof r); snprintf(r.path, sizeof r.path, "%s", e->d_name);
        if (!irs_open_run(s, &r)) continue;                      /* a torn or foreign file is not a run */
        found[nf++] = r; changed = 1;
        fprintf(stderr, "[%s] run %s: %llu records, heights [%ld,%ld]\n", s->name, r.path, r.n, r.from, r.to);
    }
    closedir(d);
    /* whatever is still mapped in s was not found this time: it vanished */
    for (int i = 0; i < s->n; i++) if (s->r[i].map){ irs_close_run(&s->r[i]); changed = 1; }
    qsort(found, (size_t)nf, sizeof found[0], cmp_run);
    memcpy(s->r, found, (size_t)nf * sizeof found[0]); s->n = nf;
    return changed;
}
long irs_covered_to(irunset_t* s){
    irs_refresh(s);
    long to = -1; for (int i = 0; i < s->n; i++) if (s->r[i].to > to) to = s->r[i].to;
    return to;
}
long irs_covered_from(irunset_t* s){
    irs_refresh(s);
    long from = -1; for (int i = 0; i < s->n; i++) if (from < 0 || s->r[i].from < from) from = s->r[i].from;
    return from;
}
