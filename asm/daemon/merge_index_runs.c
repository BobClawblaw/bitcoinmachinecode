/* daemon/merge_index_runs.c -- fold every run of a sorted index into one
 * (index_runs.h). 2026-09-16.
 *
 * A trailing build (index_trail.h) adds a run every few thousand blocks;
 * each lookup then asks every run. This merges them: a streaming k-way merge
 * of the sorted record files -- no re-walk of the archive, no bucket temp
 * files, memory bounded by one output buffer -- into a single run covering
 * [lowest from, highest to], written as <name>.r<from>-<to>.dat.tmp with the
 * header last, renamed, and only THEN the inputs unlinked. A reader that
 * still has an input mapped keeps a valid mapping: the inode outlives the
 * name. The legacy <name>.dat base, if present, is one of the inputs.
 *
 * Formats: txindex (BMCTXIDX, 20-byte records keyed by an 8-byte prefix) and
 * txospender (BMCTXOSP, 28-byte records keyed by a 12-byte prefix + u32
 * vout). Runs are disjoint by height, so equal keys across runs are distinct
 * records and are kept in (key, height, offset) order -- the order the
 * builders write, so a merged file is byte-identical to a single build over
 * the union range. Both key comparisons are the ones the builders use.
 *
 * Usage: merge_index_runs <chaindir> <name>      exit 0 = merged (or nothing
 * to merge), 1 = failed, nothing replaced. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include "index_runs.h"
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

typedef struct { const char* name; const char* magic; int rec, sparse, keylen; int vout_at; } fmt_t;
static const fmt_t FMTS[] = {
    { "txindex",    "BMCTXIDX", 20, 16,  8, -1 },
    { "txospender", "BMCTXOSP", 28, 24, 12, 12 },
};
static u32 rd32(const u8* p){ u32 v = 0; for (int i = 0; i < 4; i++) v |= (u32)p[i] << (8*i); return v; }

/* the builders' order: key, then height, then offset (height/offset sit right
 * after the key in both layouts: txindex at 8/12, txospender at 16/20) */
static int rec_cmp(const fmt_t* f, const u8* a, const u8* b){
    int c = memcmp(a, b, (size_t)f->keylen); if (c) return c;
    if (f->vout_at >= 0){ u32 va = rd32(a + f->vout_at), vb = rd32(b + f->vout_at); if (va != vb) return va < vb ? -1 : 1; }
    int ho = f->keylen + (f->vout_at >= 0 ? 4 : 0);
    u32 ha = rd32(a + ho), hb = rd32(b + ho); if (ha != hb) return ha < hb ? -1 : 1;
    u32 oa = rd32(a + ho + 4), ob = rd32(b + ho + 4); return oa < ob ? -1 : oa > ob ? 1 : 0;
}

/* ---- addr_hist: variable-length GROUPS, merged by key ---------------------
 * Same idea, different shape (addr_hist_fmt.h): each run is a sequence of
 * [group header][n events] sorted by key with a sparse index every 256th
 * group. Runs are disjoint by height and are merged in height order, so a
 * key present in several runs becomes ONE group whose events are the runs'
 * groups concatenated in that order -- which keeps them sorted by (height,
 * txpos, kind, idx) exactly as one build over the union would have them. */
#include "addr_hist_fmt.h"
#include <dirent.h>
#include <sys/mman.h>
typedef struct { char path[300]; const u8* map; size_t len; ah_header hdr; long from, to; const u8* p; const u8* end; } ahr_t;
static int ahr_cmp(const void* a, const void* b){ const ahr_t* x = a; const ahr_t* y = b; return x->from < y->from ? -1 : x->from > y->from ? 1 : (x->to < y->to ? -1 : x->to > y->to); }
static int merge_addr_hist(void){
    static ahr_t r[64]; int n = 0;
    DIR* d = opendir("."); if (!d){ perror("opendir"); return 1; }
    struct dirent* e;
    while ((e = readdir(d)) && n < 64){
        const char* f = e->d_name; size_t fl = strlen(f);
        if (fl < 13 || strncmp(f, "addr_hist", 9) || strcmp(f + fl - 4, ".dat")) continue;
        if (fl != 13 && !(f[9] == '.' && f[10] == 'r')) continue;
        struct stat sb; if (stat(f, &sb) != 0 || (size_t)sb.st_size < AH_HDR_BYTES) continue;
        int fd = open(f, O_RDONLY); if (fd < 0) continue;
        void* m = mmap(0, (size_t)sb.st_size, PROT_READ, MAP_SHARED, fd, 0); close(fd); if (m == MAP_FAILED) continue;
        ah_header h; memcpy(&h, m, sizeof h);
        if (h.magic != AH_MAGIC || h.version != AH_VERSION || h.body_off + h.body_len > (u64)sb.st_size){ munmap(m, (size_t)sb.st_size); continue; }
        snprintf(r[n].path, sizeof r[n].path, "%s", f); r[n].map = m; r[n].len = (size_t)sb.st_size; r[n].hdr = h;
        r[n].from = (long)h.pad; r[n].to = (long)h.to_height; r[n].p = r[n].map + h.body_off; r[n].end = r[n].p + h.body_len; n++;
    }
    closedir(d);
    if (n < 2){ fprintf(stderr, "[addr_hist] merge: %d run(s), nothing to merge\n", n); return 0; }
    qsort(r, (size_t)n, sizeof r[0], ahr_cmp);
    long from = r[0].from, to = r[0].to; u64 total_ev = 0;
    for (int i = 0; i < n; i++){ if (r[i].from < from) from = r[i].from; if (r[i].to > to) to = r[i].to; total_ev += r[i].hdr.n_events; }
    char out_name[320], tmp_name[340];
    snprintf(out_name, sizeof out_name, "addr_hist.r%09ld-%09ld.dat", from, to); snprintf(tmp_name, sizeof tmp_name, "%s.tmp", out_name);
    for (int i = 0; i < n; i++) if (!strcmp(r[i].path, out_name)){ fprintf(stderr, "[addr_hist] merge: %s is already an input\n", out_name); return 1; }
    fprintf(stderr, "[addr_hist] merge: %d runs, %llu events, heights [%ld,%ld] -> %s\n", n, (unsigned long long)total_ev, from, to, out_name);
    time_t t0 = time(NULL);
    FILE* out = fopen(tmp_name, "wb"); if (!out){ perror("open output"); return 1; }
    static u8 obuf[1 << 20]; setvbuf(out, (char*)obuf, _IOFBF, sizeof obuf);
    u8 zero[AH_HDR_BYTES] = {0}; fwrite(zero, 1, AH_HDR_BYTES, out);
    size_t sp_cap = 1 << 16, sp_n = 0; ah_sparse* sp = malloc(sp_cap * sizeof *sp); u64 body = 0, groups = 0, events = 0;
    for (;;){
        /* the smallest key at the head of any run */
        int best = -1; ah_group_hdr bg;
        for (int i = 0; i < n; i++){
            if (r[i].p + AH_GROUP_HDR > r[i].end) continue;
            ah_group_hdr g; memcpy(&g, r[i].p, AH_GROUP_HDR);
            if (best < 0 || ah_key_cmp(g.type, g.hash, bg.type, bg.hash) < 0){ best = i; bg = g; }
        }
        if (best < 0) break;
        /* every run whose head is this key contributes, in height order */
        u32 cnt = 0;
        for (int i = 0; i < n; i++){
            if (r[i].p + AH_GROUP_HDR > r[i].end) continue;
            ah_group_hdr g; memcpy(&g, r[i].p, AH_GROUP_HDR);
            if (ah_key_cmp(g.type, g.hash, bg.type, bg.hash) == 0) cnt += g.n;
        }
        if (groups % AH_SPARSE_STRIDE == 0){
            if (sp_n == sp_cap){ sp_cap *= 2; sp = realloc(sp, sp_cap * sizeof *sp); }
            sp[sp_n].type = bg.type; memcpy(sp[sp_n].hash, bg.hash, 32); sp[sp_n].off = body; sp_n++;
        }
        ah_group_hdr oh; oh.type = bg.type; memcpy(oh.hash, bg.hash, 32); oh.n = cnt;
        fwrite(&oh, 1, AH_GROUP_HDR, out); body += AH_GROUP_HDR;
        for (int i = 0; i < n; i++){
            if (r[i].p + AH_GROUP_HDR > r[i].end) continue;
            ah_group_hdr g; memcpy(&g, r[i].p, AH_GROUP_HDR);
            if (ah_key_cmp(g.type, g.hash, bg.type, bg.hash) != 0) continue;
            size_t bytes = (size_t)g.n * AH_EVENT_BYTES;
            fwrite(r[i].p + AH_GROUP_HDR, 1, bytes, out); body += bytes; events += g.n;
            r[i].p += AH_GROUP_HDR + bytes;
        }
        groups++;
    }
    ah_header hd; memset(&hd, 0, sizeof hd); hd.magic = AH_MAGIC; hd.version = AH_VERSION; hd.to_height = (u32)to; hd.pad = (u32)from;
    hd.n_keys = groups; hd.n_events = events; hd.body_off = AH_HDR_BYTES; hd.body_len = body; hd.sparse_off = AH_HDR_BYTES + body; hd.sparse_n = sp_n;
    fwrite(sp, AH_SPARSE_BYTES, sp_n, out);
    if (fflush(out) || fsync(fileno(out)) || fseek(out, 0, SEEK_SET) || fwrite(&hd, 1, sizeof hd, out) != sizeof hd || fflush(out) || fsync(fileno(out)) || fclose(out)){ perror("write"); unlink(tmp_name); return 1; }
    if (events != total_ev){ fprintf(stderr, "[addr_hist] merge: wrote %llu of %llu events -- not replacing anything\n", (unsigned long long)events, (unsigned long long)total_ev); unlink(tmp_name); return 1; }
    if (rename(tmp_name, out_name)){ perror("rename"); unlink(tmp_name); return 1; }
    for (int i = 0; i < n; i++){ munmap((void*)r[i].map, r[i].len); if (unlink(r[i].path) != 0) fprintf(stderr, "[addr_hist] merge: cannot unlink %s\n", r[i].path); }
    fprintf(stderr, "[addr_hist] merge DONE: %llu keys, %llu events, %.2f GB, %llds\n", (unsigned long long)groups, (unsigned long long)events, (double)(hd.sparse_off + sp_n * AH_SPARSE_BYTES) / 1e9, (long long)(time(NULL) - t0));
    return 0;
}

int main(int argc, char** argv){
    if (argc < 3){ fprintf(stderr, "usage: merge_index_runs <chaindir> <txindex|txospender|addr_hist>\n"); return 2; }
    if (!strcmp(argv[2], "addr_hist")){ if (chdir(argv[1])){ perror("chdir"); return 1; } return merge_addr_hist(); }
    const fmt_t* f = 0;
    for (size_t i = 0; i < sizeof FMTS / sizeof FMTS[0]; i++) if (!strcmp(FMTS[i].name, argv[2])) f = &FMTS[i];
    if (!f){ fprintf(stderr, "unknown index %s\n", argv[2]); return 2; }
    if (chdir(argv[1])){ perror("chdir"); return 1; }
    static irunset_t s; irs_init(&s, f->name, f->magic, f->rec, f->sparse);
    irs_dirty(&s); irs_refresh(&s);
    if (s.n < 2){ fprintf(stderr, "[%s] merge: %d run(s), nothing to merge\n", f->name, s.n); return 0; }
    long from = s.r[0].from, to = s.r[0].to; u64 total = 0;
    for (int i = 0; i < s.n; i++){ if (s.r[i].from < from) from = s.r[i].from; if (s.r[i].to > to) to = s.r[i].to; total += s.r[i].n; }
    char out_name[320], tmp_name[340];
    irs_run_name(f->name, from, to, out_name, sizeof out_name);
    snprintf(tmp_name, sizeof tmp_name, "%s.tmp", out_name);
    /* the output must not be one of the inputs (a re-run over an already
     * merged set would have exactly one run and returned above) */
    for (int i = 0; i < s.n; i++) if (!strcmp(s.r[i].path, out_name)){ fprintf(stderr, "[%s] merge: %s is already an input\n", f->name, out_name); return 1; }
    fprintf(stderr, "[%s] merge: %d runs, %llu records, heights [%ld,%ld] -> %s\n", f->name, s.n, (unsigned long long)total, from, to, out_name);
    time_t t0 = time(NULL);
    FILE* out = fopen(tmp_name, "wb"); if (!out){ perror("open output"); return 1; }
    static u8 obuf[1 << 20]; setvbuf(out, (char*)obuf, _IOFBF, sizeof obuf);
    u8 zero[IRS_HDR] = {0}; if (fwrite(zero, 1, IRS_HDR, out) != IRS_HDR){ perror("write"); return 1; }
    u64 pos[IRS_MAX_RUNS]; memset(pos, 0, sizeof pos);
    u64 written = 0, nsparse = 0, sparse_cap = total / 256 + 2;
    u8* sparse = malloc(sparse_cap * (size_t)f->sparse); if (!sparse){ fprintf(stderr, "oom\n"); return 1; }
    for (;;){
        int best = -1; const u8* br = 0;
        for (int i = 0; i < s.n; i++){
            if (pos[i] >= s.r[i].n) continue;
            const u8* r = s.r[i].map + IRS_HDR + pos[i] * (u64)f->rec;
            if (best < 0 || rec_cmp(f, r, br) < 0){ best = i; br = r; }
        }
        if (best < 0) break;
        if (written % 256 == 0){
            u8* e = sparse + nsparse * (u64)f->sparse;
            memcpy(e, br, (size_t)(f->sparse - 8));                       /* the key (+ vout for txospender) */
            u64 off = IRS_HDR + written * (u64)f->rec; for (int b = 0; b < 8; b++) e[f->sparse - 8 + b] = (u8)(off >> (8*b));
            nsparse++;
        }
        if (fwrite(br, 1, (size_t)f->rec, out) != (size_t)f->rec){ perror("write"); return 1; }
        written++; pos[best]++;
    }
    u64 sparse_off = IRS_HDR + written * (u64)f->rec;
    if (fwrite(sparse, 1, (size_t)(nsparse * (u64)f->sparse), out) != nsparse * (u64)f->sparse){ perror("write sparse"); return 1; }
    if (fflush(out) || fsync(fileno(out))){ perror("fsync"); return 1; }
    u8 hdr[IRS_HDR]; memset(hdr, 0, sizeof hdr); memcpy(hdr, f->magic, 8);
    for (int b = 0; b < 8; b++) hdr[8+b]  = (u8)(written >> (8*b));
    for (int b = 0; b < 8; b++) hdr[16+b] = (u8)(sparse_off >> (8*b));
    for (int b = 0; b < 8; b++) hdr[24+b] = (u8)(nsparse >> (8*b));
    for (int b = 0; b < 4; b++) hdr[32+b] = (u8)((u32)from >> (8*b));
    for (int b = 0; b < 4; b++) hdr[36+b] = (u8)((u32)to >> (8*b));
    if (fseek(out, 0, SEEK_SET) || fwrite(hdr, 1, IRS_HDR, out) != IRS_HDR || fflush(out) || fsync(fileno(out)) || fclose(out)){ perror("header"); return 1; }
    if (written != total){ fprintf(stderr, "[%s] merge: wrote %llu of %llu records -- not replacing anything\n", f->name, (unsigned long long)written, (unsigned long long)total); unlink(tmp_name); return 1; }
    if (rename(tmp_name, out_name)){ perror("rename"); unlink(tmp_name); return 1; }
    /* the output is durable and visible: now the inputs may go */
    for (int i = 0; i < s.n; i++){ irs_close_run(&s.r[i]); if (unlink(s.r[i].path) != 0) fprintf(stderr, "[%s] merge: cannot unlink %s\n", f->name, s.r[i].path); }
    fprintf(stderr, "[%s] merge DONE: %llu records, %llu sparse, %.2f GB, %llds\n", f->name, (unsigned long long)written, (unsigned long long)nsparse,
            (double)(sparse_off + nsparse * (u64)f->sparse) / 1e9, (long long)(time(NULL) - t0));
    return 0;
}
