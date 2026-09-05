/* daemon/addrbook.c -- see addrbook.h. */
#include <stdio.h>
#include "log_ts.h"   /* timestamped fprintf(stderr), like every other daemon line */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include "addrbook.h"

#define AB2_MAGIC     "BMCADBK3"
#define AB2_MAGIC_V2  "BMCADBK2"      /* upgraded in place on first open */
#define AB2_REC_V2    48
#define AB2_HDR   16
#define AB2_HASH  (AB2_MAX * 2)          /* open addressing, load <= 0.5 */

struct ab2 {
    int       fd, rw;
    long      n;
    long      mtime, size;      /* what the last load() saw (ab2_refresh) */
    ab2_rec_t* recs;                     /* AB2_MAX */
    int*      hash;                      /* AB2_HASH slots: index+1, 0 = empty */
    char      path[512];
};

static unsigned long long key_hash(const bmc_addr_t* a){
    unsigned long long h = 1469598103934665603ULL;
    h ^= a->net; h *= 1099511628211ULL;
    for (int i = 0; i < a->len; i++){ h ^= a->addr[i]; h *= 1099511628211ULL; }
    h ^= a->port; h *= 1099511628211ULL;
    return h;
}
static void hash_insert(ab2_t* b, long idx){
    unsigned long long h = key_hash(&b->recs[idx].a);
    for (unsigned long s = (unsigned long)(h % AB2_HASH);; s = (s + 1) % AB2_HASH)
        if (b->hash[s] == 0){ b->hash[s] = (int)idx + 1; return; }
}
static void hash_rebuild(ab2_t* b){
    memset(b->hash, 0, sizeof(int) * AB2_HASH);
    for (long i = 0; i < b->n; i++) hash_insert(b, i);
}
static long g_src_cap = AB2_SRC_CAP;
void ab2_set_src_cap(long cap){ g_src_cap = cap > 0 ? cap : AB2_SRC_CAP; }
static long g_capacity = AB2_MAX;
void ab2_set_capacity(long cap){ g_capacity = (cap > 0 && cap < AB2_MAX) ? cap : AB2_MAX; }

long ab2_count_src(const ab2_t* b, unsigned src_group){
    if (!b || !src_group) return 0;
    long c = 0;
    for (long i = 0; i < b->n; i++) if (b->recs[i].src_group == src_group) c++;
    return c;
}

/* NET-10 rule 3. "Terrible" without Core's last-try/attempt counters: an
 * address nobody has seen for a fortnight. Only ever consulted for UNTRIED
 * entries, so a peer we have actually connected to is never called terrible
 * on the strength of a gossiped timestamp. */
#define AB2_TERRIBLE_AGE (14*24*3600u)
static int ab2_terrible(const ab2_rec_t* r, unsigned now){
    return r->last_seen + AB2_TERRIBLE_AGE < now;
}

long ab2_find(const ab2_t* b, const bmc_addr_t* a){
    unsigned long long h = key_hash(a);
    for (unsigned long s = (unsigned long)(h % AB2_HASH);; s = (s + 1) % AB2_HASH){
        int v = b->hash[s]; if (!v) return -1;
        if (bmc_addr_equal(&b->recs[v-1].a, a)) return v - 1;
    }
}
static void rec_pack(unsigned char o[AB2_REC], const ab2_rec_t* r){
    memset(o, 0, AB2_REC);
    o[0] = r->a.net; o[1] = r->a.len; memcpy(o + 2, r->a.addr, 32);
    o[34] = (unsigned char)(r->a.port >> 8); o[35] = (unsigned char)r->a.port;
    for (int i = 0; i < 8; i++) o[36+i] = (unsigned char)(r->services >> (8*i));
    for (int i = 0; i < 4; i++) o[44+i] = (unsigned char)(r->last_seen >> (8*i));
    for (int i = 0; i < 4; i++) o[48+i] = (unsigned char)(r->src_group >> (8*i));
    o[52] = r->flags;
}
static int rec_unpack(ab2_rec_t* r, const unsigned char o[AB2_REC]){
    memset(r, 0, sizeof *r);
    r->a.net = o[0]; r->a.len = o[1];
    if (bmc_net_addrlen(r->a.net) != r->a.len) return 0;
    memcpy(r->a.addr, o + 2, 32);
    r->a.port = (unsigned short)((o[34] << 8) | o[35]);
    for (int i = 0; i < 8; i++) r->services |= (unsigned long long)o[36+i] << (8*i);
    for (int i = 0; i < 4; i++) r->last_seen |= (unsigned)o[44+i] << (8*i);
    for (int i = 0; i < 4; i++) r->src_group |= (unsigned)o[48+i] << (8*i);
    r->flags = o[52];
    return 1;
}
static int write_rec(ab2_t* b, long idx){
    unsigned char o[AB2_REC]; rec_pack(o, &b->recs[idx]);
    return pwrite(b->fd, o, AB2_REC, AB2_HDR + idx * AB2_REC) == AB2_REC;
}
static int write_count(ab2_t* b){
    unsigned char c[4]; for (int i = 0; i < 4; i++) c[i] = (unsigned char)(b->n >> (8*i));
    return pwrite(b->fd, c, 4, 8) == 4;
}
/* NET-10: rewrite a version-2 file (48-byte records, no source, no tried) as
 * version 3 in place. Every record survives. The first AB2_V2_TRIED_HEAD IPv4
 * entries are marked tried: the head of a v2 book is the migrated,
 * once-connected set, which is precisely what dl_pool_from_book's
 * DL_POOL_V4_WINDOW heuristic already trusts -- so the upgrade preserves
 * today's dial behaviour instead of silently discarding it. Everything else
 * arrived by gossip and starts untried. */
#define AB2_V2_TRIED_HEAD 4096
static int upgrade_v2(ab2_t* b){
    struct stat st; if (fstat(b->fd, &st) != 0) return 0;
    long n = (st.st_size - AB2_HDR) / AB2_REC_V2;
    if (n < 0) n = 0;
    if (n > AB2_MAX) n = AB2_MAX;
    ab2_rec_t* tmp = calloc((size_t)(n > 0 ? n : 1), sizeof *tmp);
    if (!tmp) return 0;
    long got = 0, tried = 0;
    for (long i = 0; i < n; i++){
        unsigned char o[AB2_REC]; memset(o, 0, sizeof o);
        if (pread(b->fd, o, AB2_REC_V2, AB2_HDR + i * AB2_REC_V2) != AB2_REC_V2) break;
        if (!rec_unpack(&tmp[got], o)) continue;     /* the v3 tail reads as zero: src 0, untried */
        if (tmp[got].a.net == BMC_NET_IPV4 && i < AB2_V2_TRIED_HEAD){ tmp[got].flags |= AB2_F_TRIED; tried++; }
        got++;
    }
    if (ftruncate(b->fd, AB2_HDR) != 0){ free(tmp); return 0; }
    unsigned char h[AB2_HDR]; memset(h, 0, sizeof h); memcpy(h, AB2_MAGIC, 8);
    if (pwrite(b->fd, h, AB2_HDR, 0) != AB2_HDR){ free(tmp); return 0; }
    for (long i = 0; i < got; i++){
        unsigned char o[AB2_REC]; rec_pack(o, &tmp[i]);
        if (pwrite(b->fd, o, AB2_REC, AB2_HDR + i * AB2_REC) != AB2_REC){ free(tmp); return 0; }
    }
    unsigned char c[4]; for (int i = 0; i < 4; i++) c[i] = (unsigned char)(got >> (8*i));
    if (pwrite(b->fd, c, 4, 8) != 4){ free(tmp); return 0; }
    free(tmp);
    fprintf(stderr, "[addrbook] upgraded peers2.dat to BMCADBK3: %ld record(s), %ld marked tried\n", got, tried);
    return 1;
}

/* A READ-ONLY opener of a not-yet-upgraded v2 file parses it in memory at the
 * v2 stride instead of failing. Without this, on the single boot where the
 * file is still v2 the serve children and the RPC parent would get NULL from
 * ab2_open (no address book at all) until the writer got round to upgrading
 * -- a real, if brief, degradation for a format change that is supposed to be
 * invisible. Nothing is written here; the writer still performs the upgrade. */
static long load_v2_readonly(ab2_t* b, const unsigned char h[AB2_HDR]){
    struct stat st; if (fstat(b->fd, &st) != 0) return -1;
    long by_size = (st.st_size - AB2_HDR) / AB2_REC_V2;
    long by_hdr = (long)h[8] | ((long)h[9] << 8) | ((long)h[10] << 16) | ((long)h[11] << 24);
    long n = by_hdr < by_size ? by_hdr : by_size;
    if (n > AB2_MAX) n = AB2_MAX;
    if (n < 0) n = 0;
    b->n = 0;
    for (long i = 0; i < n; i++){
        unsigned char o[AB2_REC]; memset(o, 0, sizeof o);
        if (pread(b->fd, o, AB2_REC_V2, AB2_HDR + i * AB2_REC_V2) != AB2_REC_V2) break;
        if (!rec_unpack(&b->recs[b->n], o)) continue;   /* the v3 tail reads as zero */
        if (ab2_find(b, &b->recs[b->n].a) >= 0) continue;
        if (b->recs[b->n].a.net == BMC_NET_IPV4 && i < AB2_V2_TRIED_HEAD)
            b->recs[b->n].flags |= AB2_F_TRIED;         /* same head rule as the upgrade */
        hash_insert(b, b->n); b->n++;
    }
    return b->n;
}

static long load(ab2_t* b){
    unsigned char h[AB2_HDR];
    if (pread(b->fd, h, AB2_HDR, 0) != AB2_HDR) return -1;
    if (!memcmp(h, AB2_MAGIC_V2, 8)){
        if (!b->rw) return load_v2_readonly(b, h);
        if (!upgrade_v2(b)) return -1;
    }
    if (pread(b->fd, h, AB2_HDR, 0) != AB2_HDR || memcmp(h, AB2_MAGIC, 8)) return -1;
    struct stat st; if (fstat(b->fd, &st) != 0) return -1;
    long by_size = (st.st_size - AB2_HDR) / AB2_REC;
    long by_hdr = (long)h[8] | ((long)h[9] << 8) | ((long)h[10] << 16) | ((long)h[11] << 24);
    long n = by_hdr < by_size ? by_hdr : by_size;      /* trust the smaller (torn tail) */
    if (n > AB2_MAX) n = AB2_MAX;
    b->n = 0;
    for (long i = 0; i < n; i++){
        unsigned char o[AB2_REC];
        if (pread(b->fd, o, AB2_REC, AB2_HDR + i * AB2_REC) != AB2_REC) break;
        if (!rec_unpack(&b->recs[b->n], o)) continue;      /* corrupt record: skip */
        if (ab2_find(b, &b->recs[b->n].a) >= 0) continue;   /* duplicate: skip */
        hash_insert(b, b->n); b->n++;
    }
    return b->n;
}
long ab2_migrate_legacy(ab2_t* b, const char* legacy_path){
    int fd = open(legacy_path, O_RDONLY); if (fd < 0) return 0;
    unsigned char r[18]; long added = 0;
    while (read(fd, r, 18) == 18){
        bmc_addr_t a; memset(&a, 0, sizeof a);
        a.net = BMC_NET_IPV4; a.len = 4; memcpy(a.addr, r, 4);
        a.port = (unsigned short)((r[4] << 8) | r[5]);               /* legacy book: BE on disk */
        unsigned long long svc = 0; for (int i = 0; i < 8; i++) svc |= (unsigned long long)r[6+i] << (8*i);
        unsigned seen = (unsigned)r[14] | ((unsigned)r[15] << 8) | ((unsigned)r[16] << 16) | ((unsigned)r[17] << 24);
        if (!bmc_addr_is_routable(&a)) continue;                     /* the old book carried garbage */
        /* NET-10: the legacy book is the once-connected set -- exactly what
         * dl_pool_from_book's head-window heuristic stands in for today. Mark
         * it tried so eviction cannot take it. */
        if (ab2_add(b, &a, svc, seen) > 0){ ab2_mark_tried(b, &a); added++; }
    }
    close(fd);
    return added;
}
ab2_t* ab2_open(const char* dir, int rw){
    ab2_t* b = calloc(1, sizeof *b); if (!b) return NULL;
    b->recs = calloc(AB2_MAX, sizeof *b->recs); b->hash = calloc(AB2_HASH, sizeof *b->hash);
    if (!b->recs || !b->hash){ ab2_close(b); return NULL; }
    snprintf(b->path, sizeof b->path, "%s/peers2.dat", dir);
    b->rw = rw;
    b->fd = open(b->path, rw ? O_RDWR : O_RDONLY);
    if (b->fd < 0 && rw){
        b->fd = open(b->path, O_RDWR | O_CREAT | O_EXCL, 0644);
        if (b->fd < 0){ ab2_close(b); return NULL; }
        unsigned char h[AB2_HDR]; memset(h, 0, sizeof h); memcpy(h, AB2_MAGIC, 8);
        if (pwrite(b->fd, h, AB2_HDR, 0) != AB2_HDR){ ab2_close(b); return NULL; }
        char legacy[512]; snprintf(legacy, sizeof legacy, "%s/peers.dat", dir);
        long m = ab2_migrate_legacy(b, legacy);
        if (m > 0) fprintf(stderr, "[addrbook] migrated %ld IPv4 address(es) from the legacy peers.dat into peers2.dat\n", m);
        return b;
    }
    if (b->fd < 0){ ab2_close(b); return NULL; }
    if (load(b) < 0){
        /* A short or unrecognised file: on the WRITE side re-create it (the
         * creation of peers2.dat is not atomic, so a kill or ENOSPC between
         * creat and the header write leaves a 0-byte file that would
         * otherwise disable the book on every boot for ever). A reader just
         * fails -- the writer will fix it. (2026-08-28 review.) */
        if (!rw){ ab2_close(b); return NULL; }
        fprintf(stderr, "[addrbook] %s is unreadable (%ld bytes) -- rebuilding it\n",
                b->path, (long)lseek(b->fd, 0, SEEK_END));
        char aside[600]; snprintf(aside, sizeof aside, "%s.bad", b->path);
        rename(b->path, aside);                       /* keep it for forensics, as Core does */
        close(b->fd);
        b->fd = open(b->path, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (b->fd < 0){ ab2_close(b); return NULL; }
        unsigned char h[AB2_HDR]; memset(h, 0, sizeof h); memcpy(h, AB2_MAGIC, 8);
        if (pwrite(b->fd, h, AB2_HDR, 0) != AB2_HDR){ ab2_close(b); return NULL; }
        b->n = 0;
        char legacy[600]; snprintf(legacy, sizeof legacy, "%.*speers.dat", (int)(strlen(b->path) - strlen("peers2.dat")), b->path);
        long m = ab2_migrate_legacy(b, legacy);
        if (m > 0) fprintf(stderr, "[addrbook] re-migrated %ld address(es) from the legacy peers.dat\n", m);
    }
    { struct stat st; if (fstat(b->fd, &st) == 0){ b->mtime = st.st_mtime; b->size = st.st_size; } }
    return b;
}
void ab2_close(ab2_t* b){
    if (!b) return;
    if (b->fd >= 0) close(b->fd);
    free(b->recs); free(b->hash); free(b);
}
long ab2_count(const ab2_t* b){ return b ? b->n : 0; }
long ab2_count_net(const ab2_t* b, int net){
    long c = 0; for (long i = 0; i < b->n; i++) if (b->recs[i].a.net == net) c++; return c;
}
int ab2_get(const ab2_t* b, long i, ab2_rec_t* out){
    if (!b || i < 0 || i >= b->n) return 0;
    *out = b->recs[i];
    return 1;
}
int ab2_mark_tried(ab2_t* b, const bmc_addr_t* a){
    if (!b || !b->rw) return 0;
    long i = ab2_find(b, a);
    if (i < 0) return 0;
    if (b->recs[i].flags & AB2_F_TRIED) return 1;
    b->recs[i].flags |= AB2_F_TRIED;
    return write_rec(b, i) ? 1 : 0;
}

/* NET-10 rule 2 + rule 3: choose a victim. Never a tried entry while any
 * untried one exists; among the untried prefer a terrible one, then the
 * oldest. Returns -1 when every entry is tried, in which case the caller
 * refuses the insert rather than dropping a peer we have connected to. */
static long ab2_victim(const ab2_t* b, unsigned now){
    long best = -1; int best_terrible = 0;
    for (long k = 0; k < b->n; k++){
        if (b->recs[k].flags & AB2_F_TRIED) continue;
        int t = ab2_terrible(&b->recs[k], now);
        if (best < 0){ best = k; best_terrible = t; continue; }
        if (t && !best_terrible){ best = k; best_terrible = 1; continue; }
        if (t == best_terrible && b->recs[k].last_seen < b->recs[best].last_seen) best = k;
    }
    return best;
}

int ab2_add_from(ab2_t* b, const bmc_addr_t* a, unsigned long long services,
                 unsigned last_seen, unsigned src_group){
    if (!b || !b->rw) return -1;
    if (bmc_net_addrlen(a->net) != a->len) return -1;
    long i = ab2_find(b, a);
    if (i >= 0){
        int changed = 0;
        if (last_seen > b->recs[i].last_seen){ b->recs[i].last_seen = last_seen; changed = 1; }
        if (services && services != b->recs[i].services){ b->recs[i].services = services; changed = 1; }
        if (changed) write_rec(b, i);
        return 0;
    }
    /* NET-10 rule 1: one source netgroup may hold at most g_src_cap live
     * entries. This is the rule that actually defeats the flood -- the others
     * decide WHO gets evicted, this one stops the eviction happening at all.
     * A source of 0 (our seeds, the legacy migration, addnode) is not capped. */
    if (src_group && ab2_count_src(b, src_group) >= g_src_cap) return 0;
    unsigned now = (unsigned)time(NULL);
    if (b->n >= g_capacity){
        long v = ab2_victim(b, now);
        if (v < 0) return 0;                  /* every entry is tried: keep them */
        b->recs[v].a = *a; b->recs[v].services = services; b->recs[v].last_seen = last_seen;
        b->recs[v].src_group = src_group; b->recs[v].flags = 0;
        hash_rebuild(b);
        return write_rec(b, v) ? 1 : -1;
    }
    i = b->n;
    b->recs[i].a = *a; b->recs[i].services = services; b->recs[i].last_seen = last_seen;
    b->recs[i].src_group = src_group; b->recs[i].flags = 0;
    if (!write_rec(b, i)) return -1;
    b->n++; hash_insert(b, i);
    return write_count(b) ? 1 : -1;
}

int ab2_add(ab2_t* b, const bmc_addr_t* a, unsigned long long services, unsigned last_seen){
    return ab2_add_from(b, a, services, last_seen, 0);
}
/* Re-read the file when the writer has touched it. A grown file is the
 * common case, but the worker also REWRITES records in place (last_seen /
 * services refresh, and eviction when the book is full), which changes no
 * size -- so mtime decides, not length (2026-08-28 review: the RPC parent
 * and the serve children served a stale book indefinitely). */
int ab2_refresh(ab2_t* b){
    if (!b) return 0;
    struct stat st; if (fstat(b->fd, &st) != 0) return 0;
    if (st.st_mtime == b->mtime && st.st_size == b->size) return 1;
    b->mtime = st.st_mtime; b->size = st.st_size;
    memset(b->hash, 0, sizeof(int) * AB2_HASH);
    return load(b) >= 0;
}
