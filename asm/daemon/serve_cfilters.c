/* daemon/serve_cfilters.c -- BIP157 compact-filter SERVING (getcfilters,
 * getcfheaders, getcfcheckpt).
 *
 * WHY: this node has built a BIP158 filter index for some time, and it is
 * proven byte-identical to Core's. It was simply unreachable: none of the
 * three request messages appeared in bitcoin_serve.asm's dispatch, so a
 * light client asking us for filters got silence. Found 2026-08-28 by
 * validation/p2p_inbound_probe.py, which asked the same three questions of
 * Core (which answers all three) and of this node (which answered none).
 *
 * The serve child holds no filter state -- it is forked per connection, so
 * nothing here needs initialising and nothing is inherited stale, the same
 * reason serve_idx_topup exists one file over. The files are opened ONCE
 * per request rather than per height: going through bfi_get_file cost four
 * open/close pairs per filter, measured at 16.7 filters/s on the live node,
 * i.e. a full minute for one 1000-filter request.
 *
 * Range cap: Core refuses a request spanning more than 1000 blocks
 * (MAX_GETCFILTERS_SIZE) and disconnects. We answer the first 1000 rather
 * than disconnect -- strictly friendlier, and a client that wanted more will
 * ask again from where the answers stopped.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

typedef unsigned char u8;

extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
extern void sha256d(u8* out, const void* data, unsigned long len);
/* height for a block hash, from the serve path's own hash index (main.c) */
extern long serve_height_of_hash(const u8 hash[32]);

/* The filter index's on-disk layout, so one request can open its files ONCE
 * instead of going through bfi_get_file per height. That routine opens both
 * files, and bfi_probe_count opens the index again, and cf_hash_at opened
 * index.dat -- four open/close pairs PER FILTER. Serving the 1000 filters a
 * getcfilters request may span therefore cost ~4000 of them, and measured
 * on the live node that was 16.7 filters/s: a light client waiting a full
 * minute for one request. */
#define BFI_DATA_F "bfilters.dat"
#define BFI_IDX_F  "bfilters.idx"
#define BFI_MAGIC_F "BMCBFIX1"
#define BFI_HDR_F  48
#define BFI_REC_F  48

typedef struct { int idx_fd, dat_fd, blk_fd; long count; } cf_files;

static int cf_open(cf_files* f){
    f->idx_fd = open(BFI_IDX_F, O_RDONLY);
    f->dat_fd = open(BFI_DATA_F, O_RDONLY);
    f->blk_fd = open("index.dat", O_RDONLY);
    f->count  = -1;
    if (f->idx_fd < 0 || f->dat_fd < 0 || f->blk_fd < 0) return 0;
    u8 h[BFI_HDR_F];
    if (pread(f->idx_fd, h, BFI_HDR_F, 0) != BFI_HDR_F) return 0;
    if (memcmp(h, BFI_MAGIC_F, 8) != 0) return 0;
    unsigned long long v = 0;
    for (int i = 0; i < 8; i++) v |= (unsigned long long)h[8+i] << (8*i);
    f->count = (long)v;
    return 1;
}
static void cf_close(cf_files* f){
    if (f->idx_fd >= 0) close(f->idx_fd);
    if (f->dat_fd >= 0) close(f->dat_fd);
    if (f->blk_fd >= 0) close(f->blk_fd);
}
/* one height's filter + its chained header, through the already-open fds */
static int cf_read(cf_files* f, long h, u8* out, unsigned long cap,
                   unsigned long* flen, u8 header[32]){
    if (h < 0 || h >= f->count) return 0;
    u8 r[BFI_REC_F];
    if (pread(f->idx_fd, r, BFI_REC_F, BFI_HDR_F + (long)h * BFI_REC_F) != BFI_REC_F) return 0;
    unsigned long long off = 0; unsigned int len = 0;
    for (int i = 0; i < 8; i++) off |= (unsigned long long)r[i] << (8*i);
    for (int i = 0; i < 4; i++) len |= (unsigned int)r[8+i] << (8*i);
    if (len > cap) return 0;
    if (pread(f->dat_fd, out, len, (long)off) != (long)len) return 0;
    if (header) memcpy(header, r + 16, 32);
    *flen = len;
    return 1;
}
/* the block hash at a height, through the already-open index.dat fd */
static int cf_hash_fd(cf_files* f, long h, u8 out[32]){
    u8 rec[48];
    if (pread(f->blk_fd, rec, 48, (long)h * 48) != 48) return 0;
    int present = 0;
    for (int i = 0; i < 32; i++) if (rec[i]){ present = 1; break; }
    if (!present) return 0;
    memcpy(out, rec, 32);
    return 1;
}

#define CF_BASIC        0            /* BIP158 basic filter type */
#define CF_MAX_RANGE    1000         /* Core MAX_GETCFILTERS_SIZE */
#define CF_MAX_FILTER   (1u << 20)

static unsigned cf_put_varint(u8* p, unsigned long long v){
    if (v < 0xfd){ p[0] = (u8)v; return 1; }
    if (v <= 0xffff){ p[0] = 0xfd; p[1] = (u8)v; p[2] = (u8)(v >> 8); return 3; }
    p[0] = 0xfe;
    for (int i = 0; i < 4; i++) p[1+i] = (u8)(v >> (8*i));
    return 5;
}

/* kind: 0 getcfilters, 1 getcfheaders, 2 getcfcheckpt */
/* -peerblockfilters (Core default 0): serve BIP157 only when asked to, and
 * advertise NODE_COMPACT_FILTERS only then (main.c ORs the bit in). Set
 * before the serve children fork, so every child inherits it. */
int g_cf_serving = 1;   /* tests and tools keep serving; the daemon sets Core's default (0) from the config */
void serve_cfilters_set_enabled(int on){ g_cf_serving = on ? 1 : 0; }
int serve_cfilters(int fd, int kind, const u8* pl, unsigned long plen){
    if (!g_cf_serving) return 0;                 /* Core: the request is ignored */
    if (!pl) return 0;
    /* getcfilters/getcfheaders: type(1) + start(4) + stop_hash(32) = 37
     * getcfcheckpt:             type(1) + stop_hash(32)            = 33 */
    unsigned long need = (kind == 2) ? 33 : 37;
    if (plen < need) return 0;
    if (pl[0] != CF_BASIC) return 0;          /* only the basic filter exists */

    const u8* stop_hash = (kind == 2) ? pl + 1 : pl + 5;
    long stop = serve_height_of_hash(stop_hash);
    if (stop < 0) return 0;                   /* unknown block: no answer, as Core */

    long start = 0;
    if (kind != 2){
        unsigned int s32 = 0;
        for (int i = 0; i < 4; i++) s32 |= (unsigned int)pl[1+i] << (8*i);
        start = (long)s32;
        if (start > stop) return 0;
        if (stop - start + 1 > CF_MAX_RANGE) stop = start + CF_MAX_RANGE - 1;
    }

    static u8 fbuf[CF_MAX_FILTER];
    static u8 out[CF_MAX_FILTER + 64];
    unsigned long flen; u8 header[32];
    cf_files ff;
    if (!cf_open(&ff)){ cf_close(&ff); return 0; }

    if (kind == 0){
        /* one cfilter message per block: type(1) block_hash(32) varint len,
         * then the filter bytes */
        long sent = 0;
        for (long h = start; h <= stop; h++){
            u8 bh[32];
            if (!cf_hash_fd(&ff, h, bh)) break;
            if (!cf_read(&ff, h, fbuf, sizeof fbuf, &flen, header)) break;
            unsigned w = 0;
            out[w++] = CF_BASIC;
            memcpy(out + w, bh, 32); w += 32;
            w += cf_put_varint(out + w, flen);
            memcpy(out + w, fbuf, flen); w += (unsigned)flen;
            if (p2p_write(fd, "cfilter", 7, out, w) <= 0) break;
            sent++;
        }
        cf_close(&ff);
        return (int)sent;
    }

    if (kind == 1){
        /* cfheaders: type(1) stop_hash(32) prev_header(32) varint n,
         * then n filter HASHES (sha256d of the filter bytes) */
        u8 prev[32];
        memset(prev, 0, 32);
        if (start > 0){
            unsigned long pl2; u8 ph[32];
            /* the previous block's filter HEADER is the running hash we
             * chain from; zero at height 0, exactly as BIP157 defines it */
            if (cf_read(&ff, start - 1, fbuf, sizeof fbuf, &pl2, ph)) memcpy(prev, ph, 32);
        }
        unsigned w = 0;
        out[w++] = CF_BASIC;
        memcpy(out + w, stop_hash, 32); w += 32;
        memcpy(out + w, prev, 32);      w += 32;
        long n = stop - start + 1;
        unsigned nw = cf_put_varint(out + w, (unsigned long long)n);
        unsigned hdr_end = w + nw;
        unsigned p = hdr_end;
        long got = 0;
        for (long h = start; h <= stop; h++){
            if (!cf_read(&ff, h, fbuf, sizeof fbuf, &flen, header)) break;
            if (p + 32 > sizeof out) break;
            sha256d(out + p, fbuf, flen);   /* the filter hash, not the header */
            p += 32; got++;
        }
        if (got != n){
            /* answer only what we actually have, with an honest count */
            cf_put_varint(out + w, (unsigned long long)got);
        }
        cf_close(&ff);
        return p2p_write(fd, "cfheaders", 9, out, p) > 0;
    }

    /* kind == 2: cfcheckpt -- type(1) stop_hash(32) varint n, then the
     * filter HEADER at every 1000th block up to stop */
    {
        unsigned w = 0;
        out[w++] = CF_BASIC;
        memcpy(out + w, stop_hash, 32); w += 32;
        long n = stop / 1000;
        unsigned nw = cf_put_varint(out + w, (unsigned long long)n);
        unsigned p = w + nw;
        long got = 0;
        for (long i = 1; i <= n; i++){
            if (!cf_read(&ff, i * 1000, fbuf, sizeof fbuf, &flen, header)) break;
            if (p + 32 > sizeof out) break;
            memcpy(out + p, header, 32); p += 32; got++;
        }
        if (got != n) cf_put_varint(out + w, (unsigned long long)got);
        cf_close(&ff);
        return p2p_write(fd, "cfcheckpt", 9, out, p) > 0;
    }
}
