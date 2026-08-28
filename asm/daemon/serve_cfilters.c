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
 * The lookups are stateless on purpose: bfi_get_file opens the index by
 * name, reads one record, and closes. A serve child is forked per
 * connection and holds no filter state, so nothing here needs initialising
 * and nothing is inherited stale -- the same reason serve_idx_topup exists
 * one file over.
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
extern int  bfi_get_file(long h, u8* out, unsigned long cap, unsigned long* flen, u8 header[32]);
extern void sha256d(u8* out, const void* data, unsigned long len);
/* height for a block hash, from the serve path's own hash index (main.c) */
extern long serve_height_of_hash(const u8 hash[32]);

#define CF_BASIC        0            /* BIP158 basic filter type */
#define CF_MAX_RANGE    1000         /* Core MAX_GETCFILTERS_SIZE */
#define CF_MAX_FILTER   (1u << 20)

/* the block hash at height h, straight out of index.dat's 48-byte records
 * (first 32 bytes are the hash, in WIRE order -- verified 2026-08-27, the
 * day a loader that assumed DISPLAY order was found to have made this node
 * unable to serve any block at all) */
static int cf_hash_at(long h, u8 out[32]){
    int fd = open("index.dat", O_RDONLY);
    if (fd < 0) return 0;
    u8 rec[48];
    int ok = (pread(fd, rec, 48, (long)h * 48) == 48);
    close(fd);
    if (!ok) return 0;
    int present = 0;
    for (int i = 0; i < 32; i++) if (rec[i]){ present = 1; break; }
    if (!present) return 0;
    memcpy(out, rec, 32);
    return 1;
}

static unsigned cf_put_varint(u8* p, unsigned long long v){
    if (v < 0xfd){ p[0] = (u8)v; return 1; }
    if (v <= 0xffff){ p[0] = 0xfd; p[1] = (u8)v; p[2] = (u8)(v >> 8); return 3; }
    p[0] = 0xfe;
    for (int i = 0; i < 4; i++) p[1+i] = (u8)(v >> (8*i));
    return 5;
}

/* kind: 0 getcfilters, 1 getcfheaders, 2 getcfcheckpt */
int serve_cfilters(int fd, int kind, const u8* pl, unsigned long plen){
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

    if (kind == 0){
        /* one cfilter message per block: type(1) block_hash(32) varint len,
         * then the filter bytes */
        long sent = 0;
        for (long h = start; h <= stop; h++){
            u8 bh[32];
            if (!cf_hash_at(h, bh)) break;
            if (!bfi_get_file(h, fbuf, sizeof fbuf, &flen, header)) break;
            unsigned w = 0;
            out[w++] = CF_BASIC;
            memcpy(out + w, bh, 32); w += 32;
            w += cf_put_varint(out + w, flen);
            memcpy(out + w, fbuf, flen); w += (unsigned)flen;
            if (p2p_write(fd, "cfilter", 7, out, w) <= 0) break;
            sent++;
        }
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
            if (bfi_get_file(start - 1, fbuf, sizeof fbuf, &pl2, ph)) memcpy(prev, ph, 32);
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
            if (!bfi_get_file(h, fbuf, sizeof fbuf, &flen, header)) break;
            if (p + 32 > sizeof out) break;
            sha256d(out + p, fbuf, flen);   /* the filter hash, not the header */
            p += 32; got++;
        }
        if (got != n){
            /* answer only what we actually have, with an honest count */
            cf_put_varint(out + w, (unsigned long long)got);
        }
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
            if (!bfi_get_file(i * 1000, fbuf, sizeof fbuf, &flen, header)) break;
            if (p + 32 > sizeof out) break;
            memcpy(out + p, header, 32); p += 32; got++;
        }
        if (got != n) cf_put_varint(out + w, (unsigned long long)got);
        return p2p_write(fd, "cfcheckpt", 9, out, p) > 0;
    }
}
