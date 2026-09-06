#include <string.h>
#include <stdio.h>
#include "ibd_pipeline.h"

#define IBD_PIPE_MAX 256          /* chunk sizes in use are 40; the cap bounds the stack arrays */

/* These MUST match daemon/main.c's declarations exactly -- there is no shared
 * header for them, so a mismatch links cleanly and misbehaves at run time.
 * The first cut of this file declared cons_verify with two parameters (it
 * takes four) and p2p_read as returning long (it returns int, so the high 32
 * bits of the register are garbage): every chunk failed, the download wrote
 * zero blocks, and only the real fixture caught it -- the unit test could
 * not, because its stubs matched the wrong declarations. */
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
extern int  p2p_read(int fd, char cmd[12], void* pl, unsigned cap, unsigned* len);
extern int  hst_get_at(void* hst, unsigned long long idx, void* rec112);
extern int  cons_verify(const void* block, long len, void* scratch, unsigned cap);
extern void block_hash(unsigned char out[32], const unsigned char* hdr80);
extern long store_append_shared(void* st, long height, const unsigned char hash[32],
                                const unsigned char* raw, unsigned len);

static long g_last_batch = 0;
long ibd_pipeline_last_batch(void){ return g_last_batch; }
static long g_wave = 0;                  /* 0 = the whole chunk in one getdata */
void ibd_pipeline_set_wave(long n){ g_wave = (n > 0 && n < IBD_PIPE_MAX) ? n : 0; }

/* CompactSize for a count < 253 (the only sizes this builds: <= IBD_PIPE_MAX). */
static unsigned build_getdata(unsigned char* out, const unsigned char hashes[][32], long n)
{
    unsigned p = 0;
    out[p++] = (unsigned char)n;                     /* inventory count */
    for (long i = 0; i < n; i++){
        out[p++] = 0x02; out[p++] = 0x00; out[p++] = 0x00; out[p++] = 0x40;  /* MSG_WITNESS_BLOCK, LE */
        memcpy(out + p, hashes[i], 32); p += 32;
    }
    return p;
}

long ibd_fetch_chunk_pipelined(int fd, void* st, void* hst, long lo_real, long nloc,
                               unsigned char* buf, unsigned buflen,
                               void* scratch, unsigned scratch_cap)
{
    if (nloc <= 0 || nloc > IBD_PIPE_MAX) return -1;
    static unsigned char want[IBD_PIPE_MAX][32];     /* the chunk's block hashes, by local index */
    static unsigned char prev[IBD_PIPE_MAX][32];     /* each block's expected prevhash */
    static unsigned char got[IBD_PIPE_MAX];
    static unsigned char gd[1 + IBD_PIPE_MAX * 36];
    unsigned char rec[112];

    for (long i = 0; i < nloc; i++){
        if (hst_get_at(hst, (unsigned long long)i, rec) != 1) return -1;
        memcpy(want[i], rec + 80, 32);               /* the header store keeps the block hash at +80 */
        memcpy(prev[i], rec + 4, 32);                /* prevhash inside the 80-byte header */
        got[i] = 0;
    }

    long stored = 0;
    long wave = g_wave > 0 ? g_wave : nloc;      /* one message for the chunk, unless a bench asks otherwise */
    long sent_to = 0;                            /* hashes requested so far */
    /* Every message the peer sends until the chunk is complete. The bound is
     * generous because a peer may interleave inv/addr/ping traffic, but it is
     * finite: a peer that never completes the chunk trips it and is dropped,
     * exactly as the serial path's own skip budget did. */
    long budget = nloc * 8 + 256;
    while (stored < nloc && budget-- > 0){
        if (sent_to < nloc && stored >= sent_to - wave + 1){    /* keep `wave` hashes outstanding */
            long take = nloc - sent_to; if (take > wave) take = wave;
            unsigned glen = build_getdata(gd, (const unsigned char (*)[32])(want + sent_to), take);
            g_last_batch = take;
            if (p2p_write(fd, "getdata", 7, gd, glen) < 0) return -1;
            sent_to += take;
        }
        char cmd[12]; unsigned len = 0;
        int r = p2p_read(fd, cmd, buf, buflen, &len);
        if (r <= 0) return -1;
        if (!strncmp(cmd, "ping", 12) && len == 8){ p2p_write(fd, "pong", 4, buf, 8); continue; }
        if (strncmp(cmd, "block", 12) != 0) continue;         /* inv, addr, feefilter, ... */
        if (len < 81) continue;

        if (cons_verify(buf, (long)len, scratch, scratch_cap) != 1) return -1;   /* same gate, same scratch, as the serial path */
        unsigned char bh[32];
        block_hash(bh, buf);

        long idx = -1;
        for (long i = 0; i < nloc; i++) if (!got[i] && memcmp(bh, want[i], 32) == 0){ idx = i; break; }
        if (idx < 0) continue;   /* a block we did not ask for, or a duplicate: drain it */

        /* the chain link, checked against the HEADERS (already linked and
         * PoW-checked by the header phase), so an out-of-order arrival is
         * verified as strictly as an in-order one. */
        if (idx > 0 && memcmp(buf + 4, want[idx - 1], 32) != 0) return -1;
        if (memcmp(buf + 4, prev[idx], 32) != 0) return -1;

        if (store_append_shared(st, lo_real + idx, bh, buf, len) < 0) return -1;
        got[idx] = 1; stored++;
    }
    return stored == nloc ? stored : -1;
}
