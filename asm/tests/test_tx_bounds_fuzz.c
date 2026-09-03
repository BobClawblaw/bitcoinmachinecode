/* tests/test_tx_bounds_fuzz.c -- the block-path parsers tx_parse / tx_txid
 * (bitcoin_tx.asm) must never read outside the transaction buffer, for ANY
 * byte string a peer can send -- including the wrapping 8-byte CompactSize
 * class the 2026-09-03 audit flagged (VAL-8 / SER-2).
 *
 * Why guard pages, not a sanitizer. bitcoin_tx.asm is hand-written assembly;
 * ASan cannot instrument it (the same reason test_segwit_bounds_fuzz exists),
 * so a one-byte over-read, or a cursor wrapped BELOW the buffer by a negative
 * CompactSize, is only a hard failure when the adjacent page is unmapped.
 * This harness places every input flush against a PROT_NONE page on BOTH
 * sides:
 *   - the upper guard catches a cursor driven PAST the end (an uncapped
 *     length, or a varint width read off the last byte);
 *   - the lower guard catches a cursor driven BELOW the start -- an 0xff
 *     CompactSize encodes any 64-bit value, so `cursor += LEN` with LEN the
 *     bit pattern of a large negative number wraps the cursor below the
 *     buffer, and the old `cmp rbx,end; ja .fail` passed instead of firing
 *     (rbx < end after the wrap). The mid-copy in tx_txid then read ~1 TiB
 *     below the buffer.
 * The ONLY assertion is survival: a fault is a SIGSEGV of this process, and
 * the harness exiting 0 means no input ever drove a read outside the mapped
 * page. Return values are the parsers' business (test_tx / test_txtxid pin
 * the well-formed paths against Core; test_cons pins the block driver).
 *
 * Inputs: a set of hand-built transactions (legacy + segwit) plus, for each,
 * every truncation 0..len and every single-byte poison at every position with
 * the four bytes that turn a benign compactsize hostile (0xff/0xfe/0xfd/0x00).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

extern int tx_parse(unsigned long long info[8], const void* tx, unsigned long txlen);
extern int tx_txid(unsigned char out[32], const void* tx, unsigned long txlen,
                   unsigned char* buf, unsigned long buflen);

/* ---- a small set of hand-built transactions covering both serializers ---- */
typedef struct { const uint8_t* b; size_t n; } txvec;

static size_t mk_coinbase(uint8_t* p){
    size_t n=0;
    p[n++]=1;p[n++]=0;p[n++]=0;p[n++]=0;         /* version 1 */
    p[n++]=1;                                     /* n_in = 1 */
    memset(p+n,0,32); n+=32;                      /* prevout hash = 0 */
    p[n++]=0xff;p[n++]=0xff;p[n++]=0xff;p[n++]=0xff; /* prevout index */
    p[n++]=4; p[n++]=0x51;p[n++]=0x02;p[n++]=0x00;p[n++]=0x1d; /* scriptSig */
    p[n++]=0xff;p[n++]=0xff;p[n++]=0xff;p[n++]=0xff; /* sequence */
    p[n++]=1;                                     /* n_out = 1 */
    for (int i=0;i<8;i++) p[n++] = (i==0)?0x00:(i<5?0x00:0x00); /* value 50 BTC LE */
    /* 5000000000 sat = 0x012A05F200 */
    n-=8; p[n++]=0x00;p[n++]=0xF2;p[n++]=0x05;p[n++]=0x2A;p[n++]=0x01;p[n++]=0;p[n++]=0;p[n++]=0;
    p[n++]=1; p[n++]=0x51;                        /* spk OP_TRUE */
    p[n++]=0;p[n++]=0;p[n++]=0;p[n++]=0;          /* locktime */
    return n;
}
static size_t mk_segwit(uint8_t* p){
    size_t n=0;
    p[n++]=2;p[n++]=0;p[n++]=0;p[n++]=0;         /* version 2 */
    p[n++]=0x00;p[n++]=0x01;                      /* marker + flag */
    p[n++]=1;                                     /* n_in */
    memset(p+n,0xAA,32); n+=32;
    p[n++]=0;p[n++]=0;p[n++]=0;p[n++]=0;          /* prevout index 0 */
    p[n++]=1; p[n++]=0x51;                        /* scriptSig: push 1 (len1) */
    p[n++]=0xff;p[n++]=0xff;p[n++]=0xff;p[n++]=0xff;
    p[n++]=1;                                     /* n_out */
    for(int i=0;i<8;i++) p[n++]=0x11;             /* value */
    p[n++]=1; p[n++]=0x51;                        /* spk */
    /* witness for the 1 input: 2 items */
    p[n++]=2; p[n++]=1; p[n++]=0x51; p[n++]=1; p[n++]=0x52;
    p[n++]=0;p[n++]=0;p[n++]=0;p[n++]=0;          /* locktime */
    return n;
}
static size_t mk_big_varint(uint8_t* p){
    /* n_out uses a 0xfd 3-byte count (257 outputs) with tiny 9-byte outs, so
     * the n_out loop runs; exercises the width-checked n_out + output walk. */
    size_t n=0;
    p[n++]=1;p[n++]=0;p[n++]=0;p[n++]=0;
    p[n++]=1; memset(p+n,0,32); n+=32;
    p[n++]=0xff;p[n++]=0xff;p[n++]=0xff;p[n++]=0xff;
    p[n++]=1; p[n++]=0x51;
    p[n++]=0xff;p[n++]=0xff;p[n++]=0xff;p[n++]=0xff;
    p[n++]=0xfd; p[n++]=0x01; p[n++]=0x01;         /* n_out = 257 (0xfd form) */
    for (int o=0;o<257;o++){
        for(int i=0;i<8;i++) p[n++]=0x22;           /* value */
        p[n++]=1; p[n++]=0x51;                       /* spk */
    }
    p[n++]=0;p[n++]=0;p[n++]=0;p[n++]=0;
    return n;
}

/* ---- a region whose usable page is bounded by PROT_NONE on both sides ---- */
static uint8_t* g_region;      /* start of the lower guard page (returned by mmap) */
static size_t   g_datacap;     /* bytes usable in the middle (mapped) page */
static size_t   g_pagesz;

/* The mapped data page starts one guard-page into the region. */
static uint8_t* put_upper(const uint8_t* src, size_t n){
    uint8_t* p = g_region + g_pagesz + g_datacap - n;
    memcpy(p, src, n);
    return p;
}
/* A cursor driven below the data page faults on the lower guard. */
static uint8_t* put_lower(const uint8_t* src, size_t n){
    uint8_t* p = g_region + g_pagesz;
    memcpy(p, src, n);
    return p;
}

static const uint8_t POISON[4] = { 0xff, 0xfe, 0xfd, 0x00 };

int main(void){
    g_pagesz = (size_t)sysconf(_SC_PAGESIZE);
    g_datacap = g_pagesz;
    /* [guard][data][guard] */
    size_t total = 3 * g_pagesz;
    g_region = (uint8_t*)mmap(0, total, PROT_READ|PROT_WRITE,
                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (g_region == MAP_FAILED){ perror("mmap"); return 1; }
    if (mprotect(g_region, g_pagesz, PROT_NONE)){ perror("mprotect lo"); return 1; }
    if (mprotect(g_region + 2*g_pagesz, g_pagesz, PROT_NONE)){ perror("mprotect hi"); return 1; }

    /* gather the vectors */
    static uint8_t cb[512], sw[256], bv[8192];
    txvec vecs[3];
    vecs[0].b = cb; vecs[0].n = mk_coinbase(cb);
    vecs[1].b = sw; vecs[1].n = mk_segwit(sw);
    vecs[2].b = bv; vecs[2].n = mk_big_varint(bv);

    unsigned char out[32];
    /* tx_txid scratch buffer, comfortably large (its own bound is checked in
     * test_txtxid; here we only care that the SCAN never leaves the input). */
    static uint8_t txbuf[8192];

    unsigned long long ncall = 0;

    /* For every input we drive both guard placements (upper for over-read,
     * lower for the wrap-below) and, for tx_txid, its reconstruction path. */
    for (int vi=0; vi<3; vi++){
        const uint8_t* full = vecs[vi].b;
        size_t len = vecs[vi].n;

        /* every truncation, both guard sides */
        for (size_t L=0; L<=len; L++){
            const uint8_t* up = put_upper(full, L);
            unsigned long long info[8];
            tx_parse(info, up, (unsigned long)L);
            tx_txid(out, up, (unsigned long)L, txbuf, sizeof txbuf);
            const uint8_t* lo = put_lower(full, L);
            tx_parse(info, lo, (unsigned long)L);
            tx_txid(out, lo, (unsigned long)L, txbuf, sizeof txbuf);
            ncall += 4;
        }
        /* single-byte poison at every position, both guard sides */
        for (size_t pos=0; pos<len; pos++){
            uint8_t save = full[pos];
            for (int pi=0; pi<4; pi++){
                uint8_t* mut = (uint8_t*)malloc(len);
                memcpy(mut, full, len); mut[pos] = POISON[pi];
                const uint8_t* up = put_upper(mut, len);
                const uint8_t* lo = put_lower(mut, len);
                unsigned long long info[8];
                tx_parse(info, up, (unsigned long)len);
                tx_txid(out, up, (unsigned long)len, txbuf, sizeof txbuf);
                tx_parse(info, lo, (unsigned long)len);
                tx_txid(out, lo, (unsigned long)len, txbuf, sizeof txbuf);
                /* and every truncation of the poisoned buffer too */
                for (size_t L=0; L<=len; L++){
                    const uint8_t* u2 = put_upper(mut, L);
                    const uint8_t* l2 = put_lower(mut, L);
                    tx_parse(info, u2, (unsigned long)L);
                    tx_parse(info, l2, (unsigned long)L);
                    ncall += 2;
                }
                ncall += 4;
                free(mut);
            }
            (void)save;
        }
    }

    /* explicit wrap vectors: a well-formed prefix whose next varint is an
     * 0xff encoding a large negative number, positioned so the wrapped
     * cursor lands below a lower guard. */
    {
        uint8_t w[256]; size_t n=0;
        w[n++]=1;w[n++]=0;w[n++]=0;w[n++]=0;   /* version */
        w[n++]=1;                               /* n_in */
        memset(w+n,0,32); n+=32;
        w[n++]=0xff;w[n++]=0xff;w[n++]=0xff;w[n++]=0xff; /* index */
        /* scriptlen = 0xff, payload = a negative offset that wraps the cursor
         * far below the buffer start */
        w[n++]=0xff;
        int64_t wrap = -((int64_t)g_pagesz*4);   /* below the lower guard */
        memcpy(w+n,&wrap,8); n+=8;
        unsigned long long info[8];
        (void)tx_parse(info, put_lower(w,n), (unsigned long)n);
        ncall++;
    }

    printf("tx bounds fuzz: %llu guarded parse calls survived (0 faults)\n", ncall);
    printf("ALL TESTS PASSED (0 failures)\n");
    return 0;   /* reaching here at all means no input caused an OOB read */
}
