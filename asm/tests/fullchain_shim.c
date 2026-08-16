/* fullchain_shim.c - batch consensus differential harness for the FULL-CHAIN
 * run (validation/fullchain_diff.py).
 *
 * Same trust model as consensus_shim.c (links the SAME asm objects, calls the
 * SAME cons_verify / block_hash / pow_check / tx_parse / tx_txid), but a
 * non-interactive BATCH protocol tuned for one process to chew through tens
 * of thousands of blocks without the per-block process-launch overhead:
 *
 *   stdin:  a sequence of raw frames, each:  <len:4 LE> <block bytes: len>
 *           (the EXACT framing Core uses in its blk*.dat block files)
 *   stdout: one compact verdict line per frame, flushed once per frame:
 *           A<0|1> H<64 hex of the ASM block_hash, little-endian digest
 *              bytes, matching consensus_shim's "OK 1 <le32hex>" convention>
 *              P<0|1> N<tx count from the wire varint>
 *
 *   A = cons_verify verdict (1 = the ASM consensus stack ACCEPTS the block:
 *       PoW + merkle + coinbase + tx-parse walk + txid/merkle-root agreement)
 *   H = ASM block_hash of the 80-byte header
 *   P = pow_check(header) direct verdict
 *   N = tx count as encoded by the block's wire varint (0 = undecodable)
 *
 * A frame shorter than 81 bytes or with len > MAX_BLOCK (4,000,000, the
 * MAX_BLOCK_SERIALIZED_SIZE consensus limit) yields an error verdict
 * "ERR <n>" (n = the offending len) instead of a crash, so one corrupt
 * frame can never take the sweep down; the Python side treats ERR as an
 * infrastructure failure and degrades it.
 *
 * Static buffers (BSS, not the 8MB default stack), same sizing rationale as
 * consensus_shim.c: a 4MB block is 4,000,000 bytes, and cons_verify allocates
 * 1MB of its own scratch per call + 64MB txid scratch + 1MB tx_txid scratch.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

extern int  cons_verify(const void* block, unsigned long len, void* txid_scratch, unsigned long cap);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern int  pow_check(const unsigned char hdr[80]);

#define MAX_BLOCK 4000000UL

static unsigned char* bbuf;
static unsigned char* scratch;

static void hex(const unsigned char* b, long n){
    static const char* d="0123456789abcdef";
    for(long i=0;i<n;i++){ putchar(d[b[i]>>4]); putchar(d[b[i]&15]); }
}

/* Read exactly n bytes from fd (raw framing, no newline assumptions). */
static int read_n(int fd, void* dst, size_t n){
    unsigned char* p = dst;
    while(n){
        ssize_t r = read(fd, p, n);
        if(r <= 0) return (r == 0) ? 0 : -1;   /* -1 = mid-frame EOF/err */
        p += r; n -= (size_t)r;
    }
    return 1;
}

/* Tx count from the wire varint at block[80]; 0 if not decodable. */
static unsigned long long txcount(const unsigned char* b, unsigned long len){
    if(len <= 80) return 0;
    unsigned char c = b[80];
    if(c < 0xfd) return c;
    if(c == 0xfd) { if(len < 83) return 0; return b[81] | ((unsigned long long)b[82]<<8); }
    if(c == 0xfe) { if(len < 85) return 0;
                    return (unsigned long long)b[81] | ((unsigned long long)b[82]<<8)
                         | ((unsigned long long)b[83]<<16) | ((unsigned long long)b[84]<<24); }
    if(len < 89) return 0;
    unsigned long long n = 0;
    for(int k = 0; k < 8; k++) n |= ((unsigned long long)b[81+k]) << (8*k);
    return n;
}

int main(void){
    /* 4MB block + 64MB txid scratch + 1MB tx scratch, anonymous-backed so the
     * page faults spread over the process lifetime instead of one stack bump. */
    bbuf = mmap(NULL, MAX_BLOCK, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    scratch = mmap(NULL, (64UL<<20) + (1UL<<20) + (1UL<<20), PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if(bbuf == MAP_FAILED || scratch == MAP_FAILED){ fprintf(stderr, "mmap fail\n"); return 2; }
    setvbuf(stdout, NULL, _IOLBF, 0);

    unsigned char lenbuf[4];
    for(;;){
        int r = read_n(0, lenbuf, 4);
        if(r <= 0) break;
        unsigned long n = (unsigned long)lenbuf[0] | ((unsigned long)lenbuf[1]<<8)
                        | ((unsigned long)lenbuf[2]<<16) | ((unsigned long)lenbuf[3]<<24);
        if(n < 81 || n > MAX_BLOCK){
            printf("ERR %lu\n", n);
            fflush(stdout);
            if(r == 0) break;
            /* a short-but-valid frame we already consumed nothing of; if the
             * frame is under 81 bytes we must still skip its body to stay in
             * sync with the framing. */
            if(n >= 81 && n <= MAX_BLOCK) continue;
            unsigned char tmp[256]; long left = (n < 81) ? (long)n : 0;
            while(left > 0){
                size_t chunk = (left < 256) ? (size_t)left : 256;
                if(read_n(0, tmp, chunk) <= 0) break;
                left -= (long)chunk;
            }
            if(left != 0) break;
            continue;
        }
        if(read_n(0, bbuf, n) <= 0){ printf("ERR %lu\n", n); break; }

        long ok = cons_verify(bbuf, n, scratch, 2000000ULL);
        /* cons_verify's scratch cap is in txid slots; pass a huge cap (the
         * 65MB scratch holds 2M+ txids; real blocks hold <= ~50k). */
        unsigned char hh[32]; block_hash(hh, bbuf);
        int pow = pow_check(bbuf);
        printf("A%ld H", ok); hex(hh, 32);
        printf(" P%d N%llu\n", pow, txcount(bbuf, n));
        fflush(stdout);
    }
    return 0;
}
