/* tests/bfilter_shim.c -- build a basic block filter from stdin, print hex.
 *
 * The differential driver (validation/blockfilter_diff.py) cannot dlopen this
 * tree: the hand-written asm is non-relocatable by design (-no-pie, see
 * docs/ENGINEERING.md 2.1), so there is no shared object to load. This is the
 * same shim shape the other cross-checks use -- consensus_shim, bip30_shim,
 * verify_p2sh_shim -- a normal binary the driver feeds over a pipe.
 *
 * stdin:
 *   line 1  block hash, DISPLAY order hex (as bitcoin-cli prints it)
 *   line 2  raw block hex
 *   line 3  count of spent prevout scripts
 *   then    one prevout scriptPubKey hex per line, in block order
 * stdout:
 *   the encoded filter, hex, one line -- or "ERR <n>" on failure.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../block_filter.h"

static long unhex(const char* s, unsigned char* out, long cap){
    long n = 0;
    for (const char* p = s; p[0] && p[1] && p[0] != '\n'; p += 2){
        if (n >= cap) return -1;
        int hi, lo;
        char a = p[0], b = p[1];
        hi = (a>='0'&&a<='9')?a-'0':(a>='a'&&a<='f')?a-'a'+10:(a>='A'&&a<='F')?a-'A'+10:-1;
        lo = (b>='0'&&b<='9')?b-'0':(b>='a'&&b<='f')?b-'a'+10:(b>='A'&&b<='F')?b-'A'+10:-1;
        if (hi < 0 || lo < 0) return -1;
        out[n++] = (unsigned char)((hi<<4)|lo);
    }
    return n;
}

#define MAXLINE (8u<<20)
#define MAXBLK  (8u<<20)
#define MAXPREV 200000

int main(void){
    static char line[MAXLINE];
    static unsigned char blk[MAXBLK];
    static unsigned char hash_disp[32], hash_wire[32];

    if (!fgets(line, sizeof line, stdin)) return 2;
    if (unhex(line, hash_disp, 32) != 32){ printf("ERR hash\n"); return 2; }
    for (int i = 0; i < 32; i++) hash_wire[i] = hash_disp[31-i];   /* display -> wire */

    if (!fgets(line, sizeof line, stdin)) return 2;
    long bl = unhex(line, blk, sizeof blk);
    if (bl < 81){ printf("ERR block\n"); return 2; }

    if (!fgets(line, sizeof line, stdin)) return 2;
    long np = atol(line);
    if (np < 0 || np > MAXPREV){ printf("ERR nprev\n"); return 2; }

    bf_script* pv = calloc((size_t)(np > 0 ? np : 1), sizeof *pv);
    unsigned char** bufs = calloc((size_t)(np > 0 ? np : 1), sizeof *bufs);
    if (!pv || !bufs){ printf("ERR oom\n"); return 2; }
    for (long i = 0; i < np; i++){
        if (!fgets(line, sizeof line, stdin)){ printf("ERR short\n"); return 2; }
        long need = (long)strlen(line) / 2 + 1;
        bufs[i] = malloc((size_t)need);
        if (!bufs[i]){ printf("ERR oom\n"); return 2; }
        long l = unhex(line, bufs[i], need);
        if (l < 0){ printf("ERR prevhex\n"); return 2; }
        pv[i].script = bufs[i]; pv[i].len = (unsigned long)l;
    }

    static unsigned char out[4u<<20];
    long n = bf_basic_build(blk, (unsigned long)bl, hash_wire, pv,
                            (unsigned long)np, out, sizeof out);
    if (n <= 0){ printf("ERR build %ld\n", n); return 1; }
    for (long i = 0; i < n; i++) printf("%02x", out[i]);
    printf("\n");
    return 0;
}
