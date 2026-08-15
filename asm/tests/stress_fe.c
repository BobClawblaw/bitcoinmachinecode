/* stress_fe.c — batch driver: reads "aHex bHex" lines (4 limbs each, LSB-first
 * but printed as 4 16-hex groups), computes fe_add/fe_sub/fe_mul, prints
 * "OK:<addhex>:<subhex>:<mulhex>". Static links the asm fe objects.
 * Usage: ./stress_fe < pairs.txt
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;
extern void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);

static void rd_limbs(const char *s, u64 *out){
    /* s is 64 hex chars (4 limbs, little-endian byte order printed as
     * "%016x" per limb, LSB limb first) */
    char t[20];
    for (int i = 0; i < 4; i++) {
        memcpy(t, s + 16 * i, 16); t[16] = 0;
        out[i] = strtoull(t, NULL, 16);
    }
}
static void pr_limbs(const u64 *v, char *buf){
    /* reconstruct the 4-limb hex string, LSB limb first */
    char tmp[72];
    for (int i = 0; i < 4; i++) sprintf(tmp + 16 * i, "%016llx", v[i]);
    strcpy(buf, tmp);
}
int main(void){
    char line[512];
    u64 a[4], b[4], ra[4], rs[4], rm[4];
    char ba[80], bs[80], bm[80];
    while (fgets(line, sizeof line, stdin)) {
        size_t n = strlen(line); while (n && (line[n-1]=='\n'||line[n-1]=='\r')) line[--n]=0;
        if (n < 129) continue;
        /* split on space */
        char *sp = strchr(line, ' ');
        if (!sp) continue;
        *sp = 0;
        rd_limbs(line, a);
        rd_limbs(sp + 1, b);
        /* strip leading zeros in each limb string to avoid strtoull overflow on
         * 16-char "ffffffffffffffff"; strtoull handles 16 digits fine. */
        fe_add(ra, a, b);
        fe_sub(rs, a, b);
        fe_mul(rm, a, b);
        pr_limbs(ra, ba); pr_limbs(rs, bs); pr_limbs(rm, bm);
        printf("OK:%s:%s:%s\n", ba, bs, bm);
    }
    return 0;
}
