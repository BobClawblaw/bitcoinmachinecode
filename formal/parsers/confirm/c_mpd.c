/* confirm X-MPD-delta on the compiled mempool_persist.c: a v1 mempool.dat
 * with 0 transactions and a delta-map count of 0x0666666666666667 (times 40
 * wraps to 24, which fits) is read as a valid dump, where Core's
 * ReadCompactSize throws "size too large" and the load reports failure. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
long mempool_dump_read(const char* path, int (*sink)(void*, const unsigned char*, unsigned long, long long, long long), void* ctx, char* err, unsigned long errcap);
int tx_parse(void* info, const unsigned char* p, unsigned long cap){ (void)info; (void)p; (void)cap; return 0; }
int main(int argc, char** argv){
    if (argc < 2 || chdir(argv[1]) != 0) return 2;
    unsigned char b[16 + 9 + 24]; memset(b, 0, sizeof b);
    b[0] = 1;                                            /* version 1, count 0 */
    b[16] = 0xff; unsigned long long nd = 0x0666666666666667ULL;
    for (int i = 0; i < 8; i++) b[17 + i] = (unsigned char)(nd >> (8*i));
    FILE* f = fopen("mempool.dat", "wb"); fwrite(b, 1, sizeof b, f); fclose(f);
    char err[128] = "";
    long r = mempool_dump_read("mempool.dat", 0, 0, err, sizeof err);
    printf("mempool_dump_read = %ld (err \"%s\"); nd*40 mod 2^64 = %llu\n", r, err, nd * 40ULL);
    unlink("mempool.dat");
    printf("%s\n", r == 0 ? "CONFIRMED: a 2^58-entry delta map in a 49-byte file is accepted" : "not reproduced");
    return r == 0 ? 0 : 1;
}
