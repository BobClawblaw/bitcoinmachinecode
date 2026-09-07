/* tests/test_shared_stress.c -- the concurrent append under the load that
 * broke it.
 *
 * On 2026-09-06 the pipelined downloader (16 helpers, a whole 40-block chunk
 * per round trip) left the archive inconsistent ON DISK: at height 44,863 the
 * index record named the right block and pointed at bytes belonging to block
 * 44,888 -- a block from the ADJACENT chunk, i.e. written by another helper.
 * test_shared2 (4 writers, 400 fixed-size appends, contiguous ranges) never
 * saw it. This test does what the helpers do: 16 writers, chunks of 40
 * heights dealt round-robin so neighbouring chunks belong to different
 * processes, variable sizes, a few re-appends of an already-written height
 * (a retried chunk), and enough of it to matter.
 *
 * Every body carries its own height in its first 8 bytes and a pattern
 * derived from it after that; every record's hash is derived from the height
 * too. Verification reads every record and checks that the bytes at the
 * recorded position are the block the record names. One mismatch is the
 * writer race, reproduced without a single network packet. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include "test_tmpdir.h"
extern int  store_init(void* st);
extern long store_append_shared(void* st, long height, const void* hash, const void* raw, unsigned long long len);
extern int  store_reload(void* st);   /* the worker calls this after every chunk */

#define NW      16
#define CHUNK   40
#define NCHUNK  200                       /* 8,000 heights, ~700 MB with the big ones */
#define TOTAL   (CHUNK * NCHUNK)
static unsigned long len_of(long h){       /* mostly 200 B .. 48 KB; every 37th is 1-3 MB, like the real chain's big blocks */
    unsigned long x = (unsigned long)h * 2654435761UL;
    if (h % 37 == 0) return (1u << 20) + (unsigned long)(x % (2u << 20));
    return 200 + (x % 49000);
}
static void fill(unsigned char* b, long h, unsigned long n){
    memcpy(b, &h, 8);
    unsigned long x = (unsigned long)h * 1103515245UL + 12345UL;
    for (unsigned long i = 8; i < n; i++){ x = x * 1103515245UL + 12345UL; b[i] = (unsigned char)(x >> 24); }
}
static void hash_of(unsigned char out[32], long h){ for (int k = 0; k < 32; k++) out[k] = (unsigned char)((h * 7 + k * 13) & 0xff); }

int main(int argc, char** argv){
    int rounds = argc > 1 ? atoi(argv[1]) : 1;
    tt_isolate();
    int bad_total = 0;
    for (int r = 0; r < rounds; r++){
        unlink("index.dat"); unlink("blk00000.dat"); unlink("blk00001.dat"); unlink("append.lock");
        int ix = open("index.dat", O_RDWR|O_CREAT, 0644); if (ftruncate(ix, (off_t)TOTAL * 48)){ perror("ftruncate"); return 1; } close(ix);
        close(open("append.lock", O_RDWR|O_CREAT, 0644));
        for (int w = 0; w < NW; w++){
            pid_t p = fork();
            if (p == 0){
                int lfd = open("append.lock", O_RDWR, 0644);        /* own descriptor: flock is per open-file-description */
                static unsigned char st[4096]; store_init(st);
                *(int*)((char*)st+40) = lfd; *(int*)((char*)st+0) = -1;
                *(int*)((char*)st+28) = 0;   *(int*)((char*)st+36) = 0xd9b4bef9;
                static unsigned char raw[4 << 20];
                unsigned seed = (unsigned)(w * 977 + r * 31);
                for (int c = w; c < NCHUNK; c += NW){                /* round-robin chunks: neighbours are other writers */
                    long lo = (long)c * CHUNK;
                    for (long h = lo; h < lo + CHUNK; h++){
                        unsigned long n = len_of(h); unsigned char hs[32]; hash_of(hs, h); fill(raw, h, n);
                        if (store_append_shared(st, h, hs, raw, n) != h) _exit(3);
                        seed = seed * 1103515245u + 12345u;
                        if ((seed >> 16) % 20 == 0 && h > lo){       /* 5%: re-append an earlier height, like a retried chunk */
                            long h2 = lo + (long)((seed >> 8) % (unsigned)(h - lo + 1));
                            unsigned long n2 = len_of(h2); unsigned char hs2[32]; hash_of(hs2, h2); fill(raw, h2, n2);
                            if (store_append_shared(st, h2, hs2, raw, n2) != h2) _exit(4);
                        }
                    }
                    store_reload(st);                                /* exactly what dlc_worker does after a chunk */
                }
                _exit(0);
            }
        }
        int child_bad = 0;
        for (int w = 0; w < NW; w++){ int s; waitpid(-1, &s, 0); if (!WIFEXITED(s) || WEXITSTATUS(s)) child_bad++; }
        /* ---- verify: the bytes at every record's position ARE the block it names ---- */
        unsigned char* idx = malloc((size_t)TOTAL * 48);
        FILE* f = fopen("index.dat", "rb"); size_t got = fread(idx, 1, (size_t)TOTAL * 48, f); fclose(f);
        int bad = 0, first_bad = -1; long checked = 0;
        static unsigned char body[4 << 20], want[4 << 20];
        for (long h = 0; h < TOTAL && got == (size_t)TOTAL * 48; h++){
            unsigned char* rec = idx + h * 48;
            uint32_t fno; memcpy(&fno, rec + 32, 4); uint64_t pos; memcpy(&pos, rec + 36, 8); uint32_t sz; memcpy(&sz, rec + 44, 4);
            unsigned char hs[32]; hash_of(hs, h);
            if (memcmp(rec, hs, 32) != 0){ bad++; if (first_bad < 0) first_bad = (int)h; continue; }
            char fn[32]; snprintf(fn, sizeof fn, "blk%05u.dat", fno);
            FILE* b = fopen(fn, "rb"); if (!b){ bad++; if (first_bad < 0) first_bad = (int)h; continue; }
            fseek(b, (long)pos + 8, SEEK_SET);
            unsigned long n = len_of(h);
            size_t rd = fread(body, 1, n, b); fclose(b);
            fill(want, h, n);
            long bh = -1; if (rd >= 8) memcpy(&bh, body, 8);
            if (rd != n || sz != n || memcmp(body, want, n) != 0){
                bad++;
                if (first_bad < 0){ first_bad = (int)h;
                    printf("  MISMATCH at height %ld: record says size %u at %s+%llu; the bytes there carry height %ld\n",
                           h, sz, fn, (unsigned long long)pos, bh); }
                continue;
            }
            checked++;
        }
        free(idx);
        printf("round %d: %ld of %d records verified, %d bad, %d writer(s) failed\n", r + 1, checked, TOTAL, bad, child_bad);
        bad_total += bad + child_bad;
    }
    printf("\n%s\n", bad_total ? "SHARED-APPEND STRESS FAIL: the archive is inconsistent on disk" : "SHARED-APPEND STRESS PASS");
    return bad_total ? 1 : 0;
}
