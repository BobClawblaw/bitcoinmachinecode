/* confirm X-MPJ-stats on the compiled mempool_journal.c: a journal whose
 * header holds next_seq = 0 makes mpj_stats walk seq from 2^64-1 down to 1.
 * The walk is stopped by SIGALRM after 3 s; a bounded walk over a 2-slot ring
 * takes microseconds. Scratch directory in argv[1]. */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include "mempool_journal.h"
static void on_alarm(int s){ (void)s; static const char m[] = "CONFIRMED: mpj_stats still walking after 3 s (next_seq = 0 in the header; capacity 2)\n"; if (write(1, m, sizeof m - 1) < 0) _exit(1); _exit(0); }
int main(int argc, char** argv){
    if (argc < 2 || chdir(argv[1]) != 0) return 2;
    unlink("j.dat");
    if (!mpj_open("j.dat", 2)) return 3;
    mpj_close();
    FILE* f = fopen("j.dat", "r+b"); unsigned char z[8] = {0}; fseek(f, 24, SEEK_SET); fwrite(z, 1, 8, f); fclose(f);
    if (!mpj_open("j.dat", 2)) return 4;
    printf("reopened: capacity %llu next_seq %llu\n", (unsigned long long)mpj_capacity(), (unsigned long long)mpj_next_seq());
    fflush(stdout);
    signal(SIGALRM, on_alarm); alarm(3);
    mpj_stats_t st; mpj_stats(&st);
    printf("not reproduced: mpj_stats returned (written=%llu)\n", (unsigned long long)st.written);
    return 1;
}
