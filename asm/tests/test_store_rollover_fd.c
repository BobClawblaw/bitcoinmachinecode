/* test_store_rollover_fd.c -- ST2-5 (audit 2026-10-23): a blk-file rollover
 * whose open fails must leave the store's fd at -1, all 64 bits of it.
 *
 * THE BUG. cur_blk_fd ([st+0]) is a qword that every reader tests by sign
 * (`mov rax,[r12]; test rax,rax; jns have_fd`). Both rollovers -- in
 * store_append and store_append_shared -- closed the old file and then
 * cleared the fd with `mov dword [r12], -1`, which leaves 0x00000000FFFFFFFF:
 * POSITIVE. When the following open_file failed, store_append_shared's next
 * call took that as an open fd and lseeked descriptor 4294967295 -- EBADF on
 * every later append, never retrying the open, for the life of the process.
 * open_file had the matching hole: it closes the fd it is handed and, when
 * its own open fails, left the closed number in [st+0] for the next caller.
 *
 * THE INJECTION. The rollover is reached cheaply: a sparse blk00000.dat just
 * under MAX_FILE (store_append_shared lseeks SEEK_END), or cur_file_pos set
 * just under it (store_append trusts its cursor). The open is made to fail by
 * a dangling symlink at blk00001.dat: the frontier probe (access F_OK follows
 * it) sees no newer file, and open(O_CREAT) through it fails with ENOENT.
 *
 * WHAT IS ASSERTED, for each path:
 *   1. the rollover append fails (the open really failed);
 *   2. cur_blk_fd is -1 as a QWORD afterwards;
 *   3. (shared) with the symlink gone, the next append succeeds and lands in
 *      blk00001.dat -- the store recovers instead of failing forever. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "test_tmpdir.h"

extern int  store_init(void* st);
extern int  store_append(void* st, const void* hash, const void* raw, unsigned long long len);
extern long store_append_shared(void* st, long height, const void* hash,
                                const void* raw, unsigned long long len);

#define MAX_FILE 0x08000000L

static int failures = 0;
static void ck(const char* l, long long g, long long e){
    if (g == e) printf("PASS %s (got %lld)\n", l, g);
    else { printf("FAIL %s got=%lld exp=%lld\n", l, g, e); failures++; }
}
static long fsize(const char* nm){ struct stat s; if (stat(nm, &s)) return -1; return (long)s.st_size; }

static unsigned char st[4096];
static void setup(void){
    int ix = open("index.dat", O_RDWR|O_CREAT|O_TRUNC, 0644);
    if (ix < 0 || ftruncate(ix, 8*48)){ perror("index.dat"); exit(2); }
    close(ix);
    memset(st, 0, sizeof st);
    ck("store_init", store_init(st), 1);
    *(int*)(st+40) = -1;                  /* no flock fd: the lock is skipped */
    *(int*)(st+36) = (int)0xd9b4bef9;     /* mainnet magic */
    *(int*)(st+28) = 0;                   /* cur_file_no = 0 */
    *(long*)(st+0) = -1;                  /* lazy blk open */
}
static void block_next_file(void){ if (symlink("no-such-dir/blk", "blk00001.dat")){ perror("symlink"); exit(2); } }
static void unblock_next_file(void){ if (unlink("blk00001.dat")){ perror("unlink"); exit(2); } }

static void shared_case(void){
    printf("-- store_append_shared --\n");
    setup();
    unsigned char h[32], b[64];
    memset(h, 0xA0, 32); memset(b, 0x10, 64);
    ck("append h0", store_append_shared(st, 0, h, b, 64), 0);
    /* blk00000 is now "full": the next append must roll to blk00001 */
    if (truncate("blk00000.dat", MAX_FILE - 16)){ perror("truncate"); exit(2); }
    memset(h, 0xA1, 32); memset(b, 0x11, 64);
    block_next_file();
    long r = store_append_shared(st, 1, h, b, 64);
    unblock_next_file();
    ck("the rollover append fails when its open fails", r < 0, 1);
    ck("cur_blk_fd is -1 as a qword", *(long*)(st+0), -1);
    ck("the retry succeeds once the open can", store_append_shared(st, 1, h, b, 64), 1);
    ck("and lands in blk00001.dat", fsize("blk00001.dat"), 72);
}

static void plain_case(void){
    printf("-- store_append --\n");
    setup();
    unsigned char h[32], b[64];
    memset(h, 0xB0, 32); memset(b, 0x20, 64);
    ck("append h0", store_append(st, h, b, 64), 0);
    *(unsigned*)(st+32) = (unsigned)(MAX_FILE - 16);   /* cur_file_pos, in the file it was measured in */
    *(unsigned*)(st+44) = *(unsigned*)(st+28);
    memset(h, 0xB1, 32); memset(b, 0x21, 64);
    block_next_file();
    long r = store_append(st, h, b, 64);
    unblock_next_file();
    ck("the rollover append fails when its open fails", r < 0, 1);
    ck("cur_blk_fd is -1 as a qword", *(long*)(st+0), -1);
    ck("the retry succeeds once the open can", store_append(st, h, b, 64), 1);
    ck("and lands in blk00001.dat", fsize("blk00001.dat"), 72);
}

static int in_child(void (*fn)(void), const char* dir){
    fflush(stdout);
    pid_t p = fork();
    if (p < 0) return 1;
    if (p == 0){
        if (mkdir(dir, 0755) || chdir(dir)) _exit(2);
        fn(); fflush(stdout); _exit(failures ? 1 : 0);
    }
    int s = 0;
    if (waitpid(p, &s, 0) != p || !WIFEXITED(s)){ printf("FAIL %s: child died\n", dir); return 1; }
    return WEXITSTATUS(s) != 0;
}

int main(void){
    tt_isolate();
    int bad = in_child(shared_case, "shared") + in_child(plain_case, "plain");
    if (bad){ printf("\nFAILED (%d case(s))\n", bad); return 1; }
    printf("\nALL TESTS PASSED (0 failures)\n");
    return 0;
}
