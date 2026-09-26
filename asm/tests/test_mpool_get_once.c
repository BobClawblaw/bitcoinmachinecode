/* test_mpool_get_once.c -- mpool_get must build the pointer it returns from
 * the blob_off it CHECKED, not from a second load of the slot.
 *
 * MEM-21 (audit 2026-09-03) made mpool_get refuse an incoherent len/blob_off
 * pair: the mempool is MAP_SHARED and read without mp_lock, and mpool_del's
 * backward shift can move a record under a reader. The check loaded
 * blob_off, verified blob_off + len <= blob_cap -- and then loaded blob_off
 * AGAIN to build the returned pointer. A move between the two loads paired
 * the checked len with an unchecked offset: the exact race MEM-21 exists
 * for, re-opened one instruction later. bmc_osx 99c940ca fixed the Mac copy;
 * the osx note worklog/2026-09-25-note-for-x86-2.md item 5 asks for x86.
 *
 * The window is one instruction wide, so this drives it with ptrace: a child
 * calls mpool_get under PTRACE_SINGLESTEP, and the parent rewrites the
 * slot's blob_off (the pool is MAP_SHARED between them) on the first step
 * at which the child holds the checked value in a register -- i.e. right
 * after the checked load. The returned pointer must then be the checked
 * one: the test fails if it points anywhere else, in particular past the
 * blob mapping.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>

extern unsigned long mpool_struct_size(unsigned long slots);
extern void mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern long mpool_put(void* mp, const unsigned char txid[32], const unsigned char* tx, unsigned long txlen);
extern const unsigned char* mpool_get(void* mp, const unsigned char txid[32], unsigned long* out_len);

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }

#define SLOTS     64ul
#define BLOB_CAP  (1ul << 18)
#define TXLEN     100ul
#define GOOD_OFF  0x2a5c3ul          /* distinctive, and GOOD_OFF + TXLEN <= BLOB_CAP */
#define BAD_OFF   0x7fff0000ul       /* far past the blob mapping */

struct shared_result { const unsigned char* ptr; unsigned long len; int done; };

static int regs_hold(const struct user_regs_struct* r, unsigned long v){
    const unsigned long long g[] = { r->rax, r->rbx, r->rcx, r->rdx, r->rsi, r->rdi, r->rbp,
                                     r->r8, r->r9, r->r10, r->r11, r->r12, r->r13, r->r14, r->r15 };
    for (size_t i = 0; i < sizeof g / sizeof g[0]; i++) if (g[i] == v) return 1;
    return 0;
}

int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);
    size_t msz = mpool_struct_size(SLOTS);
    unsigned char* mp   = mmap(0, msz, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    unsigned char* blob = mmap(0, BLOB_CAP, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    struct shared_result* res = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (mp == MAP_FAILED || blob == MAP_FAILED || res == MAP_FAILED){ printf("FAIL: mmap\n"); return 1; }
    memset(mp, 0, msz);
    mpool_init(mp, SLOTS, blob, BLOB_CAP);

    unsigned char txid[32], tx[TXLEN];
    for (int i = 0; i < 32; i++) txid[i] = (unsigned char)(0xa0 + i);
    for (unsigned i = 0; i < TXLEN; i++) tx[i] = (unsigned char)(i * 7);
    ck("put the transaction", mpool_put(mp, txid, tx, TXLEN) == 1);

    /* find its slot (80-byte records from +40: len@0, txid@8, blob_off@40)
     * and give it a distinctive offset the parent can recognise in a register */
    unsigned char* slot = 0;
    for (unsigned long i = 0; i <= SLOTS; i++){
        unsigned char* s = mp + 40 + i * 80;
        if (memcmp(s + 8, txid, 32) == 0){ slot = s; break; }
    }
    ck("found its slot", slot != 0);
    if (!slot) return 1;
    *(unsigned long*)(slot + 40) = GOOD_OFF;
    memcpy(blob + GOOD_OFF, tx, TXLEN);
    { unsigned long l = 0; const unsigned char* p = mpool_get(mp, txid, &l);
      ck("undisturbed, mpool_get returns blob + blob_off", p == blob + GOOD_OFF && l == TXLEN); }

    pid_t pid = fork();
    if (pid == 0){
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        unsigned long l = 0;
        res->ptr = mpool_get(mp, txid, &l);
        res->len = l;
        res->done = 1;
        _exit(0);
    }
    int st;
    waitpid(pid, &st, 0);
    ck("the child stopped under ptrace", WIFSTOPPED(st));
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    const unsigned long entry = (unsigned long)(void*)mpool_get;
    int entered = 0, flipped = 0;
    long steps = 0;
    for (;;){
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) != 0) break;
        if (waitpid(pid, &st, 0) < 0 || WIFEXITED(st) || WIFSIGNALED(st)) break;
        if (++steps > 2000000){ printf("FAIL: gave up single-stepping\n"); fails++; kill(pid, SIGKILL); break; }
        struct user_regs_struct r;
        if (ptrace(PTRACE_GETREGS, pid, 0, &r) != 0) break;
        if (!entered){ if (r.rip == entry) entered = 1; continue; }
        if (!flipped && regs_hold(&r, GOOD_OFF)){
            /* the checked load has happened: a concurrent del moves the record */
            *(volatile unsigned long*)(slot + 40) = BAD_OFF;
            flipped = 1;
            if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) break;   /* the rest runs freely */
            waitpid(pid, &st, 0);
            break;
        }
    }
    if (!WIFEXITED(st)) waitpid(pid, &st, 0);

    ck("the child entered mpool_get and the offset moved after its checked load", entered && flipped);
    ck("the child finished", res->done == 1);
    int inside = res->ptr == 0 ||
                 (res->ptr >= blob && res->ptr + res->len <= blob + BLOB_CAP);
    ck("the returned pointer is inside the blob mapping (or a miss)", inside);
    ck("...and it is the checked one, blob + the offset that was verified",
       res->ptr == blob + GOOD_OFF && res->len == TXLEN);
    if (!inside)
        printf("      returned blob + 0x%lx (blob_cap 0x%lx)\n",
               (unsigned long)(res->ptr - blob), BLOB_CAP);

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
