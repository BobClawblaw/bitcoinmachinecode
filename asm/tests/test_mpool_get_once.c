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
 *
 * ON THE MAC (Apple silicon) the same race is driven without a debugger:
 * reading a child's registers there needs task_for_pid, which only a
 * debugger-entitled or root process gets. Instead, in one process:
 *   - the pool is mapped TWICE from one file: mpool_get runs on a view whose
 *     pages are PROT_NONE, the test keeps a readable view of the same bytes;
 *   - every load mpool_get makes from the pool faults, and a SIGBUS/SIGSEGV
 *     handler EMULATES it: decodes the AArch64 load at the faulting pc (the
 *     two forms the Mac mpool_get and its memcmp32 use on the pool -- LDR
 *     unsigned-immediate and LDR register-offset -- anything else aborts
 *     loudly), reads the value through the readable view, writes the
 *     destination register in the signal context and steps pc past it;
 *   - the FIRST read of the slot's blob_off answers the checked value, every
 *     later read answers the moved one -- the record moving between two
 *     loads, deterministically, with no timing involved.
 * A control arm runs a four-instruction routine that re-loads blob_off after
 * checking it (the old bug) under the same handler and must come back with
 * the moved pointer, so the harness is shown to catch what it looks for.
 */
#if defined(__APPLE__) && defined(__aarch64__)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include "test_tmpdir.h"

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

/* the two views, the watched word, and what the handler saw */
static unsigned char *g_prot, *g_open;          /* PROT_NONE view (mpool_get's), readable view */
static size_t g_len;
static uintptr_t g_watch;                        /* &blob_off in the protected view */
static volatile int g_watch_reads, g_emulated, g_unknown;

static uint64_t* xreg(ucontext_t* uc, unsigned n){   /* x0..x30; n == 31 handled by callers */
    if (n < 29) return (uint64_t*)&uc->uc_mcontext->__ss.__x[n];
    if (n == 29) return (uint64_t*)&uc->uc_mcontext->__ss.__fp;
    return (uint64_t*)&uc->uc_mcontext->__ss.__lr;
}
static void on_fault(int sig, siginfo_t* si, void* ctx){
    ucontext_t* uc = ctx;
    uintptr_t a = (uintptr_t)si->si_addr;
    if (a < (uintptr_t)g_prot || a >= (uintptr_t)g_prot + g_len){      /* not ours: crash for real */
        signal(sig, SIG_DFL); return;
    }
    uint32_t insn = *(const uint32_t*)(uintptr_t)uc->uc_mcontext->__ss.__pc;
    unsigned size, rt = insn & 31, rn = (insn >> 5) & 31;
    uintptr_t ea;
    if ((insn & 0x3FC00000u) == 0x39400000u){                          /* LDR (unsigned imm), zero-extending */
        size = insn >> 30;
        ea = (rn == 31 ? (uintptr_t)uc->uc_mcontext->__ss.__sp : (uintptr_t)*xreg(uc, rn))
             + (((insn >> 10) & 0xFFFu) << size);
    } else if ((insn & 0x3FE00C00u) == 0x38600800u && ((insn >> 13) & 7) == 3 && !((insn >> 12) & 1)){
        size = insn >> 30;                                               /* LDR (register, LSL #0) */
        unsigned rm = (insn >> 16) & 31;
        ea = (uintptr_t)*xreg(uc, rn) + (rm == 31 ? 0 : (uintptr_t)*xreg(uc, rm));
    } else { g_unknown = 1; signal(sig, SIG_DFL); return; }            /* refuse to guess */
    if (ea != a){ g_unknown = 1; signal(sig, SIG_DFL); return; }
    uint64_t v = 0;
    memcpy(&v, g_open + (a - (uintptr_t)g_prot), (size_t)1 << size);   /* little-endian: low bytes */
    if (a == g_watch && size == 3){
        if (g_watch_reads++ > 0) v = BAD_OFF;                            /* moved after the first (checked) read */
    }
    if (rt != 31) *xreg(uc, rt) = v;                                     /* W destinations zero-extend: v is */
    uc->uc_mcontext->__ss.__pc += 4;
    g_emulated++;
    (void)sig;
}

/* control arm: the pre-fix shape -- check blob_off, then load it AGAIN to
 * build the pointer. x0 = slot, x1 = blob. */
__attribute__((naked)) static const unsigned char* reload_get(const unsigned char* slot, const unsigned char* blob){
    __asm__ volatile(
        "ldr x9,  [x0, #40]\n"      /* blob_off (checked) */
        "ldr x10, [x0]\n"           /* len */
        "add x11, x9, x10\n"        /* the check would use x11 */
        "ldr x9,  [x0, #40]\n"      /* ...and the re-load builds the pointer */
        "add x0,  x1, x9\n"
        "ret\n");
}

int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);
    tt_isolate();
    size_t pg = (size_t)getpagesize();
    g_len = (mpool_struct_size(SLOTS) + pg - 1) & ~(pg - 1);
    int fd = open("pool.map", O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || ftruncate(fd, (off_t)g_len) != 0){ printf("FAIL: pool file\n"); return 1; }
    g_prot = mmap(0, g_len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    g_open = mmap(0, g_len, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    unsigned char* blob = mmap(0, BLOB_CAP, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (g_prot == MAP_FAILED || g_open == MAP_FAILED || blob == MAP_FAILED){ printf("FAIL: mmap\n"); return 1; }
    mpool_init(g_prot, SLOTS, blob, BLOB_CAP);

    unsigned char txid[32], tx[TXLEN];
    for (int i = 0; i < 32; i++) txid[i] = (unsigned char)(0xa0 + i);
    for (unsigned i = 0; i < TXLEN; i++) tx[i] = (unsigned char)(i * 7);
    ck("put the transaction", mpool_put(g_prot, txid, tx, TXLEN) == 1);
    unsigned char* slot = 0;                     /* 80-byte records from +40: len@0, txid@8, blob_off@40 */
    for (unsigned long i = 0; i <= SLOTS; i++){
        unsigned char* s = g_prot + 40 + i * 80;
        if (memcmp(s + 8, txid, 32) == 0){ slot = s; break; }
    }
    ck("found its slot", slot != 0);
    if (!slot) return 1;
    *(unsigned long*)(slot + 40) = GOOD_OFF;
    memcpy(blob + GOOD_OFF, tx, TXLEN);
    { unsigned long l = 0; const unsigned char* p = mpool_get(g_prot, txid, &l);
      ck("undisturbed, mpool_get returns blob + blob_off", p == blob + GOOD_OFF && l == TXLEN); }

    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_fault; sa.sa_flags = SA_SIGINFO; sigemptyset(&sa.sa_mask);
    sigaction(SIGBUS, &sa, 0); sigaction(SIGSEGV, &sa, 0);
    g_watch = (uintptr_t)(slot + 40);

    /* the control arm first: a double load must be caught */
    g_watch_reads = 0; g_emulated = 0;
    mprotect(g_prot, g_len, PROT_NONE);
    const unsigned char* cp = reload_get(slot, blob);
    mprotect(g_prot, g_len, PROT_READ|PROT_WRITE);
    ck("control: every pool load was emulated (no unknown instruction)", !g_unknown && g_emulated == 3);
    ck("control: a routine that re-loads blob_off after checking it gets the MOVED offset",
       g_watch_reads == 2 && cp == blob + BAD_OFF);

    /* the real mpool_get under the same handler */
    g_watch_reads = 0; g_emulated = 0;
    unsigned long l = 0;
    mprotect(g_prot, g_len, PROT_NONE);
    const unsigned char* p = mpool_get(g_prot, txid, &l);
    mprotect(g_prot, g_len, PROT_READ|PROT_WRITE);
    printf("      mpool_get: %d pool loads emulated, blob_off read %d time(s)\n", g_emulated, g_watch_reads);
    ck("every pool load mpool_get made was emulated (no unknown instruction)", !g_unknown && g_emulated > 0);
    ck("mpool_get read the slot's blob_off exactly once", g_watch_reads == 1);
    int inside = p == 0 || (p >= blob && p + l <= blob + BLOB_CAP);
    ck("the returned pointer is inside the blob mapping (or a miss)", inside);
    ck("...and it is the checked one, blob + the offset that was verified", p == blob + GOOD_OFF && l == TXLEN);
    if (!inside) printf("      returned blob + 0x%lx (blob_cap 0x%lx)\n", (unsigned long)(p - blob), BLOB_CAP);

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}

#else   /* x86-64 Linux: the ptrace single-step harness */
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

#endif
