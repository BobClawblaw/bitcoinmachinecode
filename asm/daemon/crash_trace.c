/* daemon/crash_trace.c -- a fatal signal leaves a stack in the log (2026-10-03).
 *
 * The unit runs with LimitCORE=0 on purpose (audit N5): the daemon holds the
 * decrypted wallet seed for its lifetime, and a core file is that seed on
 * disk. So a crash left nothing but the kernel's one line -- on 2026-10-02
 * production crash-looped eleven times and the only evidence was
 * "segfault at 6a61e3bd8 ip ... in libc.so.6"; the cause had to be derived
 * from the fault address by arithmetic.
 *
 * On SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGABRT this writes, with write(2) only:
 *   - the signal, the fault address, pid and tid;
 *   - RIP, RSP and RBP from the signal context;
 *   - backtrace() of the crashing thread (unwind tables: C frames);
 *   - a scan of the crashing stack that prints ONLY words inside this
 *     binary's text segment -- return addresses, which the unwinder loses in
 *     the asm frames (no CFI). Nothing else on the stack is printed: data
 *     words could be key material, addresses cannot.
 * Then the handler returns with the default action restored (SA_RESETHAND),
 * so the process dies of the same signal: systemd's view and the kernel line
 * are unchanged, and LimitCORE=0 still means no core file.
 *
 * The binary is non-PIE, so every printed address resolves offline with
 * `addr2line -fe daemon/bmcbitcoind.deploy-<x> <addr>`.
 *
 * Installed once in main(); forked processes and threads inherit it. The
 * main thread gets an alternate signal stack, so a stack overflow there still
 * reports; other threads run the handler on their own stack. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <execinfo.h>
#include <ucontext.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include "crash_trace.h"

extern char __executable_start[];
extern char etext[];

static int g_ct_fd = 2;

static void ct_puts(const char* s){ size_t n = strlen(s); while (n){ ssize_t w = write(g_ct_fd, s, n); if (w <= 0) return; s += w; n -= (size_t)w; } }
static void ct_hex(unsigned long v){
    char b[19]; b[0] = '0'; b[1] = 'x';
    for (int i = 0; i < 16; i++){ int d = (int)((v >> ((15 - i) * 4)) & 15); b[2 + i] = (char)(d < 10 ? '0' + d : 'a' + d - 10); }
    b[18] = 0; ct_puts(b);
}
static void ct_dec(long v){
    char b[24]; int i = 23; b[i] = 0; int neg = v < 0; unsigned long u = neg ? (unsigned long)(-v) : (unsigned long)v;
    do { b[--i] = (char)('0' + u % 10); u /= 10; } while (u && i > 1);
    if (neg) b[--i] = '-';
    ct_puts(b + i);
}
static const char* ct_name(int sig){
    switch (sig){ case SIGSEGV: return "SIGSEGV"; case SIGBUS: return "SIGBUS"; case SIGFPE: return "SIGFPE";
                  case SIGILL: return "SIGILL"; case SIGABRT: return "SIGABRT"; default: return "signal"; }
}

static void ct_handler(int sig, siginfo_t* si, void* ctxv){
    ucontext_t* uc = (ucontext_t*)ctxv;
    unsigned long rip = 0, rsp = 0, rbp = 0;
#if defined(__x86_64__)
    if (uc){ rip = (unsigned long)uc->uc_mcontext.gregs[REG_RIP]; rsp = (unsigned long)uc->uc_mcontext.gregs[REG_RSP];
             rbp = (unsigned long)uc->uc_mcontext.gregs[REG_RBP]; }
#endif
    ct_puts("\n[crash] "); ct_puts(ct_name(sig)); ct_puts(" ("); ct_dec(sig); ct_puts(") at address ");
    ct_hex(si ? (unsigned long)si->si_addr : 0);
    ct_puts(" pid "); ct_dec((long)getpid()); ct_puts(" tid "); ct_dec((long)syscall(SYS_gettid)); ct_puts("\n");
    ct_puts("[crash] rip "); ct_hex(rip); ct_puts(" rsp "); ct_hex(rsp); ct_puts(" rbp "); ct_hex(rbp); ct_puts("\n");
    ct_puts("[crash] backtrace:\n");
    void* frames[64]; int n = backtrace(frames, 64);
    backtrace_symbols_fd(frames, n, g_ct_fd);
    /* return addresses on the crashing stack, text-segment words only */
    unsigned long lo = (unsigned long)__executable_start, hi = (unsigned long)etext;
    ct_puts("[crash] text addresses on the stack (innermost first; resolve with addr2line -fe <binary>):\n");
    if (rip >= lo && rip < hi){ ct_puts("[crash]   rip "); ct_hex(rip); ct_puts("\n"); }
    if (rsp && !(rsp & 7)){
        const unsigned long* p = (const unsigned long*)rsp; int shown = 0;
        for (int i = 0; i < 2048 && shown < 48; i++){
            unsigned long v = p[i];
            if (v >= lo && v < hi){ ct_puts("[crash]   [rsp+"); ct_dec((long)i * 8); ct_puts("] "); ct_hex(v); ct_puts("\n"); shown++; }
        }
    }
    ct_puts("[crash] end (the process now dies of the same signal; no core file by design)\n");
    if (sig == SIGABRT) raise(sig);             /* SA_RESETHAND restored the default; abort's raise returned here */
}

void crash_trace_set_fd(int fd){ g_ct_fd = fd; }

int crash_trace_install(void){
    void* warm[2]; (void)backtrace(warm, 2);    /* loads libgcc's unwinder now, not inside the handler */
    static char altstack[64 * 1024];
    stack_t ss; memset(&ss, 0, sizeof ss);
    ss.ss_sp = altstack; ss.ss_size = sizeof altstack; ss.ss_flags = 0;
    (void)sigaltstack(&ss, NULL);
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = ct_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    int sigs[] = { SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT };
    int ok = 1;
    for (unsigned i = 0; i < sizeof sigs / sizeof sigs[0]; i++) if (sigaction(sigs[i], &sa, NULL) != 0) ok = 0;
    return ok;
}
