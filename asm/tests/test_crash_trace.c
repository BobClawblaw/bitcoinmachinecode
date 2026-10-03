/* tests/test_crash_trace.c -- daemon/crash_trace.c (2026-10-03): a fatal
 * signal leaves a stack in the log, prints no data, and the process still
 * dies of the same signal.
 *
 * A child installs the handler with its report going to a pipe, plants a
 * recognisable "secret" on its own stack, and dereferences address 0x10
 * inside a known function. The parent reads the report and checks:
 *   - the signal and the fault address;
 *   - the faulting rip is inside crash_victim (the frame the unwinder may
 *     not reach through asm is exactly the one this must name);
 *   - the planted secret appears nowhere (only text-segment words are
 *     printed -- the reason this is allowed under LimitCORE=0);
 *   - the child died of SIGSEGV, not exit (systemd's view unchanged).
 * Control: without crash_trace_install the child writes nothing. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include "../daemon/crash_trace.h"

static int fails, checks;
static void ck(const char* l, int c){ checks++; if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

#define SECRET 0x5ec2e75ec2e75ec2UL
__attribute__((noinline)) int crash_victim(volatile int* p){
    volatile unsigned long secret[8];
    for (int i = 0; i < 8; i++) secret[i] = SECRET;
    __asm__ volatile("" ::: "memory");
    return *p + (int)secret[3];
}
__attribute__((noinline)) void crash_victim_end(void){ __asm__ volatile(""); }

static int run_child(int install, char* out, size_t cap, int* status){
    int pp[2]; if (pipe(pp)) return -1;
    pid_t pid = fork();
    if (pid == 0){
        close(pp[0]);
        if (install){ crash_trace_set_fd(pp[1]); crash_trace_install(); }
        else { signal(SIGSEGV, SIG_DFL); }
        crash_victim((volatile int*)16);
        _exit(0);
    }
    close(pp[1]);
    size_t n = 0; ssize_t r;
    while (n + 1 < cap && (r = read(pp[0], out + n, cap - 1 - n)) > 0) n += (size_t)r;
    out[n] = 0; close(pp[0]);
    waitpid(pid, status, 0);
    return (int)n;
}

int main(void){
    static char rep[65536]; int st = 0;
    printf("== a SIGSEGV with the handler installed ==\n");
    int n = run_child(1, rep, sizeof rep, &st);
    ck("a report was written", n > 0 && strstr(rep, "[crash] SIGSEGV (11) at address 0x0000000000000010") != NULL);
    char want[64]; snprintf(want, sizeof want, "rip 0x%016lx", 0UL);
    unsigned long lo = (unsigned long)(void*)crash_victim, hi = (unsigned long)(void*)crash_victim_end;
    unsigned long rip = 0; const char* rp = strstr(rep, "[crash] rip 0x"); if (rp) rip = strtoul(rp + 12, NULL, 16);
    printf("      crash_victim [0x%lx, 0x%lx), reported rip 0x%lx\n", lo, hi, rip);
    ck("the faulting rip is inside crash_victim", rip >= lo && rip < (hi > lo ? hi : lo + 512));
    ck("...and it is listed among the text addresses", strstr(rep, "[crash]   rip 0x") != NULL);
    ck("a backtrace section is present", strstr(rep, "[crash] backtrace:") != NULL);
    char sec[32]; snprintf(sec, sizeof sec, "%016lx", SECRET);
    ck("the planted stack secret appears nowhere in the report", strstr(rep, sec) == NULL);
    ck("the child died of SIGSEGV (not an exit): the supervisor's view is unchanged",
       WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV);
    printf("== control: no handler installed ==\n");
    n = run_child(0, rep, sizeof rep, &st);
    ck("control: no report without crash_trace_install", n == 0);
    ck("control: the child still died of SIGSEGV", WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV);
    (void)want;
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
