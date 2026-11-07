; bmc_tls_scratch.inc -- the weak fallback for bmc_tls_scratch(size).
;
; Large per-thread scratch that used to be static TLS (2026-11-07): glibc
; zero-fills a thread's static TLS when it creates the thread, so a 4 MiB
; .tbss buffer is resident in EVERY thread of every process, used or not.
; Such a buffer is now a TLS pointer filled on first use with
; bmc_tls_scratch(size) -> rax (never NULL).
;
; The daemon defines bmc_tls_scratch in C (daemon/tx_verify.c, through
; bmc_thread.h's bmc_tls_alloc), so the block is freed when its thread
; exits. This weak copy is what every other binary links (tests, the
; single-threaded index builders): malloc, abort on failure, kept for the
; life of the thread. Each .asm that needs it includes this file; the
; copies are identical and weak, so the linker keeps one, and the strong C
; definition wins wherever it is linked.
extern malloc
extern abort
global bmc_tls_scratch:function weak
bmc_tls_scratch:
    sub  rsp, 8                 ; 16-byte alignment for the call
    call malloc
    test rax, rax
    jz   .oom
    add  rsp, 8
    ret
.oom:
    call abort
