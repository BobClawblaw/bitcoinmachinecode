; tls_scratch_fallback.asm -- the weak bmc_tls_scratch(size) of
; asm/bmc_tls_scratch.inc as an archive member (bmc_win). COFF has no weak
; definitions; an archive member is only pulled in when nothing else defines
; the symbol, so the daemon's strong C definition still wins.
extern malloc
extern abort
global bmc_tls_scratch
section .text
bmc_tls_scratch:
    sub  rsp, 8
    call malloc
    test rax, rax
    jz   .oom
    add  rsp, 8
    ret
.oom:
    call abort
