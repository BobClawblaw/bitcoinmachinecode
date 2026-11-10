; ws_stub.asm -- bmc_win low-level stubs (NASM, win64).
;
; __chkstk / ___chkstk_ms: stack probes for frames > 4 KiB (MSVC and MinGW
;   spellings; neither adjusts rsp). Probes each page below rsp so the guard
;   page is walked in order.
; __bmc_sys_sv: the SysV bridge for the assembly's syscalls. tools/asm_xform.py
;   turns every `syscall` into
;       lea  rsp, [rsp-128]      ; step over the SysV red zone
;       call __bmc_sys_sv
;       lea  rsp, [rsp+128]
;   Entry: rax = Linux syscall number, rdi rsi rdx r10 r8 r9 = arguments.
;   Exit:  rax = result (-errno on failure). Like the syscall instruction,
;   only rax, rcx and r11 change; xmm0-15 are preserved too (the kernel
;   preserves vector state; the MS ABI only keeps xmm6-15).

section .text

global __chkstk
global ___chkstk_ms
__chkstk:
___chkstk_ms:
    push rcx
    push rax
    lea  rcx, [rsp+24]          ; caller's rsp at the call site
.probe:
    cmp  rax, 0x1000
    jb   .last
    sub  rcx, 0x1000
    test [rcx], rcx
    sub  rax, 0x1000
    jmp  .probe
.last:
    sub  rcx, rax
    test [rcx], rcx
    pop  rax
    pop  rcx
    ret

extern __bmc_win_syscall
global __bmc_sys_sv
__bmc_sys_sv:
    push rbp
    mov  rbp, rsp
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    and  rsp, -16
    sub  rsp, 96
    movdqu [rsp+0x00], xmm0
    movdqu [rsp+0x10], xmm1
    movdqu [rsp+0x20], xmm2
    movdqu [rsp+0x30], xmm3
    movdqu [rsp+0x40], xmm4
    movdqu [rsp+0x50], xmm5
    sub  rsp, 64                ; 32 shadow + a4 a5 a6 (+ pad)
    mov  [rsp+32], r10          ; a4
    mov  [rsp+40], r8           ; a5
    mov  [rsp+48], r9           ; a6
    mov  r9, rdx                ; a3
    mov  r8, rsi                ; a2
    mov  rdx, rdi               ; a1
    mov  rcx, rax               ; nr
    cld
    call __bmc_win_syscall
    add  rsp, 64
    movdqu xmm0, [rsp+0x00]
    movdqu xmm1, [rsp+0x10]
    movdqu xmm2, [rsp+0x20]
    movdqu xmm3, [rsp+0x30]
    movdqu xmm4, [rsp+0x40]
    movdqu xmm5, [rsp+0x50]
    lea  rsp, [rbp-48]
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rbp
    ret

; ---- Win64-ABI mem* -------------------------------------------------------
; The code generator emits these as libcalls (struct copies, large memsets)
; with the Win64 convention even inside SysV functions; the SysV C library's
; own copies are named __bmc_sv_mem* (tools/retarget.py). rdi/rsi are
; callee-saved in Win64, so they are kept in r9/r10.
global memcpy
memcpy:
    mov  rax, rcx
    mov  r9, rdi
    mov  r10, rsi
    mov  rdi, rcx
    mov  rsi, rdx
    mov  rcx, r8
    rep  movsb
    mov  rdi, r9
    mov  rsi, r10
    ret

global memmove
memmove:
    mov  rax, rcx
    mov  r9, rdi
    mov  r10, rsi
    mov  rdi, rcx
    mov  rsi, rdx
    mov  rcx, r8
    mov  r11, rdi
    sub  r11, rsi               ; dst - src (unsigned)
    cmp  r11, rcx
    jb   .back                  ; dst inside (src, src+n): copy backwards
    rep  movsb
    jmp  .done
.back:
    lea  rsi, [rsi+rcx-1]
    lea  rdi, [rdi+rcx-1]
    std
    rep  movsb
    cld
.done:
    mov  rdi, r9
    mov  rsi, r10
    ret

global memset
memset:
    mov  r9, rdi
    mov  r10, rcx
    mov  rdi, rcx
    mov  eax, edx
    mov  rcx, r8
    rep  stosb
    mov  rax, r10
    mov  rdi, r9
    ret

global memcmp
global bcmp
memcmp:
bcmp:
    xor  eax, eax
.loop:
    test r8, r8
    jz   .eq
    movzx eax, byte [rcx]
    movzx r9d, byte [rdx]
    sub  eax, r9d
    jnz  .ne
    inc  rcx
    inc  rdx
    dec  r8
    jmp  .loop
.eq:
    xor  eax, eax
.ne:
    ret
