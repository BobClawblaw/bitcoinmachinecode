; node_log.asm -- tiny leveled text logger for the Bitcoin node (all-asm).
;   Each event writes one structured line to an explicit fd passed by the
;   caller -- NO global mutable state, so it links safely anywhere.
;
;   long node_log_open(const char* path)  -> log fd, or 0 on error
;   void node_log_event(long fd, int kind, u32 a, u32 b, u32 c)
;       line: "<KIND> <a> <b> <c>\n"
;   void node_log_str(long fd, int kind, const char* s, long len)
;       line: "<KIND> <s>\n"
;
;   kinds: 0 INFO 1 HSHK 2 HDRS 3 BLOCK 4 CONS 5 STORE 6 ERROR 7 SERVE
;
; System V AMD64; callee-saved preserved; default rel.

default rel
extern fd_write_all        ; PROVEN file/socket writer (bitcoin_net.asm)

section .rodata
align 16
kind_tbl:
 db "INFO"
 db "HSHK"
 db "HDRS"
 db "BLOCK"
 db "CONS"
 db "STORE"
 db "ERROR"
 db "SERVE"
kind_len:
 dd 4,4,4,5,4,5,5,5

section .text

; ---------------------------------------------------------------------------
global node_log_open
node_log_open:
    push rbp
    mov  rbp, rsp
    push r12
    mov  r12, rdi          ; path
    mov  rsi, 0x441        ; O_WRONLY|O_APPEND|O_CREAT
    mov  rdx, 0x1b4        ; 0644
    mov  eax, 2            ; open
    syscall
    test rax, rax
    jl   .fail
    pop  r12
    pop  rbp
    ret
.fail:
    xor  eax, eax
    pop  r12
    pop  rbp
    ret

; emit_u32: rdi=buf, esi=val -> decimal + ' '; returns advanced rdi in rax
emit_u32:
    push rbp
    mov  rbp, rsp
    sub  rsp, 24
    lea  rcx, [rbp-16]
    mov  r8, rdi
    mov  r9d, esi
    test r9d, r9d
    jnz  .digits
    mov  byte [rcx-1], '0'
    dec  rcx
    jmp  .flip
.digits:
    mov  eax, r9d
    xor  edx, edx
    mov  r11d, 10
    div  r11d
    mov  r9d, eax
    add  dl, '0'
    dec  rcx
    mov  [rcx], dl
    test r9d, r9d
    jnz  .digits
.flip:
    mov  rdi, r8
.cp:
    mov  al, [rcx]
    mov  [rdi], al
    inc  rdi
    inc  rcx
    lea  rdx, [rbp-16]
    cmp  rcx, rdx
    jb   .cp
    mov  byte [rdi], ' '
    inc  rdi
    mov  rax, rdi
    add  rsp, 24
    pop  rbp
    ret

; put_kind: rdi=buf, esi=kind -> kind tag + ' '; returns advanced rdi in rax
put_kind:
    push rbp
    mov  rbp, rsp
    push r12
    lea  r12, [rel kind_tbl]
    lea  r11, [rel kind_len]
    mov  r9, 0
    test rsi, rsi
    jz   .noloop
.loop:
    mov  ecx, [r11 + r9*4]
    add  r12, rcx
    inc  r9
    cmp  r9, rsi
    jb   .loop
.noloop:
    mov  ecx, [r11 + rsi*4]
    mov  r10, 0
.w:
    mov  al, [r12 + r10]
    mov  [rdi + r10], al
    inc  r10
    cmp  r10, rcx
    jb   .w
    add  rdi, rcx
    mov  byte [rdi], ' '
    inc  rdi
    mov  rax, rdi
    pop  r12
    pop  rbp
    ret

; ---------------------------------------------------------------------------
; node_log_event(fd, kind, a, b, c)
global node_log_event
node_log_event:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    push r15
    push rbx
    sub  rsp, 96
    mov  rbx, rdi          ; fd
    mov  r12, rsi          ; kind
    mov  r13, rdx          ; a
    mov  r14, rcx          ; b
    mov  r15, r8           ; c
    lea  rdi, [rbp-96]
    mov  esi, r12d
    call put_kind
    mov  rdi, rax
    mov  esi, r13d
    call emit_u32
    mov  rdi, rax
    mov  esi, r14d
    call emit_u32
    mov  rdi, rax
    mov  esi, r15d
    call emit_u32
    dec  rdi
    mov  byte [rdi], 10
    inc  rdi
    lea  rsi, [rbp-96]
    mov  rdx, rdi
    sub  rdx, rsi
    mov  rdi, rbx          ; fd
    call fd_write_all      ; PROVEN socket/file writer from bitcoin_net.asm
    add  rsp, 96
    pop  rbx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

; ---------------------------------------------------------------------------
; node_log_str(fd, kind, s, len)
global node_log_str
node_log_str:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 48
    mov  rbx, rdi          ; fd
    mov  r12, rsi          ; kind
    mov  r13, rdx          ; s
    mov  r14, rcx          ; len
    lea  rdi, [rbp-48]
    mov  esi, r12d
    call put_kind
    mov  rcx, rax
    mov  rdx, r14
    mov  rsi, r13
.append:
    test rdx, rdx
    jz   .nl
    mov  al, [rsi]
    mov  [rcx], al
    inc  rcx
    inc  rsi
    dec  rdx
    jmp  .append
.nl:
    mov  byte [rcx], 10
    inc  rcx
    lea  rsi, [rbp-48]
    mov  rdx, rcx
    sub  rdx, rsi
    mov  rdi, rbx          ; fd
    call fd_write_all
    add  rsp, 48
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
