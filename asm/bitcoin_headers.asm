; ============================================================================
; bitcoin_headers.asm -- persistent header-chain store (raw syscalls).
;   100% AI-authored x86-64 assembly.
;
; Stores the Bitcoin header chain as an append-only file where entry N sits at
; byte offset N*112 (positional by height, no separate index file):
;     headers.dat:  [80 header][32 block_hash]   (112 bytes per entry)
;   header   = the raw 80-byte block header (version/prev/merkle/time/bits/nonce)
;   block_hash = sha256d(header) in internal (LE) order -- the node's locator /
;              chain-linking primitive for the header chain.
;
; State struct (caller supplies), offsets:
;   +0   qword fd        (open fd on headers.dat)
;   +8   qword count     (number of headers stored; 0 when empty)
;
; Exports:
;   int  hst_init(void* hst)                 -> 1 ok / -errno
;   int  hst_reload(void* hst)               -> 1 ok (count from file size)
;   long hst_append(void* hst, const u8 hdr[80], const u8 hash[32])
;                                            -> new count (1-based) or -1
;   int  hst_get_at(void* hst, u64 height, u8 out[112])
;                                            -> 1 ok / 0 out-of-range / -1 err
;   long hst_count(void* hst)                -> count (0..)
;
; Frame discipline (golden rules): callee-saved save area is [rbp-8 .. -(8*n)];
; every stack local lives strictly BELOW it; RSP 16-byte aligned before any
; nested call; one instruction per line (never join with ';').
; ============================================================================

default rel
section .text

; ============================================================================
; hst_init(hst) -> 1 ok / -errno
; Opens headers.dat O_RDWR|O_CREAT and zeroes the state.
global hst_init
hst_init:
    push rbp
    mov  rbp, rsp
    push r12
    mov  r12, rdi
    lea  rdi, [rel hdrname]
    mov  esi, 2 | 0x40          ; O_RDWR | O_CREAT
    mov  edx, 0o644
    mov  eax, 2                 ; open
    syscall
    test rax, rax
    jl   .fail
    mov  [r12], rax             ; fd
    mov  qword [r12+8], 0       ; count = 0
    mov  rax, 1
    pop  r12
    pop  rbp
    ret
.fail:
    mov  rax, -1
    pop  r12
    pop  rbp
    ret

; ============================================================================
; hst_reload(hst) -> 1 ok  (count = filesize / 112)
global hst_reload
hst_reload:
    push rbp
    mov  rbp, rsp
    push r12
    mov  r12, rdi
    mov  rdi, [r12]             ; fd
    xor  esi, esi
    mov  edx, 2                 ; SEEK_END
    mov  eax, 8                 ; lseek -> filesize
    syscall
    test rax, rax
    jl   .err
    xor  edx, edx
    mov  rcx, 112
    div  rcx
    mov  [r12+8], rax           ; count = size/112
    mov  rax, 1
    pop  r12
    pop  rbp
    ret
.err:
    mov  rax, -1
    pop  r12
    pop  rbp
    ret

; ============================================================================
; hst_append(hst, hdr[80], hash[32]) -> new count (1-based) or -1
; Appends [80 header][32 hash] at offset count*112, advances count.
global hst_append
hst_append:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    push r15
    push rbx                    ; 5 saved -> save area rbp-8..-40
    sub  rsp, 0x98              ; locals ALL BELOW save area:
                                ;  rec[112] @ rbp-0x98 (top rbp-0x2a < rbp-0x40+)
    mov  r12, rdi               ; hst
    mov  r13, rsi               ; hdr[80]
    mov  r14, rdx               ; hash[32]
    ; seek to count*112
    mov  rax, [r12+8]           ; count
    imul rax, 112
    mov  rdi, [r12]             ; fd
    mov  rsi, rax
    xor  edx, edx
    mov  eax, 8                 ; lseek
    syscall
    test rax, rax
    jl   .err
    ; build rec = hdr[80] ++ hash[32]
    lea  rdi, [rbp-0x98]
    mov  rsi, r13
    mov  rcx, 80
    rep  movsb
    lea  rdi, [rbp-0x98+80]
    mov  rsi, r14
    mov  rcx, 32
    rep  movsb
    ; write 112 bytes
    mov  rdi, [r12]             ; fd
    lea  rsi, [rbp-0x98]
    mov  edx, 112
    mov  eax, 1                 ; write
    syscall
    cmp  rax, 112
    jne  .err
    ; advance count
    mov  rax, [r12+8]
    add  rax, 1
    mov  [r12+8], rax
    add  rsp, 0x98
    pop  rbx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret
.err:
    mov  rax, -1
    add  rsp, 0x98
    pop  rbx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

; ============================================================================
; hst_get_at(hst, height, out[112]) -> 1 ok / 0 out-of-range / -1 err
; Reads the 112-byte entry for the given height into out.
global hst_get_at
hst_get_at:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    push r15                    ; 4 saved -> save area rbp-8..-32
    mov  r12, rdi               ; hst
    mov  r13, rsi               ; height
    mov  r14, rdx               ; out
    mov  rax, [r12+8]
    cmp  r13, rax
    jae  .oor                    ; height >= count
    ; seek to height*112
    mov  rax, r13
    imul rax, 112
    mov  rdi, [r12]             ; fd
    mov  rsi, rax
    xor  edx, edx
    mov  eax, 8                 ; lseek
    syscall
    test rax, rax
    jl   .err
    mov  rdi, [r12]
    mov  rsi, r14
    mov  edx, 112
    xor  eax, eax               ; read
    syscall
    cmp  rax, 112
    jne  .err
    mov  rax, 1
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret
.oor:
    xor  eax, eax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret
.err:
    mov  rax, -1
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

; ============================================================================
; hst_count(hst) -> count (0..)
global hst_count
hst_count:
    mov  rax, [rdi+8]
    ret

section .rodata
hdrname: db "headers.dat", 0

section .note.GNU-stack noalloc noexec nowrite progbits
