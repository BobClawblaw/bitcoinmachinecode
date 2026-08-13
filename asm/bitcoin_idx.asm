; bitcoin_idx.asm
;   100% AI-authored x86-64 assembly.
;
; A persisted block hash -> height open-addressing index, used to serve a
; requested block by hash in O(1) instead of a linear scan of every height
; (which never finishes on a large archive).
;
; Memory layout of the index object (caller supplies a zero-initialized buffer):
;   +0   qword  n           (number of live entries)
;   +8   qword  mask        (slot count = mask+1, a power of two)
;   +16  [8]    reserved
;   +24  ...    array of slots (48 bytes each; stride 48):
;               [ +0  qword height ][ +8  u8 hash[32] ][ +40 u8 pad[8] ]
;   slot address = (idx+24) + slot*48
;
; An empty slot has height == -1 (0xFFFFFFFFFFFFFFFF).
;
; Exports:
;   void idx_init(void* idx, unsigned long slots_pow2_cap)
;   int   idx_put(void* idx, const unsigned char hash[32], long height) -> 1 new / 0 dup / 2 full
;   int   idx_get(void* idx, const unsigned char hash[32], long* height) -> 1 found / 0
;   long  idx_count(void* idx)

default rel
STRIDE equ 48
section .text

; ============================================================================
; idx_init(idx, slots_pow2_cap)
; ============================================================================
global idx_init
idx_init:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    mov  r12, rdi            ; idx
    mov  r13, rsi            ; slots
    mov  qword [r12], 0      ; n = 0
    lea  rax, [r13-1]
    mov  [r12+8], rax        ; mask = slots-1
    ; clear every slot's height to -1
    lea  rdi, [r12+24]       ; base
    mov  rcx, r13            ; slot count
.clear:
    mov  qword [rdi], -1     ; height = -1 (empty)
    add  rdi, STRIDE
    dec  rcx
    jnz  .clear
    pop  r13
    pop  r12
    pop  rbp
    ret

; ============================================================================
; idx_hash(hash32, mask) -> rax = slot index (FNV-1a over first 8 bytes)
; ============================================================================
; In: rdi=hash32, rsi=mask. Clobbers rcx, edx, r8d, rax.
idx_hash:
    mov  ecx, 0x01000193     ; FNV prime (16777619)
    mov  eax, 0x811C9DC5     ; FNV offset basis (2166136261)
    xor  edx, edx            ; loop index (0..7) -- MUST NOT be clobbered by the read
.hashloop:
    movzx r8d, byte [rdi+rdx] ; byte into r8d (keep edx as the index)
    xor  eax, r8d
    imul eax, ecx
    add  edx, 1
    cmp  edx, 8
    jb   .hashloop
    and  rax, rsi            ; mask
    ret

; ============================================================================
; idx_put(idx, hash32, height) -> rax = 1 new / 0 dup / 2 full
;   Linear-probing insert; compares the FULL 32-byte hash for duplicates.
; ============================================================================
global idx_put
idx_put:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi            ; idx
    mov  r13, rsi            ; hash
    mov  r14, rdx            ; height
    mov  rsi, [r12+8]        ; mask
    mov  rdi, r13
    call idx_hash            ; rax = start slot
    mov  r15, rax            ; current probe slot
    mov  r8,  [r12+8]        ; probe budget
    inc  r8
    lea  rbx, [r12+24]       ; array base
.probe:
    ; slot = rbx + r15*48 ; empty if [slot] == -1
    mov  rax, r15
    imul rax, rax, STRIDE
    mov  rcx, -1
    cmp  [rbx+rax], rcx
    je   .empty
    ; occupied: compare full 32-byte hash at [slot+8]
    lea  rcx, [rbx+rax+8]
    mov  rdi, rcx
    mov  rsi, r13
    mov  rdx, 32
    call memcmp_exact
    test eax, eax
    jz   .dup                 ; equal -> duplicate
.next:
    dec  r8
    jz   .full
    add  r15, 1
    and  r15, [r12+8]        ; wrap
    jmp  .probe
.dup:
    xor  eax, eax
    jmp  .done
.full:
    mov  eax, 2
    jmp  .done
.empty:
    ; store at the current slot r15: height + full 32-byte hash
    mov  rax, r15
    imul rax, rax, STRIDE
    mov  [rbx+rax], r14      ; height
    lea  rdi, [rbx+rax+8]    ; dest hash
    mov  rsi, r13
    mov  rdx, 32
    call memcpy_len
    mov  rax, [r12]
    inc  rax
    mov  [r12], rax          ; n++
    mov  eax, 1
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; idx_get(idx, hash32, height*) -> rax = 1 found (writes *height) / 0
; ============================================================================
global idx_get
idx_get:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi            ; idx
    mov  r13, rsi            ; hash
    mov  r14, rdx            ; height*
    mov  rsi, [r12+8]        ; mask
    mov  rdi, r13
    call idx_hash
    mov  rbx, rax            ; current probe slot
    mov  r8,  [r12+8]        ; probe budget
    inc  r8
    lea  r15, [r12+24]       ; array base
.getprobe:
    mov  rax, rbx
    imul rax, rax, STRIDE
    mov  rcx, -1
    cmp  [r15+rax], rcx
    je   .notfound
    ; compare full 32-byte hash
    lea  rcx, [r15+rax+8]
    mov  rdi, rcx
    mov  rsi, r13
    mov  rdx, 32
    call memcmp_exact
    test eax, eax
    jnz  .getnext            ; not equal -> keep probing
    ; found -- recompute slot offset (memcmp clobbered rax)
    mov  rax, rbx
    imul rax, rax, STRIDE
    mov  rdx, [r15+rax]
    mov  [r14], rdx
    mov  eax, 1
    jmp  .done
.getnext:
    dec  r8
    jz   .notfound           ; exhausted the table -> not present
    add  rbx, 1
    and  rbx, [r12+8]
    jmp  .getprobe
.notfound:
    xor  eax, eax
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; memcmp_exact(dst, src, n) -> eax = 0 if equal, nonzero otherwise.
;   Deterministic byte compare; n is a multiple of 8 in practice but handled
;   generally here (32 bytes = 4 x 8).
; ============================================================================
; In: rdi=a, rsi=b, rdx=n. Clobbers rax, rcx, rdi, rsi, rdx, r8, r9.
memcmp_exact:
    xor  eax, eax
    mov  rcx, rdx
.l:
    dec  rcx
    js   .done
    mov  r8b, byte [rdi+rcx]
    mov  r9b, byte [rsi+rcx]
    cmp  r8b, r9b
    jne  .diff
    jmp  .l
.diff:
    mov  eax, 1
.done:
    ret

; ============================================================================
; memcpy_len(dst, src, n) -> copies n bytes src->dst.
; ============================================================================
; In: rdi=dst, rsi=src, rdx=n. Clobbers rcx, rdi, rsi, rax.
memcpy_len:
    xor  ecx, ecx
.c:
    cmp  rcx, rdx
    jae  .cdone
    mov  al, byte [rsi+rcx]
    mov  byte [rdi+rcx], al
    inc  rcx
    jmp  .c
.cdone:
    ret

; ============================================================================
; idx_count(idx) -> rax = n
; ============================================================================
global idx_count
idx_count:
    mov  rax, [rdi]
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
