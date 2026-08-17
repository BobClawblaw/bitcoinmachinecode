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
;   long  idx_build_from_file(void* idx, const char* path) -> 0 ok / -1 can't open
;
; idx_build_from_file is the boot-time bulk loader: scans a positional
; index.dat (48-byte records: presence = first 4 bytes non-zero, hash stored
; in big-endian DISPLAY order at rec[0..31]) and idx_puts every present
; record's byte-reversed (wire/LE) hash. Same buffered-pread64 approach as
; asm/bitcoin_idxscan.asm (192KB window, 4096 records/read) instead of a
; per-record C fread + byte-reverse + call -- on the real ~962k-record
; archive this cut build_hash_index from ~186s to a small fraction of a
; second (see asm/tests/bench_hashidx.c).

default rel
STRIDE equ 48
%define IDXBUILD_BUFRECS 4096
%define IDXBUILD_BUFBYTES (IDXBUILD_BUFRECS*48)
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
; idx_hash(hash32, mask) -> rax = slot index (FNV-1a over the full 32 bytes,
;   XOR-folded before masking)
; ============================================================================
; In: rdi=hash32, rsi=mask. Clobbers rcx, edx, r8d, r9d, rax.
;
; ROOT CAUSE (found via real-vs-synthetic data comparison, not theory): this
; originally hashed only the first 8 bytes of the 32-byte hash. Every REAL
; Bitcoin block hash's first several bytes (in the byte order this table is
; queried with) are constrained near-zero BY PROOF-OF-WORK -- that's what
; "valid hash" means -- so those 8 bytes carry almost no entropy across
; different real inputs; only bytes deeper in the array vary. A first fix
; attempt (XOR-folding the FNV output before masking, to counter FNV-1a's
; separately weak low-bit avalanche) did NOT help, because the real problem
; was insufficient entropy going INTO the hash, not how the hash's output
; bits get mixed. CONFIRMED: idx_put on 400,000 distinct real hashes took
; 15.8s (severe linear-probe clustering) vs 0.04s for 400,000 synthetic
; random hashes into the identical table (asm/tests/debug_hashidx_synth.c),
; and dumping the actual bytes (asm/tests/debug_hashidx_dist.c) showed every
; real record's first 4 bytes literally 0x00000000. Fix: hash all 32 bytes,
; so the high-entropy tail always contributes; keep the XOR-fold too since
; it's free insurance against FNV-1a's low-bit weakness on top of that.
idx_hash:
    mov  ecx, 0x01000193     ; FNV prime (16777619)
    mov  eax, 0x811C9DC5     ; FNV offset basis (2166136261)
    xor  edx, edx            ; loop index (0..31) -- MUST NOT be clobbered by the read
.hashloop:
    movzx r8d, byte [rdi+rdx] ; byte into r8d (keep edx as the index)
    xor  eax, r8d
    imul eax, ecx
    add  edx, 1
    cmp  edx, 32
    jb   .hashloop
    mov  r9d, eax             ; XOR-fold: mix high bits into low bits
    shr  r9d, 15
    xor  eax, r9d
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

; ============================================================================
; idx_build_from_file(idx, path)   (rdi, rsi)  -> rax: 0 ok, -1 can't open.
;   Bulk-loads idx from a positional index.dat: buffered pread64 (192KB
;   window) instead of a per-record open/seek/read, byte-reverses each
;   present record's display-order hash into wire/LE order, and idx_puts it.
;   Registers persistent across idx_put calls (idx_put only guarantees
;   rbx/r12-r15 survive a call, per SysV/this codebase's own convention):
;   r12=idx, r14=fd, r15=n, rbx=pos, r13=full (records in the current read).
;   The inner-loop counter i is NOT callee-saved-safe to keep in a scratch
;   reg across idx_put, so it lives in a stack local below the save area.
; ============================================================================
global idx_build_from_file
idx_build_from_file:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x30           ; le[32]@[rbp-0x28..-0x9], i@[rbp-0x30]
    mov  r12, rdi             ; idx
    mov  rdi, rsi              ; path
    xor  esi, esi                ; O_RDONLY
    xor  edx, edx
    mov  eax, 2                   ; open
    syscall
    test rax, rax
    js   .fail
    mov  r14, rax                  ; fd
    mov  rdi, r14
    xor  esi, esi
    mov  edx, 2                     ; SEEK_END
    mov  eax, 8
    syscall
    test rax, rax
    js   .close_fail
    xor  edx, edx
    mov  rcx, 48
    div  rcx
    mov  r15, rax                    ; n = total records
    xor  rbx, rbx                     ; pos = 0
.outer:
    cmp  rbx, r15
    jge  .close_ok
    mov  rax, r15
    sub  rax, rbx                      ; remaining
    mov  r9, IDXBUILD_BUFRECS
    cmp  rax, r9
    cmovg rax, r9                       ; take = min(remaining, BUFRECS)
    mov  rdx, rax
    imul rdx, 48                         ; count
    mov  rax, rbx
    imul rax, 48                          ; offset
    mov  r10, rax
    mov  rdi, r14
    lea  rsi, [rel idxbuild_buf]
    mov  eax, 17                          ; pread64
    syscall
    cmp  rax, 0
    jle  .close_ok                         ; nothing read -> stop
    mov  r11, rax                           ; bytes read
    xor  edx, edx
    mov  rax, r11
    mov  ecx, 48
    div  ecx                                 ; eax = full records in this read
    mov  r13, rax                             ; full (persists across idx_put)
    mov  qword [rbp-0x30], 0                   ; i = 0
.scanrec:
    mov  rcx, [rbp-0x30]                        ; i
    cmp  rcx, r13
    jge  .afterscan
    mov  rax, rcx
    imul rax, 48
    lea  rax, [rel idxbuild_buf + rax]            ; record ptr
    mov  edx, [rax]
    test edx, edx
    jz   .nextrec                                  ; hole, skip
    ; byte-reverse the 32-byte display-order hash at [rax] into le[]
    xor  r10, r10
.rev:
    cmp  r10, 32
    jge  .revdone
    mov  r11, 31
    sub  r11, r10
    movzx r8d, byte [rax+r11]
    mov  [rbp-0x28+r10], r8b
    inc  r10
    jmp  .rev
.revdone:
    mov  rdx, rbx
    add  rdx, rcx                                   ; height = pos + i
    mov  rdi, r12
    lea  rsi, [rbp-0x28]
    call idx_put
.nextrec:
    mov  rcx, [rbp-0x30]
    inc  rcx
    mov  [rbp-0x30], rcx
    jmp  .scanrec
.afterscan:
    add  rbx, r13
    cmp  r13, IDXBUILD_BUFRECS
    jl   .close_ok                                    ; short/final read -> stop
    jmp  .outer
.close_ok:
    mov  rdi, r14
    mov  eax, 3                                        ; close
    syscall
    xor  eax, eax
    jmp  .ret
.close_fail:
    mov  rdi, r14
    mov  eax, 3
    syscall
.fail:
    mov  rax, -1
.ret:
    add  rsp, 0x30
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .bss
align 16
idxbuild_buf: resb IDXBUILD_BUFBYTES

section .note.GNU-stack noalloc noexec nowrite progbits
