; bitcoin_mempool.asm
;   100% AI-authored x86-64 assembly.
;
; A small in-memory transaction "mempool": a txid -> serialized-tx store used by
; the server to relay transactions (answer getdata(type=MSG_TX), hold inbound
; tx, announce new ones). This is structural relay storage: it stores whatever
; tx bytes are given, dedups by txid, bounds count and byte budget, and hands
; back the exact bytes on demand. Full UTXO/script/fee validation is the
; wallet's future job.
;
; Memory layout of the mempool object (caller supplies a zero-initialized buffer
; of >= mpool_struct_size(slots), plus a separate tx-blob area):
;   +0   qword n
;   +8   qword mask   (slot count = mask+1)
;   +16  qword blob   (base of tx-blob area)
;   +24  qword blob_cap
;   +32  qword fill   (high-water fill offset into blob)
;   +40  ... slots, 48 bytes each: [+0 qword len][+8 txid[32]][+40 qword blob_off]
;   empty slot marker: len == 0xFFFFFFFFFFFFFFFF
;
; Exports:
;   size_t mpool_struct_size(unsigned long slots)
;   void   mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap)
;   long   mpool_put(void* mp, const unsigned char txid[32],
;                    const unsigned char* tx, unsigned long txlen) -> 1 new / 0 dup / 2 full
;   const unsigned char* mpool_get(void* mp, const unsigned char txid[32],
;                                  unsigned long* out_len)
;   long   mpool_count(void* mp)

default rel

section .text

; ---------------------------------------------------------------- 
; mpool_struct_size(slots) -> 40 + slots*48 + 8
global mpool_struct_size
mpool_struct_size:
    mov  rax, rdi
    imul rax, 48
    add  rax, 40 + 8
    ret

; ---------------------------------------------------------------- 
; mpool_init(mp, slots, blob, blob_cap)
global mpool_init
mpool_init:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    push rbx
    mov  r12, rdi            ; mp
    mov  r13, rsi            ; slots
    mov  r14, rdx            ; blob
    mov  rbx, rcx            ; blob_cap
    mov  qword [r12], 0      ; n = 0
    mov  qword [r12+8], r13  ; mask = slots (minus one next)
    dec  qword [r12+8]
    mov  [r12+16], r14       ; blob
    mov  [r12+24], rbx       ; blob_cap
    mov  qword [r12+32], 0   ; fill = 0
    ; mark every slot empty
    mov  rcx, r13            ; slot count
    lea  rdi, [r12+40]       ; first slot
    mov  rax, 0xFFFFFFFFFFFFFFFF
.empty_loop:
    test rcx, rcx
    jz   .done
    mov  [rdi], rax
    add  rdi, 48
    dec  rcx
    jmp  .empty_loop
.done:
    pop  rbx
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

; ---------------------------------------------------------------- 
; mpool_hash(rdi=txid, rsi=mask) -> rax = slot base offset (relative to mp)
; FNV-1a over first 8 bytes of txid, folded to mask.
mpool_hash:
    push rbp
    mov  rbp, rsp
    mov  r8, 0x811c9dc5
    xor  ecx, ecx
.hl:
    cmp  rcx, 8
    jae  .hd
    mov  eax, r8d
    imul eax, 0x01000193
    movzx edx, byte [rdi+rcx]
    xor  eax, edx
    mov  r8d, eax
    inc  rcx
    jmp  .hl
.hd:
    and  eax, esi            ; slot index
    imul rax, 48
    add  rax, 40             ; + slots region -> offset
    pop  rbp
    ret

; ---------------------------------------------------------------- 
; memcmp32(rdi=a, rsi=b, rdx=n) -> 0 if equal, else non-zero at first diff
; (length in RDX so callers can keep other regs; also matches mcopy)
memcmp32:
    push rbp
    mov  rbp, rsp
    push r8                 ; preserve r8 (callers use it as probe counter / slot ptr)
    xor  rcx, rcx
.c:
    cmp  rcx, rdx
    jae  .eq
    mov  al, [rdi+rcx]
    mov  r8b, [rsi+rcx]     ; r8b, not dl: dl is the low byte of the rdx bound
    cmp  al, r8b
    jne  .ne
    inc  rcx
    jmp  .c
.eq:
    xor  eax, eax
    pop  r8
    pop  rbp
    ret
.ne:
    mov  eax, 1
    pop  r8
    pop  rbp
    ret

; ---------------------------------------------------------------- 
; mcopy(rdi=dst, rsi=src, rdx=n) -- local byte mover (no deps)
mcopy:
    push rbp
    mov  rbp, rsp
    xor  rcx, rcx
.mcl:
    cmp  rcx, rdx
    jae  .mcd
    mov  al, [rsi+rcx]
    mov  [rdi+rcx], al
    inc  rcx
    jmp  .mcl
.mcd:
    pop  rbp
    ret

; ---------------------------------------------------------------- 
; mpool_put(mp, txid, tx, txlen) -> 1 new / 0 dup / 2 full
global mpool_put
mpool_put:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    push r15
    push rbx
    sub  rsp, 24             ; locals: -24 blen, -8 blob_off, -16 spare
    mov  r12, rdi
    mov  r13, rsi            ; txid
    mov  r14, rdx            ; tx
    mov  rbx, rcx            ; txlen
    ; probe
    mov  rdi, r13
    mov  rsi, [r12+8]
    call mpool_hash
    mov  r15, rax            ; slot offset
    xor  r10, r10            ; probe count
    mov  r9, 0xFFFFFFFFFFFFFFFF
.probe:
    mov  rax, [r12+8]
    inc  rax                 ; slot_count
    cmp  r10, rax
    jae  .full
    lea  r8, [r12+r15]       ; slot
    mov  rax, [r8]
    cmp  rax, r9
    je   .found_empty
    ; compare txid  (memcmp32 length in RDX)
    mov  rdi, r13
    lea  rsi, [r8+8]
    mov  rdx, 32
    call memcmp32
    test rax, rax
    jz   .dup
    ; advance probe with wrap-around (open addressing must wrap to slot 0)
    add  r15, 48
    mov  rax, [r12+8]
    inc  rax                ; slot_count
    imul rax, 48
    add  rax, 40            ; end = 40 + slot_count*48
    cmp  r15, rax
    jb   .nowrap1
    mov  r15, 40
.nowrap1:
    inc  r10
    jmp  .probe
.found_empty:
    ; blob bounds: fill + txlen <= blob_cap
    mov  rax, [r12+32]       ; fill
    mov  rcx, [r12+24]       ; blob_cap
    mov  r8, rax
    add  r8, rbx
    cmp  r8, rcx
    ja   .full
    mov  [rbp-8], rax        ; save fill (blob_off)
    ; copy tx into blob+fill
    mov  rdi, [r12+16]
    add  rdi, rax
    mov  rsi, r14
    mov  rdx, rbx
    call mcopy
    ; slot.len = txlen
    lea  r8, [r12+r15]
    mov  [r8], rbx
    ; slot.blob_off = fill
    mov  rax, [rbp-8]
    mov  [r8+40], rax
    ; slot.txid = r13   (mcopy length arg is RDX)
    lea  rdi, [r8+8]
    mov  rsi, r13
    mov  rdx, 32
    call mcopy
    ; fill += txlen
    mov  rax, [r12+32]
    add  rax, rbx
    mov  [r12+32], rax
    ; n++
    mov  rax, [r12]
    inc  rax
    mov  [r12], rax
    mov  rax, 1
    jmp  .ret
.dup:
    xor  eax, eax
    jmp  .ret
.full:
    mov  rax, 2
.ret:
    add  rsp, 24
    pop  rbx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

; ---------------------------------------------------------------- 
; mpool_get(mp, txid, out_len) -> rax = pointer to tx bytes in blob, or 0
global mpool_get
mpool_get:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi            ; txid
    mov  r14, rdx            ; out_len
    ; (r15 free; 4th arg rcx is scratch)
    ; probe
    mov  rdi, r13
    mov  rsi, [r12+8]
    call mpool_hash
    mov  r15, rax            ; slot offset (keep in callee-saved r15: survives memcmp32)
    xor  r8, r8              ; probe count
    mov  r9, 0xFFFFFFFFFFFFFFFF
    mov  r10, [r12+8]
    inc  r10                 ; slot_count
.gprobe:
    cmp  r8, r10
    jae  .miss
    lea  r11, [r12+r15]      ; slot
    mov  rax, [r11]
    cmp  rax, r9
    je   .miss
    ; compare txid  (memcmp32 length in RDX)
    mov  rdi, r13
    lea  rsi, [r11+8]
    mov  rdx, 32
    call memcmp32
    test rax, rax
    jz   .hit
    ; advance probe with wrap-around
    add  r15, 48
    mov  rax, [r12+8]
    inc  rax
    imul rax, 48
    add  rax, 40
    cmp  r15, rax
    jb   .nowrap2
    mov  r15, 40
.nowrap2:
    inc  r8
    jmp  .gprobe
.hit:
    mov  rax, [r11]          ; len -> *out_len
    mov  [r14], rax
    mov  rax, [r11+40]       ; blob_off
    mov  rdx, [r12+16]       ; blob base
    add  rax, rdx            ; -> tx pointer
    jmp  .ret
.miss:
    xor  eax, eax
.ret:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

; ---------------------------------------------------------------- 
; mpool_count(mp) -> n
global mpool_count
mpool_count:
    mov  rax, [rdi]
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
