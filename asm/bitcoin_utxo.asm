; ============================================================================
; bitcoin_utxo.asm -- in-memory Unspent Transaction Output (UTXO) set.
;
; A txid+index -> (value, scriptPubKey) store used to validate spends: track
; which outputs are unspent and their spending requirements. Open-addressing
; hash table, directly modeled on the proven bitcoin_mempool.asm mechanics.
;
; Memory layout (caller supplies a zero-filled buffer of >= utxo_struct_size
; and a separate blob area):
;   +0   qword n            ; entries
;   +8   qword mask         ; slot count = mask+1
;   +16  qword blob         ; base of value/script blob area
;   +24  qword blob_cap
;   +32  qword fill         ; high-water fill offset into blob
;   +40  slots, 48 bytes each:
;        [+0  qword blob_off]   (offset into blob of the record)
;        [+8  u8  txid[32]]
;        [+40 u32 index]
;        [+44 qword _pad]
;   empty slot marker: index == 0xFFFFFFFFFFFFFFFF-free: use index field 0xFFFFFFFF.
;
; Blob record at offset o:
;   [+0  u64 value][+8 u64 script_len][+16 u8 script[script_len]]
;
; Exports (System V AMD64):
;   size_t utxo_struct_size(unsigned long slots)
;   void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap)
;   long   utxo_put(void* u, const u8 txid[32], unsigned long index,
;                   unsigned long long value, const u8* script, unsigned long slen)
;               -> 1 new / 0 dup / 2 table-full
;   long   utxo_get(void* u, const u8 txid[32], unsigned long index,
;                   unsigned long long* value, const u8** script, unsigned long* slen)
;               -> 1 found / 0 miss
;   long   utxo_del(void* u, const u8 txid[32], unsigned long index) -> 1 deleted / 0 miss
;   long   utxo_count(void* u)
; ============================================================================
default rel

section .text

; utxo_struct_size(slots) -> 40 + slots*48 + 8
global utxo_struct_size
utxo_struct_size:
    mov  rax, rdi
    imul rax, 48
    add  rax, 40 + 8
    ret

; utxo_init(u, slots, blob, cap)
global utxo_init
utxo_init:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    push rbx
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  rbx, rcx
    mov  qword [r12], 0
    mov  qword [r12+8], r13
    dec  qword [r12+8]
    mov  [r12+16], r14
    mov  [r12+24], rbx
    mov  qword [r12+32], 0
    mov  rcx, r13
    lea  rdi, [r12+40]
.empty_loop:
    test rcx, rcx
    jz   .done
    mov  dword [rdi+40], 0xFFFFFFFF   ; mark empty (index field)
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

; utxo_hash(rdi=txid, rsi=index, rdx=mask) -> rax = slot offset (bytes, from +40)
; FNV-1a over txid first 8 bytes XOR index folded to mask.
utxo_hash:
    mov  r8, 0x811c9dc5
    xor  ecx, ecx
.hl:
    cmp  ecx, 8
    jae  .hdone
    movzx r9, byte [rdi+rcx]
    xor  r8d, r9d
    imul r8d, r8d, 16777619
    inc  ecx
    jmp  .hl
.hdone:
    ; fold index in
    mov  r9, rsi
    xor  r8, r9
    and  r8, rdx
    imul r8, r8, 48
    lea  rax, [r8+40]
    ret

; -----------------------------------------------------------------
; utxo_put(u, txid, index, value, script, slen)
global utxo_put
utxo_put:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x20
    mov  r12, rdi       ; u
    mov  r13, rsi       ; txid
    mov  r14, rdx       ; index
    mov  r15, rcx       ; value
    ; value is 64-bit in rcx; script in r8, slen in r9
    mov  rax, [rbp+16]
    mov  [rbp-0x28], r8     ; script
    mov  [rbp-0x30], r9     ; slen
    ; ---- find slot ----
    mov  rdi, r13
    mov  rsi, r14
    mov  rdx, [r12+8]       ; mask
    call utxo_hash
    mov  rbx, rax           ; slot offset (relative to u)
    ; linear probe from slot
.probe:
    ; compute slot base = u + rbx
    lea  rax, [r12+rbx]
    ; index field
    mov  ecx, [rax+40]
    cmp  ecx, 0xFFFFFFFF
    je   .found_empty
    ; occupied: compare txid (32) and index
    cmp  ecx, r14d
    jne  .next
    push r14
    push r13
    lea  rsi, [rax+8]
    mov  rdi, r13
    mov  rdx, 32
    push rbx
    call memcmp_asm
    pop  rbx
    pop  r13
    pop  r14
    test eax, eax
    jz   .dup
.next:
    ; wrap: slot offset spans [40 .. 40 + (mask+1)*48)
    mov  rcx, [r12+8]        ; mask
    inc  rcx                ; slot count
    imul rcx, rcx, 48
    add  rcx, 40            ; region_end_offset
    add  rbx, 48
    cmp  rbx, rcx
    jb   .probe_cont
    mov  rbx, 40            ; wrap to first slot
.probe_cont:
    jmp  .probe
.found_empty:
    ; ---- write slot ----
    lea  rdx, [r12+rbx]
    mov  [rdx+40], r14d        ; index
    ; copy txid
    mov  rdi, rdx
    add  rdi, 8
    mov  rsi, r13
    mov  rcx, 32
    push rbx
    call memcpy_asm
    pop  rbx
    ; ---- allocate blob record ----
    mov  rax, [r12+32]         ; fill = record offset
    mov  rcx, [rbp-0x30]       ; slen
    lea  rcx, [rcx+16]         ; + value(8) + slen(8)
    lea  rdx, [rax+rcx]
    cmp  rdx, [r12+24]         ; blob_cap
    ja   .full
    ; record at blob + fill
    mov  rcx, [r12+16]
    add  rcx, rax              ; record base
    ; store blob_off in the slot
    lea  rdx, [r12+rbx]
    mov  [rdx], rax
    ; write value, slen
    mov  r8, r15
    mov  [rcx], r8             ; value
    mov  r8, [rbp-0x30]
    mov  [rcx+8], r8           ; script_len
    ; copy script into record+16
    lea  rdi, [rcx+16]
    mov  rsi, [rbp-0x28]
    push rbx
    mov  rcx, [rbp-0x30]
    call memcpy_asm
    pop  rbx
    ; fill += 16 + slen ; n++
    mov  r8, [rbp-0x30]
    lea  r8, [r8+16]
    add  qword [r12+32], r8
    inc  qword [r12]
    mov  eax, 1
    jmp  .done
.dup:
    mov  eax, 0
    jmp  .done
.full:
    mov  eax, 2
.done:
    add  rsp, 0x20
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; -----------------------------------------------------------------
; utxo_get(u, txid, index, &value, &script, &slen)
global utxo_get
utxo_get:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x20
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  [rbp-0x28], rcx    ; &value
    mov  [rbp-0x30], r8     ; &script
    mov  [rbp-0x38], r9     ; &slen
    mov  rdi, r13
    mov  rsi, r14
    mov  rdx, [r12+8]
    call utxo_hash
    mov  rbx, rax
.probe:
    lea  rax, [r12+rbx]
    mov  ecx, [rax+40]
    cmp  ecx, 0xFFFFFFFF
    je   .miss
    cmp  ecx, r14d
    jne  .pn
    push r14
    push r13
    lea  rsi, [rax+8]
    mov  rdi, r13
    mov  rdx, 32
    push rbx
    call memcmp_asm
    pop  rbx
    pop  r13
    pop  r14
    test eax, eax
    jz   .hit
.pn:
    mov  rcx, [r12+8]
    inc  rcx
    imul rcx, rcx, 48
    add  rcx, 40
    add  rbx, 48
    cmp  rbx, rcx
    jb   .pc
    mov  rbx, 40
.pc:
    jmp  .probe
.hit:
    lea  rcx, [r12+rbx]
    mov  rdx, [rcx]         ; blob_off
    mov  rax, [r12+16]      ; blob base
    add  rax, rdx           ; record
    ; value
    mov  rdx, [rbp-0x28]
    mov  r8, [rax]
    mov  [rdx], r8
    ; script ptr
    mov  rdx, [rbp-0x30]
    lea  r8, [rax+16]
    mov  [rdx], r8
    ; slen
    mov  rdx, [rbp-0x38]
    mov  r8, [rax+8]
    mov  [rdx], r8
    mov  eax, 1
    jmp  .done2
.miss:
    xor  eax, eax
.done2:
    add  rsp, 0x20
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; -----------------------------------------------------------------
; utxo_del(u, txid, index) -> 1 deleted / 0 miss
global utxo_del
utxo_del:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x20
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  rdi, r13
    mov  rsi, r14
    mov  rdx, [r12+8]
    call utxo_hash
    mov  rbx, rax
.probe:
    lea  rax, [r12+rbx]
    mov  ecx, [rax+40]
    cmp  ecx, 0xFFFFFFFF
    je   .miss
    cmp  ecx, r14d
    jne  .pn
    push r14
    push r13
    lea  rsi, [rax+8]
    mov  rdi, r13
    mov  rdx, 32
    push rbx
    call memcmp_asm
    pop  rbx
    pop  r13
    pop  r14
    test eax, eax
    jz   .hit
.pn:
    mov  rcx, [r12+8]
    inc  rcx
    imul rcx, rcx, 48
    add  rcx, 40
    add  rbx, 48
    cmp  rbx, rcx
    jb   .pc
    mov  rbx, 40
.pc:
    jmp  .probe
.hit:
    lea  rdx, [r12+rbx]
    mov  dword [rdx+40], 0xFFFFFFFF   ; mark empty
    dec  qword [r12]
    mov  eax, 1
    jmp  .done3
.miss:
    xor  eax, eax
.done3:
    add  rsp, 0x20
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; utxo_count(u)
global utxo_count
utxo_count:
    mov  rax, [rdi]
    ret

; -----------------------------------------------------------------
; small helpers (local)
; memcmp_asm(a, b, n) -> 0 equal / nonzero differ
memcmp_asm:
    push rcx
.ml:
    test rdx, rdx
    jz   .meq
    mov  al, [rdi]
    mov  cl, [rsi]
    cmp  al, cl
    jne  .mne
    inc  rdi
    inc  rsi
    dec  rdx
    jmp  .ml
.meq:
    xor  eax, eax
    pop  rcx
    ret
.mne:
    mov  eax, 1
    pop  rcx
    ret

; memcpy_asm(dst, src, n)
memcpy_asm:
    push rcx
    push rsi
    push rdi
.yl:
    test rcx, rcx
    jz   .ydone
    mov  al, [rsi]
    mov  [rdi], al
    inc  rdi
    inc  rsi
    dec  rcx
    jmp  .yl
.ydone:
    pop  rdi
    pop  rsi
    pop  rcx
    ret
