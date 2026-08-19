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
; Blob record at offset o (2026-08-19, Stage D: added height/is_coinbase so
; script verification can enforce the 100-block coinbase maturity rule --
; the store previously had no data source for it at all):
;   [+0  u64 value][+8 u32 height][+12 u8 is_coinbase][+13..15 pad]
;   [+16 u64 script_len][+24 u8 script[script_len]]
; height/is_coinbase are packed into ONE qword at +8 (height in the low 32
; bits, is_coinbase in byte 32) so the read/write is a single mov, not two.
;
; Exports (System V AMD64):
;   size_t utxo_struct_size(unsigned long slots)
;   void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap)
;   long   utxo_put(void* u, const u8 txid[32], unsigned long index,
;                   unsigned long long value, unsigned long height,
;                   unsigned long is_coinbase, const u8* script, unsigned long slen)
;               -> 1 new / 0 dup / 2 table-full
;   long   utxo_get(void* u, const u8 txid[32], unsigned long index,
;                   unsigned long long* value, unsigned long* height,
;                   unsigned long* is_coinbase, const u8** script, unsigned long* slen)
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
; utxo_put(u, txid, index, value, height, is_coinbase, script, slen)
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
    ; r8=height r9=is_coinbase; script/slen are now the 7th/8th args (stack).
    ; NOTE: save area is [rbp-8..-0x28] (5 pushes); locals live at
    ; [rbp-0x30] and below so the saved callee-saved regs are not clobbered.
    mov  eax, r8d
    mov  [rbp-0x40], rax    ; height (zero-extended to 64 bits)
    mov  eax, r9d
    mov  [rbp-0x48], rax    ; is_coinbase (zero-extended to 64 bits)
    mov  rax, [rbp+16]
    mov  [rbp-0x30], rax    ; script
    mov  rax, [rbp+24]
    mov  [rbp-0x38], rax    ; slen
    ; ---- find slot ----
    mov  rdi, r13
    mov  rsi, r14
    mov  rdx, [r12+8]       ; mask
    call utxo_hash
    mov  rbx, rax           ; slot offset (relative to u)
    xor  r10, r10            ; probe count (r10 unused elsewhere in this
                               ; function; neither utxo_hash nor memcmp_asm
                               ; touch it, so it safely survives both calls
                               ; below without needing to be pushed/popped)
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
    ; Bounded probe count: with backward-shift deletion an empty slot is
    ; guaranteed to exist whenever the table isn't genuinely full, and is
    ; guaranteed to be found within one lap (slot_count probes) of linear
    ; probing -- so exceeding that here means every slot is occupied and we
    ; must report full rather than looping forever (mirrors mpool_put's
    ; existing bounded probe, bitcoin_mempool.asm).
    inc  r10
    mov  rcx, [r12+8]        ; mask
    inc  rcx                ; slot count
    cmp  r10, rcx
    jae  .full
    ; wrap: slot offset spans [40 .. 40 + (mask+1)*48)
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
    mov  rcx, [rbp-0x38]       ; slen
    lea  rcx, [rcx+24]         ; + value(8) + height/coinbase(8) + slen(8)
    lea  rdx, [rax+rcx]
    cmp  rdx, [r12+24]         ; blob_cap
    ja   .full
    ; record at blob + fill
    mov  rcx, [r12+16]
    add  rcx, rax              ; record base
    ; store blob_off in the slot
    lea  rdx, [r12+rbx]
    mov  [rdx], rax
    ; write value
    mov  r8, r15
    mov  [rcx], r8             ; value
    ; write height (low 32 bits) + is_coinbase (byte 32) as one packed qword
    mov  r8, [rbp-0x40]        ; height
    mov  r9, [rbp-0x48]        ; is_coinbase
    shl  r9, 32
    or   r8, r9
    mov  [rcx+8], r8           ; height/is_coinbase
    ; slen
    mov  r8, [rbp-0x38]
    mov  [rcx+16], r8          ; script_len
    ; copy script into record+24
    lea  rdi, [rcx+24]
    mov  rsi, [rbp-0x30]
    push rbx
    mov  rcx, [rbp-0x38]
    call memcpy_asm
    pop  rbx
    ; fill += 24 + slen ; n++
    mov  r8, [rbp-0x38]
    lea  r8, [r8+24]
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
; utxo_get(u, txid, index, &value, &height, &is_coinbase, &script, &slen)
global utxo_get
utxo_get:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x40
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    ; NOTE: save area is [rbp-8..-0x28] (5 pushes); locals live BELOW it
    ; at [rbp-0x40..] so the saved callee-saved regs are not clobbered.
    mov  [rbp-0x40], rcx    ; &value
    mov  [rbp-0x48], r8     ; &height
    mov  [rbp-0x50], r9     ; &is_coinbase
    mov  rax, [rbp+16]
    mov  [rbp-0x58], rax    ; &script
    mov  rax, [rbp+24]
    mov  [rbp-0x60], rax    ; &slen
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
    mov  rdx, [rbp-0x40]
    mov  r8, [rax]
    mov  [rdx], r8
    ; height (low 32) / is_coinbase (byte 32) -- one packed qword at [+8].
    ; NOTE: `and r8, 0xFFFFFFFF` would sign-extend the immediate to all-1s
    ; (no imm64 AND form), making the mask a no-op -- caught by nasm's own
    ; "signed dword value exceeds bounds" warning before this ever ran.
    ; `mov r8d, r9d` zero-extends the upper 32 bits instead (real x86-64
    ; semantics of a 32-bit register write), which is what's actually wanted.
    mov  r9, [rax+8]
    mov  rdx, [rbp-0x48]
    mov  r8d, r9d
    mov  [rdx], r8              ; *height
    mov  rdx, [rbp-0x50]
    mov  r8, r9
    shr  r8, 32
    and  r8, 0xFF
    mov  [rdx], r8              ; *is_coinbase
    ; script ptr
    mov  rdx, [rbp-0x58]
    lea  r8, [rax+24]
    mov  [rdx], r8
    ; slen
    mov  rdx, [rbp-0x60]
    mov  r8, [rax+16]
    mov  [rdx], r8
    mov  eax, 1
    jmp  .done2
.miss:
    xor  eax, eax
.done2:
    add  rsp, 0x40
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
    mov  r15, [r12+8]      ; mask (persists; needed again in the backward-
                             ; shift phase below after a hit)
    mov  rdi, r13
    mov  rsi, r14
    mov  rdx, r15
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
    ; ---- backward-shift deletion (NO tombstones) ----
    ; Plain "mark empty" here would break the invariant utxo_get/utxo_put's
    ; probes depend on: any key that collided with this one and got pushed
    ; past it during insertion would become unreachable the moment this slot
    ; goes empty, since their own probe stops at the first empty slot it
    ; meets. Instead we open a "gap" at the deleted slot and walk forward,
    ; pulling back any later entry whose ideal (hash) slot lies at-or-before
    ; the gap in the forward probe order -- the standard backward-shift
    ; algorithm for linear-probed open addressing (Knuth Vol 3 Algorithm R).
    ; This keeps "empty slot terminates a probe" true at all times, so
    ; utxo_get/utxo_put need no changes at all.
    ;
    ; rbx currently holds the found slot's BYTE offset; convert to a
    ; 0-based slot index (r13) since the wraparound distance comparison
    ; below needs modular arithmetic, and slot count (mask+1) is a power of
    ; two while the byte stride (48) is not.
    mov  rax, rbx
    sub  rax, 40
    xor  edx, edx
    mov  ecx, 48
    div  ecx
    mov  r13, rax              ; r13 = i (0-based gap index)

    lea  rdx, [r12+rbx]
    mov  dword [rdx+40], 0xFFFFFFFF   ; open the gap
    dec  qword [r12]                  ; n--

    mov  r14, r13               ; j := i (advanced before first use below)
.bs_loop:
    inc  r14
    and  r14, r15                ; j = (j+1) & mask  (r15 = mask, loaded above)
    mov  rax, r14
    imul rax, rax, 48
    add  rax, 40
    add  rax, r12                ; rax = &slot[j]
    mov  ecx, [rax+40]           ; slot[j]'s index field
    cmp  ecx, 0xFFFFFFFF
    je   .bs_done                 ; genuine empty: hole fully propagated, stop
    mov  rbx, rax                 ; rbx = &slot[j] (persists across the call)
    push rbx
    push r13
    push r14
    lea  rdi, [rbx+8]              ; txid ptr = slot[j]'s stored txid
    mov  esi, ecx                   ; index = slot[j]'s stored index
    mov  rdx, r15                    ; mask
    call utxo_hash                    ; rax = byte offset of slot[j]'s home slot
    pop  r14
    pop  r13
    pop  rbx
    sub  rax, 40
    xor  edx, edx
    mov  ecx, 48
    div  ecx                          ; rax = k (0-based home slot index)
    ; is i within [k, j) walking forward from k, modulo capacity? i.e. is
    ; the gap on slot[j]'s own probe path from its home to where it sits?
    mov  rcx, r13
    sub  rcx, rax
    and  rcx, r15                     ; rcx = d_i = (i - k) & mask
    mov  rdx, r14
    sub  rdx, rax
    and  rdx, r15                     ; rdx = d_j = (j - k) & mask
    cmp  rcx, rdx
    jae  .bs_loop                     ; not safe to move -- leave slot[j], keep scanning
    ; safe: pull slot[j] back into the gap at i, then the gap moves to j.
    mov  rax, r13
    imul rax, rax, 48
    add  rax, 40
    add  rax, r12                     ; rax = &slot[i]
    mov  rdi, rax
    mov  rsi, rbx
    mov  rcx, 48
    push rbx
    push r13
    push r14
    call memcpy_asm
    pop  r14
    pop  r13
    pop  rbx
    mov  dword [rbx+40], 0xFFFFFFFF   ; the old slot[j] position is now empty
    mov  r13, r14                     ; i := j (gap follows the moved entry)
    jmp  .bs_loop
.bs_done:
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
