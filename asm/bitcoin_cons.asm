; ============================================================================
; bitcoin_cons.asm -- block-level consensus checks. 100% AI-authored x86-64 asm.
;
; cons_verify(block, len, txid_scratch, cap) -> 1 valid / 0 invalid
;
; Checks: PoW (pow_check), every tx parses in-bounds, first tx is a coinbase
; (n_in==1), txids collected into txid_scratch, merkle_root(txids) == header root.
;
; ALL state in stack locals below the rbx save slot (robust to caller codegen).
; Frame: save rbx @ rbp-8.  Locals:
;     rbp-0x10 block, rbp-0x18 len, rbp-0x20 scratch, rbp-0x28 cap (qwords)
;     rbp-0x30 idx (qword), rbp-0x34 n (dword)
;     rbp-0x38 (reserved/unused), rbp-0x40 expected_txcount (qword)
;     rbp-0x98 txinfo[64], rbp-0xb8 txid_tmp[32], rbp-0xd8 merkle_out[32]
;   sub rsp, 0xf8 keeps RSP 0 mod16 at every nested call.
;
; ABI lesson baked in: `n` is a DWORD adjacent to `idx` (qword). You MUST read
; it with a 32-bit load (mov eax,[rbp-0x34]) -- an 8-byte load would pull in the
; low bytes of idx and corrupt the txid-slot index, desyncing the whole walk.
; ============================================================================
default rel
section .text

extern sha256d
extern merkle_root
extern pow_check
extern tx_parse
extern tx_txid

global cons_verify
cons_verify:
    push rbp
    mov  rbp, rsp
    push rbx
    ; frame 0x1000f8 (== 8 mod16) keeps RSP at the System V call convention
    ; (rsp==8 mod16 right before each internal call), and allocates 1MB of
    ; reconstruction scratch at rbp-0x100000 below the existing locals for
    ; tx_txid's unwitnessed-txid rebuild.
    sub  rsp, 0x1000f8
    mov  [rbp-0x10], rdi     ; block
    mov  [rbp-0x18], rsi     ; len
    mov  [rbp-0x20], rdx     ; scratch
    mov  [rbp-0x28], rcx     ; cap

    cmp  rsi, 82
    jb   .fail
    mov  rdi, [rbp-0x10]
    call pow_check
    test eax, eax
    jz   .fail

    ; ---- read the tx-count CompactSize at block+80 (wire-required field) ----
    ; r8 = block, r9 = len, r10 = cursor (caller-saved; no nested calls here).
    mov  r8, [rbp-0x10]
    mov  r9, [rbp-0x18]
    lea  r10, [r8+80]        ; cursor = &block[80] (the count byte)
    movzx ecx, byte [r10]
    cmp  ecx, 0xfd
    jb   .count1
    cmp  ecx, 0xfd
    je   .count2
    cmp  ecx, 0xfe
    je   .count4
    ; 0xff: 8-byte count (bytes 81..88)
    ; bounds: (r10+9) must be <= block+len (absolute end), NOT <= len.
    lea  rdx, [r10+9]
    lea  rax, [r8+r9]
    cmp  rdx, rax
    ja   .fail
    mov  rcx, [r10+1]
    add  r10, 9
    jmp  .havecount
.count4:
    lea  rdx, [r10+5]
    lea  rax, [r8+r9]
    cmp  rdx, rax
    ja   .fail
    mov  ecx, [r10+1]
    mov  ecx, ecx             ; zero-extend 32->64 (count is unsigned 32-bit)
    add  r10, 5
    jmp  .havecount
.count2:
    lea  rdx, [r10+3]
    lea  rax, [r8+r9]
    cmp  rdx, rax
    ja   .fail
    movzx ecx, word [r10+1]
    add  r10, 3
    jmp  .havecount
.count1:
    ; 1-byte count: ecx already holds the byte (zero-extended 0..252)
    add  r10, 1
.havecount:
    test rcx, rcx
    jz   .fail                ; a valid block has >= 1 tx (the coinbase)
    ; expected_txcount lives at rbp-0x40 (a qword) -- MUST NOT sit where the
    ; walk's n / idx live. n is a dword at -0x34 and idx a qword at -0x30;
    ; a qword here at -0x38 would overlap n (bytes -0x34..-0x37) and the walk's
    ; `inc dword [n]` would corrupt the high dword of the count.
    mov  [rbp-0x40], rcx      ; expected_txcount (qword)
    ; tx list starts where the cursor ended. r10 is an ABSOLUTE pointer;
    ; convert to a byte OFFSET (r10 - block) because the walk indexes
    ; block+idx and compares idx against len.
    sub  r10, r8
    mov  qword [rbp-0x30], r10   ; idx = tx_list_start offset (not 80!)
    mov  dword [rbp-0x34], 0
.walk:
    mov  rax, [rbp-0x18]
    mov  rcx, [rbp-0x30]
    sub  rax, rcx
    jle  .done
    ; tx_parse(&txinfo, block+idx, len-idx)
    lea  rdi, [rbp-0x98]
    mov  rsi, [rbp-0x10]
    add  rsi, rcx
    mov  rdx, rax
    call tx_parse
    test eax, eax
    jz   .fail
    mov  rax, [rbp-0x98]
    test rax, rax
    jz   .fail
    mov  rcx, [rbp-0x30]
    add  rcx, rax
    cmp  rcx, [rbp-0x18]
    ja   .fail
    cmp  dword [rbp-0x34], 0
    jne  .notcb
    mov  eax, [rbp-0x98+12]
    cmp  eax, 1
    jne  .fail
.notcb:
    mov  eax, [rbp-0x34]
    cmp  eax, [rbp-0x28]
    jae  .fail
    ; txid = tx_txid(txid_tmp, block+idx, tx_len, rbp-0x100000, 0x100000)
    ; (BIP141 unwitnessed txid -- handles legacy AND SegWit)
    mov  rax, [rbp-0x98]
    lea  rdi, [rbp-0xb8]
    mov  rsi, [rbp-0x10]
    mov  rcx, [rbp-0x30]
    add  rsi, rcx
    mov  rdx, rax
    lea  rcx, [rbp-0x100000]
    mov  r8d, 0x100000
    call tx_txid
    test eax, eax
    jz   .fail
    ; copy txid_tmp -> scratch + n*32  (n is a DWORD -- use 32-bit load!)
    mov  eax, [rbp-0x34]
    imul rax, 32
    mov  rdi, [rbp-0x20]
    add  rdi, rax
    lea  rsi, [rbp-0xb8]
    mov  rcx, 32
    rep  movsb
    inc  dword [rbp-0x34]
    mov  rax, [rbp-0x98]
    add  qword [rbp-0x30], rax
    jmp  .walk
.done:
    mov  rax, [rbp-0x30]
    cmp  rax, [rbp-0x18]
    jne  .fail
    cmp  dword [rbp-0x34], 0
    jle  .fail
    ; walked tx count (n) MUST equal the wire tx-count field
    mov  eax, [rbp-0x34]
    mov  eax, eax            ; zero-extend 32->64
    cmp  rax, [rbp-0x40]
    jne  .fail
    lea  rdi, [rbp-0xd8]
    mov  rsi, [rbp-0x20]
    mov  edx, [rbp-0x34]
    call merkle_root
    ; compare merkle_out vs header field block+36
    lea  rdi, [rbp-0xd8]
    mov  rsi, [rbp-0x10]
    add  rsi, 36
    mov  rcx, 32
    repe cmpsb
    jne  .fail
    mov  eax, 1
    jmp  .ret
.fail:
    mov  eax, 0
.ret:
    add  rsp, 0x1000f8
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
