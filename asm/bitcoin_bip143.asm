; ============================================================================
; bitcoin_bip143.asm -- the BIP143 (segwit v0) sighash builder, 100%
; AI-generated x86-64 assembly (NASM, ELF64). Phase 2 slice 12 of the C->asm
; conversion (2026-08-24). Twins of bitcoin_segwit.c's swtx_parse and
; segwit_v0_sighash; differential: tests/test_bip143_diff.c.
;
;   long swtx_parse_asm(swtx_t* t, u32* off)                  -> 1 / 0
;   long segwit_v0_sighash_asm(u8 out32[32], const u8* tx, i64 txlen,
;                              i64 n_in, u32 nHashType, u64 amount,
;                              /*stack*/ const u8* scriptCode,
;                              u64 scriptcode_len, u8* pre, long cap)
;     -> preimage length (> 0) or 0
;
; A displaced byte here is a WRONG SIGHASH, which is silent -- every segwit
; v0 input in the chain depends on this exact serialization. The twin is
; byte-for-byte, including:
;   - the canonical (minimal-encoding-enforcing) compactsize reader, shared
;     with bitcoin_strip_witness.asm's RDCSC contract;
;   - swtx_parse's SPLIT scriptSig bound (`avail < sl` then `avail - sl < 4`)
;     -- deliberately NOT the wrapping `avail < sl + 4` the tx_verify parsers
;     use; that difference is the C's, and the twin preserves it on both
;     sides rather than harmonising them;
;   - version read as a SIGN-EXTENDED int32 into an int64 field, written
;     back into the preimage as a plain u32;
;   - hashOutputs computed IN PLACE over the transaction's own output bytes
;     (no CTxOut is rebuilt), with incident #21's SW_MIDSTATE_CAP bound;
;   - the SIGHASH_SINGLE / NONE / ANYONECANPAY midstate-zeroing rules and
;     SINGLE's `n_in < nout` guard;
;   - every cap check, in the C's order, so a too-small `pre` fails at the
;     same field.
;
; swtx_t (offsetof-pinned): tx@0 txlen@8 end@16 version@24 locktime@32
;   nin@40 nout@48 inputs@56 in_off@64 out_off@72, size 80.
; Per-thread mbuf (4 MiB) and soff (600000 u32) mirror the C's __thread
; buffers: lazy .tbss + malloc, abort on OOM.
; ============================================================================

BITS 64
DEFAULT REL

extern malloc
extern abort
extern sha256_full                    ; asm

%define T_TX        0
%define T_TXLEN     8
%define T_END       16
%define T_VERSION   24
%define T_LOCKTIME  32
%define T_NIN       40
%define T_NOUT      48
%define T_INPUTS    56
%define T_INOFF     64
%define T_OUTOFF    72

%define SW_MIDSTATE_CAP (4 << 20)
%define SW_OFF_ENTRIES  600000
%define SOFF_BYTES      (SW_OFF_ENTRIES * 4)

%define SIGHASH_ALL          1
%define SIGHASH_NONE         2
%define SIGHASH_SINGLE       3
%define SIGHASH_ANYONECANPAY 0x80

section .tbss alloc noexec nowrite tls align=8
global bip143_mbuf
bip143_mbuf: resq 1
global bip143_soff
bip143_soff: resq 1

section .text

%macro TLS_ADDR 2
    mov   %1, [rel %2 wrt ..gottpoff]
    add   %1, qword [fs:0]
%endmacro

%macro TLS_LAZY 3
    TLS_ADDR rcx, %2
    mov  %1, [rcx]
    test %1, %1
    jnz  %%have
    push rcx
    push rcx
    mov  edi, %3
    call malloc
    test rax, rax
    jnz  %%ok
    call abort
%%ok:
    pop  rcx
    pop  rcx
    mov  [rcx], rax
    mov  %1, rax
%%have:
%endmacro

; RDCSC <fail>: canonical compactsize at rbx (end = r12) -> rax, rbx
; advanced; jumps to <fail> on truncation OR non-canonical encoding.
; (Same contract as bitcoin_strip_witness.asm's macro -- this file's C
; shares that reader.) Clobbers rax, rcx.
%macro RDCSC 1
    cmp  rbx, r12
    jae  %1
    movzx eax, byte [rbx]
    inc  rbx
    cmp  al, 0xfd
    jb   %%done
    je   %%two
    cmp  al, 0xfe
    je   %%four
    mov  rcx, r12
    sub  rcx, rbx
    cmp  rcx, 8
    jb   %1
    mov  rax, [rbx]
    add  rbx, 8
    mov  rcx, 0x100000000
    cmp  rax, rcx
    jb   %1
    jmp  %%done
%%four:
    mov  rcx, r12
    sub  rcx, rbx
    cmp  rcx, 4
    jb   %1
    mov  eax, [rbx]
    add  rbx, 4
    cmp  rax, 0x10000
    jb   %1
    jmp  %%done
%%two:
    mov  rcx, r12
    sub  rcx, rbx
    cmp  rcx, 2
    jb   %1
    movzx eax, word [rbx]
    add  rbx, 2
    cmp  eax, 0xfd
    jb   %1
%%done:
%endmacro

; ----------------------------------------------------------------------------
; sha256d: rdi = out32, rsi = msg, rdx = len. Double SHA-256.
; Frame: push rbp + 1 push, sub rsp,0x38 -> 0 mod 16 at both calls.
; Scratch m[32] at [rbp-0x30].
; ----------------------------------------------------------------------------
sha256d_local:
    push rbp
    mov  rbp, rsp
    push rbx
    sub  rsp, 0x38
    mov  rbx, rdi                        ; out
    lea  rdi, [rbp-0x30]                 ; m[32]
    call sha256_full                     ; rsi/rdx already set
    mov  rdi, rbx
    lea  rsi, [rbp-0x30]
    mov  edx, 32
    call sha256_full
    add  rsp, 0x38
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; swtx_parse_asm(t=rdi, off=rsi) -> 1 / 0
; Frame: push rbp + 5 pushes, sub rsp,0x58 -> rsp = rbp-0x80, 0 mod 16.
; Locals: [rbp-0x30] t  [rbp-0x38] off  [rbp-0x40] i  [rbp-0x48] nitems
;         [rbp-0x50] in_off  [rbp-0x58] out_off  [rbp-0x60] segwit
; Registers: rbx = cursor (RDCSC), r12 = end, r13 = tx base, r14/r15 scratch.
; ----------------------------------------------------------------------------
global swtx_parse_asm
swtx_parse_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x58
    mov  [rbp-0x30], rdi
    mov  [rbp-0x38], rsi
    mov  r13, [rdi+T_TX]
    mov  rax, [rdi+T_TXLEN]
    ; txlen < 10 || txlen > 0xffffffff -> 0
    cmp  rax, 10
    jl   .no
    mov  rcx, 0xffffffff
    cmp  rax, rcx
    ja   .no
    lea  r12, [r13+rax]
    mov  [rdi+T_END], r12
    ; version = (int32)tx[0..4], sign-extended into the int64 field
    movsxd rax, dword [r13]
    mov  [rdi+T_VERSION], rax
    lea  rbx, [r13+4]
    ; segwit marker/flag
    cmp  byte [rbx], 0x00
    jne  .nin
    cmp  byte [rbx+1], 0x01
    jne  .nin
    add  rbx, 2
.nin:
    RDCSC .no
    test rax, rax                        ; nin <= 0 -> 0 (also catches >= 2^63)
    jle  .no
    mov  rdi, [rbp-0x30]
    mov  [rdi+T_NIN], rax
    mov  r14, rax                        ; nin
    lea  rcx, [rax+1]
    cmp  rcx, SW_OFF_ENTRIES
    ja   .no
    mov  [rdi+T_INPUTS], rbx             ; first prevout
    mov  rsi, [rbp-0x38]
    mov  [rbp-0x50], rsi                 ; in_off = off
    xor  r15d, r15d                      ; i = 0
.in_loop:
    cmp  r15, r14
    jae  .in_done
    ; in_off[i] = q - tx
    mov  rax, rbx
    sub  rax, r13
    mov  rcx, [rbp-0x50]
    mov  [rcx+r15*4], eax
    ; avail < 36 ?
    mov  rax, r12
    sub  rax, rbx
    cmp  rax, 36
    jb   .no
    add  rbx, 36
    RDCSC .no                            ; sl
    ; SPLIT bound (the C's, deliberately non-wrapping):
    ;   avail < sl  ||  avail - sl < 4
    mov  rcx, r12
    sub  rcx, rbx                        ; avail
    cmp  rcx, rax
    jb   .no
    sub  rcx, rax
    cmp  rcx, 4
    jb   .no
    lea  rbx, [rbx+rax+4]
    inc  r15
    jmp  .in_loop
.in_done:
    mov  rax, rbx
    sub  rax, r13
    mov  rcx, [rbp-0x50]
    mov  [rcx+r14*4], eax                ; in_off[nin]
    mov  rdi, [rbp-0x30]
    mov  [rdi+T_INOFF], rcx
    RDCSC .no                            ; nout
    test rax, rax
    js   .no                             ; nout < 0
    mov  [rdi+T_NOUT], rax
    mov  r15, rax                        ; nout
    ; nin+1 + nout+1 > SW_OFF_ENTRIES ?
    lea  rcx, [r14+1]
    add  rcx, r15
    inc  rcx
    cmp  rcx, SW_OFF_ENTRIES
    ja   .no
    ; out_off = off + nin + 1
    mov  rcx, [rbp-0x50]
    lea  rcx, [rcx+r14*4+4]
    mov  [rbp-0x58], rcx
    xor  r14d, r14d                      ; i = 0 (reuse r14 as the out index)
.out_loop:
    cmp  r14, r15
    jae  .out_done
    mov  rax, rbx
    sub  rax, r13
    mov  rcx, [rbp-0x58]
    mov  [rcx+r14*4], eax
    mov  rax, r12
    sub  rax, rbx
    cmp  rax, 8
    jb   .no
    add  rbx, 8
    RDCSC .no                            ; sl
    mov  rcx, r12
    sub  rcx, rbx
    cmp  rcx, rax
    jb   .no
    add  rbx, rax
    inc  r14
    jmp  .out_loop
.out_done:
    mov  rax, rbx
    sub  rax, r13
    mov  rcx, [rbp-0x58]
    mov  [rcx+r15*4], eax                ; out_off[nout]
    mov  rdi, [rbp-0x30]
    mov  [rdi+T_OUTOFF], rcx
    ; witness walk (to reach locktime); segwit detected from tx[4:6]
    cmp  byte [r13+4], 0x00
    jne  .locktime
    cmp  byte [r13+5], 0x01
    jne  .locktime
    mov  r14, [rdi+T_NIN]
    xor  r15d, r15d
.wit_loop:
    cmp  r15, r14
    jae  .locktime
    RDCSC .no                            ; nitems
    mov  [rbp-0x48], rax
.item_loop:
    cmp  qword [rbp-0x48], 0
    je   .item_done
    RDCSC .no                            ; il
    mov  rcx, r12
    sub  rcx, rbx
    cmp  rcx, rax
    jb   .no
    add  rbx, rax
    dec  qword [rbp-0x48]
    jmp  .item_loop
.item_done:
    inc  r15
    jmp  .wit_loop
.locktime:
    mov  rax, r12
    sub  rax, rbx
    cmp  rax, 4
    jb   .no
    mov  eax, [rbx]
    mov  rdi, [rbp-0x30]
    mov  [rdi+T_LOCKTIME], eax
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    add  rsp, 0x58
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; segwit_v0_sighash_asm -- see header.
;   rdi=out32 rsi=tx rdx=txlen rcx=n_in r8d=nHashType r9=amount
;   [rbp+16]=scriptCode [rbp+24]=scriptcode_len [rbp+32]=pre [rbp+40]=cap
; Frame: push rbp + 5 pushes, sub rsp,0x148 -> 0 mod 16 at every call.
; Locals (all strictly below the save area; NON-OVERLAPPING -- slice 11's
; lesson): [rbp-0x30] out32  [rbp-0x38] n_in  [rbp-0x40] htype(dword)
;   [rbp-0x44] acp(dword)  [rbp-0x50] p  [rbp-0x58] pend  [rbp-0x60] mbuf
;   [rbp-0x68] nHashType  [rbp-0x70] amount
;   t (swtx_t, 80B) @ [rbp-0xc8 .. -0x78)
;   hashPrevouts[32] @ -0xe8   hashSequence[32] @ -0x108
;   hashOutputs[32]  @ -0x128
; Registers: rbx = write cursor p, r12 = &t, r13 = mbuf, r14 = nin, r15 = i.
; ----------------------------------------------------------------------------
global segwit_v0_sighash_asm
segwit_v0_sighash_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x148
    mov  [rbp-0x30], rdi                 ; out32
    mov  [rbp-0x38], rcx                 ; n_in
    mov  [rbp-0x68], r8                  ; nHashType (full)
    mov  [rbp-0x70], r9                  ; amount
    lea  r12, [rbp-0xc8]                 ; &t
    mov  [r12+T_TX], rsi
    mov  [r12+T_TXLEN], rdx

    TLS_LAZY r13, bip143_mbuf, SW_MIDSTATE_CAP
    mov  [rbp-0x60], r13
    TLS_LAZY rsi, bip143_soff, SOFF_BYTES
    mov  rdi, r12
    call swtx_parse_asm
    test rax, rax
    jz   .fail
    ; n_in < 0 || n_in >= nin -> 0
    mov  rax, [rbp-0x38]
    test rax, rax
    js   .fail
    mov  r14, [r12+T_NIN]
    cmp  rax, r14
    jge  .fail
    ; htype = nHashType & 0x1f ; acp = nHashType & 0x80
    mov  eax, [rbp-0x68]
    mov  ecx, eax
    and  ecx, 0x1f
    mov  [rbp-0x40], ecx
    and  eax, SIGHASH_ANYONECANPAY
    mov  [rbp-0x44], eax
    ; zero the three midstates
    lea  rdi, [rbp-0x128]
    xor  eax, eax
    mov  ecx, 96
    rep  stosb
    ; p = pre ; pend = pre + cap
    mov  rbx, [rbp+32]
    mov  [rbp-0x50], rbx
    mov  rax, [rbp+40]
    add  rax, rbx
    mov  [rbp-0x58], rax

    cmp  dword [rbp-0x44], 0             ; acp?
    jne  .outputs
    ; ---- hashPrevouts: 36 bytes per input, from in_off ----
    mov  rax, r14
    imul rax, rax, 36
    cmp  rax, SW_MIDSTATE_CAP
    ja   .fail
    xor  r15d, r15d
    xor  edx, edx                        ; n
.hp_loop:
    cmp  r15, r14
    jae  .hp_done
    mov  rcx, [r12+T_INOFF]
    mov  ecx, [rcx+r15*4]
    add  rcx, [r12+T_TX]                 ; prevout ptr
    mov  rdi, r13
    add  rdi, rdx
    mov  rax, [rcx]
    mov  [rdi], rax
    mov  rax, [rcx+8]
    mov  [rdi+8], rax
    mov  rax, [rcx+16]
    mov  [rdi+16], rax
    mov  rax, [rcx+24]
    mov  [rdi+24], rax
    mov  eax, [rcx+32]
    mov  [rdi+32], eax
    add  rdx, 36
    inc  r15
    jmp  .hp_loop
.hp_done:
    mov  [rbp-0x130], rdx                ; n (saved across the call)
    lea  rdi, [rbp-0xe8]                 ; hashPrevouts
    mov  rsi, r13
    call sha256d_local
    ; ---- hashSequence (skipped for SINGLE and NONE) ----
    mov  eax, [rbp-0x40]
    cmp  eax, SIGHASH_SINGLE
    je   .outputs
    cmp  eax, SIGHASH_NONE
    je   .outputs
    mov  rax, r14
    shl  rax, 2
    cmp  rax, SW_MIDSTATE_CAP
    ja   .fail
    xor  r15d, r15d
    xor  edx, edx
.hs_loop:
    cmp  r15, r14
    jae  .hs_done
    ; sw_seq(i) = the 4 bytes ending in_off[i+1] (sequence is the last field)
    mov  rcx, [r12+T_INOFF]
    lea  rax, [r15+1]
    mov  ecx, [rcx+rax*4]
    add  rcx, [r12+T_TX]
    mov  eax, [rcx-4]
    mov  rdi, r13
    mov  [rdi+rdx], eax
    add  rdx, 4
    inc  r15
    jmp  .hs_loop
.hs_done:
    mov  [rbp-0x130], rdx
    lea  rdi, [rbp-0x108]                ; hashSequence
    mov  rsi, r13
    call sha256d_local

.outputs:
    ; ---- hashOutputs, in place over the tx's own output bytes ----
    mov  eax, [rbp-0x40]
    cmp  eax, SIGHASH_SINGLE
    je   .single
    cmp  eax, SIGHASH_NONE
    je   .preimage                       ; NONE: hashOutputs stays zero
    ; ALL-like: the whole [out_off[0], out_off[nout]) range
    mov  rcx, [r12+T_OUTOFF]
    mov  rax, [r12+T_NOUT]
    mov  edx, [rcx+rax*4]                ; out_off[nout]
    mov  eax, [rcx]                      ; out_off[0]
    sub  rdx, rax                        ; olen
    cmp  rdx, SW_MIDSTATE_CAP
    ja   .fail
    add  rax, [r12+T_TX]                 ; obytes
    mov  rsi, rax
    lea  rdi, [rbp-0x128]                ; hashOutputs
    call sha256d_local
    jmp  .preimage
.single:
    ; SINGLE: only if n_in < nout, else hashOutputs stays zero
    mov  rax, [rbp-0x38]
    cmp  rax, [r12+T_NOUT]
    jge  .preimage
    mov  rcx, [r12+T_OUTOFF]
    lea  rdx, [rax+1]
    mov  edx, [rcx+rdx*4]                ; out_off[n_in+1]
    mov  eax, [rcx+rax*4]                ; out_off[n_in]
    sub  rdx, rax
    cmp  rdx, SW_MIDSTATE_CAP
    ja   .fail
    add  rax, [r12+T_TX]
    mov  rsi, rax
    lea  rdi, [rbp-0x128]
    call sha256d_local

.preimage:
    ; version (written as u32 from the sign-extended int64 field)
    lea  rax, [rbx+4]
    cmp  rax, [rbp-0x58]
    ja   .fail
    mov  eax, [r12+T_VERSION]
    mov  [rbx], eax
    add  rbx, 4
    ; hashPrevouts || hashSequence
    lea  rax, [rbx+64]
    cmp  rax, [rbp-0x58]
    ja   .fail
    lea  rsi, [rbp-0xe8]
    mov  rdi, rbx
    mov  ecx, 32
    rep  movsb
    lea  rsi, [rbp-0x108]
    mov  ecx, 32
    rep  movsb
    add  rbx, 64
    ; outpoint[n_in] (36 bytes)
    lea  rax, [rbx+36]
    cmp  rax, [rbp-0x58]
    ja   .fail
    mov  rcx, [r12+T_INOFF]
    mov  rax, [rbp-0x38]
    mov  ecx, [rcx+rax*4]
    add  rcx, [r12+T_TX]
    mov  rsi, rcx
    mov  rdi, rbx
    mov  ecx, 36
    rep  movsb
    add  rbx, 36
    ; scriptCode: cs_size + bytes, bounded against cap the C's way
    mov  rax, [rbp+24]                   ; scriptcode_len
    ; cs_size(len)
    mov  ecx, 1
    cmp  rax, 0xfd
    jb   .cs_have
    mov  ecx, 3
    cmp  rax, 0xffff
    jbe  .cs_have
    mov  ecx, 5
    mov  rdx, 0xffffffff
    cmp  rax, rdx
    jbe  .cs_have
    mov  ecx, 9
.cs_have:
    mov  rdx, rbx
    sub  rdx, [rbp-0x50]                 ; p - pre
    add  rdx, rcx
    add  rdx, rax
    cmp  rdx, [rbp+40]                   ; > cap ?
    ja   .fail
    ; put_cs
    cmp  rax, 0xfd
    jae  .pc_big
    mov  [rbx], al
    inc  rbx
    jmp  .pc_data
.pc_big:
    cmp  rax, 0xffff
    ja   .pc_4
    mov  byte [rbx], 0xfd
    mov  [rbx+1], ax
    add  rbx, 3
    jmp  .pc_data
.pc_4:
    mov  rdx, 0xffffffff
    cmp  rax, rdx
    ja   .pc_8
    mov  byte [rbx], 0xfe
    mov  [rbx+1], eax
    add  rbx, 5
    jmp  .pc_data
.pc_8:
    mov  byte [rbx], 0xff
    mov  [rbx+1], rax
    add  rbx, 9
.pc_data:
    mov  rcx, [rbp+24]
    mov  rsi, [rbp+16]
    mov  rdi, rbx
    add  rbx, rcx
    rep  movsb
    ; amount
    lea  rax, [rbx+8]
    cmp  rax, [rbp-0x58]
    ja   .fail
    mov  rax, [rbp-0x70]
    mov  [rbx], rax
    add  rbx, 8
    ; nSequence[n_in]
    lea  rax, [rbx+4]
    cmp  rax, [rbp-0x58]
    ja   .fail
    mov  rcx, [r12+T_INOFF]
    mov  rax, [rbp-0x38]
    inc  rax
    mov  ecx, [rcx+rax*4]
    add  rcx, [r12+T_TX]
    mov  eax, [rcx-4]
    mov  [rbx], eax
    add  rbx, 4
    ; hashOutputs
    lea  rax, [rbx+32]
    cmp  rax, [rbp-0x58]
    ja   .fail
    lea  rsi, [rbp-0x128]
    mov  rdi, rbx
    mov  ecx, 32
    rep  movsb
    add  rbx, 32
    ; locktime
    lea  rax, [rbx+4]
    cmp  rax, [rbp-0x58]
    ja   .fail
    mov  eax, [r12+T_LOCKTIME]
    mov  [rbx], eax
    add  rbx, 4
    ; nHashType
    lea  rax, [rbx+4]
    cmp  rax, [rbp-0x58]
    ja   .fail
    mov  eax, [rbp-0x68]
    mov  [rbx], eax
    add  rbx, 4
    ; prelen, then the final double-SHA over the preimage
    mov  r14, rbx
    sub  r14, [rbp-0x50]                 ; prelen
    mov  rdi, [rbp-0x30]                 ; out32
    mov  rsi, [rbp-0x50]                 ; pre
    mov  rdx, r14
    call sha256d_local
    mov  rax, r14
    jmp  .out
.fail:
    xor  eax, eax
.out:
    add  rsp, 0x148
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
