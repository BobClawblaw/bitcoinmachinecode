; ============================================================================
; bitcoin_bip341.asm -- the BIP341/342 TapSighash builder, 100% AI-generated
; x86-64 assembly (NASM, ELF64). Phase 2 slice 13b of the C->asm conversion
; (2026-08-24). Twins of bitcoin_taproot_sighash.c's ts_agg_hashes and
; taproot_sighash; differential: tests/test_bip341_diff.c.
;
;   long ts_agg_hashes_asm(const tapctx_t* c, const txview_t* t,
;                          u8 h_prev[32], u8 h_amt[32], u8 h_spk[32],
;                          u8 h_seq[32],            <-- 6th arg: r9, NOT stack
;                          /*stack*/ const u8** spk_at_nin,
;                          u64* spk_at_nin_len)                    -> 1 / 0
;   long taproot_sighash_asm(u8 out32[32], const tapctx_t* c, u8* pre,
;                            long cap)   -> preimage length (> 0) or 0
;
; The taproot analogue of slice 12: every taproot input's signature commits
; to these exact bytes, so a displaced one is a silent wrong sighash. The
; twin is byte-for-byte, and preserves the two CONSENSUS FIXES the C's
; comments record as found on 2026-08-22 -- both were false ACCEPTS, i.e.
; chain-split shaped, and both must stay closed here:
;   - hash_type validity: reject unless ht <= 0x03 or 0x81 <= ht <= 0x83
;     (Core SignatureHashSchnorr; a 0x04 hash_type was previously accepted);
;   - SIGHASH_SINGLE with n_in >= nout FAILS (BIP341), rather than
;     substituting the zero hash the way BIP143 does.
; Also preserved: the spks run walk's TS_SPK_RUN_CAP ceiling (that run has
; no length parameter -- see the C's note), sha_outputs / sha_single_output
; hashed IN PLACE over the transaction's own bytes, the annex's
; sha256(compactsize||annex) with its overflow-safe bound, and every cap
; check in the C's order.
;
; tapctx_t (offsetof-pinned, field ORDER verified against the header -- a
; first probe typed from memory had hash_type in the wrong place):
;   tx@0 txlen@8 n_in@16 hash_type@24 prevouts@32 amounts@40 spks@48
;   num_inputs@56 ext_flag@64 tapleaf@72 codesep_pos@80 annex@88
;   annexlen@96, size 104
; txview_t (offsetof-pinned; DIFFERENT from bitcoin_segwit.c's swtx_t):
;   tx@0 txlen@8 end@16 version@24 locktime@28 nin@32 nout@40 in_off@48
;   out_off@56, size 64.
; ============================================================================

BITS 64
DEFAULT REL

extern malloc
extern abort
extern sha256_full                    ; asm
extern tagged_hash256                 ; asm (secp256k1_taproot.asm)
extern ts_tx_parse_export             ; C seam: tx_parse into a caller table
extern ts_tx_seq_export               ; C seam: nSequence of input i

%define C_TX        0
%define C_TXLEN     8
%define C_NIN       16
%define C_HASHTYPE  24
%define C_PREVOUTS  32
%define C_AMOUNTS   40
%define C_SPKS      48
%define C_NUMIN     56
%define C_EXTFLAG   64
%define C_TAPLEAF   72
%define C_CODESEP   80
%define C_ANNEX     88
%define C_ANNEXLEN  96

; txview_t -- offsetof-VERIFIED against bitcoin_taproot_sighash.c. It is NOT
; the same shape as bitcoin_segwit.c's swtx_t: `version` is a plain int
; (4 bytes, so locktime sits at 28, not 32) and there is no `inputs` field.
; The first draft assumed the swtx_t layout and segfaulted on the first
; sha_outputs -- out_off read back as 1 and nout as a pointer. Probed, not
; assumed, like every other layout in this campaign.
%define V_TX        0
%define V_TXLEN     8
%define V_END       16
%define V_VERSION   24
%define V_LOCKTIME  28
%define V_NIN       32
%define V_NOUT      40
%define V_INOFF     48
%define V_OUTOFF    56
%define V_SIZE      64

%define TS_OFF_ENTRIES 600000
%define TS_OFF_BYTES   (TS_OFF_ENTRIES * 4)
%define TS_SEQ_CAP     (4 * TS_OFF_ENTRIES)
%define TS_SPK_RUN_CAP (4 << 20)
%define TS_ANNEX_CAP   ((4 << 20) + 9)

section .tbss alloc noexec nowrite tls align=8
global b341_off
b341_off:  resq 1                     ; u32* offset table (tx_parse)
global b341_seq
b341_seq:  resq 1                     ; u8*  sequence gather buffer
global b341_abuf
b341_abuf: resq 1                     ; u8*  annex staging buffer

section .rodata
tag_tapsighash: db "TapSighash",0

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

; CSSIZE_R: rcx = cs_size(rax). Clobbers rdx.
%macro CSSIZE_R 0
    mov  ecx, 1
    cmp  rax, 0xfd
    jb   %%d
    mov  ecx, 3
    cmp  rax, 0xffff
    jbe  %%d
    mov  ecx, 5
    mov  rdx, 0xffffffff
    cmp  rax, rdx
    jbe  %%d
    mov  ecx, 9
%%d:
%endmacro

; PUTCS_AT reg: write rax as a minimal compactsize at [reg]; advances reg.
; Clobbers rdx.
%macro PUTCS_AT 1
    cmp  rax, 0xfd
    jae  %%big
    mov  [%1], al
    inc  %1
    jmp  %%done
%%big:
    cmp  rax, 0xffff
    ja   %%b4
    mov  byte [%1], 0xfd
    mov  [%1+1], ax
    add  %1, 3
    jmp  %%done
%%b4:
    mov  rdx, 0xffffffff
    cmp  rax, rdx
    ja   %%b8
    mov  byte [%1], 0xfe
    mov  [%1+1], eax
    add  %1, 5
    jmp  %%done
%%b8:
    mov  byte [%1], 0xff
    mov  [%1+1], rax
    add  %1, 9
%%done:
%endmacro

; RDCS_RUN <fail>: compactsize at rbx bounded by r12 (the run ceiling).
; Canonical-encoding enforcing, same contract as the C's read_cs.
%macro RDCS_RUN 1
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
; ts_agg_hashes_asm(c=rdi, t=rsi, h_prev=rdx, h_amt=rcx, h_spk=r8, h_seq=r9,
;                   [rbp+16]=spk_at_nin, [rbp+24]=spk_len) -> 1 / 0
; SysV puts the first SIX integer args in registers -- the first draft read
; h_seq from [rbp+16] (which is the SEVENTH arg) and every aggregate hash
; came out wrong. Counted, not assumed.
; Frame: push rbp + 5 pushes, sub rsp,0x58 -> rsp 0 mod 16 at every call.
; SLOT MAP (disjoint, explicit -- slice 11/13a lesson):
;   -0x30 c   -0x38 t   -0x40 h_prev  -0x48 h_amt  -0x50 h_spk
;   -0x58 n   -0x60 i   -0x68 seqbuf  -0x70 spks base  -0x78 k
;   -0x80 h_seq
; Registers: rbx = run cursor, r12 = run ceiling, r13 = c, r14 = t, r15 = n.
; ----------------------------------------------------------------------------
global ts_agg_hashes_asm
ts_agg_hashes_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x68                       ; covers the -0x80 slot (0x28 saves + 0x68)
    mov  [rbp-0x30], rdi
    mov  [rbp-0x38], rsi
    mov  [rbp-0x40], rdx
    mov  [rbp-0x48], rcx
    mov  [rbp-0x50], r8
    mov  [rbp-0x80], r9                  ; h_seq (6th arg, in a register)
    mov  r13, rdi
    mov  r14, rsi
    mov  r15, [rdi+C_NUMIN]              ; n
    mov  [rbp-0x58], r15
    test r15, r15
    jle  .no
    cmp  r15, [rsi+V_NIN]                ; n != t->nin -> 0
    jne  .no

    ; sha_prevouts over n*36 contiguous bytes
    mov  rdi, rdx                        ; h_prev
    mov  rsi, [r13+C_PREVOUTS]
    mov  rdx, r15
    imul rdx, rdx, 36
    call sha256_full
    ; sha_amounts over n*8
    mov  rdi, [rbp-0x48]
    mov  rsi, [r13+C_AMOUNTS]
    mov  rdx, r15
    shl  rdx, 3
    call sha256_full

    ; sha_scriptpubkeys: walk the run (own ceiling; it has no length param),
    ; locating entry n_in, then hash the walked span in place.
    mov  rbx, [r13+C_SPKS]
    mov  [rbp-0x70], rbx
    mov  r12, rbx
    add  r12, TS_SPK_RUN_CAP
    xor  eax, eax
    mov  [rbp-0x60], rax                 ; i = 0
.spk_loop:
    mov  rax, [rbp-0x60]
    cmp  rax, r15
    jae  .spk_done
    RDCS_RUN .no                         ; sl
    mov  rcx, r12
    sub  rcx, rbx                        ; avail
    cmp  rcx, rax
    jb   .no
    mov  rdx, [rbp-0x60]
    cmp  rdx, [r13+C_NIN]                ; i == n_in ?
    jne  .spk_next
    mov  rcx, [rbp+16]
    mov  [rcx], rbx                      ; *spk_at_nin = p
    mov  rcx, [rbp+24]
    mov  [rcx], rax                      ; *spk_at_nin_len = sl
.spk_next:
    add  rbx, rax
    inc  qword [rbp-0x60]
    jmp  .spk_loop
.spk_done:
    mov  rdi, [rbp-0x50]                 ; h_spk
    mov  rsi, [rbp-0x70]
    mov  rdx, rbx
    sub  rdx, rsi
    call sha256_full

    ; sha_sequences: gather 4 bytes per input
    mov  rax, r15
    shl  rax, 2
    cmp  rax, TS_SEQ_CAP
    ja   .no
    TLS_LAZY rbx, b341_seq, TS_SEQ_CAP
    mov  [rbp-0x68], rbx
    xor  eax, eax
    mov  [rbp-0x60], rax                 ; i
    mov  [rbp-0x78], rax                 ; k
.seq_loop:
    mov  rax, [rbp-0x60]
    cmp  rax, r15
    jae  .seq_done
    mov  rdi, r14                        ; t
    mov  rsi, rax                        ; i
    call ts_tx_seq_export
    mov  rcx, [rbp-0x68]
    add  rcx, [rbp-0x78]
    mov  [rcx], eax
    add  qword [rbp-0x78], 4
    inc  qword [rbp-0x60]
    jmp  .seq_loop
.seq_done:
    mov  rdi, [rbp-0x80]                 ; h_seq
    mov  rsi, [rbp-0x68]
    mov  rdx, [rbp-0x78]
    call sha256_full
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    add  rsp, 0x68
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; taproot_sighash_asm(out32=rdi, c=rsi, pre=rdx, cap=rcx) -> prelen / 0
; Frame: push rbp + 5 pushes, sub rsp,0x1c8 -> rsp 0 mod 16 at every call.
; SLOT MAP (disjoint, explicit):
;   -0x30 out32  -0x38 c      -0x40 pre    -0x48 cap    -0x50 pend
;   -0x58 spk_nin  -0x60 spk_nin_len  -0x68 ht(dword; eff stays in a register)
;   -0x70 acp  -0x78 is_single  -0x80 is_none  -0x88 annex_present
;   h_prev[32]  -0xb0 .. -0x90     h_amt[32]   -0xd0 .. -0xb0
;   h_spk[32]   -0xf0 .. -0xd0     h_seq[32]   -0x110 .. -0xf0
;   ho[32]      -0x130 .. -0x110   (also used for the annex/single hashes,
;                                   one at a time, never live together)
;   t (txview_t, 80B)  -0x188 .. -0x138
; Registers: rbx = write cursor p, r12 = &t, r13 = c, r14/r15 scratch.
; ----------------------------------------------------------------------------
%define L_T 0x188

global taproot_sighash_asm
taproot_sighash_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x1c8
    mov  [rbp-0x30], rdi
    mov  [rbp-0x38], rsi
    mov  [rbp-0x40], rdx
    mov  [rbp-0x48], rcx
    mov  r13, rsi                        ; c
    lea  r12, [rbp-L_T]                  ; &t
    mov  rbx, rdx                        ; p = pre
    add  rcx, rdx
    mov  [rbp-0x50], rcx                 ; pend

    ; tx_parse into this thread's table (C seam: same table discipline)
    mov  rax, [r13+C_TX]
    mov  [r12+V_TX], rax
    mov  rax, [r13+C_TXLEN]
    mov  [r12+V_TXLEN], rax
    TLS_LAZY rsi, b341_off, TS_OFF_BYTES
    mov  rdi, r12
    call ts_tx_parse_export
    test eax, eax
    jz   .fail
    ; n_in bounds: < 0, >= t.nin, >= num_inputs
    mov  rax, [r13+C_NIN]
    test rax, rax
    js   .fail
    cmp  rax, [r12+V_NIN]
    jge  .fail
    cmp  rax, [r13+C_NUMIN]
    jge  .fail

    ; aggregates
    xor  eax, eax
    mov  [rbp-0x58], rax                 ; spk_nin = NULL
    mov  [rbp-0x60], rax
    mov  rdi, r13
    mov  rsi, r12
    lea  rdx, [rbp-0xb0]                 ; h_prev
    lea  rcx, [rbp-0xd0]                 ; h_amt
    lea  r8,  [rbp-0xf0]                 ; h_spk
    lea  r9,  [rbp-0x110]                ; h_seq (6th arg -> register)
    lea  rax, [rbp-0x60]
    push rax                             ; arg 8: spk_at_nin_len
    lea  rax, [rbp-0x58]
    push rax                             ; arg 7: spk_at_nin
    call ts_agg_hashes_asm
    add  rsp, 16
    test eax, eax
    jz   .fail
    cmp  qword [rbp-0x58], 0             ; !spk_nin -> fail
    je   .fail

    ; ---- hash_type validity (CONSENSUS: a false accept before 2026-08-22)
    movzx eax, byte [r13+C_HASHTYPE]
    mov  [rbp-0x68], eax                 ; ht
    cmp  eax, 0x03
    jbe  .ht_ok
    cmp  eax, 0x81
    jb   .fail
    cmp  eax, 0x83
    ja   .fail
.ht_ok:
    ; eff = ht ? ht : 1 ; acp = eff & 0x80 ; single = (eff&3)==3 ; none = ==2
    test eax, eax
    jnz  .eff_set
    mov  eax, 1
.eff_set:
    mov  ecx, eax
    and  ecx, 0x80
    mov  [rbp-0x70], rcx                 ; acp
    mov  ecx, eax
    and  ecx, 3
    xor  edx, edx
    cmp  ecx, 3
    sete dl
    movzx edx, dl
    mov  [rbp-0x78], rdx                 ; is_single
    xor  edx, edx
    cmp  ecx, 2
    sete dl
    movzx edx, dl
    mov  [rbp-0x80], rdx                 ; is_none
    ; annex_present = (c->annex != NULL)
    xor  edx, edx
    cmp  qword [r13+C_ANNEX], 0
    setne dl
    movzx edx, dl
    mov  [rbp-0x88], rdx

    ; ---- epoch, hash_type, nVersion, nLockTime ----
    lea  rax, [rbx+1]
    cmp  rax, [rbp-0x50]
    ja   .fail
    mov  byte [rbx], 0x00
    inc  rbx
    lea  rax, [rbx+1]
    cmp  rax, [rbp-0x50]
    ja   .fail
    mov  eax, [rbp-0x68]
    mov  [rbx], al
    inc  rbx
    lea  rax, [rbx+4]
    cmp  rax, [rbp-0x50]
    ja   .fail
    mov  eax, [r12+V_VERSION]
    mov  [rbx], eax
    add  rbx, 4
    lea  rax, [rbx+4]
    cmp  rax, [rbp-0x50]
    ja   .fail
    mov  eax, [r12+V_LOCKTIME]
    mov  [rbx], eax
    add  rbx, 4

    ; ---- the four aggregates (non-ACP) ----
    cmp  qword [rbp-0x70], 0
    jne  .after_aggs
    lea  rax, [rbx+128]
    cmp  rax, [rbp-0x50]
    ja   .fail
    lea  rsi, [rbp-0xb0]
    mov  rdi, rbx
    mov  ecx, 32
    rep  movsb
    lea  rsi, [rbp-0xd0]
    mov  ecx, 32
    rep  movsb
    lea  rsi, [rbp-0xf0]
    mov  ecx, 32
    rep  movsb
    lea  rsi, [rbp-0x110]
    mov  ecx, 32
    rep  movsb
    add  rbx, 128
.after_aggs:

    ; ---- sha_outputs (not NONE, not SINGLE), in place ----
    cmp  qword [rbp-0x80], 0
    jne  .spend_type
    cmp  qword [rbp-0x78], 0
    jne  .spend_type
    mov  rcx, [r12+V_OUTOFF]
    mov  rax, [r12+V_NOUT]
    mov  edx, [rcx+rax*4]                ; out_off[nout]
    mov  eax, [rcx]                      ; out_off[0]
    sub  rdx, rax
    add  rax, [r12+V_TX]
    lea  rdi, [rbp-0x130]                ; ho
    mov  rsi, rax
    call sha256_full
    lea  rax, [rbx+32]
    cmp  rax, [rbp-0x50]
    ja   .fail
    lea  rsi, [rbp-0x130]
    mov  rdi, rbx
    mov  ecx, 32
    rep  movsb
    add  rbx, 32
.spend_type:
    ; spend_type = ext_flag*2 + annex_present
    lea  rax, [rbx+1]
    cmp  rax, [rbp-0x50]
    ja   .fail
    mov  eax, [r13+C_EXTFLAG]
    add  eax, eax
    add  rax, [rbp-0x88]
    mov  [rbx], al
    inc  rbx

    cmp  qword [rbp-0x70], 0             ; acp?
    je   .input_index
    ; ---- ACP: outpoint || amount || cs+spk || nSequence ----
    lea  rax, [rbx+36]
    cmp  rax, [rbp-0x50]
    ja   .fail
    mov  rcx, [r12+V_INOFF]
    mov  rax, [r13+C_NIN]
    mov  ecx, [rcx+rax*4]
    add  rcx, [r12+V_TX]
    mov  rsi, rcx
    mov  rdi, rbx
    mov  ecx, 36
    rep  movsb
    add  rbx, 36
    lea  rax, [rbx+8]
    cmp  rax, [rbp-0x50]
    ja   .fail
    mov  rcx, [r13+C_AMOUNTS]
    mov  rax, [r13+C_NIN]
    mov  rax, [rcx+rax*8]                ; amount, LE both ways
    mov  [rbx], rax
    add  rbx, 8
    ; scriptPubKey: cs_size + bytes, bounded the C's overflow-safe way
    mov  rax, [rbp-0x60]                 ; sl
    CSSIZE_R
    mov  rdx, [rbp-0x48]                 ; cap
    test rdx, rdx
    js   .fail
    mov  r14, rbx
    sub  r14, [rbp-0x40]                 ; p - pre
    sub  rdx, r14                        ; cap - (p - pre)
    mov  r15, rcx
    add  r15, rax                        ; cs_size + sl
    cmp  rdx, r15
    jb   .fail
    PUTCS_AT rbx
    mov  rcx, [rbp-0x60]
    mov  rsi, [rbp-0x58]
    mov  rdi, rbx
    add  rbx, rcx
    rep  movsb
    ; nSequence
    lea  rax, [rbx+4]
    cmp  rax, [rbp-0x50]
    ja   .fail
    mov  rdi, r12
    mov  rsi, [r13+C_NIN]
    call ts_tx_seq_export
    mov  [rbx], eax
    add  rbx, 4
    jmp  .annex
.input_index:
    lea  rax, [rbx+4]
    cmp  rax, [rbp-0x50]
    ja   .fail
    mov  eax, [r13+C_NIN]
    mov  [rbx], eax
    add  rbx, 4

.annex:
    cmp  qword [rbp-0x88], 0
    je   .single
    ; sha256(compactsize(len) || annex), overflow-safe bound
    mov  rax, [r13+C_ANNEXLEN]
    mov  rcx, TS_ANNEX_CAP - 9
    cmp  rax, rcx
    ja   .fail
    TLS_LAZY r14, b341_abuf, TS_ANNEX_CAP
    mov  r15, r14
    mov  rax, [r13+C_ANNEXLEN]
    PUTCS_AT r15
    mov  rcx, [r13+C_ANNEXLEN]
    mov  rsi, [r13+C_ANNEX]
    mov  rdi, r15
    add  r15, rcx
    rep  movsb
    lea  rdi, [rbp-0x130]                ; ha (reuses the ho slot; not live)
    mov  rsi, r14
    mov  rdx, r15
    sub  rdx, r14
    call sha256_full
    lea  rax, [rbx+32]
    cmp  rax, [rbp-0x50]
    ja   .fail
    lea  rsi, [rbp-0x130]
    mov  rdi, rbx
    mov  ecx, 32
    rep  movsb
    add  rbx, 32

.single:
    cmp  qword [rbp-0x78], 0
    je   .ext
    ; BIP341: n_in >= nout FAILS (never the BIP143 zero-hash substitute)
    mov  rax, [r13+C_NIN]
    cmp  rax, [r12+V_NOUT]
    jge  .fail
    mov  rcx, [r12+V_OUTOFF]
    lea  rdx, [rax+1]
    mov  edx, [rcx+rdx*4]
    mov  eax, [rcx+rax*4]
    sub  rdx, rax
    add  rax, [r12+V_TX]
    lea  rdi, [rbp-0x130]                ; hs
    mov  rsi, rax
    call sha256_full
    lea  rax, [rbx+32]
    cmp  rax, [rbp-0x50]
    ja   .fail
    lea  rsi, [rbp-0x130]
    mov  rdi, rbx
    mov  ecx, 32
    rep  movsb
    add  rbx, 32

.ext:
    cmp  dword [r13+C_EXTFLAG], 1
    jne  .finish
    cmp  qword [r13+C_TAPLEAF], 0
    je   .fail
    lea  rax, [rbx+32]
    cmp  rax, [rbp-0x50]
    ja   .fail
    mov  rsi, [r13+C_TAPLEAF]
    mov  rdi, rbx
    mov  ecx, 32
    rep  movsb
    add  rbx, 32
    lea  rax, [rbx+1]
    cmp  rax, [rbp-0x50]
    ja   .fail
    mov  byte [rbx], 0x00                ; key_version
    inc  rbx
    lea  rax, [rbx+4]
    cmp  rax, [rbp-0x50]
    ja   .fail
    mov  eax, [r13+C_CODESEP]
    mov  [rbx], eax
    add  rbx, 4

.finish:
    mov  r14, rbx
    sub  r14, [rbp-0x40]                 ; prelen
    ; tagged_hash256(out32, "TapSighash", 10, pre, prelen)
    mov  rdi, [rbp-0x30]
    lea  rsi, [tag_tapsighash]
    mov  edx, 10
    mov  rcx, [rbp-0x40]
    mov  r8,  r14
    call tagged_hash256
    mov  rax, r14
    jmp  .out
.fail:
    xor  eax, eax
.out:
    add  rsp, 0x1c8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; SECURITY (audit 2026-08-29 finding 9): without this note the linker
; conservatively marks the whole program's stack EXECUTABLE (PT_GNU_STACK
; RWE). Nothing here needs a runnable stack; a single object missing the
; note is enough to turn it on for the entire binary, which is why every
; .asm file carries it.
section .note.GNU-stack noalloc noexec nowrite progbits
