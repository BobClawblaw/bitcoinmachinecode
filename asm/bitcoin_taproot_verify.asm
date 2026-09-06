; ============================================================================
; bitcoin_taproot_verify.asm -- BIP341/342 input verification orchestration,
; 100% AI-generated x86-64 assembly (NASM, ELF64). Phase 2 slice 13a of the
; C->asm conversion (2026-08-24). Twin of bitcoin_taproot_sighash.c's
; taproot_verify_input; differential: tests/test_taproot_verify_diff.c.
;
;   long taproot_verify_input_asm(const u8* spk, const u8* const* wit,
;                                 const u32* witlen, u32 nwit,
;                                 const u8* tx, i64 txlen,
;                                 /*stack*/ i64 n_in, const u8* prevouts,
;                                 const u8* amounts, const u8* spks,
;                                 i64 num_inputs, const char** reason)
;     -> 1 valid / 0 rejected (*reason set, byte-identical to the C's)
;
; This is the consensus fork for every taproot spend: annex detection, path
; classification, control-block validation, the merkle commitment (which
; runs at EVERY leaf version -- BIP341), the unknown-leaf-version early
; accept, Core's ExecuteWitnessScript tapscript prologue IN ITS ORDER
; (OP_SUCCESSx scan, then stack COUNT limit, then element SIZE limit -- the
; ordering is itself a fixed bug, see the C's comment), the BIP342
; validation-weight budget over the ORIGINAL full witness, and the
; interpreter invocation with the real tx context (incident #16).
;
; Leaves that stay C for this slice (each its own later work):
; taproot_keypath_verify(_annex), ts_has_op_success, taproot_checksig_fn,
; tx_parse/tx_seq (via an exported seam), script_eval. Already asm:
; tap_leaf_hash, tap_merkle_root, taproot_tweak_pubkey, stack_push.
;
; Struct layouts (offsetof-pinned, NOT hand-derived):
;   taproot_checksig_ctx: tx@0 txlen@8 n_in@16 prevouts@24 amounts@32
;     spks@40 num_inputs@48 tapleaf@56 codesep_pos@64 annex@72 annexlen@80
;     weight_left@88, size 96
;   ts_script_state: main_elems@0 main_sp@8 alt_elems@16 alt_sp@24
;     script@32 script_len@40 sigversion@48 flags@56 work@64 work_cap@72
;     error_out@80 checksig_ctx@88 checksig_fn@96 tx_locktime@104
;     in_sequence@108 tx_version@112, size 120  (zeroed before filling,
;     exactly like the C's memset)
; ============================================================================

BITS 64
DEFAULT REL

extern malloc
extern abort
extern tap_leaf_hash                  ; asm
extern tap_merkle_root                ; asm
extern taproot_tweak_pubkey           ; asm
extern stack_push                     ; asm
extern script_eval                    ; asm
extern taproot_keypath_verify         ; C
extern taproot_keypath_verify_annex   ; C
extern taproot_checksig_fn            ; C
extern ts_has_op_success_export       ; C seam
extern tap_txctx_export               ; C seam: version/locktime/sequence

%define ANNEX_TAG        0x50
%define CTRL_BASE        33
%define CTRL_NODE        32
%define CTRL_MAX         (33 + 32*128)
%define LEAF_MASK        0xfe
%define LEAF_TAPSCRIPT   0xc0

%define TS_ELEM_SIZE     528
%define TS_MAX_STACK     1000
%define TS_MAX_ELEM      520
%define TS_SIGV_TAPSCRIPT 2
%define TS_FLAGS         ((1 << 9) | (1 << 10))   ; CLTV | CSV

%define C_TX        0
%define C_TXLEN     8
%define C_NIN       16
%define C_PREVOUTS  24
%define C_AMOUNTS   32
%define C_SPKS      40
%define C_NUMIN     48
%define C_TAPLEAF   56
%define C_CODESEP   64
%define C_ANNEX     72
%define C_ANNEXLEN  80
%define C_WEIGHT    88
%define C_HARDFAIL  96                  ; int  (IR-3)
%define C_HARDERR   100                 ; int  (IR-3)

%define S_MAIN      0
%define S_MAINSP    8
%define S_ALT       16
%define S_ALTSP     24
%define S_SCRIPT    32
%define S_SCRIPTLEN 40
%define S_SIGV      48
%define S_FLAGS     56
%define S_WORK      64
%define S_WORKCAP   72
%define S_ERROUT    80
%define S_CSCTX     88
%define S_CSFN      96
%define S_LOCKTIME  104
%define S_SEQUENCE  108
%define S_VERSION   112

section .tbss alloc noexec nowrite tls align=8
global tv_main_e
tv_main_e: resq 1
global tv_alt_e
tv_alt_e:  resq 1
global tv_work
tv_work:   resq 1

section .rodata
e_empty:    db "p2tr empty witness",0
e_empty_ax: db "p2tr empty witness after annex",0
e_kp_ax:    db "p2tr keypath (annex) signature invalid",0
e_kp:       db "p2tr keypath signature invalid",0
e_ctrl:     db "p2tr control block wrong size",0
e_leafbig:  db "p2tr tapscript too large",0
e_merkle:   db "p2tr merkle root reconstruction failed",0
e_intpk:    db "p2tr script-path internal pubkey invalid",0
e_commit:   db "p2tr script-path commitment mismatch",0
e_parity:   db "p2tr control block parity mismatch",0
e_stackbig: db "p2tr tapscript initial stack too large",0
e_elembig:  db "p2tr tapscript witness item exceeds 520 bytes",0
e_overflow: db "p2tr tapscript initial stack overflow",0
e_exec:     db "p2tr tapscript execution failed",0
e_csfail:   db "p2tr tapscript checksig invalid",0

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

; ----------------------------------------------------------------------------
; taproot_verify_input_asm -- see header.
;   rdi=spk rsi=wit rdx=witlen ecx=nwit r8=tx r9=txlen
;   [rbp+16]=n_in [rbp+24]=prevouts [rbp+32]=amounts [rbp+40]=spks
;   [rbp+48]=num_inputs [rbp+56]=reason
; Frame: push rbp + 5 pushes, sub rsp,0x1f8 -> rsp 0 mod 16 at every call.
; SLOT MAP -- every slot's [start, end) written out and checked disjoint,
; because the first draft put leaf_hash[32] at -0xc0 (spanning through
; -0xa1) straight over the arena pointers at -0xa8/-0xb0: the same
; overlapping-locals class slice 11's differential caught, and the reason
; this map is now explicit rather than implied.
;   -0x30 spk      -0x38 wit      -0x40 witlen   -0x48 nwit
;   -0x50 tx       -0x58 txlen    -0x60 annex    -0x68 annexlen
;   -0x70 eff      -0x78 control  -0x80 clen     -0x88 script
;   -0x90 slen     -0x98 weight   -0xa0 sp       -0xa8 alt arena
;   -0xb0 work arena
;   leaf_hash[32]    -0xd0  .. -0xb0
;   merkle_root[32]  -0xf0  .. -0xd0
;   computed_q[32]   -0x110 .. -0xf0
;   err (8)          -0x118 .. -0x110
;   ctx (104)        -0x180 .. -0x118   (IR-3: was 96 at -0x178, so hard_fail
;                                       at +96 aliased the err slot and was
;                                       never read -- sizeof is 104)
;   st  (120)        -0x1f8 .. -0x180
; ----------------------------------------------------------------------------
%define L_CTX   0x180
%define L_ST    0x1f8

global taproot_verify_input_asm
taproot_verify_input_asm:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x1f8
    mov  [rbp-0x30], rdi                 ; spk
    mov  [rbp-0x38], rsi                 ; wit
    mov  [rbp-0x40], rdx                 ; witlen
    mov  [rbp-0x48], rcx                 ; nwit (u32 in ecx)
    mov  [rbp-0x50], r8                  ; tx
    mov  [rbp-0x58], r9                  ; txlen
    mov  r13, rsi                        ; wit
    mov  r14, rdx                        ; witlen
    mov  r15d, ecx                       ; nwit

    test r15d, r15d
    jz   .r_empty

    ; ---- annex: nwit >= 2 && witlen[nwit-1] >= 1 && wit[nwit-1][0] == 0x50
    xor  eax, eax
    mov  [rbp-0x60], rax                 ; annex = NULL
    mov  [rbp-0x68], rax                 ; annexlen = 0
    mov  r12d, r15d                      ; eff = nwit
    cmp  r15d, 2
    jb   .eff_done
    mov  ecx, r15d
    dec  ecx
    mov  eax, [r14+rcx*4]                ; witlen[nwit-1]
    test eax, eax
    jz   .eff_done
    mov  rdx, [r13+rcx*8]                ; wit[nwit-1]
    cmp  byte [rdx], ANNEX_TAG
    jne  .eff_done
    mov  [rbp-0x60], rdx
    mov  [rbp-0x68], rax
    dec  r12d                            ; eff = nwit - 1
.eff_done:
    mov  [rbp-0x70], r12
    test r12d, r12d
    jz   .r_empty_ax

    ; ---- key path: eff == 1 ----
    cmp  r12d, 1
    jne  .script_path
    mov  rdi, [rbp-0x30]                 ; spk
    mov  rsi, [r13]                      ; wit[0]
    mov  edx, [r14]                      ; witlen[0] (as int)
    mov  rcx, [rbp-0x50]                 ; tx
    mov  r8,  [rbp-0x58]                 ; txlen
    mov  r9,  [rbp+16]                   ; n_in
    cmp  qword [rbp-0x60], 0
    jne  .kp_annex
    ; taproot_keypath_verify(spk, sig, siglen, tx, txlen, n_in,
    ;                        prevouts, amounts, spks, num_inputs)
    push qword [rbp+48]                  ; num_inputs
    push qword [rbp+40]                  ; spks
    push qword [rbp+32]                  ; amounts
    push qword [rbp+24]                  ; prevouts
    call taproot_keypath_verify
    add  rsp, 32
    test eax, eax
    jz   .r_kp
    jmp  .accept
.kp_annex:
    ; taproot_keypath_verify_annex(..., annex, annexlen, NULL)
    sub  rsp, 8                          ; 7 stack args -> realign
    push 0                               ; NULL
    push qword [rbp-0x68]                ; annexlen
    push qword [rbp-0x60]                ; annex
    push qword [rbp+48]                  ; num_inputs
    push qword [rbp+40]                  ; spks
    push qword [rbp+32]                  ; amounts
    push qword [rbp+24]                  ; prevouts
    call taproot_keypath_verify_annex
    add  rsp, 64
    test eax, eax
    jz   .r_kp_ax
    jmp  .accept

.script_path:
    ; control = wit[eff-1], script = wit[eff-2]
    mov  ecx, r12d
    dec  ecx
    mov  rax, [r13+rcx*8]
    mov  [rbp-0x78], rax                 ; control
    mov  edx, [r14+rcx*4]
    mov  [rbp-0x80], rdx                 ; clen
    dec  ecx
    mov  rax, [r13+rcx*8]
    mov  [rbp-0x88], rax                 ; script
    mov  edx, [r14+rcx*4]
    mov  [rbp-0x90], rdx                 ; slen
    ; control-block size rules
    mov  rax, [rbp-0x80]
    cmp  rax, CTRL_BASE
    jb   .r_ctrl
    cmp  rax, CTRL_MAX
    ja   .r_ctrl
    sub  rax, CTRL_BASE
    and  rax, (CTRL_NODE - 1)            ; % 32 (power of two)
    jnz  .r_ctrl
    ; leaf_version = control[0] & 0xfe ; internal_pk = control + 1
    mov  rcx, [rbp-0x78]
    movzx ebx, byte [rcx]
    and  ebx, LEAF_MASK                  ; rbx = leaf_version (held)
    ; tap_leaf_hash(leaf_hash, leaf_version, script, slen)
    lea  rdi, [rbp-0xd0]
    mov  esi, ebx
    mov  rdx, [rbp-0x88]
    mov  rcx, [rbp-0x90]
    call tap_leaf_hash
    cmp  eax, 1
    jne  .r_leafbig
    ; tap_merkle_root(merkle_root, leaf_hash, 1, control, clen)
    lea  rdi, [rbp-0xf0]
    lea  rsi, [rbp-0xd0]
    mov  edx, 1
    mov  rcx, [rbp-0x78]
    mov  r8,  [rbp-0x80]
    call tap_merkle_root
    cmp  eax, 1
    jne  .r_merkle
    ; taproot_tweak_pubkey(computed_q, internal_pk, merkle_root)
    lea  rdi, [rbp-0x110]
    mov  rsi, [rbp-0x78]
    inc  rsi                             ; control + 1
    lea  rdx, [rbp-0xf0]
    call taproot_tweak_pubkey
    ; 0 = failure; 1 = success/even Y; 2 = success/odd Y. The parity is
    ; consensus data (BIP341 control[0]&1) -- see the note in
    ; secp256k1_taproot.asm and the C twin in bitcoin_taproot_sighash.c.
    test eax, eax
    jz   .r_intpk
    ; control[0]&1 must equal (tweaked Y is odd)
    dec  eax                             ; 0 = even, 1 = odd
    mov  rcx, [rbp-0x78]                 ; control
    movzx edx, byte [rcx]
    and  edx, 1
    cmp  eax, edx
    jne  .r_parity
    ; memcmp(computed_q, spk + 2, 32)
    mov  rcx, [rbp-0x30]
    mov  rax, [rbp-0x110]
    xor  rax, [rcx+2]
    mov  rdx, [rbp-0x108]
    xor  rdx, [rcx+10]
    or   rax, rdx
    mov  rdx, [rbp-0x100]
    xor  rdx, [rcx+18]
    or   rax, rdx
    mov  rdx, [rbp-0xf8]
    xor  rdx, [rcx+26]
    or   rax, rdx
    jnz  .r_commit
    ; unknown leaf version -> accept without executing anything
    cmp  ebx, LEAF_TAPSCRIPT
    jne  .accept
    ; OP_SUCCESSx scan comes FIRST (Core's order)
    mov  rdi, [rbp-0x88]
    mov  rsi, [rbp-0x90]
    call ts_has_op_success_export
    test eax, eax
    jnz  .accept
    ; ninit = eff - 2 ; count limit, then per-element size limit
    mov  rax, [rbp-0x70]
    sub  rax, 2
    mov  r12, rax                        ; ninit
    cmp  rax, TS_MAX_STACK
    ja   .r_stackbig
    xor  r15d, r15d
.size_loop:
    cmp  r15, r12
    jae  .size_done
    mov  eax, [r14+r15*4]
    cmp  eax, TS_MAX_ELEM
    ja   .r_elembig
    inc  r15
    jmp  .size_loop
.size_done:

    ; ---- BIP342 weight budget over the ORIGINAL full witness ----
    mov  rax, [rbp-0x48]                 ; nwit
    CSSIZE_R
    mov  r8, rcx                         ; weight = cs_size(nwit)
    xor  r15d, r15d
    mov  r9, [rbp-0x48]
.w_loop:
    cmp  r15, r9
    jae  .w_done
    mov  eax, [r14+r15*4]
    mov  r10, rax                        ; len
    CSSIZE_R
    add  r8, rcx
    add  r8, r10
    inc  r15
    jmp  .w_loop
.w_done:
    add  r8, 50
    mov  [rbp-0x98], r8

    ; ---- fill taproot_checksig_ctx ----
    mov  rax, [rbp-0x50]
    mov  [rbp-L_CTX+C_TX], rax
    mov  rax, [rbp-0x58]
    mov  [rbp-L_CTX+C_TXLEN], rax
    mov  rax, [rbp+16]
    mov  [rbp-L_CTX+C_NIN], rax
    mov  rax, [rbp+24]
    mov  [rbp-L_CTX+C_PREVOUTS], rax
    mov  rax, [rbp+32]
    mov  [rbp-L_CTX+C_AMOUNTS], rax
    mov  rax, [rbp+40]
    mov  [rbp-L_CTX+C_SPKS], rax
    mov  rax, [rbp+48]
    mov  [rbp-L_CTX+C_NUMIN], rax
    lea  rax, [rbp-0xd0]                 ; tapleaf = leaf_hash
    mov  [rbp-L_CTX+C_TAPLEAF], rax
    mov  dword [rbp-L_CTX+C_CODESEP], 0xffffffff
    mov  rax, [rbp-0x60]
    mov  [rbp-L_CTX+C_ANNEX], rax
    mov  rax, [rbp-0x68]
    mov  [rbp-L_CTX+C_ANNEXLEN], rax
    mov  rax, [rbp-0x98]
    mov  [rbp-L_CTX+C_WEIGHT], rax
    ; IR-3: the C twin zero-initialises the whole ctx; these two are filled by
    ; the callback and READ after script_eval, so they must start at 0
    mov  dword [rbp-L_CTX+C_HARDFAIL], 0
    mov  dword [rbp-L_CTX+C_HARDERR], 0

    ; ---- per-thread arenas, then push the initial stack ----
    TLS_LAZY r13, tv_main_e, (TS_MAX_STACK*TS_ELEM_SIZE)
    TLS_LAZY rbx, tv_alt_e,  (TS_MAX_STACK*TS_ELEM_SIZE)
    mov  [rbp-0xa8], rbx                 ; alt arena
    TLS_LAZY rbx, tv_work,   (1 << 16)
    mov  [rbp-0xb0], rbx                 ; work arena
    mov  r14, [rbp-0x40]                 ; witlen (reload: TLS_LAZY clobbers)
    mov  rbx, [rbp-0x38]                 ; wit
    xor  eax, eax
    mov  [rbp-0xa0], rax                 ; sp = 0
    xor  r15d, r15d
.push_loop:
    cmp  r15, r12                        ; i + 2 < eff  <=>  i < ninit
    jae  .push_done
    lea  rdi, [rbp-0xa0]                 ; &sp
    mov  rsi, r13                        ; elems
    mov  rdx, [rbx+r15*8]                ; wit[i]
    mov  ecx, [r14+r15*4]                ; witlen[i]
    call stack_push
    test eax, eax
    jz   .r_overflow
    inc  r15
    jmp  .push_loop
.push_done:

    ; ---- fill ts_script_state (zeroed first, like the C's memset) ----
    lea  rdi, [rbp-L_ST]
    xor  eax, eax
    mov  ecx, 120
    rep  stosb
    mov  [rbp-L_ST+S_MAIN], r13
    mov  rax, [rbp-0xa0]
    mov  [rbp-L_ST+S_MAINSP], rax
    mov  rax, [rbp-0xa8]
    mov  [rbp-L_ST+S_ALT], rax
    mov  rax, [rbp-0x88]
    mov  [rbp-L_ST+S_SCRIPT], rax
    mov  rax, [rbp-0x90]
    mov  [rbp-L_ST+S_SCRIPTLEN], rax
    mov  dword [rbp-L_ST+S_SIGV], TS_SIGV_TAPSCRIPT
    mov  qword [rbp-L_ST+S_FLAGS], TS_FLAGS
    mov  rax, [rbp-0xb0]
    mov  [rbp-L_ST+S_WORK], rax
    mov  qword [rbp-L_ST+S_WORKCAP], (1 << 16)
    lea  rax, [rbp-0x118]                ; &err
    mov  qword [rbp-0x118], 0
    mov  [rbp-L_ST+S_ERROUT], rax
    lea  rax, [rbp-L_CTX]
    mov  [rbp-L_ST+S_CSCTX], rax
    lea  rax, [taproot_checksig_fn]
    mov  [rbp-L_ST+S_CSFN], rax
    ; tx context (version/locktime/sequence), via the C seam -- left at the
    ; memset zeros when the parse fails or n_in is out of range, exactly
    ; like the C's `if (tx_parse(...) && ...)` guard
    mov  rdi, [rbp-0x50]                 ; tx
    mov  rsi, [rbp-0x58]                 ; txlen
    mov  rdx, [rbp+16]                   ; n_in
    lea  rcx, [rbp-L_ST+S_VERSION]
    lea  r8,  [rbp-L_ST+S_LOCKTIME]
    lea  r9,  [rbp-L_ST+S_SEQUENCE]
    call tap_txctx_export
    ; run the tapscript
    lea  rdi, [rbp-L_ST]
    call script_eval
    test eax, eax
    jz   .r_exec
    ; IR-3: a checksig that set hard_fail invalidates the script even if the
    ; stack ends truthy (Core's EvalChecksigTapscript set_error cases: invalid
    ; non-empty sig, empty pubkey, weight budget). Mirrors the C twin exactly.
    cmp  dword [rbp-L_CTX+C_HARDFAIL], 0
    jne  .r_csfail
.accept:
    mov  eax, 1
    jmp  .out

.r_empty:     lea rsi, [e_empty]
              jmp .reject
.r_empty_ax:  lea rsi, [e_empty_ax]
              jmp .reject
.r_kp_ax:     lea rsi, [e_kp_ax]
              jmp .reject
.r_kp:        lea rsi, [e_kp]
              jmp .reject
.r_ctrl:      lea rsi, [e_ctrl]
              jmp .reject
.r_leafbig:   lea rsi, [e_leafbig]
              jmp .reject
.r_merkle:    lea rsi, [e_merkle]
              jmp .reject
.r_parity:    lea rsi, [e_parity]
              jmp .reject
.r_intpk:     lea rsi, [e_intpk]
              jmp .reject
.r_commit:    lea rsi, [e_commit]
              jmp .reject
.r_stackbig:  lea rsi, [e_stackbig]
              jmp .reject
.r_elembig:   lea rsi, [e_elembig]
              jmp .reject
.r_overflow:  lea rsi, [e_overflow]
              jmp .reject
.r_csfail:    lea rsi, [e_csfail]
              jmp .reject
.r_exec:      lea rsi, [e_exec]
.reject:
    mov  rax, [rbp+56]
    mov  [rax], rsi
    xor  eax, eax
.out:
    add  rsp, 0x1f8
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
