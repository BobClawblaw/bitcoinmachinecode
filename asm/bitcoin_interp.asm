; ============================================================================
; bitcoin_interp.asm -- Full Bitcoin Script interpreter (all opcodes), built on
; the verified support layer bitcoin_scriptcodec.asm.
;
;   int script_eval(struct script_state* st)
;     Evaluates st->script over the initial stack in st->main_elems[0..main_sp)
;     per st->sigversion / st->flags (Core's EvalScript core semantics).
;     Returns 1 on success, 0 on failure; *st->error_out is set on failure.
;
; struct script_state {         offsets
;   uint8_t* main_elems;        +0
;   size_t   main_sp;           +8
;   uint8_t* alt_elems;         +16
;   size_t   alt_sp;            +24
;   uint8_t* script;            +32
;   size_t   script_len;        +40
;   int      sigversion;        +48
;   uint64_t flags;             +56
;   uint8_t* work;              +64
;   size_t   work_cap;          +72
;   uint64_t* error_out;        +80
;   void*    checksig_ctx;      +88
;   uint64_t (*checksig_fn)(void* ctx, const uint8_t* sig, size_t siglen,
;                           const uint8_t* pub, size_t publen,
;                           const uint8_t* sc, size_t sc_len);  +96
; }
;
; Element record: +0 len(4), +4 data[520] (ELEM_SIZE=528).
; ABI: SysV AMD64; rbx,r12-r15 preserved; rsp 8mod16 at nested calls.
; ============================================================================
    default rel
    global script_eval

    extern stack_depth
    extern stack_top_ptr
    extern stack_second_ptr
    extern stack_third_ptr
    extern stack_elem_ptr
    extern stack_pop
    extern stack_push
    extern stack_push_copy
    extern stack_swap_two
    extern stack_dup_index
    extern stack_erase_index
    extern stack_insert_index
    extern elem_move
    extern scriptnum_decode
    extern scriptnum_serialize
    extern scriptnum_buf
    extern cast_to_bool
    extern check_minimal_push
    extern get_op
    extern vfexec_push
    extern vfexec_pop
    extern vfexec_depth
    extern vfexec_toggle_top
    extern vfexec_all_true
    extern vfexec_sp_reset
    ; CHECKMULTISIG's up-front scriptCode strip (bitcoin_sighash.asm).
    extern script_push_encode
    extern script_find_and_delete
    ; BIP66 strict-DER signature encoding (bitcoin_scriptcodec.asm) -- Core's
    ; IsValidSignatureEncoding. See the CheckSignatureEncoding note below.
    extern der_sig_strict
    ; cross-file TLS accessors (bitcoin_scriptcodec.asm) -- see that file's
    ; header note by their definitions for why these are function calls
    ; rather than direct wrt ..gottpoff references to an extern symbol.
    extern elem_tmp0_addr
    extern elem_tmp1_addr
    extern elem_tmp2_addr
    extern elem_tmp3_addr
    extern snum_overflow_addr

    extern sha256_full
    extern ripemd160
    extern sha256d
    extern sha1_full

%define ELEM_SIZE 528
%define ELEM_DATA_OFF 4
%define OP_1NEGATE 0x4f
%define OP_1 0x51
%define OP_16 0x60
%define OP_NOP 0x61
%define OP_IF 0x63
%define OP_NOTIF 0x64
%define OP_ELSE 0x67
%define OP_ENDIF 0x68
%define OP_VERIFY 0x69
%define OP_RETURN 0x6a
%define OP_TOALTSTACK 0x6b
%define OP_FROMALTSTACK 0x6c
%define OP_2DROP 0x6d
%define OP_2DUP 0x6e
%define OP_3DUP 0x6f
%define OP_2OVER 0x70
%define OP_2ROT 0x71
%define OP_2SWAP 0x72
%define OP_IFDUP 0x73
%define OP_DEPTH 0x74
%define OP_DROP 0x75
%define OP_DUP 0x76
%define OP_NIP 0x77
%define OP_OVER 0x78
%define OP_PICK 0x79
%define OP_ROLL 0x7a
%define OP_ROT 0x7b
%define OP_SWAP 0x7c
%define OP_TUCK 0x7d
%define OP_CAT 0x7e
%define OP_SUBSTR 0x7f
%define OP_LEFT 0x80
%define OP_RIGHT 0x81
%define OP_SIZE 0x82
%define OP_INVERT 0x83
%define OP_AND 0x84
%define OP_OR 0x85
%define OP_XOR 0x86
%define OP_EQUAL 0x87
%define OP_EQUALVERIFY 0x88
%define OP_1ADD 0x8b
%define OP_1SUB 0x8c
%define OP_2MUL 0x8d
%define OP_2DIV 0x8e
%define OP_NEGATE 0x8f
%define OP_ABS 0x90
%define OP_NOT 0x91
%define OP_0NOTEQUAL 0x92
%define OP_ADD 0x93
%define OP_SUB 0x94
%define OP_MUL 0x95
%define OP_DIV 0x96
%define OP_MOD 0x97
%define OP_LSHIFT 0x98
%define OP_RSHIFT 0x99
%define OP_BOOLAND 0x9a
%define OP_BOOLOR 0x9b
%define OP_NUMEQUAL 0x9c
%define OP_NUMEQUALVERIFY 0x9d
%define OP_NUMNOTEQUAL 0x9e
%define OP_LESSTHAN 0x9f
%define OP_GREATERTHAN 0xa0
%define OP_LESSTHANOREQUAL 0xa1
%define OP_GREATERTHANOREQUAL 0xa2
%define OP_MIN 0xa3
%define OP_MAX 0xa4
%define OP_WITHIN 0xa5
%define OP_RIPEMD160 0xa6
%define OP_SHA1 0xa7
%define OP_SHA256 0xa8
%define OP_HASH160 0xa9
%define OP_HASH256 0xaa
%define OP_CODESEPARATOR 0xab
%define OP_CHECKSIG 0xac
%define OP_CHECKSIGVERIFY 0xad
%define OP_CHECKMULTISIG 0xae
%define OP_CHECKMULTISIGVERIFY 0xaf
%define OP_NOP1 0xb0
%define OP_CHECKLOCKTIMEVERIFY 0xb1
%define OP_CHECKSEQUENCEVERIFY 0xb2
%define OP_NOP4 0xb3
%define OP_NOP5 0xb4
%define OP_NOP6 0xb5
%define OP_NOP7 0xb6
%define OP_NOP8 0xb7
%define OP_NOP9 0xb8
%define OP_NOP10 0xb9
%define OP_CHECKSIGADD 0xba
%define OP_PUSHDATA4 0x4e

%define MAX_SCRIPT_ELEMENT_SIZE 520
%define MAX_OPS_PER_SCRIPT 201
%define MAX_STACK_SIZE 1000
%define MAX_SCRIPT_SIZE 10000

%define SIGVERSION_BASE 0
%define SIGVERSION_WITNESS_V0 1
%define SIGVERSION_TAPSCRIPT 2

%define SCRIPT_VERIFY_STRICTENC (1<<1)
%define SCRIPT_VERIFY_DERSIG (1<<2)
%define SCRIPT_VERIFY_LOW_S (1<<3)
%define SCRIPT_VERIFY_NULLDUMMY (1<<4)
%define SCRIPT_VERIFY_MINIMALDATA (1<<6)
%define SCRIPT_VERIFY_MINIMALIF (1<<13)
%define SCRIPT_VERIFY_NULLFAIL (1<<14)       ; BIP146 policy: a failing non-empty signature is an error, not false
%define SCRIPT_VERIFY_CONST_SCRIPTCODE (1<<16) ; policy: a signature found in the scriptCode (legacy FindAndDelete) is an error
; SNUM_MAX n: rdx = maxsize for scriptnum_decode, plus bit 8 when MINIMALDATA
; is set (Core passes fRequireMinimal to every CScriptNum read). r12 = state.
%macro SNUM_MAX 1
    mov   rdx, %1
    test  qword [r12+56], SCRIPT_VERIFY_MINIMALDATA
    jz    %%nomin
    or    rdx, 0x100
%%nomin:
%endmacro
%define SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY (1<<9)
%define SCRIPT_VERIFY_CHECKSEQUENCEVERIFY (1<<10)
%define SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS (1<<19)   ; Core bit 19 (bit 18 is DISCOURAGE_UPGRADABLE_TAPROOT_VERSION); was 18 until 2026-09-02, nothing set it

%define SCRIPT_ERR_OK                                    0
%define SCRIPT_ERR_UNKNOWN_ERROR                         1
%define SCRIPT_ERR_EVAL_FALSE                            2
%define SCRIPT_ERR_OP_RETURN                             3
%define SCRIPT_ERR_SCRIPTNUM                             4
%define SCRIPT_ERR_SCRIPT_SIZE                           5
%define SCRIPT_ERR_PUSH_SIZE                             6
%define SCRIPT_ERR_OP_COUNT                              7
%define SCRIPT_ERR_STACK_SIZE                            8
%define SCRIPT_ERR_SIG_COUNT                             9
%define SCRIPT_ERR_PUBKEY_COUNT                          10
%define SCRIPT_ERR_VERIFY                                11
%define SCRIPT_ERR_EQUALVERIFY                           12
%define SCRIPT_ERR_CHECKMULTISIGVERIFY                   13
%define SCRIPT_ERR_CHECKSIGVERIFY                        14
%define SCRIPT_ERR_NUMEQUALVERIFY                        15
%define SCRIPT_ERR_BAD_OPCODE                            16
%define SCRIPT_ERR_DISABLED_OPCODE                       17
%define SCRIPT_ERR_INVALID_STACK_OPERATION               18
%define SCRIPT_ERR_INVALID_ALTSTACK_OPERATION            19
%define SCRIPT_ERR_UNBALANCED_CONDITIONAL                20
%define SCRIPT_ERR_NEGATIVE_LOCKTIME                     21
%define SCRIPT_ERR_UNSATISFIED_LOCKTIME                  22
%define SCRIPT_ERR_SIG_HASHTYPE                          23
%define SCRIPT_ERR_SIG_DER                               24
%define SCRIPT_ERR_MINIMALDATA                           25
%define SCRIPT_ERR_SIG_PUSHONLY                          26
%define SCRIPT_ERR_SIG_HIGH_S                            27
%define SCRIPT_ERR_SIG_NULLDUMMY                         28
%define SCRIPT_ERR_PUBKEYTYPE                            29
%define SCRIPT_ERR_CLEANSTACK                            30
%define SCRIPT_ERR_MINIMALIF                             31
%define SCRIPT_ERR_SIG_NULLFAIL                          32
%define SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS            33
%define SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM 34
%define SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION 35
%define SCRIPT_ERR_DISCOURAGE_OP_SUCCESS                 36
%define SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE      37
%define SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH          38
%define SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY         39
%define SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH              40
%define SCRIPT_ERR_WITNESS_MALLEATED                     41
%define SCRIPT_ERR_WITNESS_MALLEATED_P2SH                42
%define SCRIPT_ERR_WITNESS_UNEXPECTED                    43
%define SCRIPT_ERR_WITNESS_PUBKEYTYPE                    44
%define SCRIPT_ERR_SCHNORR_SIG_SIZE                      45
%define SCRIPT_ERR_SCHNORR_SIG_HASHTYPE                  46
%define SCRIPT_ERR_SCHNORR_SIG                           47
%define SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE            48
%define SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT           49
%define SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG               50
%define SCRIPT_ERR_TAPSCRIPT_MINIMALIF                   51
%define SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY                52
%define SCRIPT_ERR_OP_CODESEPARATOR                      53
%define SCRIPT_ERR_SIG_FINDANDDELETE                     54
%define SCRIPT_ERR_ERROR_COUNT                           55

; ---- THREAD-LOCAL scratch (2026-08-19, parallel per-input verification) --
; interp_tmp/bool_buf/interp_err/interp_slice/cms_keyrefs/cms_sigrefs used
; to be plain .bss globals -- one shared instance for the whole process.
; That was fine for the original fork()-per-worker parallelism (each forked
; child gets its own COW copy of everything), but fork()'s page-table setup
; cost scales with the parent's resident size, which made it progressively
; more expensive as the UTXO memtable grew during a from-scratch replay
; (confirmed via production stack sampling: every sample landed inside
; fork() itself). Threads avoid that cost entirely -- but ONLY if nothing
; they touch is process-global mutable state, which these six buffers were.
; .tbss (NASM's thread-local BSS) + the ELF Initial-Exec TLS model gives
; each thread its own private instance with no signature/struct-layout
; changes needed anywhere that calls into this file.
;
; script_eval computes each buffer's per-thread ADDRESS once, at entry, into
; six local slots below (interp_checkmultisig shares this same frame via
; its documented "rbp = script_eval frame" convention, so it reads the same
; slots rather than re-deriving them) -- every other reference in this file
; was previously a compile-time-constant label; those become a load from
; the matching slot instead, same instruction shape, same register usage.
section .tbss alloc noexec nowrite tls align=16
global interp_tmp
global bool_buf
global interp_err
global interp_slice
interp_tmp: resb ELEM_SIZE
bool_buf: resb 1
interp_err: resq 1
; interp_slice: { p, n, codesep_pos }. p/n = the scriptCode slice starting at
; the last executed OP_CODESEPARATOR (legacy/witness-v0 sighash).
; codesep_pos = BIP342 opcode position of the last EXECUTED OP_CODESEPARATOR,
; 0xffffffff if none (tapscript sighash field); only set meaningfully under
; SIGVERSION_TAPSCRIPT -- legacy checksig_fn readers look at p/n only.
interp_slice: resq 3
; SCR-3 (audit 2026-09-03): the script_state pointer of the running
; script_eval, so the checksig helpers (which have their own frames and
; their own r12) can gate the tapscript empty-pubkey rule on sigversion.
global interp_state
interp_state: resq 1

section .text

; TLS_ADDR dst, sym -- dst = this thread's address of `sym` (ELF x86-64
; Initial-Exec model: a GOT-style offset loaded from a fixed, link-time
; location, added to the thread pointer at %fs:0). Clobbers only `dst`.
%macro TLS_ADDR 2
    mov   %1, [rel %2 wrt ..gottpoff]
    add   %1, qword [fs:0]
%endmacro

; ============================================================================
; script_eval(state*)   rdi = state
; Frame: r12=state throughout. Locals:
;   -0x08 fExec   -0x10 pc   -0x18 pend   -0x20 pbegincodehash
;   -0x28 nOpCount -0x30 opcode_pos -0x38 opcode -0x40 pushlen
;   -0x48 codesep_pos (BIP342: opcode_pos of the last EXECUTED
;         OP_CODESEPARATOR, 0xffffffff if none; tapscript only)
;   -0x60 &interp_tmp (this thread)   -0x68 &bool_buf   -0x70 &interp_err
;   -0x78 &interp_slice   -0x80 &cms_keyrefs   -0x88 &cms_sigrefs
;   -0x90 &elem_tmp0   -0x98 &elem_tmp1   -0xA0 &elem_tmp2   -0xA8 &elem_tmp3
;   -0xB0 &snum_overflow (scriptnum_buf is only referenced from within
;   bitcoin_scriptcodec.asm's own scriptnum_serialize, already TLS-converted
;   there -- no slot needed here)
;   (computed once here; unused-but-reserved scratch space, no frame resize)
;
; CALLEE-SAVED SAVE AREA IS *ABOVE* RBP, NOT BELOW IT.
;   The five pushes come before `push rbp`, so rbx/r12/r13/r14/r15 are saved at
;   [rbp+0x08 .. rbp+0x28] and every local listed above -- which starts at
;   rbp-0x08 and runs to rbp-0xB0 -- lies inside this function's own 0x108
;   reservation. Nothing aliases.
;   Before this change the order was `push rbp` / `mov rbp,rsp` / five pushes,
;   which put saved rbx at rbp-0x08, r12 at rbp-0x10, r13 at rbp-0x18, r14 at
;   rbp-0x20 and r15 at rbp-0x28 -- i.e. exactly on fExec, pc, pend,
;   pbegincodehash and nOpCount. The epilogue's five pops therefore handed the
;   CALLER interpreter state instead of its own registers, on the consensus
;   path, for every input of every transaction. Nothing had broken yet only
;   because every C caller on that path is pinned to -O0 (see asm/Makefile),
;   and -O0 keeps nothing live in callee-saved registers across a call.
;   tests/bench_abi_audit reproduces the pre-fix behaviour: CLOBBERS rbx r12
;   r13 r14 r15.
;
;   ALIGNMENT IS UNCHANGED (incidents #18/#20, docs/ABI_STACK_ALIGNMENT.md):
;   this is the same six pushes and the same 0x108 reservation, only reordered,
;   so RSP has an identical value modulo 16 at every instruction after the
;   prologue. Before: entry 8 -> push rbp -> 0 -> 5 pushes -> 8 -> sub 0x108
;   -> 0. After: entry 8 -> 5 pushes -> 0 -> push rbp -> 8 -> sub 0x108 -> 0.
;   All 215 nested call sites, including `call qword [r12+96]` into the C
;   checksig callback, still see RSP == 0 mod 16. NO FRAME WAS RESIZED.
; ============================================================================
script_eval:
    push  rbx
    push  r12
    push  r13
    push  r14
    push  r15
    push  rbp
    mov   rbp, rsp
    sub   rsp, 0x108          ; ODD multiple of 8, on purpose -- SysV alignment.
                              ;   Entry RSP == 8 mod16; `push rbp` -> 0 mod16;
                              ;   the 5 callee-saved pushes -> 8 mod16 again.
                              ;   The reservation must therefore be 8 mod16 to
                              ;   put RSP == 0 mod16 at every nested `call`.
                              ;   This was 0x100 (0 mod16), which left RSP at
                              ;   8 mod16 at all 215 call sites in this
                              ;   function -- including `call qword [r12+96]`
                              ;   in interp_checksig / interp_checksig_add /
                              ;   interp_checkmultisig, the C checksig callback
                              ;   (sv_checksig, taproot_checksig_fn). Any C on
                              ;   that path that reaches a printf-family call
                              ;   died: glibc's vsnprintf does
                              ;   `movaps %xmm0,-0xc0(%rbp)` -> #GP ->
                              ;   SIGSEGV with si_addr == NULL. Same failure
                              ;   mode as incident #18 (b18114b). (2026-08-22)
                              ; All locals here are rbp-relative, so growing the
                              ;   reservation by 8 moves no operand.
    mov   r12, rdi            ; state
    ; SCR-3: interp_checksig/_add run in their own frames (their own r12); the
    ; tapscript empty-pubkey rule gates on sigversion, so stash the state
    ; pointer in a per-thread slot they can reach. Written straight through
    ; rax -- no frame slot and no frame resize: the prologue's local map ends
    ; at -0xB0 and the frame size is ABI-frozen (see the notes above).
    ; script_eval is non-reentrant, so one slot per thread is exactly as safe
    ; as interp_slice below.
    TLS_ADDR rax, interp_state
    mov   [rax], rdi

    ; per-thread scratch addresses, computed once (see file-header note
    ; above script_eval and the TLS_ADDR macro) -- unused-but-reserved
    ; frame space, no resize needed.
    TLS_ADDR rax, interp_tmp
    mov   [rbp-0x60], rax
    TLS_ADDR rax, bool_buf
    mov   [rbp-0x68], rax
    TLS_ADDR rax, interp_err
    mov   [rbp-0x70], rax
    TLS_ADDR rax, interp_slice
    mov   [rbp-0x78], rax
    TLS_ADDR rax, cms_keyrefs
    mov   [rbp-0x80], rax
    TLS_ADDR rax, cms_sigrefs
    mov   [rbp-0x88], rax
    call  elem_tmp0_addr
    mov   [rbp-0x90], rax
    call  elem_tmp1_addr
    mov   [rbp-0x98], rax
    call  elem_tmp2_addr
    mov   [rbp-0xA0], rax
    call  elem_tmp3_addr
    mov   [rbp-0xA8], rax
    call  snum_overflow_addr
    mov   [rbp-0xB0], rax

    ; script size limit for BASE/WITNESS_V0
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    je    .ss_ok
    mov   rax, [r12+40]
    cmp   rax, MAX_SCRIPT_SIZE
    jbe   .ss_ok
    mov   rax, SCRIPT_ERR_SCRIPT_SIZE
    jmp   .err_ret0
.ss_ok:
    ; pc = script, pend = script+len, pbegincodehash = script
    mov   rax, [r12+32]
    mov   [rbp-0x10], rax
    mov   rax, [r12+32]
    add   rax, [r12+40]
    mov   [rbp-0x18], rax
    mov   rax, [r12+32]
    mov   [rbp-0x20], rax
    mov   qword [rbp-0x28], 0
    mov   qword [rbp-0x30], 0
    mov   rax, 0xffffffff          ; codesep_pos = "none executed" (Core:
    mov   [rbp-0x48], rax          ; execdata.m_codeseparator_pos = 0xFFFFFFFF)
    call  vfexec_sp_reset

    ; ---- tapscript OP_SUCCESSx pre-scan (BIP342 / ExecuteWitnessScript) ----
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    jne   .prescan_done
    ; scan a temporary pc through the script; find any OP_SUCCESSx
    mov   [rbp-0x50], rax      ; (unused slot)
    mov   rax, [r12+32]
    mov   [rbp-0x50], rax      ; scan pc
    mov   rax, [r12+32]
    add   rax, [r12+40]
    mov   [rbp-0x58], rax      ; scan pend
.prescan_loop:
    lea   rdi, [rbp-0x50]
    mov   rsi, [rbp-0x58]
    call  get_op
    test  rax, rax
    jz    .prescan_done        ; end of script or bad opcode -> no successx found
    dec   rax                   ; opcode
    call  is_opsuccess
    test  rax, rax
    jz    .prescan_loop
    ; found an OP_SUCCESSx
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS
    jnz   .prescan_discourage
    ; success immediately
    mov   rax, [r12+80]
    test  rax, rax
    jz    .prescan_ret1
    mov   qword [rax], SCRIPT_ERR_OK
.prescan_ret1:
    mov   eax, 1
    jmp   .done
.prescan_discourage:
    mov   rax, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS
    jmp   .err_ret0
.prescan_done:

.loop:
    mov   rax, [rbp-0x10]
    cmp   rax, [rbp-0x18]
    jae   .loop_done

    call  vfexec_all_true
    mov   [rbp-0x08], rax      ; fExec

    ; get_op
    lea   rdi, [rbp-0x10]
    mov   rsi, [rbp-0x18]
    call  get_op
    test  rax, rax
    jnz   .op_ok
    mov   rax, SCRIPT_ERR_BAD_OPCODE
    jmp   .err_ret0
.op_ok:
    dec   rax                   ; recover opcode (get_op returns opcode+1)
    mov   [rbp-0x38], rax      ; opcode
    mov   [rbp-0x40], rdx      ; pushlen

    cmp   rdx, MAX_SCRIPT_ELEMENT_SIZE
    jbe   .ps_ok
    mov   rax, SCRIPT_ERR_PUSH_SIZE
    jmp   .err_ret0
.ps_ok:

    ; opcount
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    je    .oc_skip
    mov   rax, [rbp-0x38]
    cmp   rax, OP_16
    jbe   .oc_skip
    inc   qword [rbp-0x28]
    mov   rax, [rbp-0x28]
    cmp   rax, MAX_OPS_PER_SCRIPT
    jbe   .oc_skip
    mov   rax, SCRIPT_ERR_OP_COUNT
    jmp   .err_ret0
.oc_skip:

    ; disabled opcodes
    mov   rax, [rbp-0x38]
    cmp   rax, OP_CAT
    je    .disabled
    cmp   rax, OP_SUBSTR
    je    .disabled
    cmp   rax, OP_LEFT
    je    .disabled
    cmp   rax, OP_RIGHT
    je    .disabled
    cmp   rax, OP_INVERT
    je    .disabled
    cmp   rax, OP_AND
    je    .disabled
    cmp   rax, OP_OR
    je    .disabled
    cmp   rax, OP_XOR
    je    .disabled
    cmp   rax, OP_2MUL
    je    .disabled
    cmp   rax, OP_2DIV
    je    .disabled
    cmp   rax, OP_MUL
    je    .disabled
    cmp   rax, OP_DIV
    je    .disabled
    cmp   rax, OP_MOD
    je    .disabled
    cmp   rax, OP_LSHIFT
    je    .disabled
    cmp   rax, OP_RSHIFT
    je    .disabled
    jmp   .not_disabled
.disabled:
    mov   rax, SCRIPT_ERR_DISABLED_OPCODE
    jmp   .err_ret0
.not_disabled:

    ; push opcode 0..PUSHDATA4
    mov   rax, [rbp-0x38]
    cmp   rax, OP_PUSHDATA4
    ja    .not_push
    mov   rax, [rbp-0x08]
    test  rax, rax
    jz    .next_op
    ; minimal push
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_MINIMALDATA
    jz    .mp_ok
    mov   rdi, [rbp-0x38]
    mov   rsi, [rbp-0x40]
    mov   rdx, [rbp-0x10]
    sub   rdx, [rbp-0x40]
    call  check_minimal_push
    test  rax, rax
    jnz   .mp_ok
    mov   rax, SCRIPT_ERR_MINIMALDATA
    jmp   .err_ret0
.mp_ok:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0x10]
    sub   rdx, [rbp-0x40]
    mov   rcx, [rbp-0x40]
    call  stack_push
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0
.not_push:
    ; if not executing and not IF..ENDIF, skip
    mov   rax, [rbp-0x08]
    test  rax, rax
    jnz   .dispatch
    mov   rax, [rbp-0x38]
    cmp   rax, OP_IF
    jb    .next_op
    cmp   rax, OP_ENDIF
    ja    .next_op

.dispatch:
    mov   rax, [rbp-0x38]
    ; OP_RESERVED(0x50), OP_VER..., OP_RESERVED1/2 -> handled as BAD_OPCODE
    cmp   rax, OP_1NEGATE
    je    .pushnum
    cmp   rax, OP_1
    jb    .bad_opcode
    cmp   rax, OP_16
    jbe   .pushnum
    ; small dispatch
    cmp   rax, OP_NOP
    je    .next_op
    cmp   rax, OP_IF
    je    .op_if
    cmp   rax, OP_NOTIF
    je    .op_notif
    cmp   rax, OP_ELSE
    je    .op_else
    cmp   rax, OP_ENDIF
    je    .op_endif
    cmp   rax, OP_VERIFY
    je    .op_verify
    cmp   rax, OP_RETURN
    je    .op_return
    cmp   rax, OP_TOALTSTACK
    je    .op_toalt
    cmp   rax, OP_FROMALTSTACK
    je    .op_fromalt
    cmp   rax, OP_2DROP
    je    .op_2drop
    cmp   rax, OP_2DUP
    je    .op_2dup
    cmp   rax, OP_3DUP
    je    .op_3dup
    cmp   rax, OP_2OVER
    je    .op_2over
    cmp   rax, OP_2ROT
    je    .op_2rot
    cmp   rax, OP_2SWAP
    je    .op_2swap
    cmp   rax, OP_IFDUP
    je    .op_ifdup
    cmp   rax, OP_DEPTH
    je    .op_depth
    cmp   rax, OP_DROP
    je    .op_drop
    cmp   rax, OP_DUP
    je    .op_dup
    cmp   rax, OP_NIP
    je    .op_nip
    cmp   rax, OP_OVER
    je    .op_over
    cmp   rax, OP_PICK
    je    .op_pick
    cmp   rax, OP_ROLL
    je    .op_roll
    cmp   rax, OP_ROT
    je    .op_rot
    cmp   rax, OP_SWAP
    je    .op_swap
    cmp   rax, OP_TUCK
    je    .op_tuck
    cmp   rax, OP_SIZE
    je    .op_size
    cmp   rax, OP_EQUAL
    je    .op_equal
    cmp   rax, OP_EQUALVERIFY
    je    .op_equalverify
    cmp   rax, OP_1ADD
    je    .op_mono1
    cmp   rax, OP_1SUB
    je    .op_mono2
    cmp   rax, OP_NEGATE
    je    .op_mono3
    cmp   rax, OP_ABS
    je    .op_mono4
    cmp   rax, OP_NOT
    je    .op_mono5
    cmp   rax, OP_0NOTEQUAL
    je    .op_mono6
    cmp   rax, OP_ADD
    je    .op_bin1
    cmp   rax, OP_SUB
    je    .op_bin2
    cmp   rax, OP_BOOLAND
    je    .op_bin3
    cmp   rax, OP_BOOLOR
    je    .op_bin4
    cmp   rax, OP_NUMEQUAL
    je    .op_bin5
    cmp   rax, OP_NUMEQUALVERIFY
    je    .op_bin6
    cmp   rax, OP_NUMNOTEQUAL
    je    .op_bin7
    cmp   rax, OP_LESSTHAN
    je    .op_bin8
    cmp   rax, OP_GREATERTHAN
    je    .op_bin9
    cmp   rax, OP_LESSTHANOREQUAL
    je    .op_bin10
    cmp   rax, OP_GREATERTHANOREQUAL
    je    .op_bin11
    cmp   rax, OP_MIN
    je    .op_bin12
    cmp   rax, OP_MAX
    je    .op_bin13
    cmp   rax, OP_WITHIN
    je    .op_within
    cmp   rax, OP_RIPEMD160
    je    .op_crypto
    cmp   rax, OP_SHA1
    je    .op_crypto
    cmp   rax, OP_SHA256
    je    .op_crypto
    cmp   rax, OP_HASH160
    je    .op_crypto
    cmp   rax, OP_HASH256
    je    .op_crypto
    cmp   rax, OP_CODESEPARATOR
    je    .op_cs
    cmp   rax, OP_CHECKSIG
    je    .op_checksig
    cmp   rax, OP_CHECKSIGVERIFY
    je    .op_checksigverify
    cmp   rax, OP_CHECKSIGADD
    je    .op_checksigadd
    cmp   rax, OP_CHECKMULTISIG
    je    .op_checkmultisig
    cmp   rax, OP_CHECKMULTISIGVERIFY
    je    .op_checkmultisigverify
    cmp   rax, OP_CHECKLOCKTIMEVERIFY
    je    .op_cltv
    cmp   rax, OP_CHECKSEQUENCEVERIFY
    je    .op_csv
    ; OP_NOP1 (0xb0) and OP_NOP4..OP_NOP10 (0xb3..0xb9): consensus no-ops.
    ; Only OP_NOP2 (0xb1, -> CLTV/BIP65) and OP_NOP3 (0xb2, -> CSV/BIP112)
    ; were ever repurposed; the rest of the original reserved-for-upgrade
    ; NOP range must still do nothing, exactly like plain OP_NOP -- treating
    ; them as bad opcodes rejects real, historically-mined mainnet
    ; transactions that used OP_NOP1 as part of a non-standard (but
    ; consensus-valid) script (e.g. a hash-reveal script ending in
    ; OP_EQUALVERIFY OP_NOP1 instead of OP_EQUALVERIFY OP_CHECKSIG).
    ; SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS is a mempool/relay POLICY
    ; flag (like STRICTENC, removed above) that never appears in Core's
    ; consensus GetBlockScriptFlags, so it does not gate this here.
    cmp   rax, OP_NOP1
    je    .next_op
    cmp   rax, OP_NOP4
    je    .next_op
    cmp   rax, OP_NOP5
    je    .next_op
    cmp   rax, OP_NOP6
    je    .next_op
    cmp   rax, OP_NOP7
    je    .next_op
    cmp   rax, OP_NOP8
    je    .next_op
    cmp   rax, OP_NOP9
    je    .next_op
    cmp   rax, OP_NOP10
    je    .next_op
    jmp   .bad_opcode

; --- pushnum ---
.pushnum:
    mov   rax, [rbp-0x38]
    sub   rax, (OP_1 - 1)
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rax
    call  interp_push_num
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0

; ============================================================================
; Control flow
; ============================================================================
.op_if:
.op_notif:
    mov   rax, [rbp-0x08]
    test  rax, rax
    jz    .if_notexec
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    cmp   rax, 1
    jae   .if_sok
    mov   rax, SCRIPT_ERR_INVALID_STACK_OPERATION
    jmp   .err_ret0
.if_sok:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    ; tapscript minimal-if
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    jne   .if_tapd
    mov   r14d, [r13]
    cmp   r14d, 2
    jae   .tap_minif
    test  r14d, r14d
    jz    .if_minif_ok
    cmp   byte [r13+ELEM_DATA_OFF], 1
    je    .if_minif_ok
.tap_minif:
    mov   rax, SCRIPT_ERR_TAPSCRIPT_MINIMALIF
    jmp   .err_ret0
.if_tapd:
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_WITNESS_V0
    jne   .if_minif_ok
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_MINIMALIF
    jz    .if_minif_ok
    mov   r14d, [r13]
    cmp   r14d, 2
    jae   .wif_minif
    test  r14d, r14d
    jz    .if_minif_ok
    cmp   byte [r13+ELEM_DATA_OFF], 1
    je    .if_minif_ok
.wif_minif:
    mov   rax, SCRIPT_ERR_MINIMALIF    ; was MINIMALDATA (wrong code, same verdict) until 2026-09-02
    jmp   .err_ret0
.if_minif_ok:
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    call  cast_to_bool
    mov   r14, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    mov   rax, [rbp-0x38]
    cmp   rax, OP_NOTIF
    jne   .if_ni
    xor   r14, 1
.if_ni:
    mov   rdi, r14
    call  vfexec_push
    test  rax, rax
    jz    .vfexec_full           ; SCR-2: condition stack cannot grow further
    jmp   .next_op
.if_notexec:
    xor   edi, edi
    call  vfexec_push
    test  rax, rax
    jz    .vfexec_full
    jmp   .next_op
.vfexec_full:
    ; Unreachable for any script that fits the 4 MiB block-witness limit (the
    ; condition stack is sized for 5 MiB of OP_IF). If it ever trips, the
    ; correct response is a hard script error, never a silent continue -- the
    ; pre-fix overflow of vfexec into vfexec_sp produced exactly that.
    mov   rax, SCRIPT_ERR_UNKNOWN_ERROR
    jmp   .err_ret0

.op_else:
    call  vfexec_depth
    test  rax, rax
    jnz   .else_ok
    mov   rax, SCRIPT_ERR_UNBALANCED_CONDITIONAL
    jmp   .err_ret0
.else_ok:
    call  vfexec_toggle_top
    jmp   .next_op

.op_endif:
    call  vfexec_depth
    test  rax, rax
    jnz   .endif_ok
    mov   rax, SCRIPT_ERR_UNBALANCED_CONDITIONAL
    jmp   .err_ret0
.endif_ok:
    call  vfexec_pop
    jmp   .next_op

.op_verify:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    cmp   rax, 1
    jae   .vfy_ok
    mov   rax, SCRIPT_ERR_INVALID_STACK_OPERATION
    jmp   .err_ret0
.vfy_ok:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    call  cast_to_bool
    test  rax, rax
    jz    .vfy_fail
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    jmp   .next_op
.vfy_fail:
    mov   rax, SCRIPT_ERR_VERIFY
    jmp   .err_ret0

.op_return:
    mov   rax, SCRIPT_ERR_OP_RETURN
    jmp   .err_ret0

; ============================================================================
; Stack ops
; ============================================================================
.op_toalt:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    cmp   rax, 1
    jae   .toalt_ok
    mov   rax, SCRIPT_ERR_INVALID_STACK_OPERATION
    jmp   .err_ret0
.toalt_ok:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   rdi, [rbp-0x60]
    mov   rsi, r13
    call  elem_move
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+24]
    mov   rsi, [r12+16]
    mov   rdx, [rbp-0x60]
    mov   ecx, [rdx]           ; len is a uint32 (ELEM_LEN_OFF); a 64-bit
                                ; load pulls in 4 garbage DATA bytes as high
                                ; bits of the length passed to stack_push --
                                ; same bug class as OP_SIZE's fix above
    add   rdx, ELEM_DATA_OFF   ; stack_push's data-pointer arg must point
                                ; PAST the length field elem_move just wrote
                                ; -- this was pointing at the record's BASE
                                ; (the length field itself), so stack_push
                                ; copied the length field's own bytes as if
                                ; they were data. Real production incident
                                ; 2026-08-20 (height 269613): OP_TUCK hit
                                ; this same bug at all three of its pushes,
                                ; corrupting a genuinely-valid spend's
                                ; OP_WITHIN check into a false rejection.
    call  stack_push
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0

.op_fromalt:
    lea   rdi, [r12+24]
    mov   rsi, [r12+16]
    call  stack_depth
    cmp   rax, 1
    jae   .fromalt_ok
    mov   rax, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION
    jmp   .err_ret0
.fromalt_ok:
    lea   rdi, [r12+24]
    mov   rsi, [r12+16]
    call  stack_top_ptr
    mov   r13, rax
    mov   rdi, [rbp-0x60]
    mov   rsi, r13
    call  elem_move
    lea   rdi, [r12+24]
    mov   rsi, [r12+16]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0x60]
    mov   ecx, [rdx]           ; len is a uint32 (ELEM_LEN_OFF); a 64-bit
                                ; load pulls in 4 garbage DATA bytes as high
                                ; bits of the length passed to stack_push --
                                ; same bug class as OP_SIZE's fix above
    add   rdx, ELEM_DATA_OFF   ; must point PAST the length field elem_move
                                ; wrote, not at it -- see op_toalt's comment
    call  stack_push
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0

.op_2drop:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    cmp   rax, 2
    jae   .d2_ok
    mov   rax, SCRIPT_ERR_INVALID_STACK_OPERATION
    jmp   .err_ret0
.d2_ok:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    jmp   .next_op

.op_2dup:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 2
    mov   rbx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rbx
    call  stack_dup_index
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 2
    mov   rbx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rbx
    call  stack_dup_index
    jmp   .next_op

.op_3dup:
    mov   rdi, 3
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 3
    mov   rbx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rbx
    call  stack_dup_index
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 3
    mov   rbx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rbx
    call  stack_dup_index
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 3
    mov   rbx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rbx
    call  stack_dup_index
    jmp   .next_op

.op_2over:
    mov   rdi, 4
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 4
    mov   rbx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rbx
    call  stack_dup_index
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 4
    mov   rbx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, rbx
    call  stack_dup_index
    jmp   .next_op

.op_2rot:
    mov   rdi, 6
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    ; x1..x6 ; -> x3 x4 x5 x6 x1 x2
    ; copy x1(0), x2(1) ; erase them ; push x1,x2
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 6
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   rdi, [rbp-0x90]
    mov   rsi, rax
    call  elem_move
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 5
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   rdi, [rbp-0x98]
    mov   rsi, rax
    call  elem_move
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 6
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_erase_index
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 5
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_erase_index
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0x90]
    mov   rax, [rbp-0x90]
    mov   ecx, [rax]           ; len is a uint32 (ELEM_LEN_OFF); a 64-bit
                                ; load pulls in 4 garbage DATA bytes as high
                                ; bits of the length passed to stack_push --
                                ; same bug class as OP_SIZE's fix above
    add   rdx, ELEM_DATA_OFF   ; must point PAST the length field elem_move
                                ; wrote, not at it -- see op_toalt's comment
    call  stack_push
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0x98]
    mov   rax, [rbp-0x98]
    mov   ecx, [rax]           ; len is a uint32 (ELEM_LEN_OFF); a 64-bit
                                ; load pulls in 4 garbage DATA bytes as high
                                ; bits of the length passed to stack_push --
                                ; same bug class as OP_SIZE's fix above
    add   rdx, ELEM_DATA_OFF   ; must point PAST the length field elem_move
                                ; wrote, not at it -- see op_toalt's comment
    call  stack_push
    jmp   .next_op

.op_2swap:
    mov   rdi, 4
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    ; swap x1(0)<->x3(2), x2(1)<->x4(3)
    ; put each into tmp via elem ptr
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 4
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r13, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 2
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r14, rax
    call  interp_swap_recs
    ; x2(1) <-> x4(3)
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 3
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r13, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 1
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r14, rax
    call  interp_swap_recs
    jmp   .next_op

.op_ifdup:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    call  cast_to_bool
    test  rax, rax
    jz    .next_op
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 1
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_dup_index
    jmp   .next_op

.op_depth:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  interp_push_num
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0

.op_drop:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    jmp   .next_op

.op_dup:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 1
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_dup_index
    jmp   .next_op

.op_nip:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 2
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_erase_index
    jmp   .next_op

.op_over:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 2
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_dup_index
    jmp   .next_op

.op_pick:
.op_roll:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    SNUM_MAX 4
    call  scriptnum_decode
    mov   rcx, [rbp-0xB0]     ; &snum_overflow: size or (under MINIMALDATA) encoding -> SCRIPT_ERR_SCRIPTNUM
    mov   rcx, [rcx]
    test  rcx, rcx
    jnz   .snum_fail
    mov   rbx, rax            ; n
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    test  rbx, rbx
    js    .pk_fail
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    cmp   rbx, rax
    jae   .pk_fail
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 1
    sub   rax, rbx
    mov   r14, rax            ; idx
    mov   rax, [rbp-0x38]
    cmp   rax, OP_ROLL
    jne   .pkdup
    ; roll: copy idx, erase idx, push
    lea   rdi, [r12+8]          ; &sp -- was `mov` (loading the sp VALUE, not
                                 ; its address) at all 4 sites in this ROLL/
                                 ; PICK handler; stack_erase_index/stack_push/
                                 ; stack_dup_index below all write through
                                 ; this as a real pointer, so a garbage small
                                 ; integer here is an immediate SIGSEGV --
                                 ; found via the stack_push length-register
                                 ; regression test crashing even after that
                                 ; fix, real production incident 2026-08-20
    mov   rsi, [r12+0]
    mov   rdx, r14
    call  stack_elem_ptr
    mov   rdi, [rbp-0x90]
    mov   rsi, rax
    call  elem_move
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, r14
    call  stack_erase_index
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0x90]
    mov   rax, [rbp-0x90]
    mov   ecx, [rax]           ; len is a uint32 (ELEM_LEN_OFF); a 64-bit
                                ; load pulls in 4 garbage DATA bytes as high
                                ; bits of the length passed to stack_push --
                                ; same bug class as OP_SIZE's fix above
    add   rdx, ELEM_DATA_OFF   ; must point PAST the length field elem_move
                                ; wrote, not at it -- see op_toalt's comment
    call  stack_push
    jmp   .next_op
.pkdup:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, r14
    call  stack_dup_index
    jmp   .next_op
.pk_fail:
    mov   rax, SCRIPT_ERR_INVALID_STACK_OPERATION
    jmp   .err_ret0

.op_rot:
    mov   rdi, 3
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    ; swap top-3 <-> top-2 ; swap top-2 <-> top-1
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 3
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r13, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 2
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r14, rax
    call  interp_swap_recs
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 2
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r13, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    sub   rax, 1
    mov   rdx, rax
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   r14, rax
    call  interp_swap_recs
    jmp   .next_op

.op_swap:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_swap_two
    jmp   .next_op

.op_tuck:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    ; x1 x2 -> x2 x1 x2 : copy top to tmp2; erase top&second; push x2,x1,x2
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   rdi, [rbp-0xA0]
    mov   rsi, r13
    call  elem_move              ; tmp2 = x2
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_second_ptr
    mov   r13, rax
    mov   rdi, [rbp-0xA8]
    mov   rsi, r13
    call  elem_move              ; tmp3 = x1
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    ; push x2, x1, x2
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0xA0]
    mov   rax, [rbp-0xA0]
    mov   ecx, [rax]           ; len is a uint32 (ELEM_LEN_OFF); a 64-bit
                                ; load pulls in 4 garbage DATA bytes as high
                                ; bits of the length passed to stack_push --
                                ; same bug class as OP_SIZE's fix above
    add   rdx, ELEM_DATA_OFF   ; must point PAST the length field elem_move
                                ; wrote, not at it -- see op_toalt's comment
    call  stack_push
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0xA8]
    mov   rax, [rbp-0xA8]
    mov   ecx, [rax]           ; len is a uint32 (ELEM_LEN_OFF); a 64-bit
                                ; load pulls in 4 garbage DATA bytes as high
                                ; bits of the length passed to stack_push --
                                ; same bug class as OP_SIZE's fix above
    add   rdx, ELEM_DATA_OFF   ; must point PAST the length field elem_move
                                ; wrote, not at it -- see op_toalt's comment
    call  stack_push
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0xA0]
    mov   rax, [rbp-0xA0]
    mov   ecx, [rax]           ; len is a uint32 (ELEM_LEN_OFF); a 64-bit
                                ; load pulls in 4 garbage DATA bytes as high
                                ; bits of the length passed to stack_push --
                                ; same bug class as OP_SIZE's fix above
    add   rdx, ELEM_DATA_OFF   ; must point PAST the length field elem_move
                                ; wrote, not at it -- see op_toalt's comment
    call  stack_push
    jmp   .next_op

.op_size:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   edx, [r13]          ; len is a uint32 (ELEM_LEN_OFF); a 64-bit
                                ; load here pulls in the element's own first
                                ; 4 DATA bytes as garbage high bits of the
                                ; pushed "size" number -- found via a real
                                ; mainnet block (height 251683) using
                                ; OP_SIZE on a 20-byte element whose first 4
                                ; data bytes were nonzero, corrupting the
                                ; result into a bogus multi-byte CScriptNum
                                ; that a later numeric op then rejected as
                                ; oversized.
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  interp_push_num
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0

; ============================================================================
; Equality
; ============================================================================
.op_equal:
.op_equalverify:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax          ; x2
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_second_ptr
    mov   r14, rax          ; x1
    mov   eax, [r13]
    mov   ecx, [r14]
    cmp   eax, ecx
    jne   .eq_false
    mov   rdi, r14
    add   rdi, ELEM_DATA_OFF
    mov   rsi, r13
    add   rsi, ELEM_DATA_OFF
    mov   rdx, rax
    call  interp_memeq
    test  rax, rax
    jz    .eq_false
    mov   r15d, 1
    jmp   .eq_have
.eq_false:
    mov   r15d, 0
.eq_have:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, r15
    call  interp_push_bool
    mov   rax, [rbp-0x38]
    cmp   rax, OP_EQUALVERIFY
    jne   .next_op
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    call  cast_to_bool
    test  rax, rax
    jz    .eqv_fail
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    jmp   .next_op
.eqv_fail:
    mov   rax, SCRIPT_ERR_EQUALVERIFY
    jmp   .err_ret0

; ============================================================================
; Monadic numeric
; ============================================================================
.op_mono1: mov  rbx, 1
    jmp   .mono_common
.op_mono2: mov  rbx, 2
    jmp   .mono_common
.op_mono3: mov  rbx, 3
    jmp   .mono_common
.op_mono4: mov  rbx, 4
    jmp   .mono_common
.op_mono5: mov  rbx, 5
    jmp   .mono_common
.op_mono6: mov  rbx, 6
    jmp   .mono_common
.mono_common:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    SNUM_MAX 4
    call  scriptnum_decode
    mov   rcx, [rbp-0xB0]
    mov   rcx, [rcx]
    test  rcx, rcx
    jnz   .snum_fail
    mov   r14, rax          ; bn
    cmp   rbx, 1
    je    .mo1
    cmp   rbx, 2
    je    .mo2
    cmp   rbx, 3
    je    .mo3
    cmp   rbx, 4
    je    .mo4
    cmp   rbx, 5
    je    .mo5
.mo6:  test  r14, r14
    setnz r14b
    movzx r14, r14b         ; SETcc writes ONLY the low byte -- without this the
                            ; operand's upper 56 bits survive into the result
                            ; (LOG.md incident #28). Core's OP_0NOTEQUAL is
                            ; `bn = (bn != 0)`: exactly 0 or 1, nothing else.
    jmp   .mo_out
.mo1:  add   r14, 1
    jmp   .mo_out
.mo2:  sub   r14, 1
    jmp   .mo_out
.mo3:  neg   r14
    jmp   .mo_out
.mo4:  test  r14, r14
    jns   .mo_out
    neg   r14
    jmp   .mo_out
.mo5:  test  r14, r14
    setz  r14b
    movzx r14, r14b         ; ditto: Core's OP_NOT is `bn = (bn == 0)`.
    jmp   .mo_out
.mo_out:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, r14
    call  interp_push_num
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0
.snum_fail:
    mov   rax, SCRIPT_ERR_SCRIPTNUM
    jmp   .err_ret0

; ============================================================================
; Binary numeric
; ============================================================================
.op_bin1: mov  rbx, 1
    jmp   .bin_common
.op_bin2: mov  rbx, 2
    jmp   .bin_common
.op_bin3: mov  rbx, 3
    jmp   .bin_common
.op_bin4: mov  rbx, 4
    jmp   .bin_common
.op_bin5: mov  rbx, 5
    jmp   .bin_common
.op_bin6: mov  rbx, 6
    jmp   .bin_common
.op_bin7: mov  rbx, 7
    jmp   .bin_common
.op_bin8: mov  rbx, 8
    jmp   .bin_common
.op_bin9: mov  rbx, 9
    jmp   .bin_common
.op_bin10: mov rbx, 10
    jmp   .bin_common
.op_bin11: mov rbx, 11
    jmp   .bin_common
.op_bin12: mov rbx, 12
    jmp   .bin_common
.op_bin13: mov rbx, 13
    jmp   .bin_common
.bin_common:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_second_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    SNUM_MAX 4
    call  scriptnum_decode
    mov   r14, rax          ; bn1
    mov   rcx, [rbp-0xB0]
    mov   rcx, [rcx]
    test  rcx, rcx
    jnz   .snum_fail
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r15d, [r13]
    add   r13, ELEM_DATA_OFF
    mov   rdi, r15
    mov   rsi, r13
    SNUM_MAX 4
    call  scriptnum_decode
    mov   r15, rax          ; bn2
    mov   rcx, [rbp-0xB0]
    mov   rcx, [rcx]
    test  rcx, rcx
    jnz   .snum_fail
    ; rbx = op id
    cmp   rbx, 1
    je    .b_add
    cmp   rbx, 2
    je    .b_sub
    cmp   rbx, 3
    je    .b_band
    cmp   rbx, 4
    je    .b_bor
    cmp   rbx, 5
    je    .b_eq
    cmp   rbx, 6
    je    .b_eq
    cmp   rbx, 7
    je    .b_ne
    cmp   rbx, 8
    je    .b_lt
    cmp   rbx, 9
    je    .b_gt
    cmp   rbx, 10
    je    .b_le
    cmp   rbx, 11
    je    .b_ge
    cmp   rbx, 12
    je    .b_min
.b_max:
    cmp   r14, r15
    cmovl r14, r15
    jmp   .b_out
.b_min:
    cmp   r14, r15
    cmovg r14, r15
    jmp   .b_out
.b_add: add   r14, r15
    jmp   .b_out
.b_sub: sub   r14, r15
    jmp   .b_out
; Every arm below ends in SETcc, which writes ONLY the low 8 bits of its
; destination. r14 and r15 still hold the DECODED OPERANDS at that point, so
; without a zero-extension the operand's upper 56 bits survive into what gets
; pushed -- `256 512 NUMEQUAL` pushed 256 (true) where Core pushes 0 (false).
; See LOG.md incident #28. Core's every one of these is a bool: 0 or 1.
.b_band:
    test  r14, r14
    setnz r14b
    movzx r14, r14b
    test  r15, r15
    setnz r15b
    movzx r15, r15b
    and   r14d, r15d
    jmp   .b_out
.b_bor:
    test  r14, r14
    setnz r14b
    movzx r14, r14b
    test  r15, r15
    setnz r15b
    movzx r15, r15b
    or    r14d, r15d
    jmp   .b_out
.b_eq: cmp   r14, r15
    sete  r14b
    movzx r14, r14b
    jmp   .b_out
.b_ne: cmp   r14, r15
    setne r14b
    movzx r14, r14b
    jmp   .b_out
.b_lt: cmp   r14, r15
    setl  r14b
    movzx r14, r14b
    jmp   .b_out
.b_gt: cmp   r14, r15
    setg  r14b
    movzx r14, r14b
    jmp   .b_out
.b_le: cmp   r14, r15
    setle r14b
    movzx r14, r14b
    jmp   .b_out
.b_ge: cmp   r14, r15
    setge r14b
    movzx r14, r14b
    jmp   .b_out
.b_out:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, r14
    call  interp_push_num
    test  rax, rax
    jnz   .b_post
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0
.b_post:
    mov   rax, [rbp-0x38]
    cmp   rax, OP_NUMEQUALVERIFY
    jne   .next_op
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    add   r13, ELEM_DATA_OFF
    mov   rdi, r14
    mov   rsi, r13
    call  cast_to_bool
    test  rax, rax
    jz    .neqv_fail
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    jmp   .next_op
.neqv_fail:
    mov   rax, SCRIPT_ERR_NUMEQUALVERIFY
    jmp   .err_ret0

.op_within:
    mov   rdi, 3
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    ; x1(val) x2(min) x3(max); f=(min<=val && val<max)
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_third_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    mov   rsi, r15
    SNUM_MAX 4
    call  scriptnum_decode
    mov   rcx, [rbp-0xB0]     ; &snum_overflow: size or (under MINIMALDATA) encoding -> SCRIPT_ERR_SCRIPTNUM
    mov   rcx, [rcx]
    test  rcx, rcx
    jnz   .snum_fail
    mov   r15, rax          ; val -- must survive the two scriptnum_decode
                             ; calls below; they used to clobber it via a
                             ; `lea r15, [r13+ELEM_DATA_OFF]` scratch step
                             ; that was never restored, so the final
                             ; min<=val<max check compared min/max against a
                             ; leftover heap POINTER instead of val -- real
                             ; production incident 2026-08-20 (height
                             ; 256960): a genuinely-valid 1<=1<16 spend was
                             ; wrongly rejected. Fixed by computing the
                             ; pointer straight into rsi (its only use)
                             ; instead of staging it through r15.
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_second_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   rsi, [r13+ELEM_DATA_OFF]
    mov   rdi, r14
    SNUM_MAX 4
    call  scriptnum_decode
    mov   rcx, [rbp-0xB0]     ; &snum_overflow: size or (under MINIMALDATA) encoding -> SCRIPT_ERR_SCRIPTNUM
    mov   rcx, [rcx]
    test  rcx, rcx
    jnz   .snum_fail
    mov   r14, rax          ; min -- must also survive the max lookup below;
                             ; loading max's length straight into edi (not
                             ; via r14) so this doesn't clobber it the same
                             ; way val was clobbered above.
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    lea   rsi, [r13+ELEM_DATA_OFF]
    mov   edi, [r13]
    SNUM_MAX 4
    call  scriptnum_decode
    mov   rcx, [rbp-0xB0]     ; &snum_overflow: size or (under MINIMALDATA) encoding -> SCRIPT_ERR_SCRIPTNUM
    mov   rcx, [rcx]
    test  rcx, rcx
    jnz   .snum_fail
    mov   rbx, rax          ; max
    ; `setl r14b` below has incident #28's shape -- r14 still holds min -- but
    ; the answer is CORRECT here, and only because r13d is zeroed first: r13d
    ; is then 0 or 1, so `and r13d, r14d` masks r14's surviving upper bits away
    ; and leaves exactly the SETcc bit. Keep the xor. (Swept by
    ; tests/test_scriptnum_bool, so deleting it fails there rather than
    ; silently.)
    xor   r13d, r13d
    cmp   r14, r15
    setle r13b
    cmp   r15, rbx
    setl  r14b
    and   r13d, r14d
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    mov   rdx, r13
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  interp_push_bool
    jmp   .next_op

; ============================================================================
; Crypto
; ============================================================================
.op_crypto:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    mov   rax, [rbp-0x38]
    cmp   rax, OP_SHA256
    je    .cr_sha
    cmp   rax, OP_RIPEMD160
    je    .cr_rip
    cmp   rax, OP_HASH160
    je    .cr_h160
    cmp   rax, OP_HASH256
    je    .cr_h256
    cmp   rax, OP_SHA1
    je    .cr_sha1
    jmp   .bad_opcode
.cr_sha:
    mov   rdi, [rbp-0x60]
    mov   rsi, r15
    mov   rdx, r14
    call  sha256_full
    mov   r15d, 32
    jmp   .cr_out
.cr_sha1:
    mov   rdi, [rbp-0x60]
    mov   rsi, r15
    mov   rdx, r14
    call  sha1_full
    mov   r15d, 20
    jmp   .cr_out
.cr_rip:
    mov   rdi, [rbp-0x60]
    mov   rsi, r15
    mov   rdx, r14
    call  ripemd160
    mov   r15d, 20
    jmp   .cr_out
.cr_h160:
    ; sha256 -> ripemd160
    mov   rdi, [rbp-0x60]
    mov   rsi, r15
    mov   rdx, r14
    call  sha256_full
    mov   rdi, [rbp-0x60]
    add   rdi, 32
    mov   rsi, [rbp-0x60]
    mov   rdx, 32
    call  ripemd160
    ; result in interp_tmp+32 (20 bytes)
    mov   r15d, 20
    jmp   .cr_out2
.cr_h256:
    mov   rdi, [rbp-0x60]
    mov   rsi, r15
    mov   rdx, r14
    call  sha256d
    mov   r15d, 32
    jmp   .cr_out
.cr_out:
    ; pop, push (interp_tmp, r15d)
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0x60]
    mov   rcx, r15
    call  stack_push
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0
.cr_out2:
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    mov   rdx, [rbp-0x60]
    add   rdx, 32
    mov   rcx, r15
    call  stack_push
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0

.op_cs:
    ; Reached only when EXECUTED (fExec), like Core's switch arm
    ; (interpreter.cpp, case OP_CODESEPARATOR): pbegincodehash = pc for the
    ; legacy/witness-v0 scriptCode, and -- tapscript only -- record
    ; execdata.m_codeseparator_pos = opcode_pos. [rbp-0x30] counts every
    ; opcode iterated so far (pushes and unexecuted branches included) and
    ; is bumped at .next_op AFTER this op, so right now it holds this
    ; OP_CODESEPARATOR's own 0-based position -- the same value Core's
    ; for-loop post-increment (++opcode_pos) leaves it at.
    mov   rax, [rbp-0x10]
    mov   [rbp-0x20], rax
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    jne   .next_op
    mov   rax, [rbp-0x30]
    mov   [rbp-0x48], rax
    jmp   .next_op

; ============================================================================
; CHECKSIG family
; ============================================================================
.op_checksig:
.op_checksigverify:
    mov   rdi, 2
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    call  interp_checksig
    cmp   rax, -1           ; strict-DER encoding failure -> hard script error
    je    .err_sigder
    cmp   rax, -2           ; STRICTENC pubkey encoding failure -> hard script error
    je    .err_pubkeytype
    cmp   rax, -3
    je    .err_highs
    cmp   rax, -4
    je    .err_hashtype
    cmp   rax, -5           ; the C checker: CONST_SCRIPTCODE found the sig in the scriptCode
    je    .err_findanddelete
    mov   r13, rax          ; success
    ; BIP146 NULLFAIL (2026-09-02): a failing signature that is not empty is
    ; an error under the flag, not a pushed false (Core: "Signature must be
    ; zero for failed CHECK(MULTI)SIG operation").
    test  r13, r13
    jnz   .cs_nullfail_ok
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_NULLFAIL
    jz    .cs_nullfail_ok
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_second_ptr    ; the signature element
    cmp   dword [rax], 0
    jne   .err_nullfail
.cs_nullfail_ok:
    ; pop sig, pub, push bool
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    mov   rdx, r13
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  interp_push_bool
    mov   rax, [rbp-0x38]
    cmp   rax, OP_CHECKSIGVERIFY
    jne   .next_op
    ; incident #16: OP_CHECKSIGVERIFY is VALID under SIGVERSION_TAPSCRIPT.
    ; BIP342 keeps CHECKSIG/CHECKSIGVERIFY (re-specified for schnorr) and
    ; disables only CHECKMULTISIG(VERIFY); Core runs the same switch arm and the
    ; same trailing "if CHECKSIGVERIFY: pop-or-SCRIPT_ERR_CHECKSIGVERIFY" for
    ; every sigversion. This used to "je .bad_opcode" under tapscript, rejecting
    ; every real HTLC-style leaf (<pk> OP_CHECKSIGVERIFY ... OP_CSV) -- the true
    ; cause of the mainnet tapscript-CSV reject wall (a spend Core accepted at
    ; height 806500). Schnorr semantics are unchanged: interp_checksig already
    ; pushed the bool, so the VERIFY pop/fail below is the same as CHECKSIG.
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    add   r13, ELEM_DATA_OFF
    mov   rdi, r14
    mov   rsi, r13
    call  cast_to_bool
    test  rax, rax
    jz    .csigv_fail
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    jmp   .next_op
.csigv_fail:
    mov   rax, SCRIPT_ERR_CHECKSIGVERIFY
    jmp   .err_ret0
.err_sigder:
    mov   rax, SCRIPT_ERR_SIG_DER
    jmp   .err_ret0
.err_pubkeytype:
    mov   rax, SCRIPT_ERR_PUBKEYTYPE
    jmp   .err_ret0
.err_highs:
    mov   rax, SCRIPT_ERR_SIG_HIGH_S
    jmp   .err_ret0
.err_hashtype:
    mov   rax, SCRIPT_ERR_SIG_HASHTYPE
    jmp   .err_ret0
.err_nullfail:
    mov   rax, SCRIPT_ERR_SIG_NULLFAIL
    jmp   .err_ret0
.err_findanddelete:
    mov   rax, SCRIPT_ERR_SIG_FINDANDDELETE
    jmp   .err_ret0

.op_checksigadd:
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    je    .csa_go
    mov   rax, SCRIPT_ERR_BAD_OPCODE
    jmp   .err_ret0
.csa_go:
    mov   rdi, 3
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    ; (sig num pubkey) -> decode num at sp-2
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_second_ptr
    mov   r13, rax
    mov   r14d, [r13]
    add   r13, ELEM_DATA_OFF
    mov   rdi, r14
    mov   rsi, r13
    SNUM_MAX 4
    call  scriptnum_decode
    mov   rcx, [rbp-0xB0]     ; &snum_overflow: size or (under MINIMALDATA) encoding -> SCRIPT_ERR_SCRIPTNUM
    mov   rcx, [rcx]
    test  rcx, rcx
    jnz   .snum_fail
    mov   rbx, rax          ; num (rbx preserved)
    call  interp_checksig_add
    mov   r13, rax          ; success
    add   rbx, r13
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    mov   rdx, rbx
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  interp_push_num
    test  rax, rax
    jnz   .next_op
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0

.op_checkmultisig:
.op_checkmultisigverify:
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    jne   .cms_go
    mov   rax, SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG
    jmp   .err_ret0
.cms_go:
    ; full OP_CHECKMULTISIG handled by helper which returns 1 ok or sets interp_err
    call  interp_checkmultisig
    test  rax, rax
    jnz   .cms_ok
    mov   rax, [rbp-0x70]
    mov   rax, [rax]
    test  rax, rax
    jz    .bad_opcode
    mov   rax, [rbp-0x70]
    mov   rax, [rax]
    jmp   .err_ret0
.cms_ok:
    ; interp_checkmultisig always pushes its bool result (mirrors real
    ; CHECKMULTISIG, which is not itself a VERIFY op). CHECKMULTISIGVERIFY
    ; must then pop-and-fail-on-false, exactly like every other VERIFY
    ; opcode (op_checksigverify above is the same pattern) -- this used to
    ; be missing entirely: .op_checkmultisigverify was a bare alias for
    ; .op_checkmultisig with no additional behavior, so CHECKMULTISIGVERIFY
    ; silently degraded to plain CHECKMULTISIG and left its bool on the
    ; stack instead of consuming it, corrupting every opcode's stack
    ; position after it. Found via a real mainnet block (height 324663)
    ; whose redeem script chains CHECKMULTISIGVERIFY into a second
    ; CHECKMULTISIG -- the stray leftover bool was consumed as that second
    ; check's first "signature", which of course never verifies.
    mov   rax, [rbp-0x38]
    cmp   rax, OP_CHECKMULTISIGVERIFY
    jne   .next_op
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    add   r13, ELEM_DATA_OFF
    mov   rdi, r14
    mov   rsi, r13
    call  cast_to_bool
    test  rax, rax
    jz    .cmsv_fail
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    jmp   .next_op
.cmsv_fail:
    mov   rax, SCRIPT_ERR_CHECKMULTISIGVERIFY
    jmp   .err_ret0

.op_cltv:
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
    jnz   .cltv_go
    jmp   .next_op
.cltv_go:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    add   r13, ELEM_DATA_OFF
    mov   rdi, r14
    mov   rsi, r13
    SNUM_MAX 5
    call  scriptnum_decode
    mov   rcx, [rbp-0xB0]     ; &snum_overflow: size or (under MINIMALDATA) encoding -> SCRIPT_ERR_SCRIPTNUM
    mov   rcx, [rcx]
    test  rcx, rcx
    jnz   .snum_fail
    test  rax, rax
    jns   .cltv_nn
    mov   rax, SCRIPT_ERR_NEGATIVE_LOCKTIME
    jmp   .err_ret0
.cltv_nn:
    ; BIP65 CheckLockTime (real Core algorithm, script/interpreter.cpp),
    ; using the tx.nLockTime / this input's nSequence that sv_verify_script
    ; now threads into script_state (added 2026-08-21 -- this used to be a
    ; hardcoded "no tx context in pure interpreter -> unsatisfied", i.e.
    ; every CHECKLOCKTIMEVERIFY spend was unconditionally rejected. Found
    ; via a real mainnet block, height 388431, right at BIP65's real
    ; activation -- the first CLTV-locked spend the replay ever reached).
    ; rax = scriptTime (non-negative CScriptNum, already confirmed above).
    mov   r15, rax                     ; r15 = scriptTime
    mov   eax, [r12+104]               ; tx_locktime (u32, zero-extends into rax)
    mov   r14, rax                     ; r14 = tx.nLockTime (u64)
    mov   rax, 500000000               ; LOCKTIME_THRESHOLD
    cmp   r15, rax
    jl    .cltv_script_below
    cmp   r14, rax
    jl    .cltv_unsatisfied            ; type mismatch: script>=thresh, tx<thresh
    jmp   .cltv_type_ok
.cltv_script_below:
    cmp   r14, rax
    jge   .cltv_unsatisfied            ; type mismatch: script<thresh, tx>=thresh
.cltv_type_ok:
    cmp   r15, r14
    jg    .cltv_unsatisfied            ; scriptTime > tx.nLockTime -> not yet satisfied
    mov   eax, [r12+108]               ; in_sequence (u32)
    cmp   eax, 0xffffffff              ; SEQUENCE_FINAL
    je    .cltv_unsatisfied            ; finalized input bypasses nLockTime -> reject
    jmp   .next_op
.cltv_unsatisfied:
    mov   rax, SCRIPT_ERR_UNSATISFIED_LOCKTIME
    jmp   .err_ret0

.op_csv:
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
    jnz   .csv_go
    jmp   .next_op
.csv_go:
    mov   rdi, 1
    call  interp_require_depth
    test  rax, rax
    jnz   .err_ret0
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    add   r13, ELEM_DATA_OFF
    mov   rdi, r14
    mov   rsi, r13
    SNUM_MAX 5
    call  scriptnum_decode
    mov   rcx, [rbp-0xB0]     ; &snum_overflow: size or (under MINIMALDATA) encoding -> SCRIPT_ERR_SCRIPTNUM
    mov   rcx, [rcx]
    test  rcx, rcx
    jnz   .snum_fail
    test  rax, rax
    jns   .csv_nn
    mov   rax, SCRIPT_ERR_NEGATIVE_LOCKTIME
    jmp   .err_ret0
.csv_nn:
    ; disable flag (bit 31) on the SCRIPT's own operand -> NOP (pre-existing,
    ; correct -- unrelated to the input's real nSequence checked below).
    ; bit 31 ONLY (Core: nSequence & SEQUENCE_LOCKTIME_DISABLE_FLAG, the flag is
    ; 1<<31 as int64). NOT `test rax, 0x80000000`: that imm32 sign-extends to
    ; 0xFFFFFFFF80000000, so a 5-byte operand with any of bits 32-39 set and
    ; bit 31 clear was treated as "disabled" -> NOP -> accepted, where Core
    ; masks the operand and enforces it (false-accept, fixed 2026-09-02).
    test  eax, 0x80000000
    jnz   .next_op
    ; BIP68/BIP112 CheckSequence (real Core algorithm, script/interpreter.cpp),
    ; using tx.nVersion / this input's nSequence now threaded into
    ; script_state (added 2026-08-21, same fix as CHECKLOCKTIMEVERIFY above
    ; -- this was also a hardcoded unconditional reject).
    mov   r15, rax                     ; r15 = scriptSequence
    mov   eax, [r12+112]               ; tx_version (u32)
    cmp   eax, 2
    ; SCR-4 fix (audit 2026-09-03): CTransaction::version is uint32_t and
    ; CheckSequence does `txTo->version < 2` UNSIGNED (interpreter.cpp). A
    ; transaction with nVersion >= 0x80000000 HAS BIP68 enforced by Core; the
    ; old `jl` read it as negative and false-rejected every CSV spend it.
    jb    .csv_unsatisfied             ; BIP68 requires tx.nVersion >= 2
    mov   eax, [r12+108]               ; in_sequence (u32)
    test  eax, 0x80000000              ; this input's OWN disable flag
    jnz   .csv_unsatisfied
    mov   r14, rax                     ; r14 = txToSequence (u64, zero-extended)
    mov   rcx, 0x0040ffff              ; SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK
    and   r14, rcx                     ; txToSequenceMasked
    mov   r13, r15
    and   r13, rcx                     ; nSequenceMasked
    mov   rax, 0x00400000              ; SEQUENCE_LOCKTIME_TYPE_FLAG
    cmp   r13, rax
    jl    .csv_script_below
    cmp   r14, rax
    jl    .csv_unsatisfied             ; type mismatch: script>=flag, tx<flag
    jmp   .csv_type_ok
.csv_script_below:
    cmp   r14, rax
    jge   .csv_unsatisfied             ; type mismatch: script<flag, tx>=flag
.csv_type_ok:
    cmp   r13, r14
    jg    .csv_unsatisfied             ; nSequenceMasked > txToSequenceMasked -> not yet satisfied
    jmp   .next_op
.csv_unsatisfied:
    mov   rax, SCRIPT_ERR_UNSATISFIED_LOCKTIME
    jmp   .err_ret0

.bad_opcode:
    mov   rax, SCRIPT_ERR_BAD_OPCODE
    jmp   .err_ret0

.next_op:
    ; SCR-1 fix (audit 2026-09-03): Core checks, AFTER EVERY OPCODE,
    ; "if (stack.size() + altstack.size() > MAX_STACK_SIZE) return
    ; SCRIPT_ERR_STACK_SIZE" (interpreter.cpp, end of the EvalScript for
    ; body). The per-stack guards in stack_push et al. cap each stack at
    ; 1000 INDEPENDENTLY, so a script could run with up to 2000 live
    ; elements -- a consensus false accept under tapscript (no opcode
    ; limit) and a false accept under witness v0 too. The buffers stay at
    ; 1000 each (memory-safety backstop); the consensus rule is the sum.
    mov   rax, [r12+8]        ; main_sp
    add   rax, [r12+24]       ; + alt_sp
    cmp   rax, MAX_STACK_SIZE
    ja    .stack_size_err
    inc   qword [rbp-0x30]
    jmp   .loop
.stack_size_err:
    mov   rax, SCRIPT_ERR_STACK_SIZE
    jmp   .err_ret0

.loop_done:
    call  vfexec_depth
    test  rax, rax
    jz    .cstack
    mov   rax, SCRIPT_ERR_UNBALANCED_CONDITIONAL
    jmp   .err_ret0
.cstack:
    ; Tapscript (BIP342 ExecuteWitnessScript) enforces cleanstack: the final
    ; stack must have exactly one element (else CLEANSTACK) and that element
    ; must CastToBool to true (else EVAL_FALSE). BASE/WITNESS_V0 leave
    ; cleanstack/truthiness to the outer VerifyScript, so only gate on
    ; SIGVERSION_TAPSCRIPT here. The "empty-stack treatment": a tapscript that
    ; evaluates to an empty (or multi-item / false) stack must be rejected.
    mov   eax, dword [r12+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    jne   .final_ok
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    cmp   rax, 1
    jne   .cstack_fail          ; stack.size() != 1 -> CLEANSTACK
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax
    mov   r14d, [r13]
    add   r13, ELEM_DATA_OFF
    mov   rdi, r14
    mov   rsi, r13
    call  cast_to_bool
    test  rax, rax
    jz    .evalfalse           ; !CastToBool(top) -> EVAL_FALSE
    jmp   .final_ok
.cstack_fail:
    mov   rax, SCRIPT_ERR_CLEANSTACK
    jmp   .err_ret0
.evalfalse:
    mov   rax, SCRIPT_ERR_EVAL_FALSE
    jmp   .err_ret0
.final_ok:
    mov   rax, [r12+80]
    test  rax, rax
    jz    .ret1
    mov   qword [rax], SCRIPT_ERR_OK
.ret1:
    mov   eax, 1
    jmp   .done
.err_ret0:
    mov   rcx, rax
    mov   rax, [r12+80]
    test  rax, rax
    jz    .ret0
    mov   [rax], rcx
.ret0:
    xor   eax, eax
.done:
    add   rsp, 0x108          ; must match the prologue reservation above
    pop   rbp                 ; save area is ABOVE rbp -- rbp pops first
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    ret

; ============================================================================
; is_opsuccess(opcode in rax) -> rax = 1 if OP_SUCCESSx else 0.
;   Bitcoin Core IsOpSuccess (script.cpp:365), BIP342:
;     opcode==80(OP_RESERVED) || opcode==98(OP_VER) ||
;     (126..129)=CAT/SUBSTR/LEFT/RIGHT ||
;     (131..134)=INVERT/AND/OR/XOR || (137..138)=RESERVED1/RESERVED2 ||
;     (141..142)=2MUL/2DIV || (149..153)=MUL/DIV/MOD/LSHIFT/RSHIFT ||
;     (187..254)=undefined tapscript opcodes (starts at OP_NOP11=0xbb=187).
;   Leaf; uses only rax/rcx/rdx so callee-saved (rbx,r12-r15) stay untouched.
; ============================================================================
global is_opsuccess
is_opsuccess:
    cmp   rax, 80
    je    .yes
    cmp   rax, 98
    je    .yes
    cmp   rax, 126
    jb    .r131
    cmp   rax, 129
    jbe   .yes
.r131:
    cmp   rax, 131
    jb    .r137
    cmp   rax, 134
    jbe   .yes
.r137:
    cmp   rax, 137
    jb    .r141
    cmp   rax, 138
    jbe   .yes
.r141:
    cmp   rax, 141
    jb    .r149
    cmp   rax, 142
    jbe   .yes
.r149:
    cmp   rax, 149
    jb    .r187
    cmp   rax, 153
    jbe   .yes
.r187:
    cmp   rax, 187
    jb    .no
    cmp   rax, 254
    jbe   .yes
.no:
    xor   eax, eax
    ret
.yes:
    mov   eax, 1
    ret

; is_opsuccess_c(int opcode) : C-ABI wrapper (opcode in edi per SysV) that
; tail-calls into the rax-based is_opsuccess logic above. Used by C harnesses.
global is_opsuccess_c
is_opsuccess_c:
    mov   rax, rdi
    jmp   is_opsuccess

; ============================================================================
; interp_swap_recs(a=rdi, b=rsi)  : swap two element records pointed by r13,r14
;   -- uses the values already loaded in r13 (a) and r14 (b)
; ============================================================================
interp_swap_recs:
    push  rbx
    ; r13 = a, r14 = b. rbp is script_eval's frame here (interp_swap_recs is
    ; only ever reached via script_eval's own call graph, same convention as
    ; interp_checkmultisig/interp_push_num/interp_push_bool).
    mov   rdi, [rbp-0x90]
    mov   rsi, r13
    call  elem_move            ; tmp0 = *a
    mov   rdi, r13
    mov   rsi, r14
    call  elem_move            ; *a = *b
    mov   rdi, r14
    mov   rsi, [rbp-0x90]
    call  elem_move            ; *b = tmp0
    pop   rbx
    ret

; ============================================================================
; interp_memeq(a=rdi, b=rsi, len=rdx) -> rax 1 if equal
; ============================================================================
interp_memeq:
    xor   ecx, ecx
.loop:
    cmp   rcx, rdx
    jae   .yes
    movzx r8d, byte [rdi+rcx]
    movzx r9d, byte [rsi+rcx]
    cmp   r8b, r9b
    jne   .no
    inc   rcx
    jmp   .loop
.yes:
    mov   eax, 1
    ret
.no:
    xor   eax, eax
    ret

; ============================================================================
; interp_push_num(&sp, elems, value) -> rax 1/0
;   Serializes value (ScriptNum) and pushes; uses scriptnum_buf + rdx=len.
; ============================================================================
interp_push_num:
    ; rdi=&sp, rsi=elems, rdx=value
    push  r12
    push  r13
    push  r14
    mov   r12, rdi
    mov   r13, rsi
    mov   r14, rdx            ; value (preserved)
    mov   rdi, r14
    call  scriptnum_serialize  ; rax=ptr, rdx=len
    ; copy the serialized bytes into interp_tmp
    push  rdx
    mov   r14, rdx            ; len
    mov   rdi, rdx
    ; copy rax[0..rdx) -> interp_tmp (interp_tmp is thread-local, 528 bytes;
    ; interp_push_num is only ever reached via script_eval's own call graph,
    ; so rbp is always script_eval's frame here -- same convention as
    ; interp_checkmultisig)
    mov   rdi, [rbp-0x60]
    mov   rsi, rax
    mov   rcx, r14
    rep movsb
    pop   rdx
    ; push (interp_tmp, r14)
    mov   rdi, r12
    mov   rsi, r13
    mov   rdx, [rbp-0x60]
    mov   rcx, r14
    call  stack_push
    pop   r14
    pop   r13
    pop   r12
    ret

; ============================================================================
; interp_push_bool(&sp, elems, bool in rdx) -> rax 1/0
; ============================================================================
interp_push_bool:
    push  r12
    push  r13
    push  r14
    mov   r12, rdi
    mov   r13, rsi
    mov   r14, rdx            ; bool
    ; build the single byte
    mov   rax, [rbp-0x68]      ; this thread's bool_buf address (interp_push_bool
                                ; is only reached via script_eval's call graph,
                                ; incl. through interp_checkmultisig, which shares
                                ; script_eval's frame -- same convention as -0x60).
                                ; rax is caller-saved/volatile, safe to clobber
                                ; here and hold across .put0/.have/.pushit below
                                ; (nothing in this function relies on an incoming
                                ; rax value -- r12/r13/r14 are its only locals).
    test  r14, r14
    jz    .put0
    mov   byte [rax], 1
    jmp   .have
.put0:
    mov   byte [rax], 0
.have:
    ; push either empty (len 0) or 1 byte. For bool true push 0x01; false push empty.
    xor   ecx, ecx
    test  r14, r14
    jz    .pushit
    mov   ecx, 1
.pushit:
    mov   rdi, r12
    mov   rsi, r13
    mov   rdx, rax
    ; rcx = 0 or 1
    call  stack_push
    pop   r14
    pop   r13
    pop   r12
    ret

; ============================================================================
; interp_require_depth(min in rdi) -> rax = 0 ok / SCRIPT_ERR_INVALID_STACK_OP
;   Preserves callee-saved. Uses r14 to hold min across the stack_depth call.
; ============================================================================
interp_require_depth:
    push  r14
    mov   r14, rdi            ; min (preserved)
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_depth
    cmp   rax, r14
    jae   .ok
    mov   rax, SCRIPT_ERR_INVALID_STACK_OPERATION
    pop   r14
    ret
.ok:
    xor   eax, eax
    pop   r14
    ret




; ============================================================================
; checksig helpers.
; checksig_fn (6 args, all in regs):
;   rdi=ctx, rsi=sig, rdx=siglen, rcx=pub, r8=publen, r9=&interp_slice
;   where interp_slice={sc_ptr, sc_len}; returns rax = success 0/1.
; Preserve callee-saved rbx,r12-r15. rbp = script_eval frame (for slice).
; ============================================================================

; ----------------------------------------------------------------------------
; interp_sig_encoding_ok(rdi = signature STACK ELEMENT ptr) -> rax = 1 ok / 0 =
; the script must fail with SCRIPT_ERR_SIG_DER. r12 = script_state.
;
; Core's CheckSignatureEncoding (script/interpreter.cpp), reduced to the part
; that is ever CONSENSUS here:
;
;   if (vchSig.size() == 0) return true;                       // -> .sigenc_ok
;   if ((flags & (DERSIG|LOW_S|STRICTENC)) != 0
;       && !IsValidSignatureEncoding(vchSig)) return SIG_DER;   // -> der_sig_strict
;   else if (flags & LOW_S) ... else if (flags & STRICTENC) ...
;
; The trailing LOW_S / STRICTENC arms are deliberately NOT implemented: neither
; flag is ever produced by GetBlockScriptFlags (validation.cpp) and neither is
; ever set by script_flags_for_block (bitcoin_script_flags.asm) -- both are
; mempool/relay POLICY only (policy.h STANDARD_SCRIPT_VERIFY_FLAGS). They are
; named in the mask above solely to keep this a faithful transcription of the
; guard Core actually writes; on this codebase's consensus path DERSIG is the
; only one of the three that can be set. (Removing an identical STRICTENC
; hashtype check from sv_checksig on 2026-08-19 was what unblocked the archive
; replay at height 110299 -- see bitcoin_scriptverify.c's note. This must not
; reintroduce it.)
;
; SIGVERSION gate: Core reaches CheckSignatureEncoding only from
; EvalChecksigPreTapscript, i.e. SigVersion BASE and WITNESS_V0.
; SIGVERSION_TAPSCRIPT goes to EvalChecksigTapscript, whose signature rule is
; BIP342's schnorr 64/65-byte one and has nothing to do with DER -- running
; this check there would reject every tapscript spend.
;
; Clobbers rax,rcx,rsi,rdi,r8,r9 (der_sig_strict is a leaf that touches no
; callee-saved register), so both call sites keep their live rbx/r13-r15.
; ----------------------------------------------------------------------------
interp_sig_encoding_ok:
    mov   eax, dword [r12+48]        ; sigversion
    cmp   rax, SIGVERSION_TAPSCRIPT
    je    .sigenc_ok
    mov   rax, [r12+56]              ; flags
    test  rax, SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC
    jz    .sigenc_ok
    mov   esi, dword [rdi]           ; siglen (elem length field)
    test  esi, esi
    jz    .sigenc_ok                 ; empty signature: Core returns true
    add   rdi, ELEM_DATA_OFF
    call  der_sig_strict             ; leaf: clobbers only rax/rcx/r8/r9, rdi/rsi survive
    test  rax, rax
    jz    .sigenc_der                ; -> 0 = SCRIPT_ERR_SIG_DER
    ; ---- Core's trailing arms (2026-09-02, Core differential with real
    ; signatures): after strict DER passed, LOW_S then STRICTENC hashtype.
    ; Returns -1 = SIG_HIGH_S, -2 = SIG_HASHTYPE; the callers map them.
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_LOW_S
    jz    .sigenc_ht
    ; S: lenR = sig[3], lenS = sig[5+lenR], S bytes at sig[6+lenR]. Strict DER
    ; already holds, so a 33-byte S has a 0x00 pad before a >=0x80 byte (high),
    ; a <32-byte S is below 2^248 (low), a 32-byte S compares against N/2.
    movzx ecx, byte [rdi+3]
    movzx r8d, byte [rdi+5+rcx]      ; lenS
    cmp   r8d, 33
    je    .sigenc_highs
    cmp   r8d, 32
    jb    .sigenc_ht
    lea   r9, [rdi+6+rcx]            ; S, 32 bytes big-endian
    lea   rcx, [rel half_order_n]
    xor   r8d, r8d
.sigenc_cmp:
    movzx eax, byte [r9+r8]
    cmp   al, byte [rcx+r8]
    jb    .sigenc_ht                 ; S < N/2: low
    ja    .sigenc_highs              ; S > N/2: high
    inc   r8d
    cmp   r8d, 32
    jb    .sigenc_cmp                ; equal so far; all equal = N/2 exactly = low
.sigenc_ht:
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_STRICTENC
    jz    .sigenc_ok
    movzx eax, byte [rdi+rsi-1]      ; hashtype byte
    and   eax, 0x7f                  ; drop ANYONECANPAY
    cmp   eax, 1
    jb    .sigenc_badht
    cmp   eax, 3
    ja    .sigenc_badht
.sigenc_ok:
    mov   eax, 1
    ret
.sigenc_der:
    xor   eax, eax
    ret
.sigenc_highs:
    mov   rax, -1
    ret
.sigenc_badht:
    mov   rax, -2
    ret
; secp256k1 group order / 2, big-endian: the LOW_S bound (BIP62, Core's
; IsLowDERSignature). Read-only data kept next to its only reader.
half_order_n: db 0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
              db 0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0

; interp_pubkey_encoding_ok(rdi = publen, rsi = pubdata) -> rax = 1 ok / 0 = the
; script must fail with SCRIPT_ERR_PUBKEYTYPE. r12 = script_state.
; Core's CheckPubKeyEncoding: under STRICTENC the key must be 33 bytes starting
; 02/03 or 65 bytes starting 04 (IsCompressedOrUncompressedPubKey). Runs
; BEFORE the empty-signature shortcut, as in Core. (2026-09-02, Core
; differential: STRICTENC scripts with a malformed key passed here.)
interp_pubkey_encoding_ok:
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_STRICTENC
    jz    .pke_ok
    cmp   rdi, 33
    jne   .pke_65
    movzx eax, byte [rsi]
    cmp   al, 2
    je    .pke_ok
    cmp   al, 3
    je    .pke_ok
    jmp   .pke_bad
.pke_65:
    cmp   rdi, 65
    jne   .pke_bad
    cmp   byte [rsi], 4
    je    .pke_ok
.pke_bad:
    xor   eax, eax
    ret
.pke_ok:
    mov   eax, 1
    ret

; interp_checksig() -> rax = 0/1, or -1 = SCRIPT_ERR_SIG_DER (bad encoding is a
;                      hard script ERROR in Core, not a false CHECKSIG result)
;                      ; -5 = SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY (SCR-3)
;                      ; sig = sp-2, pub = sp-1
interp_checksig:
    push  r12
    push  r13
    push  r14
    push  r15
    push  rbx
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax            ; pub elem
    mov   r14d, [r13]         ; publen
    lea   r15, [r13+ELEM_DATA_OFF]
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_second_ptr
    mov   r13, rax            ; sig elem
    mov   ebx, [r13]          ; siglen (32-bit elem length; was rbx[8])
    ; ---- SCR-3 (audit 2026-09-03): under SIGVERSION_TAPSCRIPT the ENTIRE
    ; pre-tapscript arm is wrong (Core routes tapscript through
    ; EvalChecksigTapscript): no sig-encoding checks, no pubkey-encoding
    ; checks -- and no empty-signature shortcut before the pubkey rules.
    ; Gate straight into the callback, which implements Core's sequence
    ; (weight charge only for a non-empty sig; publen == 0 -> hard fail
    ; REGARDLESS of the signature; publen != 32 -> upgradable success).
    TLS_ADDR rax, interp_state
    mov   rax, [rax]
    mov   eax, dword [rax+48]
    cmp   rax, SIGVERSION_TAPSCRIPT
    je    .cs_call
    ; ---- BIP66/DERSIG. Core runs CheckSignatureEncoding at the TOP of
    ; EvalChecksigPreTapscript, before any hashing or ECDSA work, and its
    ; failure aborts the whole script (SCRIPT_ERR_SIG_DER) rather than making
    ; CHECKSIG push false. The distinction is consensus-visible: with a mere
    ; false, `<sig> <pk> CHECKSIG OP_NOT` would still ACCEPT a signature Core
    ; rejects. -1 carries the error out to .op_checksig.
    ; Core order (2026-09-02): sig encoding (true for an empty sig), then
    ; pubkey encoding (STRICTENC), THEN the empty-sig -> false shortcut.
    mov   rdi, r13
    call  interp_sig_encoding_ok
    cmp   rax, 1
    je    .encoding_ok
    cmp   rax, -1
    je    .enc_highs
    cmp   rax, -2
    je    .enc_badht
    mov   rax, -1             ; SCRIPT_ERR_SIG_DER
    jmp   .end
.enc_highs:
    mov   rax, -3             ; SCRIPT_ERR_SIG_HIGH_S
    jmp   .end
.enc_badht:
    mov   rax, -4             ; SCRIPT_ERR_SIG_HASHTYPE
    jmp   .end
.encoding_ok:
    mov   rdi, r14            ; publen
    mov   rsi, r15            ; pubdata
    call  interp_pubkey_encoding_ok
    test  rax, rax
    jnz   .pubenc_ok
    mov   rax, -2             ; SCRIPT_ERR_PUBKEYTYPE (the caller maps it)
    jmp   .end
.pubenc_ok:
    ; Empty signature -> false. EXCEPT under CONST_SCRIPTCODE (2026-09-02):
    ; Core runs FindAndDelete of the signature's push (OP_0 for an empty one)
    ; against the scriptCode BEFORE the checker, and finding it is
    ; SIG_FINDANDDELETE. That search lives in the C callback, so with the
    ; flag set the callback must see the empty signature too (it returns
    ; false for it after the search).
    test  rbx, rbx
    jnz   .cs_call
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_CONST_SCRIPTCODE
    jz    .false
.cs_call:
    mov   rax, [r12+96]
    test  rax, rax
    jz    .false
    ; build slice
    mov   rax, [rbp-0x20]
    TLS_ADDR r10, interp_slice
    mov   [r10], rax
    mov   rax, [rbp-0x18]
    sub   rax, [rbp-0x20]
    TLS_ADDR r10, interp_slice
    mov   [r10+8], rax
    mov   rax, [rbp-0x48]     ; BIP342 codesep_pos -> slice[2] (tapscript)
    mov   [r10+16], rax
    ; args
    mov   rdi, [r12+88]
    lea   rsi, [r13+ELEM_DATA_OFF]
    mov   rdx, rbx
    mov   rcx, r15
    mov   r8,  r14
    TLS_ADDR r9, interp_slice
    call  qword [r12+96]
    jmp   .end
.false:
    xor   eax, eax
.end:
    pop   rbx
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret

; interp_checksig_add() -> rax = 0/1 ; sig = sp-3, pub = sp-1 (tapscript CHECKSIGADD)
;   (interp_checksig_add is reached ONLY from .op_checksigadd, which is
;   BAD_OPCODE outside tapscript -- so r12+48 is SIGVERSION_TAPSCRIPT here by
;   construction, and the sigversion is read straight from r12.)
interp_checksig_add:
    push  r12
    push  r13
    push  r14
    push  r15
    push  rbx
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_top_ptr
    mov   r13, rax            ; pub elem
    mov   r14d, [r13]
    lea   r15, [r13+ELEM_DATA_OFF]
    ; sig = third (sp-3)
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_third_ptr
    mov   r13, rax
    mov   ebx, [r13]          ; siglen (32-bit elem length; was rbx[8])
    ; SCR-3 (audit 2026-09-03): the empty-signature shortcut must NOT skip
    ; the callback under tapscript -- Core's EvalChecksigTapscript evaluates
    ; the pubkey rules regardless of the signature, and an empty pubkey is a
    ; hard script failure (TAPSCRIPT_EMPTY_PUBKEY), not a pushed 0. The C
    ; callback implements Core's full sequence (weight charge only for a
    ; non-empty sig; publen==0 -> hard fail; publen!=32 -> upgradable).
    mov   rax, [r12+96]
    test  rax, rax
    jz    .false
    mov   rax, [rbp-0x20]
    TLS_ADDR r10, interp_slice
    mov   [r10], rax
    mov   rax, [rbp-0x18]
    sub   rax, [rbp-0x20]
    TLS_ADDR r10, interp_slice
    mov   [r10+8], rax
    mov   rax, [rbp-0x48]     ; BIP342 codesep_pos -> slice[2] (tapscript)
    mov   [r10+16], rax
    mov   rdi, [r12+88]
    lea   rsi, [r13+ELEM_DATA_OFF]
    mov   rdx, rbx
    mov   rcx, r15
    mov   r8,  r14
    TLS_ADDR r9, interp_slice
    call  qword [r12+96]
    jmp   .end
.false:
    xor   eax, eax
.end:
    pop   rbx
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret

; interp_checkmultisig() -> rax = 1 ok / 0 failed (error in interp_err)
;   Full OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY. Tapscript handled by caller.
;   Handles the classic (dummy) [sig...] m [pub...] n layout, signature checking
;   via checksig_fn against each key in order.
;
;   Stack (bottom..top): ... [dummy] sig1..sigm m pub1..pubn n
;   On entry r12 = script_state (checksig_ctx at +88, checksig_fn at +96),
;   rbp = script_eval frame ([rbp-0x20]..[rbp-0x18] = current scriptCode slice).
;
;   Consensus algorithm (matches Core EvalScript's CheckMultisig over the
;   functor): read nKeys=n, nSigs=m; walk the keys left-to-right, checking each
;   against the current signature via checksig_fn; consume a signature only on a
;   match. If fewer than mSigs verify, the multisig is false. Pops all operands
;   (incl. the dummy), pushes the boolean result, returns 1 (ok). On a bad
;   operand count / NULLDUMMY violation returns 0 with interp_err set.
interp_checkmultisig:
    push  r12
    push  r13
    push  r14
    push  r15
    push  rbx
    sub   rsp, 64               ; locals: [rsp+24]=nKeys, [rsp+16]=nSigs, [rsp+8]=sp, [rsp+0]=remaining
    mov   qword [rsp+56], 0     ; [rsp+56] = NULLDUMMY violation seen; raised AFTER the signature loop (Core order, 2026-09-02)
                                 ; [rsp+32]=cur_src ptr, [rsp+40]=cur_src len, [rsp+48]=dst buf ptr
                                 ; (used only by the up-front scriptCode-strip loop below)
    mov   rax, [rbp-0x70]
    mov   qword [rax], 0

    ; r12 = script_state stays fixed. The stack layout (bottom..top) is:
    ;   ... dummy sig1..sigm m pub1..pubn n
    ; i.e. using stacktop(k) (1-based from top): k=1 is n, k=2..nkeys+1 are the
    ; pubkeys (pubn..pub1), k=nkeys+2 is m, k=nkeys+3..nkeys+nsigs+2 are the
    ; sigs (sigm..sig1), k=need+1 (=nkeys+nsigs+3) is the dummy.
    ; This mirrors the Core-differential bitcoin_verify.c EvalMultisig layout
    ; exactly (stacktop(nkeys+2)=m, stacktop(2+j)=keys top-first, etc).

    ; ---- helper to read stacktop(k): elem ptr = stack_elem_ptr(&sp, elems, sp-k).
    ;       We read [r12+0]=elems, [r12+8]=&sp. Local [rsp+0] caches the sp
    ;       VALUE so index arithmetic is stable across the operand reads. ----
    mov   rax, [r12+8]
    mov   [rsp+8], rax           ; sp value (cached)

    ; ---- 1. nKeys = CScriptNum(stacktop(1)), validate 0..20. Core's real
    ; check is `nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_MULTISIG`
    ; (interpreter.cpp) -- nKeys=0 (a degenerate 0-of-0 multisig, real
    ; historical mainnet usage e.g. as a P2SH redeem script that's a bare
    ; OP_CHECKMULTISIG run against three empty stack items) is explicitly
    ; VALID, not rejected. This used to reject anything below 1, which is
    ; wrong -- only a genuinely negative CScriptNum should fail here, same
    ; as the nSigs check just below already does correctly. ----
    mov   r15, [rsp+8]
    sub   r15, 1                 ; idx_from_bottom = sp - 1
    mov   rdi, r12
    add   rdi, 8
    mov   rsi, [r12+0]
    mov   rdx, r15
    call  stack_elem_ptr
    mov   r15, rax               ; elem ptr
    mov   r13d, [r15]            ; len
    lea   r14, [r15+ELEM_DATA_OFF]
    mov   rdi, r13
    mov   rsi, r14
    SNUM_MAX 4
    call  scriptnum_decode
    mov   rcx, [rbp-0xB0]     ; &snum_overflow: size or (under MINIMALDATA) encoding -> SCRIPT_ERR_SCRIPTNUM
    mov   rcx, [rcx]
    test  rcx, rcx
    jnz   .snum_fail
    mov   r15d, eax              ; nKeys
    test  eax, eax
    js    .err_pubcount
    cmp   r15d, 20
    jg    .err_pubcount
    mov   [rsp+24], r15d         ; locals: nKeys

    ; ---- Core: nOpCount += nKeysCount, THEN re-check MAX_OPS_PER_SCRIPT
    ; (interpreter.cpp's OP_CHECKMULTISIG arm). The key count is charged to
    ; the opcode budget, not just the single opcode -- so ten 0-of-20
    ; multisigs are 200 keys + 10 opcodes = 210 and must be REJECTED even
    ; though only ten opcodes were executed.
    ;
    ; This was missing until 2026-08-26: the budget saw only the opcode, so
    ; such a script verified here while Core rejected it with
    ; SCRIPT_ERR_OP_COUNT -- a false accept in the chain-split direction,
    ; found by validation/synth_corpus_diff.py's resource sweep. No key
    ; material is needed to build one (0-of-N checks no signatures), so it
    ; was trivially reachable in a bare or P2WSH script.
    ;
    ; rbp is script_eval's frame (see this file's header note on the shared
    ; frame), so [rbp-0x28] is the same counter the main loop increments.
    ; Tapscript never reaches here -- CHECKMULTISIG is disabled there --
    ; so no sigversion gate is needed, matching Core's own arm.
    movsxd rax, r15d
    add   [rbp-0x28], rax
    mov   rax, [rbp-0x28]
    cmp   rax, MAX_OPS_PER_SCRIPT
    ja    .err_opcount

    ; stacktop(nkeys+2) = m
    mov   eax, [rsp+24]
    add   eax, 2
    mov   rcx, [rsp+8]
    sub   rcx, rax               ; idx = sp - (nkeys+2)
    mov   rdi, r12
    add   rdi, 8
    mov   rsi, [r12+0]
    mov   rdx, rcx
    call  stack_elem_ptr
    mov   r15, rax
    mov   r13d, [r15]
    lea   r14, [r15+ELEM_DATA_OFF]
    mov   rdi, r13
    mov   rsi, r14
    SNUM_MAX 4
    call  scriptnum_decode
    mov   rcx, [rbp-0xB0]     ; &snum_overflow: size or (under MINIMALDATA) encoding -> SCRIPT_ERR_SCRIPTNUM
    mov   rcx, [rcx]
    test  rcx, rcx
    jnz   .snum_fail
    mov   r14d, eax              ; nSigs
    test  eax, eax
    js    .err_sigcount
    cmp   eax, [rsp+24]
    jg    .err_sigcount
    mov   [rsp+16], r14d         ; locals: nSigs

    ; need = nKeys + nSigs + 2 ;  dummy at stacktop(need+1)
    mov   eax, [rsp+24]
    add   eax, [rsp+16]
    add   eax, 2                 ; need
    ; ---- stack depth: need+1 elements (operands + the dummy) must exist.
    ; Without this, too few operands fell through to "multisig is false"
    ; (EVAL_FALSE) where Core reports INVALID_STACK_OPERATION.
    mov   ecx, eax               ; need
    inc   ecx                    ; need+1
    mov   edx, [rsp+8]           ; sp
    cmp   edx, ecx
    jl    .err_stackop

    ; ---- BIP147 NULLDUMMY. This MUST live here, not in the caller.
    ; The comment this replaces claimed the caller enforces it, but this
    ; function pops the dummy as part of its operand cleanup, so by the time
    ; script_eval returns there is nothing left to inspect. Core checks it
    ; inside EvalScript for the same reason. Leaving it to the caller meant
    ; the interpreter ACCEPTED a spend Core rejects.
    mov   rax, [r12+56]          ; flags
    test  rax, SCRIPT_VERIFY_NULLDUMMY
    jz    .cms_dummy_ok
    mov   ecx, [rsp+24]          ; nKeys
    add   ecx, [rsp+16]          ; + nSigs
    add   ecx, 3                 ; = need+1
    mov   edx, [rsp+8]           ; sp
    sub   edx, ecx               ; idx of the dummy, from the bottom
    movsxd rdx, edx
    mov   rdi, r12
    add   rdi, 8
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    mov   ecx, [rax]             ; dummy length
    test  ecx, ecx
    jz    .cms_dummy_ok
    mov   qword [rsp+56], 1      ; remember; a SIG_DER/PUBKEYTYPE from the loop takes precedence, as in Core
.cms_dummy_ok:
    ; recompute need: the checks above clobbered eax.
    mov   eax, [rsp+24]
    add   eax, [rsp+16]
    add   eax, 2

    ; ---- 2. collect keys[]/sigs[] pointers into scratch (live-stack refs) --
    ; keys[j] = stacktop(2+j), j=0..nkeys-1   (pubn down to pub1)
    ; sigs[j] = stacktop(nkeys+3+j), j=0..nsigs-1  (sigm down to sig1)
    ; Store the ELEMENT POINTERS (not copies); the live stack is not modified
    ; until the final pop, exactly as bitcoin_verify.c holds Ref* operands.
    xor   r13d, r13d            ; j = 0
.collect_keys:
    mov   eax, [rsp+24]
    cmp   r13d, eax
    jge   .collect_keys_done
    ; idx = sp - (2 + j)
    mov   r15d, r13d
    add   r15d, 2
    mov   eax, [rsp+8]
    sub   eax, r15d
    mov   rdi, r12
    add   rdi, 8
    mov   rsi, [r12+0]
    mov   edx, eax
    call  stack_elem_ptr
    ; store pointer to cms_keyrefs[j]
    mov   ecx, 8
    imul  rcx, r13
    TLS_ADDR rdx, cms_keyrefs
    add   rdx, rcx
    mov   [rdx], rax
    inc   r13d
    jmp   .collect_keys
.collect_keys_done:
    xor   r13d, r13d            ; j = 0
.collect_sigs:
    mov   eax, [rsp+16]
    cmp   r13d, eax
    jge   .collect_sigs_done
    ; idx = sp - (nkeys + 3 + j)
    mov   eax, [rsp+24]
    add   eax, 3
    add   eax, r13d
    mov   r15d, [rsp+8]
    sub   r15d, eax
    mov   rdi, r12
    add   rdi, 8
    mov   rsi, [r12+0]
    mov   edx, r15d
    call  stack_elem_ptr
    mov   ecx, 8
    imul  rcx, r13
    TLS_ADDR rdx, cms_sigrefs
    add   rdx, rcx
    mov   [rdx], rax
    inc   r13d
    jmp   .collect_sigs
.collect_sigs_done:

    ; ---- 2b. Core's real CHECKMULTISIG scriptCode (bitcoin_verify.c /
    ; Core's interpreter.cpp): EVERY signature currently on the stack (all
    ; nSigsCount of them) is stripped from scriptCode ONCE, up front, before
    ; any signature check runs -- not just "the signature under test in the
    ; current loop iteration", which is what a naive per-checksig-call
    ; FindAndDelete (correct for plain OP_CHECKSIG, which only ever has one
    ; signature) would do. A signature's bytes can appear inside scriptCode
    ; for reasons unrelated to being the one currently checked -- e.g. a
    ; multisig redeem script that reuses one signature's own bytes as a
    ; deliberately-unparseable decoy pubkey slot (a legitimate, if unusual,
    ; historical construction) -- so stripping only the current signature
    ; produces the WRONG scriptCode, and thus the wrong sighash, for every
    ; OTHER signature check that doesn't happen to match its own occurrence.
    ; Confirmed via a real mainnet block (height ~290328) whose 2-of-3
    ; CHECKMULTISIG spend embeds sig1's bytes as one "pubkey", and was
    ; rejected (EVAL_FALSE on sig2) until this up-front stripping was added.
    mov   rax, [rbp-0x20]
    mov   [rsp+32], rax          ; cur_src ptr
    mov   rax, [rbp-0x18]
    sub   rax, [rbp-0x20]
    mov   [rsp+40], rax          ; cur_src len
    ; FindAndDelete of the signatures from scriptCode is a BASE-sigversion
    ; rule ONLY. Core applies it inside OP_CHECKMULTISIG solely under
    ; SigVersion::BASE (interpreter.cpp: `if (sigversion == SigVersion::BASE)
    ; { ... FindAndDelete ... }`); for SigVersion::WITNESS_V0 (BIP143) and
    ; TAPSCRIPT the scriptCode is the witnessScript verbatim. Stripping under
    ; witness produces the wrong sighash and rejects every valid witness
    ; multisig (found 2026-08-22 on real chain: P2SH-P2WSH 2-of-3 at height
    ; 481945, and every native/wrapped m-of-n after). Skip the strip loop for
    ; any non-BASE sigversion; the checksig callback for witness (see
    ; bitcoin_scriptverify.c's sv_checksig_witness_v0) also omits FindAndDelete.
    mov   eax, dword [r12+48]     ; sigversion
    test  eax, eax
    jnz   .cms_strip_done         ; != BASE -> no FindAndDelete
    xor   r13d, r13d             ; j = 0
.cms_strip_loop:
    mov   eax, [rsp+16]          ; nSigs
    cmp   r13d, eax
    jge   .cms_strip_done
    mov   eax, r13d
    mov   rcx, 8
    imul  rcx, rax
    TLS_ADDR r14, cms_sigrefs
    add   r14, rcx
    mov   r14, [r14]             ; sigs[j] elem ptr
    mov   ecx, [r14]             ; siglen
    lea   rdx, [r14+ELEM_DATA_OFF]
    TLS_ADDR rdi, cms_needle
    mov   rsi, 600
    call  script_push_encode     ; rdi=dst rsi=dstcap rdx=data rcx=datalen -> rax=outlen
    mov   r15, rax               ; needlelen
    test  r13d, 1
    jnz   .cms_strip_dst1
    TLS_ADDR rdi, cms_scstrip0
    jmp   .cms_strip_call
.cms_strip_dst1:
    TLS_ADDR rdi, cms_scstrip1
.cms_strip_call:
    mov   [rsp+48], rdi          ; save dst ptr (becomes next src)
    mov   rsi, 10008
    mov   rdx, [rsp+32]          ; src
    mov   rcx, [rsp+40]          ; srclen
    TLS_ADDR r8, cms_needle
    mov   r9, r15                ; needlelen
    call  script_find_and_delete ; rdi dst rsi dstcap rdx src rcx srclen r8 needle r9 needlelen -> rax outlen
    cmp   rax, [rsp+40]          ; shorter than the source = the signature WAS in the scriptCode
    jge   .cms_strip_nofind
    mov   rcx, [r12+56]
    test  rcx, SCRIPT_VERIFY_CONST_SCRIPTCODE
    jnz   .err_findanddelete     ; Core: SIG_FINDANDDELETE, raised while stripping, before the loop
.cms_strip_nofind:
    mov   rdi, [rsp+48]
    mov   [rsp+32], rdi
    mov   [rsp+40], rax
    inc   r13d
    jmp   .cms_strip_loop
.cms_strip_done:
    TLS_ADDR r10, interp_slice
    mov   rax, [rsp+32]
    mov   [r10], rax
    mov   rax, [rsp+40]
    mov   [r10+8], rax

    ; ---- 3. Core matching loop (bitcoin_verify.c check_multisig) ----
    ;   isig->r13d, ikey->r15d, remaining->[rsp+0].
    ;   We replicate: while(remaining>0 && ikey<nkeys):
    ;     ok=check(sigs[isig],keys[ikey]); if ok {isig++; remaining--}
    ;     ikey++; if(remaining > (nkeys-ikey)) -> fail.
    xor   r13d, r13d             ; isig
    xor   r15d, r15d             ; ikey
    mov   eax, [rsp+16]          ; orig nSigs
    mov   [rsp+0], eax           ; remaining
    ; pop count = need+1 = nkeys+nsigs+3, computed once in .cms_finish (locals
    ; nKeys/nSigs are never overwritten, so no need to pre-store it).
.cms_loop:
    mov   eax, [rsp+0]           ; remaining
    test  eax, eax
    jle   .cms_end               ; remaining<=0 -> done (success)
    mov   eax, [rsp+24]          ; nkeys
    cmp   r15d, eax
    jge   .cms_end               ; ikey>=nkeys -> done
    ; load vSig = sigs[isig], vPub = keys[ikey]
    mov   eax, r13d
    mov   rcx, 8
    imul  rcx, rax
    TLS_ADDR rbx, cms_sigrefs
    mov   rbx, [rbx+rcx]         ; vSig elem ptr
    mov   eax, r15d
    mov   rcx, 8
    imul  rcx, rax
    TLS_ADDR r14, cms_keyrefs
    mov   r14, [r14+rcx]         ; vPub elem ptr
    ; ---- BIP66/DERSIG. Core checks the encoding of the signature CURRENTLY
    ; under consideration inside this same loop (interpreter.cpp's
    ; CHECKMULTISIG arm: `if (!CheckSignatureEncoding(vchSig, flags, serror)
    ; || !CheckPubKeyEncoding(...)) return false;`), immediately before the
    ; ECDSA check and as a hard script error. Signatures the loop never
    ; reaches -- because it ran out of keys first -- are never checked, in
    ; Core and here alike, which is why this belongs here and not in the
    ; up-front collect loop.
    mov   rdi, rbx               ; vSig elem ptr
    call  interp_sig_encoding_ok
    cmp   rax, 1
    je    .cms_enc_ok
    cmp   rax, -1
    je    .err_highs
    cmp   rax, -2
    je    .err_hashtype
    jmp   .err_sigder
.cms_enc_ok:
    mov   edi, [r14]             ; publen
    lea   rsi, [r14+ELEM_DATA_OFF]
    call  interp_pubkey_encoding_ok
    test  rax, rax
    jz    .err_pubkeytype
    ; scriptCode (interp_slice) was already built once, with ALL on-stack
    ; signatures stripped, in the .cms_strip_loop above -- do not rebuild it
    ; per iteration (see the comment there for why per-call stripping of
    ; only "the current signature" is wrong for CHECKMULTISIG).
    ; call checksig_fn(ctx, sig, siglen, pub, publen, &slice)
    mov   rdi, [r12+88]
    mov   eax, [rbx]
    mov   rdx, rax               ; siglen
    lea   rsi, [rbx+ELEM_DATA_OFF]
    mov   eax, [r14]
    mov   r8,  rax               ; publen
    lea   rcx, [r14+ELEM_DATA_OFF]
    TLS_ADDR r9, interp_slice
    mov   rax, [r12+96]
    test  rax, rax
    jz    .cms_key_fail
    call  rax
    test  rax, rax
    jz    .cms_key_fail
    ; ok -> isig++, remaining--
    inc   r13d
    mov   eax, [rsp+0]
    dec   eax
    mov   [rsp+0], eax
.cms_key_fail:
    ; ikey++, then if remaining > (nkeys-ikey) -> fSuccess=0 (fail)
    inc   r15d
    mov   eax, [rsp+24]
    sub   eax, r15d              ; nkeys - ikey
    mov   ecx, [rsp+0]           ; remaining
    cmp   ecx, eax
    jg    .cms_fail              ; remaining > keys-left -> cannot satisfy -> fail
    jmp   .cms_loop
.cms_end:
    cmp   qword [rsp+56], 0      ; deferred BIP147 NULLDUMMY (see the check above the loop)
    jne   .err_nulldummy
    ; loop ended; success iff remaining==0 (all sigs matched)
    mov   eax, [rsp+0]
    test  eax, eax
    jne   .cms_fail
    ; ---- success ----
    mov   edx, 1
    jmp   .cms_finish
.cms_fail:
    ; BIP146 NULLFAIL first (Core's order: the sig loop, then NULLFAIL over the
    ; still-present signatures, then the pops, then NULLDUMMY on the dummy).
    mov   rax, [r12+56]
    test  rax, SCRIPT_VERIFY_NULLFAIL
    jz    .cms_nullfail_done
    xor   ebx, ebx               ; j
.cms_nullfail_loop:
    cmp   ebx, [rsp+16]          ; nSigs
    jge   .cms_nullfail_done
    mov   ecx, [rsp+24]          ; nKeys
    add   ecx, 3
    add   ecx, ebx               ; k = nKeys+3+j (1-based from top)
    mov   edx, [rsp+8]           ; sp
    sub   edx, ecx               ; idx from the bottom
    movsxd rdx, edx
    mov   rdi, r12
    add   rdi, 8
    mov   rsi, [r12+0]
    call  stack_elem_ptr
    cmp   dword [rax], 0
    jne   .err_nullfail
    inc   ebx
    jmp   .cms_nullfail_loop
.cms_nullfail_done:
    cmp   qword [rsp+56], 0      ; deferred BIP147 NULLDUMMY (see the check above the loop)
    jne   .err_nulldummy
    mov   edx, 0
.cms_finish:
    ; pop total = need+1 = nkeys+nsigs+3 elements (locals nKeys/nSigs intact)
    mov   ecx, [rsp+24]
    add   ecx, [rsp+16]
    add   ecx, 3
    ; save bool (edx) across the pops.
    push  rdx                     ; stash bool
    push  rdx                     ; 2nd push = padding: an odd number of pushes
                                  ; here would flip RSP off 16-byte alignment
                                  ; for the `call stack_pop` below (same
                                  ; correction b18114b made to node_serve_loop's
                                  ; four push/call/pop sites).
.pop_all:
    test  ecx, ecx
    jz    .pop_all_done
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  stack_pop
    dec   ecx
    jmp   .pop_all
.pop_all_done:
    pop   rdx                     ; discard the padding push
    pop   rdx                     ; restore bool
    ; push the result bool
    lea   rdi, [r12+8]
    mov   rsi, [r12+0]
    call  interp_push_bool
    xor   eax, eax
    inc   eax                     ; return 1 (ok)
    add   rsp, 64
    pop   rbx
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret

.err_stackop:
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_INVALID_STACK_OPERATION
    jmp   .err_exit
.err_nulldummy:
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_SIG_NULLDUMMY
    jmp   .err_exit
.err_opcount:
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_OP_COUNT
    jmp   .err_exit
.err_pubcount:
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_PUBKEY_COUNT
    jmp   .err_exit
.err_sigcount:
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_SIG_COUNT
    jmp   .err_exit
.err_sigder:
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_SIG_DER
    jmp   .err_exit
.snum_fail:                          ; 2026-09-02: a count that overflows 4 bytes or is non-minimal under MINIMALDATA
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_SCRIPTNUM
    jmp   .err_exit
.err_pubkeytype:                     ; 2026-09-02: STRICTENC pubkey encoding (Core's CheckPubKeyEncoding per pair)
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_PUBKEYTYPE
    jmp   .err_exit
.err_highs:
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_SIG_HIGH_S
    jmp   .err_exit
.err_hashtype:
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_SIG_HASHTYPE
    jmp   .err_exit
.err_nullfail:
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_SIG_NULLFAIL
    jmp   .err_exit
.err_findanddelete:
    mov   rax, [rbp-0x70]
    mov   qword [rax], SCRIPT_ERR_SIG_FINDANDDELETE
    jmp   .err_exit
.err_exit:
    xor   eax, eax
    add   rsp, 64
    pop   rbx
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret

section .tbss alloc noexec nowrite tls align=16
global cms_keyrefs
global cms_sigrefs
global cms_scstrip0
global cms_scstrip1
global cms_needle
cms_keyrefs: resq 20
cms_sigrefs: resq 20
; MAX_SCRIPT_SIZE (consensus) is 10000; +8 slack. Ping-ponged by
; .cms_strip_loop above so each script_find_and_delete call's dst never
; aliases its own src.
cms_scstrip0: resb 10008
cms_scstrip1: resb 10008
cms_needle: resb 600


; SECURITY (audit 2026-08-29 finding 9): without this note the linker
; conservatively marks the whole program's stack EXECUTABLE (PT_GNU_STACK
; RWE). Nothing here needs a runnable stack; a single object missing the
; note is enough to turn it on for the entire binary, which is why every
; .asm file carries it.
section .note.GNU-stack noalloc noexec nowrite progbits
