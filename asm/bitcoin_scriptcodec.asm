; ============================================================================
; bitcoin_scriptcodec.asm -- support layer for the Bitcoin script interpreter.
;
; Element stack engine, ScriptNum encode/decode, CastToBool, CheckMinimalPush,
; GetOp instruction reader, and the vfExec condition-stack helpers. These are
; the primitives the interpreter dispatch (bitcoin_interp.asm) is built on,
; mirroring Bitcoin Core's CScriptNum / GetScriptOp / CastToBool /
; CheckMinimalPush semantics exactly.
;
; Record of one stack element (ELEM_SIZE = 528 bytes, 8-aligned):
;     +0  uint32 len   ( <= 520 )
;     +4  uint8  data[520]
;
; SysV AMD64 ABI; rbx,r12-r15 preserved. Helpers don't call subroutines.
; ============================================================================
    default rel

%define ELEM_SIZE 528
%define ELEM_LEN_OFF 0
%define ELEM_DATA_OFF 4
%define MAX_STACK_SIZE 1000
%define MAX_SCRIPT_ELEMENT_SIZE 520

; ---- THREAD-LOCAL scratch (2026-08-19, parallel per-input verification) --
; Was plain .bss (one shared instance for the whole process) -- unsafe once
; these helpers (stack_swap_two, scriptnum_decode/serialize, the vfexec_*
; condition-stack functions) can run concurrently from multiple worker
; threads. Found the hard way: a dedicated multi-thread stress test
; (tests/test_scriptverify_thread_stress.c) caught intermittent SIG_COUNT/
; INVALID_STACK_OPERATION errors on genuinely-valid CHECKMULTISIG spends --
; this file's globals, not bitcoin_interp.asm's/bitcoin_sighash.asm's (which
; were converted first and are NOT the source of that race). See those two
; files' matching header notes for the full TLS_ADDR/.tbss rationale.
    section .tbss alloc noexec nowrite tls align=16
global elem_tmp0, elem_tmp1, elem_tmp2, elem_tmp3
elem_tmp0:  resb ELEM_SIZE
elem_tmp1:  resb ELEM_SIZE
elem_tmp2:  resb ELEM_SIZE
elem_tmp3:  resb ELEM_SIZE
scriptnum_buf: resb 16
global scriptnum_buf
global snum_overflow
snum_overflow: resq 1

; vfExec condition stack.
; CORE HAS NO NESTING LIMIT UNDER TAPSCRIPT: there is no opcode limit and no
; script-size limit for a tapscript leaf, so OP_IF nesting can run to one
; conditional per script byte. A 1 MiB leaf therefore needs 1,048,576 slots;
; the old 1024-byte buffer overflowed into vfexec_sp itself on the 1025th
; nested OP_IF -- an attacker-controlled out-of-bounds write from P2P input
; AND a false accept of an unbalanced script (audit SCR-2, 2026-09-03). The
; buffer now covers 5 MiB of script bytes (a leaf cannot exceed the 4 MiB
; block witness limit, so no validly-framed script can reach the cap) and
; vfexec_push enforces it.
alignb 16                 ; alignb, not align: this is .tbss, padding bytes cannot be "initialized" (nasm -w+other)
VFEXEC_MAX equ 5*1024*1024
vfexec:     resb VFEXEC_MAX
vfexec_sp:  resq 1
; ---- IR-6 (INTERP_REVIEW_2026-09-05): position -> slot handle table -------
; stack_erase_index shifted whole 524-byte records to close a hole, so a
; tapscript of `<998> OP_ROLL` repeated cost O(rolls x records) in bytes
; moved (~445 GB, ~10 s, for a 3.4 MB leaf -- a denial of service by a
; consensus-VALID block). Core moves a 24-byte vector header instead.
;
; Records now stay put and POSITIONS move: hnd_tab[p] is the slot holding the
; element at position p, so a roll rotates 4-byte handles. hnd_tab is always a
; permutation of [0, MAX_STACK_SIZE), which is what lets pop/push reuse slots
; without a free list: pop leaves its slot at hnd_tab[sp], push takes it back.
;
; The table belongs to ONE arena, hnd_base -- the MAIN stack, the only one
; that rolls. Any other arena (the alt stack, and every caller outside
; script_eval) matches nothing, falls through to identity, and behaves exactly
; as it did before this change.
;
; script_eval registers the table on entry and, ONLY IF hnd_dirty, applies the
; permutation to the records on exit, so every reader outside still finds
; element p at elems + p*ELEM_SIZE with its data inline -- the ABI that
; bitcoin_scriptverify.c's sv_rec/sv_len/sv_dat and five test harnesses use.
; A script that never rolls leaves hnd_dirty clear and pays nothing, which is
; what keeps IR-7's removal of the per-input arena traffic intact.
global hnd_base, hnd_dirty, hnd_tab   ; TLS_ADDR's gottpoff needs them global
hnd_base:   resq 1
hnd_dirty:  resq 1
hnd_tab:    resd MAX_STACK_SIZE
; IR-4 (INTERP_REVIEW_2026-09-05): Core's ConditionStack keeps the position
; of the FIRST false entry (or NO_FALSE), so "is every entry true" is one
; compare. vfexec_all_true used to scan the whole buffer on every opcode --
; O(depth) per opcode, O(N^2) per script, and tapscript has no opcode or
; script-size cap: a valid ~4 MB leaf of nested OP_IF took tens of minutes.
; The byte buffer stays (memory-safety backstop, SCR-2 tests); this caches.
vfexec_ff:  resq 1        ; index of first false, or VFEXEC_NO_FALSE
global vfexec, vfexec_sp, vfexec_ff
VFEXEC_NO_FALSE equ -1

    section .text

; TLS_ADDR dst, sym -- dst = this thread's address of `sym` (ELF x86-64
; Initial-Exec model: a GOT-style offset loaded from a fixed, link-time
; location, added to the thread pointer at %fs:0). Clobbers only `dst`.
; Mirrors bitcoin_interp.asm's identical macro (kept per-file since NASM
; macros aren't visible across separately-assembled files).
%macro TLS_ADDR 2
    mov   %1, [rel %2 wrt ..gottpoff]
    add   %1, qword [fs:0]
%endmacro

; ---- cross-file TLS accessors --------------------------------------------
; bitcoin_interp.asm needs elem_tmp0..3 and snum_overflow too, but NASM's
; `extern sym` doesn't carry a TLS type across object files the way a local
; `wrt ..gottpoff` reference does within ONE file -- the linker rejects it
; ("TLS definition ... mismatches non-TLS reference") because the
; REFERENCING file's undefined symbol comes out untyped (STT_NOTYPE) with
; no NASM syntax found to mark it otherwise. Confirmed empirically with a
; minimal 2-file probe before writing these. A plain function call sidesteps
; the whole problem -- completely ordinary cross-file linkage, no special
; relocation type involved at the call site at all.
global elem_tmp0_addr
elem_tmp0_addr:
    TLS_ADDR rax, elem_tmp0
    ret
global elem_tmp1_addr
elem_tmp1_addr:
    TLS_ADDR rax, elem_tmp1
    ret
global elem_tmp2_addr
elem_tmp2_addr:
    TLS_ADDR rax, elem_tmp2
    ret
global elem_tmp3_addr
elem_tmp3_addr:
    TLS_ADDR rax, elem_tmp3
    ret
global snum_overflow_addr
snum_overflow_addr:
    TLS_ADDR rax, snum_overflow
    ret

; ============================================================================
; stack_depth(&sp) -> rax = *sp
; ============================================================================
; ---- IR-6 handle layer ---------------------------------------------------
; hnd_addr(rsi=elems, rdx=position) -> rax = that element's record address.
; Falls back to elems + position*ELEM_SIZE when this arena has no table.
; Clobbers rax only.
hnd_addr:
    push  rcx
    push  rdx
    TLS_ADDR rcx, hnd_base
    cmp   rsi, [rcx]
    jne   .direct
    TLS_ADDR rcx, hnd_tab
    mov   ecx, [rcx + rdx*4]
    mov   rdx, rcx
.direct:
    imul  rdx, ELEM_SIZE
    lea   rax, [rsi + rdx]
    pop   rdx
    pop   rcx
    ret

; hnd_of(rsi=elems) -> rax = table address, or 0 when this arena has none.
hnd_of:
    push  rcx
    TLS_ADDR rcx, hnd_base
    cmp   rsi, [rcx]
    jne   .none
    TLS_ADDR rax, hnd_tab
    pop   rcx
    ret
.none:
    xor   eax, eax
    pop   rcx
    ret

; hnd_begin(rdi=main_elems) -> rax = 1 if this call registered the table (the
; caller must pair it with hnd_end), 0 if a table was already registered --
; a nested script_eval, which then simply runs on identity like the old code.
global hnd_begin
hnd_begin:
    push  rcx
    push  rdx
    TLS_ADDR rcx, hnd_base
    cmp   qword [rcx], 0
    jne   .busy
    mov   [rcx], rdi
    TLS_ADDR rcx, hnd_dirty
    mov   qword [rcx], 0
    TLS_ADDR rcx, hnd_tab
    xor   edx, edx
.init:
    mov   [rcx + rdx*4], edx
    inc   rdx
    cmp   rdx, MAX_STACK_SIZE
    jb    .init
    mov   eax, 1
    pop   rdx
    pop   rcx
    ret
.busy:
    xor   eax, eax
    pop   rdx
    pop   rcx
    ret

; hnd_end(rdi=&sp, rsi=main_elems) -- put the records back in position order
; (only if anything rolled) and unregister. Cycle-following: every record is
; moved at most once, at most sp swaps, and only for a script that rolled.
global hnd_end
hnd_end:
    push  rbx
    push  r12
    push  r13
    push  r14
    push  r15
    TLS_ADDR rax, hnd_dirty
    cmp   qword [rax], 0
    je    .clear
    mov   r12, [rdi]              ; sp
    mov   r13, rsi                ; elems
    TLS_ADDR r14, hnd_tab
    xor   r15, r15                ; i
    ; Apply the permutation in place: slot p must end up holding the record
    ; for position p, and hnd_tab[p] says where that record is now. Walk each
    ; cycle once, carrying one record in elem_tmp0, and mark visited entries
    ; by setting hnd_tab[j] = j -- so every record moves at most once.
    ;
    ; (The first draft swapped hnd_tab[p] with hnd_tab[q] alongside the record
    ; swap. That is wrong: exchanging the CONTENTS of slots p and q has to
    ; update whichever entries HOLD the values p and q, not the entries AT
    ; indices p and q. It produced the mirrored permutation -- the IR-6
    ; vectors caught it, which is what they were written for.)
.outer:
    cmp   r15, r12
    jae   .clear
    mov   eax, [r14 + r15*4]
    cmp   rax, r15
    je    .nexti                  ; already home
    mov   rax, r15
    imul  rax, ELEM_SIZE
    lea   rsi, [r13 + rax]
    TLS_ADDR rdi, elem_tmp0
    call  elem_move               ; carry = rec[i]
    mov   rbx, r15                ; j = i
.cyc:
    mov   eax, [r14 + rbx*4]      ; k = hnd_tab[j]
    mov   [r14 + rbx*4], ebx      ; hnd_tab[j] = j  (visited)
    cmp   rax, r15
    je    .cycend
    mov   rcx, rax                ; k survives elem_move (it preserves rcx)
    imul  rax, ELEM_SIZE
    lea   rsi, [r13 + rax]        ; &rec[k]
    mov   rax, rbx
    imul  rax, ELEM_SIZE
    lea   rdi, [r13 + rax]        ; &rec[j]
    call  elem_move               ; rec[j] = rec[k]
    mov   rbx, rcx                ; j = k
    jmp   .cyc
.cycend:
    mov   rax, rbx
    imul  rax, ELEM_SIZE
    lea   rdi, [r13 + rax]
    TLS_ADDR rsi, elem_tmp0
    call  elem_move               ; rec[j] = carry
.nexti:
    inc   r15
    jmp   .outer
.clear:
    TLS_ADDR rax, hnd_base
    mov   qword [rax], 0
    TLS_ADDR rax, hnd_dirty
    mov   qword [rax], 0
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    ret

global stack_depth
stack_depth:
    mov   rax, [rdi]
    ret

; ============================================================================
; stack_top_ptr(&sp, elems) -> rax = ptr to top element record
; ============================================================================
global stack_top_ptr
stack_top_ptr:
    push  rdx                  ; IR-6: position -> slot
    mov   rdx, [rdi]
    sub   rdx, 1
    call  hnd_addr
    pop   rdx
    ret

; ============================================================================
; stack_second_ptr(&sp, elems) -> ptr to element at index sp-2
; ============================================================================
global stack_second_ptr
stack_second_ptr:
    push  rdx                  ; IR-6: position -> slot
    mov   rdx, [rdi]
    sub   rdx, 2
    call  hnd_addr
    pop   rdx
    ret

; ============================================================================
; stack_third_ptr(&sp, elems) -> ptr to element at index sp-3
; ============================================================================
global stack_third_ptr
stack_third_ptr:
    push  rdx                  ; IR-6: position -> slot
    mov   rdx, [rdi]
    sub   rdx, 3
    call  hnd_addr
    pop   rdx
    ret

; ============================================================================
; stack_elem_ptr(&sp, elems, idx_from_bottom) -> rax = ptr
;   idx 0 = bottom-most element. No bounds check.
; ============================================================================
global stack_elem_ptr
stack_elem_ptr:
    sub   rsp, 8               ; IR-6
    call  hnd_addr
    add   rsp, 8
    ret

; ============================================================================
; stack_pop(&sp, elems)  (pops top; caller ensures sp>=1)
; ============================================================================
global stack_pop
stack_pop:
    mov   rax, [rdi]
    test  rax, rax
    jz    .empty
    sub   qword [rdi], 1
.empty:
    ret

; ============================================================================
; stack_push(&sp, elems, data_ptr, len) -> rax = 1 ok / 0 stack full
;   Copies len bytes from data_ptr into a fresh top element.
; ============================================================================
global stack_push
stack_push:
    push  r12
    push  r13
    push  r14
    push  r15
    mov   r12, rdi            ; &sp
    mov   r13, rsi            ; elems
    mov   r14, rdx            ; data
    mov   r15, rcx            ; len
    mov   rax, [r12]
    cmp   rax, MAX_STACK_SIZE
    jae   .fail
    mov   rdx, rax            ; IR-6: the record for position sp
    mov   rsi, r13
    sub   rsp, 8
    call  hnd_addr
    add   rsp, 8
    mov   [rax], r15d         ; len
    lea   rdi, [rax+ELEM_DATA_OFF]
    mov   rsi, r14
    mov   rcx, r15            ; rep movsb with rcx==0 is a no-op
    rep   movsb
    inc   qword [r12]
    mov   eax, 1
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret
.fail:
    xor   eax, eax
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret

; ============================================================================
; stack_push_copy(&sp, elems, src_rec) -> rax = 1 ok / 0 full
;   Pushes a copy of the element record at src_rec.
; ============================================================================
global stack_push_copy
stack_push_copy:
    push  r12
    push  r13
    push  r14
    push  r15
    mov   r12, rdi
    mov   r13, rsi
    mov   r15, rdx            ; src record (already an address)
    mov   rax, [r12]
    cmp   rax, MAX_STACK_SIZE
    jae   .fail
    mov   rdx, rax            ; IR-6
    mov   rsi, r13
    sub   rsp, 8
    call  hnd_addr
    add   rsp, 8
    mov   r14d, [r15]
    mov   [rax], r14d
    lea   rdi, [rax+ELEM_DATA_OFF]
    lea   rsi, [r15+ELEM_DATA_OFF]
    mov   rcx, r14
    rep movsb
    inc   qword [r12]
    mov   eax, 1
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret
.fail:
    xor   eax, eax
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret

; ============================================================================
; elem_move(dst_rec, src_rec) -- full record copy (*dst = *src)
; ============================================================================
global elem_move
elem_move:
    push  rcx
    mov   eax, [rsi]
    mov   [rdi], eax
    mov   ecx, eax
    add   rdi, ELEM_DATA_OFF
    add   rsi, ELEM_DATA_OFF
    rep movsb
    pop   rcx
    ret

; ============================================================================
; stack_swap_two(&sp, elems) -- swap the top two elements (full record swap)
; ============================================================================
global stack_swap_two
stack_swap_two:
    push  r12
    push  r13
    push  r14
    push  r15
    sub   rsp, 24              ; [rsp+0]=elem_tmp0 addr [rsp+8]=elem_tmp1 addr
                                ; 24, not 16: entry RSP == 8 mod16 and the four
                                ; pushes above leave it at 8 mod16, so the
                                ; reservation must be 8 mod16 to put RSP at
                                ; 0 mod16 for the `call elem_move`s below.
                                ; (The old comment called 16 "alignment-neutral,
                                ; preserves whatever call-site alignment already
                                ; existed" -- that is precisely the incident-#18
                                ; mistake: preserving an 8-mod-16 RSP is not
                                ; neutral, it is a SysV ABI violation. The two
                                ; locals sit at the LOW end of the frame, so
                                ; growing it moves neither operand.)
    mov   r12, rdi
    mov   r13, rsi
    ; IR-6: with a handle table, swapping two POSITIONS is swapping two
    ; 4-byte handles; the records do not move.
    mov   rsi, r13
    call  hnd_of
    test  rax, rax
    jz    .records
    mov   rcx, [r12]
    mov   edx, [rax + rcx*4 - 4]      ; handles[sp-1]
    mov   r8d, [rax + rcx*4 - 8]      ; handles[sp-2]
    mov   [rax + rcx*4 - 4], r8d
    mov   [rax + rcx*4 - 8], edx
    TLS_ADDR rax, hnd_dirty
    mov   qword [rax], 1
    add   rsp, 24
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret
.records:
    mov   rsi, r13
    TLS_ADDR rax, elem_tmp0
    mov   [rsp+0], rax
    TLS_ADDR rax, elem_tmp1
    mov   [rsp+8], rax
    ; A = top (sp-1), B = second (sp-2)
    mov   rax, [r12]
    sub   rax, 1
    imul  rax, ELEM_SIZE
    add   rax, r13
    mov   r14, rax            ; A
    mov   rax, [r12]
    sub   rax, 2
    imul  rax, ELEM_SIZE
    add   rax, r13
    mov   r15, rax            ; B
    ; tmp0 = *A ; tmp1 = *B ; *A = tmp1 ; *B = tmp0
    mov   rdi, [rsp+0]
    mov   rsi, r14
    call  elem_move
    mov   rdi, [rsp+8]
    mov   rsi, r15
    call  elem_move
    mov   rdi, r14
    mov   rsi, [rsp+8]
    call  elem_move
    mov   rdi, r15
    mov   rsi, [rsp+0]
    call  elem_move
    add   rsp, 24              ; must match the prologue reservation
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret

; ============================================================================
; scriptnum_decode(len, data, maxsize) -> rax = int64 value
;   Sets snum_overflow=1 if len > maxsize. Port of CScriptNum::set_vch.
; ============================================================================
global scriptnum_decode
scriptnum_decode:
    push  rbx
    push  r12
    push  r13
    push  r14
    TLS_ADDR rax, snum_overflow   ; rax free here (rdi/rsi/rdx are the incoming
                                   ; len/data/maxsize params, untouched by this)
    mov   qword [rax], 0
    ; rdx: low byte = maxsize; bit 8 = "require minimal encoding" (the caller
    ; sets it under SCRIPT_VERIFY_MINIMALDATA -- Core's fRequireMinimal). Both
    ; failures are reported through snum_overflow, i.e. SCRIPT_ERR_SCRIPTNUM,
    ; exactly Core's error for either. (2026-09-02, differential vs Core.)
    mov   rcx, rdx
    and   rdx, 0xff
    cmp   rdi, rdx
    jbe   .size_ok
    mov   qword [rax], 1
.size_ok:
    test  rcx, 0x100
    jz    .min_ok
    test  rdi, rdi
    jz    .min_ok
    movzx ecx, byte [rsi+rdi-1]
    test  cl, 0x7f
    jnz   .min_ok             ; top byte carries magnitude: minimal
    cmp   rdi, 1
    je    .min_bad            ; lone 0x00 / 0x80: negative or padded zero
    movzx ecx, byte [rsi+rdi-2]
    test  cl, 0x80
    jnz   .min_ok             ; the pad byte is needed for the sign
.min_bad:
    mov   qword [rax], 1
.min_ok:
    mov   r12, rdi            ; len
    mov   r13, rsi            ; data
    mov   r14, 0              ; result
    mov   rbx, 0              ; i
    cmp   r12, 0
    je    .positive
.accum:
    cmp   rbx, r12
    jae   .sign_check
    movzx eax, byte [r13+rbx]
    mov   rcx, rbx
    shl   rcx, 3
    mov   rdx, rax
    shl   rdx, cl
    or    r14, rdx
    inc   rbx
    jmp   .accum
.sign_check:
    mov   rax, r12
    dec   rax
    movzx ecx, byte [r13+rax]
    test  cl, 0x80
    jz    .positive
    mov   rcx, r12
    dec   rcx
    shl   rcx, 3
    mov   rdx, 0x80
    shl   rdx, cl
    not   rdx
    mov   rax, r14
    and   rax, rdx
    neg   rax
    jmp   .done
.positive:
    mov   rax, r14
.done:
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    ret

; ============================================================================
; scriptnum_serialize(value) -> writes ScriptNum byte encoding into
;   scriptnum_buf; returns rax = pointer to bytes, rdx = length.
;   Port of CScriptNum::serialize.
;   NOTE: scriptnum_buf is a shared buffer; safe because callers copy out
;   before the next formatter use.
; ============================================================================
global scriptnum_serialize
scriptnum_serialize:
    push  rbx
    push  r12
    push  r13
    push  r14
    push  r15
    TLS_ADDR r15, scriptnum_buf
    ; rdi = value (int64)
    mov   r12, rdi            ; value
    test  r12, r12
    jnz   .nonzero
    ; value==0 -> empty vector
    mov   rax, r15
    xor   edx, edx
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    ret
.nonzero:
    mov   r13, 0              ; neg flag
    cmp   r12, 0
    jge   .pos
    mov   r13, 1
    neg   r12                 ; absvalue
.pos:
    mov   r14, 0              ; out index
.build:
    test  r12, r12
    jz    .build_done
    mov   rax, r12
    and   eax, 0xff
    mov   byte [r15+r14], al
    shr   r12, 8
    inc   r14
    jmp   .build
.build_done:
    ; result[r14-1] is the last byte
    lea   rdi, [r15+r14-1]
    movzx eax, byte [rdi]
    test  al, 0x80
    jz    .last_nonsign
    ; top byte & 0x80: push 0x80 (neg) or 0x00 (pos)
    mov   rdx, 0x80
    test  r13, r13
    jnz   .store_sign
    xor   edx, edx
.store_sign:
    mov   byte [r15+r14], dl
    inc   r14
    jmp   .out
.last_nonsign:
    test  r13, r13
    jz    .out
    ; negative with top byte < 0x80: OR in 0x80 to the last byte
    or    byte [rdi], 0x80
    jmp   .out
.out:
    mov   rax, r15
    mov   rdx, r14
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    pop   rbx
    ret

; ============================================================================
; cast_to_bool(len, data) -> rax = 0/1  (port of Core CastToBool)
;   False if all zero bytes, or if the last byte is 0x80 (negative zero).
; ============================================================================
global cast_to_bool
cast_to_bool:
    test  rdi, rdi
    jz    .false
    xor   ecx, ecx
.loop:
    cmp   rcx, rdi
    jae   .false
    movzx eax, byte [rsi+rcx]
    test  al, al
    jnz   .maybe
    inc   rcx
    jmp   .loop
.maybe:
    ; nonzero byte: false only if it's the last byte and == 0x80
    mov   rdx, rdi
    dec   rdx
    cmp   rcx, rdx
    jne   .true
    cmp   al, 0x80
    je    .false
.true:
    mov   eax, 1
    ret
.false:
    xor   eax, eax
    ret

; ============================================================================
; der_sig_strict(rdi=sig, rsi=siglen) -> rax = 1 valid / 0 invalid
;
; Bitcoin Core's IsValidSignatureEncoding (src/script/interpreter.cpp), the
; BIP66 strict-DER rule, transcribed check-for-check IN CORE'S OWN ORDER:
;
;     if (sig.size() < 9) return false;
;     if (sig.size() > 73) return false;
;     if (sig[0] != 0x30) return false;
;     if (sig[1] != sig.size() - 3) return false;
;     unsigned int lenR = sig[3];
;     if (5 + lenR >= sig.size()) return false;
;     unsigned int lenS = sig[5 + lenR];
;     if ((size_t)(lenR + lenS + 7) != sig.size()) return false;
;     if (sig[2] != 0x02) return false;
;     if (lenR == 0) return false;
;     if (sig[4] & 0x80) return false;
;     if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) return false;
;     if (sig[lenR + 4] != 0x02) return false;
;     if (lenS == 0) return false;
;     if (sig[lenR + 6] & 0x80) return false;
;     if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) return false;
;     return true;
;
; The argument is the FULL scriptSig/witness push, i.e. DER + the trailing
; one-byte SIGHASH type -- that byte is why the length descriptor is
; size-3 and not size-2, and why the minimum is 9 rather than 8.
;
; IN-BOUNDS ARGUMENT for every load, in the order the checks run:
;   sig[0..8]        siglen >= 9 by the first check.
;   sig[5+lenR]      guarded immediately above by 5+lenR < siglen.
;   sig[lenR+4]      lenR+4 < 5+lenR < siglen.
;   sig[lenR+6]      reached only after lenS != 0 and lenR+lenS+7 == siglen,
;                    so lenR+6 = siglen-lenS-1 <= siglen-2.
;   sig[lenR+7]      reached only when lenS > 1, so lenR+7 <= siglen-2.
; Note that Core's own ordering is what makes this safe: the lenS==0 test
; must precede the sig[lenR+6] load, and it does, in both.
;
; Leaf, no stack frame, no callee-saved registers touched (clobbers only
; rax/rcx/r8/r9), so bitcoin_interp.asm can call it from inside its checksig
; helpers without disturbing their live r12-r15/rbx.
; ============================================================================
global der_sig_strict
der_sig_strict:
    cmp   rsi, 9
    jb    .ds_bad
    cmp   rsi, 73
    ja    .ds_bad
    cmp   byte [rdi], 0x30
    jne   .ds_bad
    movzx eax, byte [rdi+1]
    lea   rcx, [rsi-3]              ; siglen >= 9, so no wrap
    cmp   rax, rcx
    jne   .ds_bad
    movzx r8d, byte [rdi+3]         ; lenR
    lea   rax, [r8+5]               ; 5 + lenR
    cmp   rax, rsi
    jae   .ds_bad
    movzx r9d, byte [rdi+rax]       ; lenS = sig[5+lenR]
    lea   rax, [r8+r9+7]
    cmp   rax, rsi
    jne   .ds_bad
    cmp   byte [rdi+2], 0x02
    jne   .ds_bad
    test  r8, r8                    ; lenR == 0
    jz    .ds_bad
    test  byte [rdi+4], 0x80        ; R negative
    jnz   .ds_bad
    cmp   r8, 1                     ; excess padding on R
    jbe   .ds_r_ok
    cmp   byte [rdi+4], 0x00
    jne   .ds_r_ok
    test  byte [rdi+5], 0x80
    jz    .ds_bad
.ds_r_ok:
    cmp   byte [rdi+r8+4], 0x02
    jne   .ds_bad
    test  r9, r9                    ; lenS == 0
    jz    .ds_bad
    test  byte [rdi+r8+6], 0x80     ; S negative
    jnz   .ds_bad
    cmp   r9, 1                     ; excess padding on S
    jbe   .ds_ok
    cmp   byte [rdi+r8+6], 0x00
    jne   .ds_ok
    test  byte [rdi+r8+7], 0x80
    jz    .ds_bad
.ds_ok:
    mov   eax, 1
    ret
.ds_bad:
    xor   eax, eax
    ret

; ============================================================================
; check_minimal_push(opcode, pushlen, data_ptr) -> rax = 0/1  (port of Core)
;   1 = the push is minimal for the given data/opcode.
; ============================================================================
global check_minimal_push
check_minimal_push:
    ; rdi=opcode, rsi=pushlen, rdx=data
    test  rsi, rsi
    jnz   .not_empty
    ; empty: must be OP_0
    test  rdi, rdi
    setz  al
    movzx eax, al
    ret
.not_empty:
    mov   ecx, 1
    cmp   rsi, 1
    jne   .not_one
    movzx eax, byte [rdx]
    cmp   al, 0x81
    je    .one_nonmin         ; 0x81 -> should use OP_1NEGATE. (Before 2026-09-02 this
                              ; test sat behind a `jb` that only a 0x00 byte reached, so a
                              ; pushed 0x81 passed MINIMALDATA; found by the Core differential.)
    cmp   al, 1
    jb    .not_one
    cmp   al, 16
    ja    .not_one
.one_nonmin:
    xor   eax, eax            ; 1..16 -> should use OP_1..OP_16
    ret
.not_one:
    ; size<=75 -> direct push, opcode must equal size
    cmp   rsi, 75
    ja    .sz_255
    mov   rax, rdi
    cmp   rax, rsi
    sete  al
    movzx eax, al
    ret
.sz_255:
    cmp   rsi, 255
    ja    .sz_65535
    ; opcode must be OP_PUSHDATA1 (0x4c)
    cmp   rdi, 0x4c
    sete  al
    movzx eax, al
    ret
.sz_65535:
    cmp   rsi, 65535
    ja    .big
    ; must be OP_PUSHDATA2 (0x4d)
    cmp   rdi, 0x4d
    sete  al
    movzx eax, al
    ret
.big:
    mov   eax, 1
    ret

; ============================================================================
; get_op(&pc, pend) -> rax = opcode, rdx = pushlen (advances *pc)
;   Returns 0 (rax=0) on a malformed script (bad opcode). Matches GetScriptOp.
;   rdi = pointer to pc (8 bytes), rsi = pend.
; ============================================================================
global get_op
get_op:
    push  rbx
    push  r12
    push  r13
    ; rdi=&pc, rsi=pend
    mov   r12, rdi            ; &pc
    mov   r13, [rdi]          ; pc
    cmp   r13, rsi
    jae   .bad
    movzx eax, byte [r13]     ; opcode byte
    inc   r13
    ; if opcode > OP_PUSHDATA4 (0x4e) -> not a push
    cmp   eax, 0x4e
    ja    .plain              ; plain opcode
    ; it's a push: determine nSize
    xor   edx, edx
    cmp   eax, 0x4c
    jb    .direct             ; opcode < PUSHDATA1: size = opcode
    je    .pd1
    cmp   eax, 0x4d
    je    .pd2
    ; OP_PUSHDATA4
    lea   rbx, [r13+4]
    cmp   rbx, rsi
    ja    .bad
    mov   edx, [r13]          ; LE 4-byte
    add   r13, 4
    jmp   .sized
.plain:
    xor   edx, edx            ; non-push: pushlen = 0
    jmp   .done
.direct:
    mov   rdx, rax
    jmp   .sized
.pd1:
    cmp   r13, rsi
    jae   .bad
    movzx edx, byte [r13]
    inc   r13
    jmp   .sized
.pd2:
    lea   rbx, [r13+2]
    cmp   rbx, rsi
    ja    .bad
    movzx edx, word [r13]
    add   r13, 2
.sized:
    ; check enough bytes remain for the push data
    lea   rbx, [r13+rdx]
    cmp   rbx, rsi
    ja    .bad
    add   r13, rdx
    ; opcode stays the original (in eax)
.done:
    mov   [r12], r13          ; *pc = advanced
    inc   rax                 ; return opcode+1 (so OP_0=0x00 -> rax=1, distinct from fail 0)
    pop   r13
    pop   r12
    pop   rbx
    ret
.bad:
    xor   eax, eax
    xor   edx, edx
    pop   r13
    pop   r12
    pop   rbx
    ret

; ============================================================================
; vfexec helpers (condition stack, static)
; ============================================================================
; vfexec_push(value in edi) -- push a 0/1
;   SCR-2 fix (audit 2026-09-03): the push is now bounded. The buffer covers
;   every nesting depth a script that fits in a block can express, so hitting
;   the cap means the script is malformed; fail the push (rax=0) and let the
;   interpreter treat it as an internal error rather than scribbling past
;   vfexec into vfexec_sp.
global vfexec_push
vfexec_push:
    push  rdx
    push  r8
    TLS_ADDR r8, vfexec_sp
    mov   rcx, [r8]
    cmp   rcx, VFEXEC_MAX
    jae   .full
    TLS_ADDR rdx, vfexec
    mov   [rdx+rcx], dil
    test  dil, dil
    jnz   .ff_done
    TLS_ADDR rdx, vfexec_ff       ; IR-4: first false, if none yet
    cmp   qword [rdx], VFEXEC_NO_FALSE
    jne   .ff_done
    mov   [rdx], rcx
.ff_done:
    inc   qword [r8]
    xor   eax, eax
    inc   rax
    pop   r8
    pop   rdx
    ret
.full:
    xor   eax, eax                ; 0 = refused (caller must fail the script)
    pop   r8
    pop   rdx
    ret
; vfexec_pop()
global vfexec_pop
vfexec_pop:
    push  rdx
    TLS_ADDR rcx, vfexec_sp
    mov   rax, [rcx]
    test  rax, rax
    jz    .empty
    dec   qword [rcx]
    mov   rax, [rcx]              ; new depth == index of the popped slot
    TLS_ADDR rdx, vfexec_ff       ; IR-4: popping the first false clears it
    cmp   [rdx], rax
    jne   .empty
    mov   qword [rdx], VFEXEC_NO_FALSE
.empty:
    pop   rdx
    ret
; vfexec_depth() -> rax
global vfexec_depth
vfexec_depth:
    TLS_ADDR rax, vfexec_sp
    mov   rax, [rax]
    ret
; vfexec_toggle_top()
global vfexec_toggle_top
vfexec_toggle_top:
    push  rax
    push  rcx
    push  rdx
    push  r8
    push  r9
    TLS_ADDR r8, vfexec_sp
    mov   rax, [r8]
    test  rax, rax
    jz    .empty
    mov   rcx, [r8]
    TLS_ADDR r9, vfexec
    movzx eax, byte [r9+rcx-1]
    xor   eax, 1
    mov   [r9+rcx-1], al
    ; IR-4: Core's ConditionStack::toggle_top -- if nothing was false the top
    ; just became the first false; if the top WAS the first false it is now
    ; true and nothing is false; a false below the top leaves it unchanged.
    dec   rcx                     ; index of top
    TLS_ADDR rdx, vfexec_ff
    cmp   qword [rdx], VFEXEC_NO_FALSE
    jne   .tt_had_false
    mov   [rdx], rcx
    jmp   .empty
.tt_had_false:
    cmp   [rdx], rcx
    jne   .empty
    mov   qword [rdx], VFEXEC_NO_FALSE
.empty:
    pop   r9
    pop   r8
    pop   rdx
    pop   rcx
    pop   rax
    ret
; vfexec_all_true() -> rax = 1 if no zero, else 0 (empty => true)
global vfexec_all_true
vfexec_all_true:
    push  rcx
    push  rdx
    ; IR-4: one compare against the cached first-false position (Core's
    ; ConditionStack::all_true). The byte scan this replaced is what made a
    ; deeply nested tapscript quadratic.
    TLS_ADDR rcx, vfexec_ff
    cmp   qword [rcx], VFEXEC_NO_FALSE
    jne   .no
    jmp   .yes
.no:
    xor   eax, eax
    pop   rdx
    pop   rcx
    ret
.yes:
    mov   eax, 1
    pop   rdx
    pop   rcx
    ret

; ============================================================================
; stack_dup_index(&sp, elems, raw_index) -> rax = 1 ok / 0 full
;   Pushes a copy of the element at raw_index (0 = bottom).
; ============================================================================
global stack_dup_index
stack_dup_index:
    push  r12
    push  r13
    push  r14
    push  r15
    mov   r12, rdi
    mov   r13, rsi
    mov   r15, rdx            ; raw_index
    mov   rax, [r12]
    cmp   rax, MAX_STACK_SIZE
    jae   .fail
    mov   rdx, r15            ; IR-6: src is position raw_index
    mov   rsi, r13
    sub   rsp, 8
    call  hnd_addr
    add   rsp, 8
    mov   r15, rax            ; src address
    mov   rdx, [r12]          ; dst is position sp
    mov   rsi, r13
    sub   rsp, 8
    call  hnd_addr
    add   rsp, 8
    mov   r14d, [r15]
    mov   [rax], r14d
    lea   rdi, [rax+ELEM_DATA_OFF]
    lea   rsi, [r15+ELEM_DATA_OFF]
    mov   rcx, r14
    rep movsb
    inc   qword [r12]
    mov   eax, 1
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret
.fail:
    xor   eax, eax
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret

; ============================================================================
; stack_erase_index(&sp, elems, raw_index) -- remove element at raw_index
;   (0 = bottom) shifting above elements down. Caller ensures index < sp.
; ============================================================================
global stack_erase_index
stack_erase_index:
    push  r12
    push  r13
    push  r14
    push  r15
    mov   r12, rdi
    mov   r13, rsi
    mov   r14, rdx            ; raw_index
    ; IR-6: THE finding. Closing the hole used to shift every record above
    ; the index -- 524 bytes each. With a table it shifts handles, 4 bytes
    ; each, and the erased slot lands at handles[sp-1] where the next push
    ; picks it up (the table stays a permutation of [0, MAX_STACK_SIZE)).
    mov   rsi, r13
    sub   rsp, 8
    call  hnd_of
    add   rsp, 8
    test  rax, rax
    jz    .records
    mov   r11d, [rax + r14*4]         ; h = handles[idx]
    mov   r8, [r12]
    dec   r8                          ; last = sp-1
    mov   r9, r14                     ; j = idx
.hshift:
    cmp   r9, r8
    jae   .hdone
    mov   edx, [rax + r9*4 + 4]
    mov   [rax + r9*4], edx
    inc   r9
    jmp   .hshift
.hdone:
    mov   [rax + r8*4], r11d
    TLS_ADDR rax, hnd_dirty
    mov   qword [rax], 1
    dec   qword [r12]
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret
.records:
    mov   rax, [r12]          ; sp
    sub   rax, 1              ; last index
    ; move each element at index j in [raw+1 .. sp-1] down to j-1
    mov   r15, r14
    inc   r15                 ; j = raw+1
.shift:
    mov   rax, [r12]
    cmp   r15, rax
    jae   .done
    ; src = elems + j*ELEM_SIZE ; dst = elems + (j-1)*ELEM_SIZE
    mov   rdx, r15
    imul  rdx, ELEM_SIZE
    add   rdx, r13            ; src
    mov   rcx, r15
    sub   rcx, 1
    imul  rcx, ELEM_SIZE
    add   rcx, r13            ; dst
    push  rdx
    push  rcx
    push  rcx                 ; padding: 4 pushes above + 2 here left RSP at
                              ; 8 mod16 for the call; a 3rd push restores
                              ; 0 mod16, as SysV requires at a `call`.
    mov   rdi, rcx
    mov   rsi, rdx
    call  elem_move
    pop   rcx                 ; discard padding
    pop   rcx
    pop   rdx
    inc   r15
    jmp   .shift
.done:
    dec   qword [r12]
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret

; ============================================================================
; stack_insert_index(&sp, elems, raw_index, data, len) -> rax 1/0
;   Inserts a NEW element (copied from data) at raw_index, shifting the rest up.
; ============================================================================
global stack_insert_index
stack_insert_index:
    push  r12
    push  r13
    push  r14
    push  r15
    push  rbx
    ; rdi=&sp, rsi=elems, rdx=raw_index, rcx=data, r8=len
    mov   r12, rdi
    mov   r13, rsi
    mov   r14, rdx            ; raw_index
    mov   rbx, rcx            ; data
    mov   r15, r8             ; len
    mov   rax, [r12]
    cmp   rax, MAX_STACK_SIZE
    jae   .fail
    ; IR-6: opening the hole shifts handles, and the new element is written
    ; into handles[sp] -- the slot the last pop/erase freed.
    mov   rsi, r13
    call  hnd_of
    test  rax, rax
    jz    .records
    mov   r9, [r12]                   ; sp
    mov   r11d, [rax + r9*4]          ; h = the free slot
    mov   r10, r9                     ; j = sp
.ishift:
    cmp   r10, r14
    jbe   .idone
    mov   edx, [rax + r10*4 - 4]
    mov   [rax + r10*4], edx
    dec   r10
    jmp   .ishift
.idone:
    mov   [rax + r14*4], r11d
    mov   edx, r11d
    imul  rdx, ELEM_SIZE
    lea   rdi, [r13 + rdx]
    mov   [rdi], r15d                 ; len
    add   rdi, ELEM_DATA_OFF
    mov   rsi, rbx
    mov   rcx, r15
    rep   movsb
    TLS_ADDR rax, hnd_dirty
    mov   qword [rax], 1
    inc   qword [r12]
    mov   eax, 1
    pop   rbx
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret
.records:
    ; j from sp-1 down to raw_index
    mov   rax, [r12]
    sub   rax, 1
    mov   r9, rax             ; j = sp-1  (r9 caller-saved by elem_move? no, elem_move only pushes rcx, so r9 is clobbered)
    ; use a preserved reg for j: reload approach
    ; j in r10? r10 is caller-saved and elem_move doesn't touch it (only rcx).
    mov   r10, rax            ; j
.shift:
    cmp   r10, r14
    jb    .shift_done
    ; src = elems + j*ELEM_SIZE ; dst = elems + (j+1)*ELEM_SIZE
    mov   rdx, r10
    imul  rdx, ELEM_SIZE
    add   rdx, r13            ; src
    mov   rcx, r10
    inc   rcx
    imul  rcx, ELEM_SIZE
    add   rcx, r13            ; dst
    push  rdx
    push  rcx
    push  r10
    push  r10                 ; padding: 5 pushes above + 3 here left RSP at
                              ; 8 mod16 for the call; a 4th push restores
                              ; 0 mod16, as SysV requires at a `call`.
    mov   rdi, rcx
    mov   rsi, rdx
    call  elem_move
    pop   r10                 ; discard padding
    pop   r10
    pop   rcx
    pop   rdx
    dec   r10
    jmp   .shift
.shift_done:
    ; write (len, data) into elem[raw_index]
    mov   rdx, r14
    imul  rdx, ELEM_SIZE
    add   rdx, r13            ; rec
    mov   [rdx], r15d         ; len
    lea   rdi, [rdx+ELEM_DATA_OFF]
    mov   r8, r15             ; copy len bytes from rbx
    test  r8, r8
    jz    .copied
.copy:
    mov   r9b, byte [rbx]
    mov   [rdi], r9b
    inc   rdi
    inc   rbx
    dec   r8
    jnz   .copy
.copied:
    inc   qword [r12]
    mov   eax, 1
    pop   rbx
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret
.fail:
    xor   eax, eax
    pop   rbx
    pop   r15
    pop   r14
    pop   r13
    pop   r12
    ret

; ============================================================================
; vfexec_sp_reset() -- zero the condition-stack pointer (start of a script eval)
; ============================================================================
global vfexec_sp_reset
vfexec_sp_reset:
    TLS_ADDR rax, vfexec_sp
    mov   qword [rax], 0
    TLS_ADDR rax, vfexec_ff
    mov   qword [rax], VFEXEC_NO_FALSE   ; IR-4
    ret

; SECURITY (audit 2026-08-29 finding 9): without this note the linker
; conservatively marks the whole program's stack EXECUTABLE (PT_GNU_STACK
; RWE). Nothing here needs a runnable stack; a single object missing the
; note is enough to turn it on for the entire binary, which is why every
; .asm file carries it.
section .note.GNU-stack noalloc noexec nowrite progbits
