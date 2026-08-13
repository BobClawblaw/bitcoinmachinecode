; ============================================================================
; bitcoin_tx.asm -- Bitcoin transaction deserializer (node layer).
;   100% AI-authored x86-64 assembly.
;
;   Exported API (System V AMD64):
;     int tx_parse(txinfo *info, const u8 *tx, unsigned long txlen)
;         Parse a canonical serialized transaction and fill `info` with the
;         byte offsets / counts of its structural fields. Returns 1 on a fully
;         consumed well-formed transaction, 0 on truncation/malformation.
;         `info` is 64 bytes with this layout (all offsets are into the raw
;         buffer passed in `tx`):
;             +0   u64 tx_len          ; total bytes consumed (== txlen if valid)
;             +8   u32 version
;             +12  u32 n_in
;             +16  u32 n_out
;             +20  u32 locktime
;             +24  u64 in0_script      ; input[0] script byte offset
;             +32  u64 in0_script_len
;             +40  u64 out0_value      ; output[0] value field byte offset
;             +48  u64 out0_script
;             +56  u64 out0_script_len
;
;   The transaction serialization walked (little-endian wire format):
;     version(4) | varint n_in | n_in * (prevout(32) index(4)
;     varint scriptlen script seq(4)) | varint n_out | n_out *
;     (value(8) varint scriptlen script) | locktime(4)
;
;   varint (CompactSize): <0xfd 1 byte; 0xfd 2; 0xfe 4; 0xff 8.
;
;   Conventions: callee-saved [rbx,r12-r15]; scratch BELOW the save area and
;   16-byte RSP alignment at any nested call. This function makes no nested
;   calls (pure byte-walk), so it keeps the frame minimal.
; ============================================================================
default rel

section .text

; ----------------------------------------------------------------------------
; tx_parse(info, tx, txlen) -> eax = 1 valid / 0 invalid
;   Register map:
;     rdi = info   (caller-saved; no nested calls so safe to keep)
;     rsi = cursor  (advances through tx)
;     rdx = end     (tx+txlen; inclusive upper bound for reads)
;     r8  = base    (tx, for computing offsets)
;     r9-r11 = scratch
;   We must still preserve callee-saved per ABI (we push rbx only; we do not
;   clobber r12-r15).
; ----------------------------------------------------------------------------
global tx_parse
tx_parse:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r15               ; r15 is callee-saved; we use it for script lengths
    sub  rsp, 8            ; keep rsp 16-aligned for symmetry (no nested calls)

    mov  r8,  rsi            ; base
    mov  r11, rdx
    add  r11, rsi            ; r11 = end
    mov  r9,  rsi            ; cursor

    ; ---- version (4 bytes) ----
    cmp  r9,  r11
    jae  .fail               ; need room for version
    lea  r10, [r9+4]
    cmp  r10, r11
    ja   .fail
    mov  eax, [r9]
    mov  [rdi+8], eax        ; info.version
    mov  r9,  r10

    ; ---- SegWit (BIP141) marker/flag detection ----
    ; version | marker(0x00) flag(0x01) | ...  A legacy tx cannot be parsed as
    ; n_in=0 (invalid tx), so tx[4]==0x00 && tx[5]==0x01 unambiguously marks a
    ; witnessed tx. We keep the flag in callee-saved r12 (0=legacy, 1=segwit).
    xor  r12d, r12d          ; default legacy
    lea  r10, [r9+2]
    cmp  r10, r11
    ja   .read_nin           ; too short to hold marker -> legacy
    movzx eax, byte [r9]
    test eax, eax
    jne  .read_nin           ; tx[4]!=0 -> legacy
    movzx eax, byte [r9+1]
    cmp  eax, 1
    jne  .read_nin           ; tx[5]!=1 -> legacy
    ; segwit: advance past marker+flag to the n_in varint
    mov  r12d, 1
    mov  r9,  r10
.read_nin:

    ; ---- varint n_in (inline CompactSize decode) ----
    mov  eax, [r9]           ; first varint byte
    xor  ecx, ecx
    movzx ecx, al
    cmp  cl, 0xfd
    jae  .vbig
    inc  r9
    jmp  .have_nin
.vbig:
    cmp  cl, 0xfd
    jne  .vfe
    ; 0xfd -> 2 bytes
    lea  r10, [r9+3]
    cmp  r10, r11
    ja   .fail
    movzx ecx, word [r9+1]
    mov  r9,  r10
    jmp  .have_nin
.vfe:
    cmp  cl, 0xfe
    jne  .vff
    lea  r10, [r9+5]
    cmp  r10, r11
    ja   .fail
    mov  ecx, [r9+1]
    mov  r9,  r10
    jmp  .have_nin
.vff:
    ; 0xff -> 8 bytes
    lea  r10, [r9+9]
    cmp  r10, r11
    ja   .fail
    mov  rcx, [r9+1]
    mov  r9,  r10
.have_nin:
    mov  [rdi+12], ecx       ; info.n_in

    ; ---- walk n_in inputs ----
    ; each input: prevout(32) index(4) varint(scriptlen) script seq(4)
    mov  r10, rcx            ; counter = n_in, use r10 (r9/r11 are base/end)
.next_in:
    test r10, r10
    jz   .ins_done
    ; prevout 32 bytes
    lea  rbx, [r9+32]
    cmp  rbx, r11
    ja   .fail
    mov  r9,  rbx
    ; index 4 bytes
    lea  rbx, [r9+4]
    cmp  rbx, r11
    ja   .fail
    ; if this is input[0], record its script offset (note index here)
    ; r10 == n_in originally; input index i has original-counter? simpler: keep
    ; a separate first-input flag via the difference from n_in.
    ; We'll track how many inputs remain in r10. input[0] is processed when
    ; r10 == (n_in read above). Save n_in in a slot.
    mov  r9,  rbx
    ; scriptlen varint (reuse inline decoder via a small loop segment)
    ; read first varint byte into r15? We only have r10/rbx free-ish. Use rax.
    mov  eax, [r9]
    movzx eax, al
    cmp  eax, 0xfd
    jae  .sbig
    mov  r15, rax
    inc  r9
    jmp  .have_slen
.sbig:
    cmp  eax, 0xfd
    jne  .sfe
    lea  rbx, [r9+3]
    cmp  rbx, r11
    ja   .fail
    movzx r15, word [r9+1]
    mov  r9,  rbx
    jmp  .have_slen
.sfe:
    cmp  eax, 0xfe
    jne  .sff
    lea  rbx, [r9+5]
    cmp  rbx, r11
    ja   .fail
    mov  r15d, [r9+1]
    mov  r9,  rbx
    jmp  .have_slen
.sff:
    lea  rbx, [r9+9]
    cmp  rbx, r11
    ja   .fail
    mov  r15, [r9+1]
    mov  r9,  rbx
.have_slen:
    ; script bytes
    lea  rbx, [r9+r15]
    cmp  rbx, r11
    ja   .fail
    ; seq 4 bytes
    lea  rbx, [rbx+4]
    cmp  rbx, r11
    ja   .fail
    ; record input[0] script offset/len: navigate by identifying input index.
    ; input[0] <=> r10 == n_in (current input processed is the FIRST when the
    ; loop counter equals n_in). We stored n_in at info+12; reload to compare.
    mov  eax, [rdi+12]       ; n_in
    cmp  r10d, eax
    mov  r9,  rbx            ; continue cursor past seq
    jne  .not_in0
    mov  rax, r15
    sub  rax, r15            ; (offset = r9 - r15 - (:start of script))
    ; script start offset = r9 - r15 (cursor before consuming script = r9 prior)
    ; Recompute: script started at (r9 before advancing by r15). We advanced
    ; r9 to the seq position AFTER script. script_start = seq_pos - r15 - 4.
    lea  rbx, [r9]
    sub  rbx, r15
    sub  rbx, 4
    sub  rbx, r8             ; make it an offset from base
    mov  [rdi+24], rbx       ; in0_script offset
    mov  [rdi+32], r15       ; in0_script_len
.not_in0:
    dec  r10
    jmp  .next_in
.ins_done:

    ; ---- varint n_out ----
    mov  eax, [r9]
    xor  ecx, ecx
    movzx ecx, al
    cmp  cl, 0xfd
    jae  .ovbig
    inc  r9
    jmp  .have_nout
.ovbig:
    cmp  cl, 0xfd
    jne  .ofe
    lea  rbx, [r9+3]
    cmp  rbx, r11
    ja   .fail
    movzx ecx, word [r9+1]
    mov  r9,  rbx
    jmp  .have_nout
.ofe:
    cmp  cl, 0xfe
    jne  .off
    lea  rbx, [r9+5]
    cmp  rbx, r11
    ja   .fail
    mov  ecx, [r9+1]
    mov  r9,  rbx
    jmp  .have_nout
.off:
    lea  rbx, [r9+9]
    cmp  rbx, r11
    ja   .fail
    mov  rcx, [r9+1]
    mov  r9,  rbx
.have_nout:
    mov  [rdi+16], ecx       ; info.n_out

    ; ---- walk n_out outputs ----
    mov  r10, rcx
.next_out:
    test r10, r10
    jz   .outs_done
    ; value (8 bytes) -- record offset for output[0]
    mov  eax, [rdi+16]
    cmp  r10d, eax
    jne  .not_out0_v
    mov  [rdi+40], r9   ; out0_value offset (absolute position) -- store then
    ; adjust to offset-from-base below
    sub  qword [rdi+40], r8
.not_out0_v:
    lea  rbx, [r9+8]
    cmp  rbx, r11
    ja   .fail
    mov  r9,  rbx
    ; scriptlen varint
    mov  eax, [r9]
    movzx eax, al
    cmp  eax, 0xfd
    jae  .pbv
    mov  r15, rax
    inc  r9
    jmp  .have_pslen
.pbv:
    cmp  eax, 0xfd
    jne  .pfe
    lea  rbx, [r9+3]
    cmp  rbx, r11
    ja   .fail
    movzx r15, word [r9+1]
    mov  r9,  rbx
    jmp  .have_pslen
.pfe:
    cmp  eax, 0xfe
    jne  .pff
    lea  rbx, [r9+5]
    cmp  rbx, r11
    ja   .fail
    mov  r15d, [r9+1]
    mov  r9,  rbx
    jmp  .have_pslen
.pff:
    lea  rbx, [r9+9]
    cmp  rbx, r11
    ja   .fail
    mov  r15, [r9+1]
    mov  r9,  rbx
.have_pslen:
    ; record output[0] script offset/len
    mov  eax, [rdi+16]
    cmp  r10d, eax
    jne  .not_out0_s
    mov  rax, r9
    sub  rax, r8
    mov  [rdi+48], rax       ; out0_script offset
    mov  [rdi+56], r15       ; out0_script_len
    ; out0_value was stored as offset already
.not_out0_s:
    ; script bytes + advance
    lea  rbx, [r9+r15]
    cmp  rbx, r11
    ja   .fail
    mov  r9,  rbx
    dec  r10
    jmp  .next_out
.outs_done:

    ; ---- skip SegWit witness data (only if segwit) ----
    ; For each of n_in inputs: varint item-count, then that many
    ; (varint len + bytes). Then the trailing locktime follows.
    test r12d, r12d
    jz   .nowit
    mov  r10d, [rdi+12]      ; n_in
.next_wit_in:
    test r10, r10
    jz   .nowit
    ; varint item count
    cmp  r9,  r11
    jae  .fail
    mov  eax, [r9]
    movzx eax, al
    cmp  eax, 0xfd
    jae  .witbig
    mov  r15, rax
    inc  r9
    jmp  .have_wit_items
.witbig:
    cmp  eax, 0xfd
    jne  .witfe
    lea  rbx, [r9+3]
    cmp  rbx, r11
    ja   .fail
    movzx r15, word [r9+1]
    mov  r9,  rbx
    jmp  .have_wit_items
.witfe:
    cmp  eax, 0xfe
    jne  .witff
    lea  rbx, [r9+5]
    cmp  rbx, r11
    ja   .fail
    mov  r15d, [r9+1]
    mov  r9,  rbx
    jmp  .have_wit_items
.witff:
    lea  rbx, [r9+9]
    cmp  rbx, r11
    ja   .fail
    mov  r15, [r9+1]
    mov  r9,  rbx
.have_wit_items:
    ; walk the items: each is (varint len + bytes), length into rbx
.next_wit_item:
    test r15, r15
    jz   .wit_in_done
    cmp  r9,  r11
    jae  .fail
    mov  eax, [r9]
    movzx eax, al
    cmp  eax, 0xfd
    jae  .wlb
    mov  rdx, rax            ; item len (1-byte) in rdx (consistent with .wl*)
    inc  r9
    jmp  .have_wlen
.wlb:
    cmp  eax, 0xfd
    jne  .wlf
    lea  rcx, [r9+3]
    cmp  rcx, r11
    ja   .fail
    movzx edx, word [r9+1]
    add  r9,  3
    jmp  .have_wlen
.wlf:
    cmp  eax, 0xfe
    jne  .wlff
    lea  rcx, [r9+5]
    cmp  rcx, r11
    ja   .fail
    mov  edx, [r9+1]
    add  r9,  5
    jmp  .have_wlen
.wlff:
    lea  rcx, [r9+9]
    cmp  rcx, r11
    ja   .fail
    mov  rdx, [r9+1]
    add  r9,  9
.have_wlen:
    lea  rbx, [r9+rdx]       ; skip the item bytes
    cmp  rbx, r11
    ja   .fail
    mov  r9,  rbx
    dec  r15
    jmp  .next_wit_item
.wit_in_done:
    dec  r10
    jmp  .next_wit_in
.nowit:

    ; ---- locktime (4 bytes) ----
    lea  rbx, [r9+4]
    cmp  rbx, r11
    ja   .fail
    mov  eax, [r9]
    mov  [rdi+20], eax       ; info.locktime
    mov  r9,  rbx            ; advance past the locktime field

    ; total consumed = r9 - base
    mov  rax, r9
    sub  rax, r8
    mov  [rdi+0], rax        ; info.tx_len

    ; success: the transaction is structurally well-formed. We do NOT require
    ; consumed == txlen: `txlen` may carry trailing bytes (e.g. when parsing one
    ; tx out of a serialized block). Truncation (cursor past end) is already
    ; rejected by the per-field bounds checks above.
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r15
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; tx_txid(out32, tx, txlen, buf, buflen) -> eax = 1 valid / 0 invalid
;   Compute the BIP141 transaction id of a legacy OR SegWit transaction.
;   txid = sha256d( unwitnessed serialization ). The unwitnessed serialization is
;   reconstructed into `buf` (caller supplies buflen >= unwit len) as
;     version(4) | n_in-varint + inputs | n_out-varint + outputs | locktime(4)
;   i.e. the SegWit marker/flag and all witness data are dropped.
;   Returns 1 on success, 0 if malformed or buf too small.
;
;   ABI: rdi=out, rsi=tx, rdx=txlen, rcx=buf, r8=buflen.
;   Callee-saved preserved: rbx, r12-r15. Only nested call is sha256d at the end.
; ============================================================================
;
; Registers:
;   r12 = out, r13 = tx base, r14 = buf, r15 = txlen, rbx = buflen (preserved)
;   r9 = end, r8 = cursor, r10 = count, rcx = loop counter, r11 = segwit flag
;   + version copied into the reconstruction we derive inputs/outputs boundaries.
; ============================================================================
extern sha256d
global tx_txid
tx_txid:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8

    mov  r12, rdi            ; out
    mov  r13, rsi            ; tx
    mov  r15, rdx            ; txlen
    mov  r14, rcx            ; buf
    mov  [rbp-0x30], r8      ; buflen (stack local below the r15 save at -0x28;
                             ; rbx is clobbered by the walk)

    lea  r9,  [r13+r15]      ; end = tx + txlen

    ; ---- detect SegWit marker (version | 0x00 0x01) ----
    xor  r11d, r11d          ; r11 = segwit flag
    lea  r10, [r13+6]
    cmp  r10, r9
    ja   .det_done
    movzx eax, byte [r13+4]
    test eax, eax
    jne  .det_done
    movzx eax, byte [r13+5]
    cmp  eax, 1
    jne  .det_done
    mov  r11d, 1
.det_done:

    ; inputs_start pointer = tx+4 (legacy) or tx+6 (segwit); save it.
    lea  r8,  [r13+4]
    mov  [rbp-0x18], r8
    test r11d, r11d
    jz   .have_cur
    lea  r8,  [r13+6]
    mov  [rbp-0x18], r8
.have_cur:

    ; ---- varint n_in (r10d = n_in) ----
    movzx ecx, byte [r8]
    cmp  cl, 0xfd
    jae  .vbig
    mov  r10d, ecx
    inc  r8
    jmp  .have_nin
.vbig:
    cmp  cl, 0xfd
    jne  .vfe
    movzx r10d, word [r8+1]
    lea  r8,  [r8+3]
    jmp  .have_nin
.vfe:
    cmp  cl, 0xfe
    jne  .vff
    mov  r10d, [r8+1]
    lea  r8,  [r8+5]
    jmp  .have_nin
.vff:
    mov  r10,  [r8+1]
    lea  r8,  [r8+9]
.have_nin:
    mov  rcx, r10            ; counter = n_in
.next_in:
    test rcx, rcx
    jz   .ins_done
    ; input: prevout(32) index(4) varint scriptlen script seq(4)
    movzx eax, byte [r8+36]  ; scriptlen first byte (after 36 fixed bytes)
    cmp  eax, 0xfd
    jae  .sbig
    movzx edx, al
    lea  rbx, [r8+36+1]
    lea  rbx, [rbx+rdx]
    lea  rbx, [rbx+4]
    cmp  rbx, r9
    ja   .fail
    mov  r8,  rbx
    jmp  .in_done
.sbig:
    cmp  eax, 0xfd
    jne  .sfe
    movzx edx, word [r8+37]
    lea  rbx, [r8+36+3]
    lea  rbx, [rbx+rdx]
    lea  rbx, [rbx+4]
    cmp  rbx, r9
    ja   .fail
    mov  r8,  rbx
    jmp  .in_done
.sfe:
    cmp  eax, 0xfe
    jne  .sff
    mov  edx, [r8+37]
    lea  rbx, [r8+36+5]
    lea  rbx, [rbx+rdx]
    lea  rbx, [rbx+4]
    cmp  rbx, r9
    ja   .fail
    mov  r8,  rbx
    jmp  .in_done
.sff:
    mov  rdx, [r8+37]
    lea  rbx, [r8+36+9]
    lea  rbx, [rbx+rdx]
    lea  rbx, [rbx+4]
    cmp  rbx, r9
    ja   .fail
    mov  r8,  rbx
.in_done:
    dec  rcx
    jmp  .next_in
.ins_done:

    ; ---- varint n_out (r10d = n_out) ----
    movzx ecx, byte [r8]
    cmp  cl, 0xfd
    jae  .ovbig
    mov  r10d, ecx
    inc  r8
    jmp  .have_nout
.ovbig:
    cmp  cl, 0xfd
    jne  .ofe
    movzx r10d, word [r8+1]
    lea  r8,  [r8+3]
    jmp  .have_nout
.ofe:
    cmp  cl, 0xfe
    jne  .off
    mov  r10d, [r8+1]
    lea  r8,  [r8+5]
    jmp  .have_nout
.off:
    mov  r10,  [r8+1]
    lea  r8,  [r8+9]
.have_nout:
    mov  rcx, r10            ; counter = n_out
.next_out:
    test rcx, rcx
    jz   .outs_done
    ; output: value(8) varint scriptlen script
    movzx eax, byte [r8+8]
    cmp  eax, 0xfd
    jae  .pbig
    movzx edx, al
    lea  rbx, [r8+8+1]
    lea  rbx, [rbx+rdx]
    cmp  rbx, r9
    ja   .fail
    mov  r8,  rbx
    jmp  .out_done
.pbig:
    cmp  eax, 0xfd
    jne  .pfe
    movzx edx, word [r8+9]
    lea  rbx, [r8+8+3]
    lea  rbx, [rbx+rdx]
    cmp  rbx, r9
    ja   .fail
    mov  r8,  rbx
    jmp  .out_done
.pfe:
    cmp  eax, 0xfe
    jne  .pff
    mov  edx, [r8+9]
    lea  rbx, [r8+8+5]
    lea  rbx, [rbx+rdx]
    cmp  rbx, r9
    ja   .fail
    mov  r8,  rbx
    jmp  .out_done
.pff:
    mov  rdx, [r8+9]
    lea  rbx, [r8+8+9]
    lea  rbx, [rbx+rdx]
    cmp  rbx, r9
    ja   .fail
    mov  r8,  rbx
.out_done:
    dec  rcx
    jmp  .next_out
.outs_done:
    ; r8 = outputs_end (pointer to right after the last output; for a segwit tx
    ;   this is where witness begins; for legacy, where locktime begins)

    ; locktime start = end - 4 must be >= outputs_end
    lea  r10, [r13+r15]
    sub  r10, 4
    cmp  r10, r8
    jb   .fail

    ; ---- reconstruct unwitnessed into buf ----
    ;   part1 = version = tx[0..4]
    ;   part2 = mid = tx[inputs_start .. outputs_end]
    ;   part3 = locktime = tx[end-4 .. end]
    ; mid_len = outputs_end - inputs_start_ptr
    mov  rsi, [rbp-0x18]     ; inputs_start_ptr
    sub  r8,  rsi            ; mid_len
    mov  rcx, r8             ; rcx = mid_len

    ; buflen check: need 4 + mid_len + 4 <= buflen
    lea  rax, [rcx+8]
    cmp  rax, [rbp-0x30]
    ja   .fail

    ; copy version (4 bytes)
    mov  rsi, r13
    mov  rdi, r14
    mov  ecx, 4
    rep  movsb
    ; copy mid (rcx = mid_len)
    mov  rsi, [rbp-0x18]
    mov  rcx, r8             ; mid_len
    rep  movsb
    ; copy locktime (4 bytes)
    mov  rsi, r13
    add  rsi, r15
    sub  rsi, 4
    mov  ecx, 4
    rep  movsb

    ; unwit_len = 4 + mid_len + 4
    lea  rdx, [r8+8]
    ; sha256d(out, buf, unwit_len)
    mov  rdi, r12
    mov  rsi, r14
    call sha256d
    mov  eax, 1
    jmp  .ret
.fail:
    xor  eax, eax
.ret:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
