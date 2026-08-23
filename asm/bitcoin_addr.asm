; ============================================================================
; bitcoin_addr.asm -- wallet address generation (pure x86-64).
;
; PURPOSE
;   Turns public keys into the addresses users send money to. A Bitcoin P2PKH
;   address is a base58check encoding of the 20-byte HASH160 of a public key:
;       hash160  = RIPEMD-160( SHA-256(pubkey) )
;       payload  = 0x00 (mainnet version) || hash160      (21 bytes)
;       checksum = first 4 bytes of SHA-256(SHA-256(payload))
;       address  = base58( payload || checksum )          (25 bytes)
;
; PUBLIC ABI (System V AMD64)
;   void hash160(u8 out[20], const void *in, i64 len)
;         out = RIPEMD-160( SHA-256(in) )
; ============================================================================

BITS 64
DEFAULT REL

extern sha256_full
extern sha256d
extern ripemd160

section .text
global hash160

; ----------------------------------------------------------------------------
; hash160(u8 out[20], const void *in, i64 len) -> rdi, rsi, rdx
;   Step 1: h = SHA-256(in)        (32 bytes)
;   Step 2: out = RIPEMD-160(h)    (20 bytes)
;   Locals live at [rbp-0x30..-0x50]; note ripemd160/sha256_full preserve
;   callee-saved regs, so we keep out/in/len in rbx/r12/r13 across the two
;   calls.
;
;   CALLEE-SAVED SAVE AREA IS *ABOVE* RBP. The pushes precede `push rbp`, so
;   rbx/r12/r13/r14 live at [rbp+0x08..rbp+0x20] and the 32-byte SHA-256 buffer
;   at [rbp-0x30..rbp-0x11] is inside this function's own 0x50 reservation.
;   Previously the pushes followed `mov rbp,rsp`, putting saved r13 at rbp-0x18
;   and saved r14 at rbp-0x20 -- both underneath that buffer -- so the epilogue
;   popped SHA-256 digest bytes into the CALLER's r13 and r14. (The caller also
;   lost r15, but that came from ripemd160, fixed separately.)
;   ALIGNMENT IS UNCHANGED: same five pushes and same 0x50 reservation, merely
;   reordered. Entry 8 -> 4 pushes -> 8 -> push rbp -> 0 -> sub 0x50 -> 0, the
;   same 0 mod 16 the two nested calls saw before.
; ----------------------------------------------------------------------------
hash160:
    push rbx
    push r12
    push r13
    push r14
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x50           ; locals [rbp-0x30..-0x50], all inside the frame

    mov  rbx, rdi            ; out
    mov  r12, rsi            ; in
    mov  r13, rdx            ; len

    ; h = sha256_full([rbp-0x30], in, len)
    lea  rdi, [rbp-0x30]
    mov  rsi, r12
    mov  rdx, r13
    call sha256_full

    ; out = ripemd160(out, h@[rbp-0x30], 32)
    mov  rdi, rbx
    lea  rsi, [rbp-0x30]
    mov  rdx, 32
    call ripemd160

    add  rsp, 0x50
    pop  rbp
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ----------------------------------------------------------------------------
; base58 alphabet (Bitcoin): no 0/O/I/l and no +/.
; ----------------------------------------------------------------------------
section .rodata
align 16
ALPHABET:
    db "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

section .text
global base58check_encode

; ----------------------------------------------------------------------------
; base58check_encode(char *out, const u8 *payload, i64 paylen)
;   Encode `payload` (version||hash160, typically 21 bytes) as a Bitcoin
;   base58check string in `out` (NULL-terminated). Computes the double-SHA256
;   checksum appended by base58check.
;
;   data(paylen+4) = payload || checksum[0..4]
;   Then standard base58 encoding of that big-endian number with leading-zero
;   '1' preservation.
;
;   paylen must be 0..78. Anything larger writes out[0] = 0 and returns rather
;   than overrunning `data` -- see the frame note below for why that matters.
;
; FRAME LAYOUT -- read this before moving any offset.
;
;   push rbp / mov rbp,rsp puts the five callee-saved saves at fixed negative
;   offsets from rbp:
;
;       [rbp-0x08] rbx   [rbp-0x10] r12   [rbp-0x18] r13
;       [rbp-0x20] r14   [rbp-0x28] r15
;
;   Every local buffer therefore has to live BELOW [rbp-0x28], and -- because
;   these buffers are filled with an ascending index -- its TOP end, not just
;   its base, has to stay below it.
;
;   That is exactly what went wrong. `data` used to sit at [rbp-0x58] and is
;   filled forwards for paylen+4 bytes, so it had only 0x58-0x28 = 48 bytes of
;   headroom. A 21-byte P2PKH payload gives data = 25 bytes and fits. The
;   78-byte BIP32 extended key gives data = 82 bytes, running from [rbp-0x58]
;   up to [rbp-0x06] -- straight over saved r15, r14, r13, r12 and the low two
;   bytes of saved rbx. The epilogue then popped payload bytes into all five.
;   The frame was already 0x200 bytes and its comment already said "sized for
;   the 78-byte extended key"; the SIZE was right, the PLACEMENT was not.
;   (`work` at [rbp-0x140] also ran two bytes into `checksum` at [rbp-0xf0];
;   harmless only because the checksum is consumed before work is filled.)
;
;   Nothing crashed in production, because gcc -O0 -- which is what
;   daemon/bitcoind is pinned to -- reloads every value from memory around a
;   call and so never trusts a callee-saved register. At -O2 it does trust
;   them, and tests/test_bip32_extkey segfaulted in strcmp on a `char*` gcc
;   had parked in r15 across the call. Caught by tests/test_abi_coverage,
;   which probes BOTH 21 and 78 bytes for this reason: a 21-byte-only probe
;   reports this function clean.
;
;   Current layout, all four buffers disjoint and all strictly below -0x28:
;
;       digitRev [rbp-0x1b0 .. rbp-0x110)   160 B, >= 112 digits for data=82
;       work     [rbp-0x110 .. rbp-0x0b0)    96 B, holds data being divided
;       checksum [rbp-0x0b0 .. rbp-0x090)    32 B, sha256d output
;       data     [rbp-0x090 .. rbp-0x030)    96 B, top is 8 B clear of -0x28
;
;   Frame is 0x200, deepest use is 0x1b0. Do not raise the paylen bound above
;   78 without re-checking `out` too: 82 data bytes is already ~112 base58
;   digits plus a NUL, and every caller declares out as char[128].
; ----------------------------------------------------------------------------
base58check_encode:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x200

    ; ---- refuse a payload that would not fit `data` (see frame note) ----
    ; Unsigned compare, so a negative paylen is caught here too.
    cmp  rdx, 78
    jbe  .len_ok
    mov  byte [rdi], 0
    add  rsp, 0x200
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
.len_ok:

    mov  r13, rdi            ; out
    ; persistent regs: out(rbx), payload(r14), paylen(r15) -- all callee-saved
    mov  rbx, rdi            ; out
    mov  r14, rsi            ; payload
    mov  r15, rdx            ; paylen

    ; ---- build data[] at [rbp-0x90]: payload then checksum ----
    lea  rdi, [rbp-0x90]     ; data dst
    mov  rsi, r14
    xor  r11, r11
.cp1:
    cmp  r11, r15
    jae  .cp1_done
    mov  al, [rsi + r11]
    mov  [rdi + r11], al
    inc  r11
    jmp  .cp1
.cp1_done:
    ; checksum = sha256d(out=[rbp-0xb0], in=payload(r14), len(r15))
    lea  rdi, [rbp-0xb0]
    mov  rsi, r14
    mov  rdx, r15
    call sha256d
    ; append first 4 checksum bytes at data+paylen
    lea  rsi, [rbp-0xb0]
    lea  rdi, [rbp-0x90]
    add  rdi, r15
    mov  rax, [rsi]
    mov  [rdi], eax
    ; total length = paylen + 4
    add  r15, 4

    ; ---- count leading zero bytes of data ----
    xor  r10, r10
    lea  rsi, [rbp-0x90]
.czl:
    cmp  r10, r15
    jae  .czl_done
    cmp  byte [rsi + r10], 0
    jne  .czl_done
    inc  r10
    jmp  .czl
.czl_done:
    ; emit r10 leading '1's
    mov  rdi, rbx
    xor  r12, r12             ; output cursor
    xor  r11, r11
.ez:
    cmp  r11, r10
    jae  .ez_done
    mov  byte [rdi + r12], '1'
    inc  r12
    inc  r11
    jmp  .ez
.ez_done:
    ; ---- copy data to work [rbp-0x110], then repeatedly divide by 58 ----
    lea  rdi, [rbp-0x110]
    lea  rsi, [rbp-0x90]
    mov  rcx, r15
    xor  r8, r8
.bcopy:
    cmp  r8, rcx
    jae  .bcopy_done
    mov  al, [rsi + r8]
    mov  [rdi + r8], al
    inc  r8
    jmp  .bcopy
.bcopy_done:
    mov  r9, r15              ; length of work number
    xor  r14, r14             ; ndigits (in r14; r14's payload value no longer needed)
.divloop:
    ; is work [[rbp-0x110]..+r9) all zero?
    lea  rsi, [rbp-0x110]
    xor  r11, r11
    xor  rcx, rcx
.iszero:
    cmp  r11, r9
    jae  .iszero_done
    cmp  byte [rsi + r11], 0
    je   .iszero_next
    mov  rcx, 1
.iszero_next:
    inc  r11
    jmp  .iszero
.iszero_done:
    test rcx, rcx
    jz   .divide_done
    ; one division pass: divide work by 58 (MSB->LSB), quotient back to work,
    ; final remainder is the base58 digit for this pass.
    xor  eax, eax             ; rem
    xor  r11, r11             ; index
    lea  rsi, [rbp-0x110]
.dv:
    cmp  r11, r9
    jae  .dv_done
    movzx edx, byte [rsi + r11]   ; b
    imul eax, eax, 256
    add  eax, edx
    mov  ecx, 58
    xor  edx, edx
    div  ecx
    mov  [rsi + r11], al
    mov  eax, edx
    inc  r11
    jmp  .dv
.dv_done:
    ; eax = remainder = least-significant base58 digit now
    lea  r8, [ALPHABET]
    movzx ecx, byte [r8 + rax]      ; base58 char
    lea  r8, [rbp-0x1b0]             ; digitRev buffer (accumulate LSB-first)
    mov  [r8 + r14], cl
    inc  r14                        ; ndigits++
    jmp  .divloop
.divide_done:
    ; reverse-copy ndigits(r14) chars from [rbp-0x1b0] into out after the '1's
    mov  rdi, rbx
    add  rdi, r12                   ; past the leading '1's
    lea  rsi, [rbp-0x1b0]
    mov  r8, r14                    ; count
.rv:
    test r8, r8
    jz   .rv_done
    dec  r8
    mov  al, [rsi + r8]
    mov  [rdi], al
    inc  rdi
    jmp  .rv
.rv_done:
    mov  byte [rdi], 0
    add  rsp, 0x200
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
