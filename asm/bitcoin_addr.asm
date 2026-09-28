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
;   daemon/bmcbitcoind is pinned to -- reloads every value from memory around a
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
    cmp  rdx, 78
    jbe  .len_ok
    mov  byte [rdi], 0
    jmp  .epilogue
.len_ok:
    mov  r13, rdi            ; out
    mov  r14, rsi            ; payload
    mov  r15, rdx            ; paylen
    ; ---- data = payload || sha256d(payload)[0..3], at [rbp-0x90] ----
    lea  rdi, [rbp-0x90]
    xor  r11, r11
.cp1:
    cmp  r11, r15
    jae  .cp1_done
    mov  al, [r14 + r11]
    mov  [rdi + r11], al
    inc  r11
    jmp  .cp1
.cp1_done:
    lea  rdi, [rbp-0xb0]     ; checksum
    mov  rsi, r14
    mov  rdx, r15
    call sha256d
    mov  eax, [rbp-0xb0]
    lea  rdi, [rbp-0x90]
    mov  [rdi + r15], eax
    add  r15, 4              ; n = data length (5..82)
    ; ---- leading zero bytes -> that many '1' characters ----
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
    xor  r12, r12            ; out cursor
.ones:
    cmp  r12, r10
    jae  .ones_done
    mov  byte [r13 + r12], '1'
    inc  r12
    jmp  .ones
.ones_done:
    ; ---- the number as big-endian 64-bit limbs at [rbp-0x110] (2026-09-28) ----
    ;   nl = ceil(n / 8) limbs; the data bytes are placed right-aligned in a
    ;   zeroed nl*8-byte buffer and each limb is loaded with bswap. The old
    ;   loop divided the number BYTE by byte, one `div` per byte per digit
    ;   (~4.8 us for a 32-byte payload, 3.1x behind Core); this divides it
    ;   LIMB by limb by 58^10 (the largest power of 58 below 2^64), ten
    ;   digits per pass, and splits each remainder with ten more `div`s:
    ;   ~25 + 44 divisions for the 44 digits of a 32-byte payload instead
    ;   of ~1,600.
    lea  rbx, [r15 + 7]
    shr  rbx, 3              ; nl
    lea  rdi, [rbp-0x110]
    xor  eax, eax
    mov  rcx, 11
.zl:
    mov  [rdi + rcx*8 - 8], rax
    dec  rcx
    jnz  .zl
    mov  rax, rbx
    shl  rax, 3
    sub  rax, r15            ; pad = nl*8 - n (0..7)
    lea  rdi, [rbp-0x110]
    add  rdi, rax            ; data goes at buffer + pad
    lea  rsi, [rbp-0x90]
    xor  r11, r11
.cp2:
    cmp  r11, r15
    jae  .cp2_done
    mov  al, [rsi + r11]
    mov  [rdi + r11], al
    inc  r11
    jmp  .cp2
.cp2_done:
    lea  rdi, [rbp-0x110]
    xor  r11, r11
.bs:
    cmp  r11, rbx
    jae  .bs_done
    mov  rax, [rdi + r11*8]
    bswap rax
    mov  [rdi + r11*8], rax
    inc  r11
    jmp  .bs
.bs_done:
    ; ---- digits, least significant first, into digitRev at [rbp-0x1b0] ----
    xor  r14, r14            ; ndigits
    mov  r8, 430804206899405824   ; 58^10
    mov  r9, 58
    xor  r11, r11            ; top = first limb that may be non-zero
.skip0:
    cmp  r11, rbx
    jae  .digits_done        ; the number is zero: base58 of it is empty
    cmp  qword [rdi + r11*8], 0
    jne  .pass
    inc  r11
    jmp  .skip0
.pass:
    ; limbs[top..nl) /= 58^10, remainder in rdx
    xor  edx, edx
    mov  rcx, r11
.dl:
    mov  rax, [rdi + rcx*8]
    div  r8
    mov  [rdi + rcx*8], rax
    inc  rcx
    cmp  rcx, rbx
    jb   .dl
    mov  rsi, rdx            ; r = the remainder, < 58^10
    ; drop leading zero limbs of the quotient
.skipq:
    cmp  r11, rbx
    jae  .last_chunk
    cmp  qword [rdi + r11*8], 0
    jne  .full_chunk
    inc  r11
    jmp  .skipq
.full_chunk:
    ; quotient non-zero: exactly ten digits of r (zeros included)
    mov  ecx, 10
.fd:
    mov  rax, rsi
    xor  edx, edx
    div  r9
    mov  rsi, rax
    lea  rax, [ALPHABET]
    movzx edx, byte [rax + rdx]
    mov  [rbp-0x1b0 + r14], dl
    inc  r14
    dec  ecx
    jnz  .fd
    jmp  .pass
.last_chunk:
    ; quotient zero: the digits of r until it is exhausted (no leading zeros)
    test rsi, rsi
    jz   .digits_done
    mov  rax, rsi
    xor  edx, edx
    div  r9
    mov  rsi, rax
    lea  rax, [ALPHABET]
    movzx edx, byte [rax + rdx]
    mov  [rbp-0x1b0 + r14], dl
    inc  r14
    jmp  .last_chunk
.digits_done:
    ; ---- reverse into out after the '1's, NUL-terminate ----
.rev:
    test r14, r14
    jz   .rev_done
    dec  r14
    mov  al, [rbp-0x1b0 + r14]
    mov  [r13 + r12], al
    inc  r12
    jmp  .rev
.rev_done:
    mov  byte [r13 + r12], 0
.epilogue:
    add  rsp, 0x200
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
