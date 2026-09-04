; ============================================================================
; bitcoin_bip39.asm -- BIP39 mnemonic <-> seed, x86-64 (System V AMD64).
;
;   BIP39 (Mnemonic code for generating deterministic keys) built on the
;   already-verified asm core. Pairs with bitcoin_bip32.asm so a wallet CLI can
;   produce a recoverable mnemonic, derive a 64-byte seed via PBKDF2-HMAC-SHA512,
;   and feed that seed straight into BIP32 (bip32_master -> m/44'/0'/0'/0/0).
;
;   STRUCTURE
;     entropy (128..256 bits) --11-bit-groups--> mnemonic words (12..24)
;       last CS bits of the stream = first CS bits of SHA256(entropy)  (CS=ENT/32)
;     mnemonic -> seed : PBKDF2-HMAC-SHA512(P=mnemonic, S="mnemonic"||pass,
;                          c=2048, dkLen=64)
;
;   PUBLIC ABI (System V AMD64)
;     int  bip39_generate(char* out, const u8* entropy, i64 ent_bits)
;          -> 1 on success, 0 on bad ent_bits. Writes "<w0 w1 ... wn\0>".
;    int  bip39_validate(const char* mnemonic)
;          -> word count (12/15/18/21/24) on success, -1 if invalid.
;    int  bip39_mnemonic_to_entropy(u8 out[32], const char* mnemonic)
;          -> entropy BIT count on success, -1 if invalid; writes entropy bytes.
;    int  bip39_mnemonic_to_seed(u8 seed[64], const char* mnemonic,
;                                const char* passphrase, i64 passlen)
;          -> 1 on success (passphrase may be NULL/empty).
;
;   DEPENDENCIES: sha256_full (checksum), hmac_sha512 (PBKDF2 PRF).
;   The wordlist is a fixed-width (9-byte record) table in wordlist.inc.
; ============================================================================

BITS 64
DEFAULT REL

%include "wordlist.inc"

section .rodata
align 8
m39_seed_salt: db "mnemonic"          ; 8-byte BIP39 salt prefix

section .bss
align 16
m39_bits: resb 40                    ; concatenated entropy||checksum bit stream (264 bits max)
m39_idx:  resb 24*4                  ; up to 24 dword word-indices
m39_salt: resb 512                   ; "mnemonic" || passphrase (also scratch digest)
m39_msg:  resb 520                   ; salt || INT(1) first-PBKDF2-iteration message
m39_prev: resb 64
m39_cur:  resb 64
m39_acc:  resb 64
m39_nw:   resq 1                     ; parsed word count (bip39_parse)

section .text
extern sha256_full
extern hmac_sha512

; ============================================================================
; Helper: bip39_bit_at(buf, bitpos) -> eax = bit (0/1); clobbers rdx, r8, rcx.
;   rdi = buf, rsi = bitpos. Bit order: MSB of a byte is bit (bitpos%8)==0.
; ============================================================================
bip39_bit_at:
    mov  rdx, rsi
    shr  rdx, 3                      ; byte index
    mov  r8, rsi
    and  r8, 7                       ; offset in byte (0 = MSB)
    movzx eax, byte [rdi+rdx]        ; the byte
    mov  ecx, 7
    sub  ecx, r8d                    ; shift = 7 - offset
    shr  eax, cl
    and  eax, 1
    ret

; ============================================================================
; Helper: bip39_set_bit(buf, bitpos, val)
;   rdi = buf, rsi = bitpos, rdx = 0/1. Sets/clears the bit (buffer pre-zeroed)
;   so for val=1 we simply OR in a mask; val=0 is a no-op.
; ============================================================================
bip39_set_bit:
    test rdx, rdx
    jz   .zero                      ; val==0: nothing to set on a zeroed buffer
    mov  rax, rsi
    shr  rax, 3                      ; byte index
    mov  ecx, esi
    and  ecx, 7
    mov  r8d, 7
    sub  r8d, ecx                    ; shift = 7 - offset
    mov  ecx, r8d                    ; cl = shift (required for shl r/m8, cl)
    mov  r9d, 1
    shl  r9b, cl                     ; mask = 1 << shift
    or   byte [rdi+rax], r9b
.zero:
    ret

; ============================================================================
; Helper: bip39_read11(buf, bitpos) -> rax = 11-bit group (big-endian bit order).
;   rdi = buf, rsi = bitpos. Uses r12/r13 callee-saved + scratch.
; ============================================================================
bip39_read11:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push rbx
    mov  r12, rdi                    ; buf (survives the bit_at call)
    mov  r13, rsi                    ; bitpos
    xor  ebx, ebx                    ; result
    xor  rcx, rcx                    ; counter
.loop:
    cmp  rcx, 11
    jae  .done
    ; bit = bit_at(buf, r13+rcx)
    lea  rsi, [r13+rcx]
    mov  rdi, r12
    push rcx
    push rbx
    call bip39_bit_at
    pop  rbx
    pop  rcx
    shl  ebx, 1
    or   ebx, eax
    inc  rcx
    jmp  .loop
.done:
    mov  eax, ebx
    pop  rbx
    pop  r13
    pop  r12
    pop  rbp
    ret

; ============================================================================
; Helper: find_word_index(token, toklen) -> eax = index (>=0) or -1.
;   rdi = pointer to a word token, rsi = token length (no NUL needed).
;   Compares against the embedded fixed-width 9-byte records. Does NOT modify
;   the input. A match requires the record's first 'toklen' bytes to equal the
;   token and the record's byte at position 'toklen' to be NUL (the word has
;   exactly that length).
; ============================================================================
find_word_index:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, rdi                    ; token start
    mov  r14, rsi                    ; token length
    lea  r15, [bip39_words]          ; table base
    xor  r12, r12                    ; index counter
.loop:
    cmp  r12, BIP39_WORD_COUNT
    jae  .notfound
    ; record address = table base + r12*9
    mov  rax, r12
    imul rax, 9
    add  rax, r15                    ; rax = &record
    mov  rbx, rax                    ; keep in rbx
    ; compare first r14 bytes
    xor  rdi, rdi                    ; byte offset (use rdi as counter)
.cmp:
    cmp  rdi, r14
    jae  .lenchk                     ; all token bytes matched
    mov  al, byte [r13+rdi]          ; token byte
    mov  r9b, byte [rbx+rdi]         ; record byte (clobbers r9b only)
    cmp  al, r9b
    jne  .next
    inc  rdi
    jmp  .cmp
.lenchk:
    ; ensure the word is exactly toklen chars: record[toklen] must be NUL
    cmp  byte [rbx+rdi], 0
    jne  .next
.found:
    mov  eax, r12d
    jmp  .ret
.next:
    inc  r12
    jmp  .loop
.notfound:
    mov  eax, -1
.ret:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; Helper: bip39_strlen(str) -> rax = byte length (excludes NUL).
; ============================================================================
bip39_strlen:
    xor  eax, eax
.l:
    cmp  byte [rdi+rax], 0
    je   .d
    inc  rax
    jmp  .l
.d:
    ret

; ============================================================================
; int bip39_generate(char* out, const u8* entropy, i64 ent_bits)
;   Builds the mnemonic string for the given entropy.
; ============================================================================
global bip39_generate
; CALLEE-SAVED SAVE AREA IS *ABOVE* RBP: the pushes precede `push rbp`, so
;   rbx r12 r13 r14 r15 are saved at [rbp+0x08 ...] and every [rbp-N] local is inside this
;   function's own 0x38 reservation. Previously the pushes followed
;   `mov rbp,rsp`, which put the save area at [rbp-0x08 ...] -- underneath the
;   locals listed below -- so the epilogue's pops handed the CALLER out/entropy/ent_bits/cs_bits instead of r12/r13/r14/r15.
;   ALIGNMENT IS UNCHANGED: same pushes, same reservation, only reordered, so
;   RSP has the same value mod 16 at every instruction after the prologue.
bip39_generate:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x38
    mov  [rbp-0x10], rdi             ; out
    mov  [rbp-0x18], rsi             ; entropy
    mov  [rbp-0x20], rdx             ; ent_bits

    ; valid ent_bits: 128,160,192,224,256
    cmp  rdx, 128
    je   .ok
    cmp  rdx, 160
    je   .ok
    cmp  rdx, 192
    je   .ok
    cmp  rdx, 224
    je   .ok
    cmp  rdx, 256
    je   .ok
    xor  eax, eax
    jmp  .ret1
.ok:
    ; nwords = ent_bits/32*3 ; cs_bits = ent_bits/32
    mov  rax, rdx
    shr  rax, 5
    mov  [rbp-0x28], rax             ; cs_bits
    mov  rcx, rax
    lea  rax, [rax + rcx*2]          ; = ent_bits/32 * 3 = nwords
    mov  [rbp-0x30], rax             ; nwords

    ; ---- zero the bit buffer ----
    lea  rdi, [m39_bits]
    xor  eax, eax
    mov  ecx, 40
.zbt:
    mov  byte [rdi+rcx-1], 0
    loop .zbt

    ; ---- copy entropy bytes into bit buffer [0 .. ent_bytes) ----
    mov  rax, [rbp-0x20]
    shr  rax, 3                      ; ent_bytes
    mov  r13, rax
    mov  r14, [rbp-0x18]
    lea  r15, [m39_bits]
    xor  r12, r12
.ec:
    cmp  r12, r13
    jae  .ec_done
    mov  al, byte [r14+r12]
    mov  byte [r15+r12], al
    inc  r12
    jmp  .ec
.ec_done:

    ; ---- checksum = SHA256(entropy) -> m39_salt[0..31] ----
    lea  r12, [m39_salt]             ; scratch 32-byte digest
    push r12
    mov  rdi, r12
    mov  rsi, [rbp-0x18]
    mov  rdx, [rbp-0x20]
    shr  rdx, 3
    call sha256_full
    pop  r12

    ; ---- append cs_bits (<=8) bits of digest[0] at bit position ent_bits ----
    ;   bit value i (0..cs_bits-1) = (digest[0] >> (7-i)) & 1
    mov  rbx, [rbp-0x20]             ; bitpos = ent_bits
    xor  rcx, rcx                    ; cs index
.appendcs:
    mov  rax, [rbp-0x28]
    cmp  rcx, rax
    jae  .append_done
    movzx eax, byte [r12]            ; digest[0]
    mov  r8d, 7
    sub  r8d, ecx                    ; bit index = 7 - i
    bt   eax, r8d                    ; CF = bit i
    setc r9b
    movzx r9d, r9b                   ; val (0/1)
    ; set_bit(buf=m39_bits, bitpos=rbx, val=r9d)
    push rcx
    push rbx
    push r9
    lea  rdi, [m39_bits]
    mov  rsi, rbx
    mov  rdx, r9
    call bip39_set_bit
    pop  r9
    pop  rbx
    pop  rcx
    inc  rcx
    inc  rbx                         ; advance bit position
    jmp  .appendcs
.append_done:
    nop

    ; ---- extract 11-bit groups (indices) and write words ----
    lea  r12, [m39_bits]
    mov  r13, [rbp-0x30]             ; nwords
    xor  r14, r14                    ; bitpos
    mov  r15, [rbp-0x10]             ; out
    xor  rbx, rbx                    ; word counter
.wloop:
    cmp  rbx, r13
    jae  .wloop_done
    push rbx
    push r13
    push r14
    push r15
    mov  rdi, r12
    mov  rsi, r14
    call bip39_read11                ; rax = index
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ; copy the record's characters (up to its NUL) -> out; count length
    lea  rdi, [bip39_words]
    mov  rcx, rax
    imul rcx, 9
    add  rdi, rcx                    ; rdi = &record
    mov  rsi, r15                    ; out cursor
    xor  rdx, rdx                    ; length counter
.cpw:
    mov  al, byte [rdi+rdx]
    test al, al
    jz   .cpw_done
    mov  byte [rsi], al
    inc  rsi
    inc  rdx
    jmp  .cpw
.cpw_done:
    ; out cursor now past the word chars
    mov  r15, rsi
    ; separator: space unless this is the last word
    lea  rax, [rbx+1]
    cmp  rax, r13
    jae  .nospace
    mov  byte [r15], ' '
    inc  r15
.nospace:
    add  r14, 11
    inc  rbx
    jmp  .wloop
.wloop_done:
    mov  byte [r15], 0
    mov  eax, 1
.ret1:
    add  rsp, 0x38
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; Helper: bip39_parse(mnemonic) -> eax = word count (12/15/18/21/24) or -1.
;   rdi = mnemonic string.
;   Parses the mnemonic, looks up every word, rebuilds the ENT||CS bit stream
;   (into m39_bits) and the dword index array (m39_idx), and verifies the
;   SHA-256 checksum. Used by bip39_validate / bip39_mnemonic_to_entropy.
;   INTERNAL state (bss): m39_bits (bit stream), m39_idx (indices),
;   m39_salt (scratch digest), m39_nw (word count).
; ============================================================================
; CALLEE-SAVED SAVE AREA IS *ABOVE* RBP: the pushes precede `push rbp`, so
;   rbx/r12/r13/r14/r15 are saved at [rbp+0x08 ...] and the locals (mnemonic
;   @-0x10, ent_bits @-0x20, cs_bits @-0x28; deepest reference -0x28) are inside
;   this function's own 0x30 reservation. Previously the pushes followed
;   `mov rbp,rsp` and those three locals sat exactly on saved r12, r14 and r15.
;   bip39_parse is internal, but it is called from bip39_mnemonic_to_entropy and
;   bip39_validate, so the damage escaped into them.
;   ALIGNMENT IS UNCHANGED: same pushes, same reservation, only reordered.
bip39_parse:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x30
    mov  [rbp-0x10], rdi             ; mnemonic
    ; ---- split into word tokens, counting words ----
    xor  r13, r13                    ; word count
    mov  r15, rdi                    ; current scan pointer
.tokloop:
.skipsp:
    cmp  byte [r15], ' '
    jne  .have_tok
    inc  r15
    jmp  .skipsp
.have_tok:
    cmp  byte [r15], 0
    je   .tok_done                  ; end of string
    mov  r14, r15                   ; token start
.tlok:
    cmp  byte [r14], 0
    je   .tok_end
    cmp  byte [r14], ' '
    je   .tok_end
    inc  r14
    jmp  .tlok
.tok_end:
    ; token = [r15, r14) ; len = r14 - r15. Look up without touching input.
    mov  rdi, r15                    ; token start
    mov  rsi, r14
    sub  rsi, r15                    ; token length
    push r13
    call find_word_index
    pop  r13
    cmp  eax, -1
    je   .invalid                   ; unknown word (or degenerate empty token)
    mov  rcx, r13
    mov  [m39_idx + rcx*4], eax
    inc  r13
    mov  r15, r14
    jmp  .tokloop
.tok_done:
    ; ---- word count must be 12/15/18/21/24 ----
    cmp  r13, 12
    je   .nok
    cmp  r13, 15
    je   .nok
    cmp  r13, 18
    je   .nok
    cmp  r13, 21
    je   .nok
    cmp  r13, 24
    je   .nok
    jmp  .invalid
.nok:
    mov  [m39_nw], r13
    ; ent_bits = nwords*32/3 ; cs_bits = ent_bits/32
    mov  rax, r13
    imul rax, 32
    xor  edx, edx
    mov  ecx, 3
    div  rcx                        ; rax = ent_bits
    mov  [rbp-0x20], rax            ; ent_bits
    shr  rax, 5
    mov  [rbp-0x28], rax            ; cs_bits

    ; ---- zero the bit buffer ----
    lea  rdi, [m39_bits]
    xor  eax, eax
    mov  ecx, 40
.zb2:
    mov  byte [rdi+rcx-1], 0
    loop .zb2

    ; ---- write each index's 11 bits at position i*11 ----
    xor  r12, r12                   ; word counter
.wbin:
    cmp  r12, r13
    jae  .wbin_done
    mov  eax, [m39_idx + r12*4]
    mov  rbx, rax                   ; index (survives set_bit calls)
    mov  rax, r12
    imul rax, 11
    mov  r14, rax                   ; bitpos = r12*11
    xor  r15, r15                   ; bit within the 11
.bilin:
    cmp  r15, 11
    jae  .bilin_done
    mov  ecx, 10
    sub  ecx, r15d
    mov  rax, rbx
    shr  rax, cl
    and  eax, 1
    lea  rdi, [m39_bits]
    lea  rsi, [r14+r15]
    mov  rdx, rax
    push r12
    push rbx
    push r14
    push r15
    call bip39_set_bit
    pop  r15
    pop  r14
    pop  rbx
    pop  r12
    inc  r15
    jmp  .bilin
.bilin_done:
    inc  r12
    jmp  .wbin
.wbin_done:

    ; ---- extract entropy bytes (first ent_bits bits) into m39_salt ----
    xor  r12, r12                   ; byte index
    xor  r14, r14                   ; bitpos
.entb:
    mov  rax, [rbp-0x20]
    shr  rax, 3                     ; ent_bytes
    cmp  r12, rax
    jae  .entb_done
    xor  ebx, ebx                   ; byte accumulator
    xor  r15, r15                   ; bit within byte
.bybit:
    cmp  r15, 8
    jae  .bybit_done
    lea  rdi, [m39_bits]
    mov  rsi, r14
    push r12
    push r14
    push r15
    push rbx
    call bip39_bit_at
    pop  rbx
    pop  r15
    pop  r14
    pop  r12
    shl  ebx, 1
    or   ebx, eax
    inc  r14
    inc  r15
    jmp  .bybit
.bybit_done:
    mov  eax, ebx
    mov  rcx, r12
    mov  [m39_salt + rcx], al       ; entropy byte (scratch)
    inc  r12
    jmp  .entb
.entb_done:

    ; ---- checksum: SHA256(entropy) ; compare first cs_bits with stream's
    ;      last cs_bits (positions ent_bits .. ent_bits+cs_bits-1) ----
    lea  rdi, [m39_salt]            ; out digest (reuse after we hold entropy)
    lea  rsi, [m39_salt]
    mov  rdx, [rbp-0x20]
    shr  rdx, 3                     ; entropy byte length
    push rbx
    push r12
    push r13
    push r14
    push r15
    call sha256_full
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ; digest now at m39_salt[0..31] (overwrote the entropy bytes -- fine)
    ; bit position in stream of the first checksum bit:
    mov  r12, [rbp-0x20]            ; ent_bits
    xor  r13, r13                   ; cs index
.csloop:
    mov  rax, [rbp-0x28]
    cmp  r13, rax
    jae  .valid
    ; stream bit = bit_at(m39_bits, r12)
    lea  rdi, [m39_bits]
    mov  rsi, r12
    push r12
    push r13
    call bip39_bit_at
    pop  r13
    pop  r12
    mov  r14, rax                   ; stream bit
    ; digest bit = (digest[0] >> (7 - r13)) & 1
    movzx eax, byte [m39_salt]
    mov  ecx, 7
    sub  ecx, r13d
    shr  eax, cl
    and  eax, 1
    cmp  eax, r14d
    jne  .invalid                  ; checksum mismatch
    inc  r12
    inc  r13
    jmp  .csloop
.valid:
    mov  eax, [m39_nw]
    jmp  .pret
.invalid:
    mov  eax, -1
.pret:
    add  rsp, 0x30
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret



; ============================================================================
; int bip39_validate(const char* mnemonic)
;   Returns the word count (12/15/18/21/24) on success, -1 if invalid.
; ============================================================================
global bip39_validate
bip39_validate:
    call bip39_parse
    ret

; ============================================================================
; int bip39_mnemonic_to_entropy(u8 out[32], const char* mnemonic)
;   Validates the mnemonic (wordlist + checksum) and writes the recovered
;   entropy bytes to out. Returns the entropy BIT count (128..256) on success,
;   -1 if the mnemonic is invalid.
; ============================================================================
global bip39_mnemonic_to_entropy
; CALLEE-SAVED SAVE AREA IS *ABOVE* RBP: the pushes precede `push rbp`, so
;   rbx r12 r13 r14 r15 are saved at [rbp+0x08 ...] and every [rbp-N] local is inside this
;   function's own 0x20 reservation. Previously the pushes followed
;   `mov rbp,rsp`, which put the save area at [rbp-0x08 ...] -- underneath the
;   locals listed below -- so the epilogue's pops handed the CALLER out/mnemonic/ent_bits instead of r12/r13/r14.
;   ALIGNMENT IS UNCHANGED: same pushes, same reservation, only reordered, so
;   RSP has the same value mod 16 at every instruction after the prologue.
bip39_mnemonic_to_entropy:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x20
    mov  [rbp-0x10], rdi             ; out
    mov  [rbp-0x18], rsi             ; mnemonic
    mov  rdi, rsi
    call bip39_parse                 ; eax = nwords or -1
    cmp  eax, -1
    je   .bad
    ; nwords -> ent_bits = nwords*32/3
    mov  r12, rax
    mov  rax, r12
    imul rax, 32
    xor  edx, edx
    mov  ecx, 3
    div  rcx                         ; rax = ent_bits
    mov  [rbp-0x20], rax             ; ent_bits
    ; entropy bytes are at m39_salt[0 .. ent_bytes) from the parse's checksum
    ; step? NO -- the parse overwrote m39_salt with the SHA-256 digest. Rebuild
    ; the entropy directly from the bit stream (m39_bits) which is intact.
    xor  r12, r12                    ; byte index into out
    xor  r14, r14                    ; bitpos
    mov  rbx, [rbp-0x10]             ; out
.eb:
    mov  rax, [rbp-0x20]
    shr  rax, 3
    cmp  r12, rax
    jae  .eb_done
    xor  r15, r15                    ; bit within byte
    xor  ecx, ecx                    ; byte accumulator (use ecx)
.bit:
    cmp  r15, 8
    jae  .bit_done
    lea  rdi, [m39_bits]
    mov  rsi, r14
    push rcx
    push r12
    push r14
    push r15
    call bip39_bit_at
    pop  r15
    pop  r14
    pop  r12
    pop  rcx
    shl  ecx, 1
    or   ecx, eax
    inc  r14
    inc  r15
    jmp  .bit
.bit_done:
    mov  byte [rbx+r12], cl
    inc  r12
    jmp  .eb
.eb_done:
    mov  rax, [rbp-0x20]
    jmp  .ret
.bad:
    mov  rax, -1
.ret:
    add  rsp, 0x20
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; int bip39_mnemonic_to_seed(u8 seed[64], const char* mnemonic,
;                            const char* passphrase, i64 passlen)
;   BIP39 seed derivation: PBKDF2-HMAC-SHA512(P=mnemonic, S="mnemonic"||pass,
;   c=2048, dkLen=64) -> 64-byte seed. passphrase may be NULL (treated empty).
;   Returns 1 on success.
; ============================================================================
global bip39_mnemonic_to_seed
; CALLEE-SAVED SAVE AREA IS *ABOVE* RBP: the pushes precede `push rbp`, so
;   rbx r12 r13 r14 r15 are saved at [rbp+0x08 ...] and every [rbp-N] local is inside this
;   function's own 0x40 reservation. Previously the pushes followed
;   `mov rbp,rsp`, which put the save area at [rbp-0x08 ...] -- underneath the
;   locals listed below -- so the epilogue's pops handed the CALLER seed/mnemonic/passphrase/passlen instead of r12/r13/r14/r15.
;   ALIGNMENT IS UNCHANGED: same pushes, same reservation, only reordered, so
;   RSP has the same value mod 16 at every instruction after the prologue.
bip39_mnemonic_to_seed:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x40
    mov  [rbp-0x10], rdi             ; seed
    mov  [rbp-0x18], rsi             ; mnemonic
    mov  [rbp-0x20], rdx             ; passphrase (may be NULL)
    mov  [rbp-0x28], rcx             ; passlen

    ; ---- CRY-4 (audit 2026-09-03): BOUND THE PASSPHRASE ----
    ;
    ; The salt is built as "mnemonic" || passphrase into m39_salt, which is
    ; 512 bytes -- so a passphrase over 504 bytes wrote past it into m39_msg,
    ; and the copy had no bound at all. Reachable without any RPC: the wallet
    ; store reads BMC_WALLET_PASS with strlen and daemon/wallet_cli.c takes
    ; the passphrase as a command-line argument, neither of which was capped.
    ; (hmac_sha512's own `tmp` scratch has 1032 bytes of room for the message,
    ; so THIS buffer is the one that goes first.)
    ;
    ; 504 is the real capacity, not a smaller round number: anything that
    ; derived a seed correctly before must still derive the SAME seed, or a
    ; wallet becomes unopenable. Everything past it produced corruption, and
    ; now produces a clean 0.
    ;
    ; A negative length is refused for the same reason -- the copy loop's
    ; bound is a signed compare.
    cmp  rcx, 0
    jl   .b39s_toolong
    cmp  rcx, 504
    jg   .b39s_toolong

    ; ---- mnemonic length (HMAC key) ----
    mov  rdi, rsi
    call bip39_strlen
    mov  [rbp-0x30], rax             ; mnlen

    ; ---- build salt = "mnemonic" || passphrase into m39_salt ----
    lea  rdi, [m39_seed_salt]
    lea  rsi, [m39_salt]
    mov  rcx, 8
.cs:
    mov  al, byte [rdi]
    mov  byte [rsi], al
    inc  rdi
    inc  rsi
    dec  rcx
    jnz  .cs
    ; saltlen = 8 + passlen
    xor  rbx, rbx                    ; saltlen
    mov  rbx, 8
    mov  rax, [rbp-0x20]             ; passphrase
    test rax, rax
    jz   .salt_done
    mov  rcx, [rbp-0x28]             ; passlen
    xor  r13, r13
.pcloop:
    cmp  r13, rcx
    jae  .salt_done
    mov  r9b, byte [rax+r13]         ; passphrase byte (r9b, NOT al: al would clobber rax)
    mov  byte [rsi+r13], r9b
    inc  r13
    inc  rbx
    jmp  .pcloop
.salt_done:

    ; ---- first message = salt || INT(1) (4-byte BE 0x00000001) into m39_msg ----
    lea  rdi, [m39_salt]
    lea  rsi, [m39_msg]
    mov  rcx, rbx                    ; saltlen
    xor  r14, r14
.fm:
    cmp  r14, rcx
    jae  .fm_done
    mov  al, byte [rdi+r14]
    mov  byte [rsi+r14], al
    inc  r14
    jmp  .fm
.fm_done:
    mov  byte [m39_msg+rbx+0], 0
    mov  byte [m39_msg+rbx+1], 0
    mov  byte [m39_msg+rbx+2], 0
    mov  byte [m39_msg+rbx+3], 1
    ; first message length = saltlen + 4
    lea  rax, [rbx+4]
    mov  [rbp-0x38], rax             ; msg1_len

    ; ---- U1 = HMAC-SHA512(key=mnemonic, msg = salt||1) ----
    mov  rdi, [rbp-0x18]
    call bip39_strlen
    push rax
    push rbx
    push rdi
    lea  rdi, [m39_prev]             ; out
    mov  rsi, [rbp-0x18]             ; key = mnemonic
    mov  rdx, [rbp-0x30]             ; keylen
    lea  rcx, [m39_msg]              ; msg = salt||1
    mov  r8, [rbp-0x38]              ; msglen
    call hmac_sha512
    pop  rdi
    pop  rbx
    pop  rax

    ; ---- acc = U1 ----
    lea  rdi, [m39_acc]
    lea  rsi, [m39_prev]
    mov  rcx, 64
.a1:
    mov  al, byte [rsi]
    mov  byte [rdi], al
    inc  rdi
    inc  rsi
    dec  rcx
    jnz  .a1

    ; ---- loop 2047 more times: U = HMAC(mn, prev) ; acc ^= U ; prev = U ----
    mov  r15, 2047
.pbloop:
    test r15, r15
    jz   .pbdone
    ; HMAC(cur=out, key=mnemonic, keylen, msg=prev, 64)
    lea  rdi, [m39_cur]
    mov  rsi, [rbp-0x18]
    mov  rdx, [rbp-0x30]
    lea  rcx, [m39_prev]
    mov  r8, 64
    push r15
    call hmac_sha512
    pop  r15
    ; acc = acc XOR cur
    lea  r12, [m39_acc]
    lea  r13, [m39_cur]
    mov  rcx, 64
.xor:
    mov  al, byte [r13]
    xor  byte [r12], al
    inc  r12
    inc  r13
    dec  rcx
    jnz  .xor
    ; prev = cur
    lea  rdi, [m39_prev]
    lea  rsi, [m39_cur]
    mov  rcx, 64
.pc:
    mov  al, byte [rsi]
    mov  byte [rdi], al
    inc  rdi
    inc  rsi
    dec  rcx
    jnz  .pc
    dec  r15
    jmp  .pbloop
.pbdone:

    ; ---- seed = acc (64 bytes) ----
    mov  rdi, [rbp-0x10]
    lea  rsi, [m39_acc]
    mov  rcx, 64
.se:
    mov  al, byte [rsi]
    mov  byte [rdi], al
    inc  rdi
    inc  rsi
    dec  rcx
    jnz  .se

    mov  eax, 1
    jmp  .b39s_ret
.b39s_toolong:
    xor  eax, eax                    ; CRY-4: passphrase over m39_salt capacity
.b39s_ret:
    add  rsp, 0x40
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
