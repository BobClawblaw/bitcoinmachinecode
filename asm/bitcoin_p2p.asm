; ============================================================================
; bitcoin_p2p.asm -- Bitcoin P2P message payload builders/parsers.
;   100% AI-authored x86-64 assembly.  Byte-exact vs validation/p2p_oracle.py.
;
; All wire integers are LITTLE-endian (Bitcoin convention).
;
; Exports:
;   long p2p_getheaders(u8* out, const u8 locator[32], long count, const u8 stop[32])
;        -> 69 (count==1) serialized getheaders payload.
;   long p2p_getdata_block(u8* out, const u8 hash[32])   -> 37.
;   long p2p_ping(u8* out, u64 nonce)                   -> 8.
;   long p2p_headers_count(const u8* payload, long plen) -> #header entries
;        (parses the leading CompactSize), or -1 on malformed.
; ============================================================================

default rel
section .text

global p2p_getheaders
; out[rdi], locator[rsi], count[rdx], stop[rcx]
p2p_getheaders:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi          ; out
    mov  r13, rsi          ; locator
    mov  r14, rcx          ; stop
    ; version = 70016 (0x011180) little-endian -> 80 11 01 00
    mov  r8, r12
    mov  dword [r8], 0x00011180
    ; locator count = count (assume small <= 252 -> 1-byte varint)
    mov  r9, r12
    add  r9, 4
    mov  al, dl            ; count (low byte)
    mov  [r9], al
    add  r9, 1
    ; locator hashes: we only build count==1 (one hash) in v1
    mov  ecx, edx
    cmp  ecx, 1
    jne  .err
    ; copy locator[32] -> r9
    mov  rdi, r9
    mov  rsi, r13
    mov  rcx, 32
    rep  movsb
    add  r9, 32
    ; stop hash[32]
    mov  rdi, r9
    mov  rsi, r14
    mov  rcx, 32
    rep  movsb
    add  r9, 32
    ; length = r9 - out
    mov  rax, r9
    sub  rax, r12
    jmp  .ret
.err:
    mov  rax, -1
.ret:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

global p2p_getdata_block
; out[rdi], hash[rsi] -> 37
; Wire-correct inventory getdata (verified byte-exact vs validation/p2p_oracle.py AND
; confirmed LIVE against a real node): [count varint=0x01][type int32 LE=2][hash 32].
; The inventory `type` is a 4-byte little-endian int32 (NOT a single-byte varint --
; that was a mistaken "fix" in an earlier LOG stage that emitted a 34-byte/short
; message real peers ignore). Correct msg: 1 + 4 + 32 = 37 bytes, hash at +5.
p2p_getdata_block:
    push rbp
    mov  rbp, rsp
    push r12
    mov  r12, rdi
    mov  byte [r12], 1          ; inventory count varint = 1
    mov  dword [r12+1], 2       ; MSG_BLOCK type = 2 (int32 LE at +1)
    lea  rdi, [r12+5]           ; hash at +5
    mov  rsi, rsi               ; hash
    mov  rcx, 32
    rep  movsb
    mov  rax, 37                ; 1 + 4 + 32
    pop  r12
    pop  rbp
    ret

global p2p_ping
; out[rdi], nonce[rsi]
p2p_ping:
    push rbp
    mov  rbp, rsp
    mov  [rdi], rsi             ; 8-byte LE nonce
    mov  rax, 8
    pop  rbp
    ret

global p2p_headers_count
; payload[rdi], plen[rsi] -> count or -1
p2p_headers_count:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    mov  r12, rsi               ; plen
    cmp  rsi, 1
    jb   .err
    mov  al, [rdi]              ; first varint byte
    mov  r8, 1                  ; varint byte count (default 1)
    xor  ecx, ecx
    movzx ecx, al
    cmp  al, 0xfd
    jb   .chk                   ; 1-byte varint path
    cmp  al, 0xfc
    je   .chk                   ; (0xfc never used; treat as len)
    ; 0xfd/0xfe/0xff: needs more bytes
    cmp  al, 0xfd
    jne  .err
    cmp  rsi, 3
    jb   .err
    movzx ecx, word [rdi+1]     ; count (LE u16)
    mov  r8, 3                  ; varint byte count = 3
.chk:
    ; bytes needed = varintlen + count*81 ; verify <= plen
    mov  rax, rcx               ; count
    imul rax, 81
    add  rax, r8
    cmp  rax, r12
    ja   .err
    mov  rax, rcx
    jmp  .ret
.err:
    mov  rax, -1
.ret:
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
