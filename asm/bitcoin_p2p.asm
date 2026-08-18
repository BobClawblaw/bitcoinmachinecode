; ============================================================================
; bitcoin_p2p.asm -- Bitcoin P2P message payload builders/parsers.
;   100% AI-authored x86-64 assembly.  Byte-exact vs validation/p2p_oracle.py.
;
; All wire integers are LITTLE-endian (Bitcoin convention).
;
; Exports:
;   long p2p_getheaders(u8* out, const u8* locator, long count, const u8 stop[32])
;        -> serialized getheaders payload length, or -1 (count out of
;        [1,252]). `locator` is COUNT*32 contiguous hash bytes (Stage A
;        extension -- was fixed at exactly one 32-byte hash/count==1 before;
;        count==1 callers are unaffected byte-for-byte, see below).
;   long p2p_getdata_block(u8* out, const u8 hash[32])   -> 37.
;   long p2p_ping(u8* out, u64 nonce)                   -> 8.
;   long p2p_headers_count(const u8* payload, long plen) -> #header entries
;        (parses the leading CompactSize), or -1 on malformed.
;
; STAGE A NOTE (real multi-hash locator, reorg/fork-choice primitive #2):
;   p2p_getheaders used to `jne .err` on any count != 1. It now accepts
;   count in [1,252] (a single-byte CompactSize varint covers that whole
;   range; Bitcoin's own doubling-gap locator construction -- see
;   daemon/locator_build.c -- never needs more than ~32 entries to reach
;   genesis from any realistic chain height, so 252 is a generous, still
;   provably-safe ceiling rather than an arbitrary smaller cap). Every
;   existing call site (bitcoind.asm's node_sync / node_ibd_headers) still
;   hardcodes count=1 and is byte-for-byte unaffected: for count=1 the new
;   code path produces the exact same 69-byte payload the old count==1-only
;   path did. This extension is standalone/additive -- nothing new calls
;   count>1 yet; wiring a real multi-hash locator into the live sync loop is
;   a later, separately reviewed stage.
; ============================================================================

%include "version.inc"   ; single source of truth: NODE_PROTOCOL_VER for getheaders

default rel
section .text

global p2p_getheaders
; out[rdi], locator[rsi] (count*32 contiguous hash bytes), count[edx], stop[rcx]
p2p_getheaders:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi          ; out
    mov  r13, rsi          ; locator array
    mov  r14, rcx          ; stop
    mov  ebx, edx          ; count
    cmp  ebx, 1
    jl   .err
    cmp  ebx, 252          ; single-byte CompactSize varint range (0..0xfc)
    ja   .err
    ; protocol version (from version.inc single source of truth)
    mov  dword [r12], NODE_PROTOCOL_VER
    ; locator count varint (1 byte, count in [1,252])
    mov  al, bl
    mov  [r12+4], al
    ; locator hashes at out+5, count*32 bytes
    lea  rdi, [r12+5]
    mov  rsi, r13
    mov  eax, ebx
    imul eax, 32
    mov  ecx, eax
    rep  movsb
    ; stop hash at out+5+count*32 (eax still holds count*32 -- rep movsb
    ; only clobbers rcx/rdi/rsi, not rax)
    lea  rdi, [r12+5]
    add  rdi, rax
    mov  rsi, r14
    mov  ecx, 32
    rep  movsb
    ; length = 5 + count*32 + 32
    add  eax, 37
    jmp  .ret
.err:
    mov  rax, -1              ; MUST be a 64-bit mov: `mov eax,-1` zero-extends
                               ; to 0x00000000FFFFFFFF, not true -1, breaking
                               ; any caller comparing the `long` return value
                               ; against -1 (caught by tests/test_locator.c).
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

; ============================================================================
; p2p_inv_count(payload, plen) -> # inventory entries (CompactSize), or -1.
;   inv payload = [count varint][per item 36B = type u32 LE + hash32].
;   Validates that plen holds count*36 + varintlen.
; ============================================================================
global p2p_inv_count
p2p_inv_count:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    mov  r12, rsi                ; plen
    cmp  rsi, 1
    jb   .err
    mov  al, [rdi]               ; first varint byte
    mov  r8, 1
    xor  ecx, ecx
    movzx ecx, al
    cmp  al, 0xfd
    jb   .chk
    cmp  al, 0xfe
    je   .err                    ; 0xfe/0xff (u32/u64) not used for inv
    cmp  al, 0xfd
    jne  .err
    cmp  rsi, 3
    jb   .err
    movzx ecx, word [rdi+1]      ; count (LE u16)
    mov  r8, 3
.chk:
    mov  rax, rcx
    imul rax, 36
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

; ============================================================================
; p2p_inv_get(payload, i, out_type, out_hash32) -> 1 ok / 0 (i out of range).
;   Returns the i-th inventory item's wire type (u32 LE) and 32-byte hash.
;   Assumes count validated by p2p_inv_count (varint is 1 or 3 bytes).
; ============================================================================
global p2p_inv_get
p2p_inv_get:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi                ; payload
    mov  r13, rsi                ; i
    mov  r14, rdx                ; out_type*
    mov  r15, rcx                ; out_hash*
    ; parse the count varint and bounds-check i < count
    mov  al, [r12]
    xor  r10, r10
    mov  r8, 1                   ; varint len (default 1)
    mov  r10b, al
    movzx r10, r10b              ; count (1-byte path)
    cmp  al, 0xfd
    jb   .cok
    cmp  al, 0xfe
    je   .err                    ; 0xfe not used for inv
    ; 0xfd u16
    mov  r8, 3
    movzx r10, word [r12+1]
.cok:
    ; if i >= count -> out of range
    cmp  r13, r10
    jae  .err
    ; item offset = varintlen + i*36
    mov  rax, r13
    imul rax, 36
    add  rax, r8
    add  rax, r12                 ; &type
    ; type u32 LE
    mov  edx, [rax]
    mov  [r14], edx
    ; hash at +4
    lea  rdx, [rax+4]
    ; copy 32 bytes hash -> out_hash
    xor  ecx, ecx
.hloop:
    cmp  rcx, 32
    jae  .hdone
    mov  r9b, byte [rdx+rcx]
    mov  byte [r15+rcx], r9b
    inc  rcx
    jmp  .hloop
.hdone:
    mov  eax, 1
    jmp  .ret
.err:
    xor  eax, eax
.ret:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
