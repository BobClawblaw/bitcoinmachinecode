; ============================================================================
; bitcoin_cmpct.asm -- BIP152 compact blocks: SipHash-2-4 short-tx-ids and the
;   compact-block wire codecs (sendcmpct / cmpctblock / getblocktxn / blocktxn).
;   100% AI-authored x86-64 assembly.
;
; Byte-exact vs Bitcoin Core (v31.99 master at storage/bitcoin-core-source):
;   short-tx-id = SipHash24_uint256(key=sha256(hdr80||nonceLE8) low16,
;                                   msg=wtxid) & 0xffffffffffff
;   verified LIVE: the cmpctblock short IDs Core put on the wire over loopback
;   equal these functions' output (validation/bip152_vectors.h).
;
; Exports:
;   u64  siphash24_uint256(u64 k0, u64 k1, const u8 msg32[32])
;   void bip152_shortid(u8 out[6], const u8 hdr[80], u64 nonce, const u8 wtxid[32])
;   long p2p_sendcmpct(u8* out, u8 announce, u64 version)          -> 9
;   long p2p_getblocktxn_build(u8* out, const u8 bh[32], const u16* idx, long n)
;        -> BlockTransactionsRequest with DifferenceFormatter-encoded indexes
;   long p2p_blocktxn_build(u8* out, const u8 bh[32],
;                           const u8* const* txs, const long* lens, long n)
;   long cmpctblock_shorttxids_count(const u8* payload, long plen)  -> n or -1
;   long cmpctblock_shorttxid(u8 out6[6], const u8* payload, long i)
;        -> 1 ok / 0 out of range
; ============================================================================
default rel

extern sha256_full

section .text

; ============================================================================
; siphash24_uint256(k0=rdi, k1=rsi, msg32=rdx) -> rax (u64 hash)
;   Faithful port of crypto/siphash.cpp PresaltedSipHasher::operator()(uint256)
;   For the 32-byte message d_i = LE64 word i, then a final (32<<56) block.
;   State kept in callee-saved: v0=rbx v1=r12 v2=r13 v3=r14; d in r15.
; ============================================================================
global siphash24_uint256
siphash24_uint256:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r8,  rdx          ; msg
    ; v0 = C0 ^ k0
    mov  rax, [C0]
    xor  rax, rdi
    mov  rbx, rax
    ; v1 = C1 ^ k1
    mov  rax, [C1]
    xor  rax, rsi
    mov  r12, rax
    ; v2 = C2 ^ k0
    mov  rax, [C2]
    xor  rax, rdi
    mov  r13, rax
    ; v3 = C3 ^ k1
    mov  rax, [C3]
    xor  rax, rsi
    mov  r14, rax
    ; 4x Compress2(words)
    xor  ecx, ecx
.l0:
    cmp  rcx, 4
    jae  .l0d
    mov  r15, [r8 + rcx*8]   ; d (LE)
    xor  r14, r15            ; v3 ^= d
    call .sipround2
    xor  rbx, r15            ; v0 ^= d
    inc  rcx
    jmp  .l0
.l0d:
    ; Compress2(32<<56)
    mov  r15, 32
    shl  r15, 56
    xor  r14, r15
    call .sipround2
    xor  rbx, r15
    ; Finalize4: v2 ^= 0xFF ; 4x SipRound (NOT 4x SipRound2!)
    mov  rax, 0xFF
    xor  r13, rax
    mov  rcx, 4
.f0:
    call .sipround
    dec  rcx
    jnz  .f0
    ; out = v0 ^ v1 ^ v2 ^ v3
    mov  rax, rbx
    xor  rax, r12
    xor  rax, r13
    xor  rax, r14
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; .sipround2 -- two SipRounds on v0=rbx v1=r12 v2=r13 v3=r14. Clobbers rax,rdx.
.sipround2:
    call .sipround
    call .sipround
    ret
; .sipround -- one SipRound. Clobbers rax,rdx.
.sipround:
    ; v0 += v1 ; v1 = rotl(v1,13) ; v1 ^= v0 ; v0 = rotl(v0,32)
    add  rbx, r12
    mov  rax, r12
    rol  rax, 13
    mov  r12, rax
    xor  r12, rbx
    rol  rbx, 32
    ; v2 += v3 ; v3 = rotl(v3,16) ; v3 ^= v2
    add  r13, r14
    mov  rax, r14
    rol  rax, 16
    mov  r14, rax
    xor  r14, r13
    ; v0 += v3 ; v3 = rotl(v3,21) ; v3 ^= v0
    add  rbx, r14
    mov  rax, r14
    rol  rax, 21
    mov  r14, rax
    xor  r14, rbx
    ; v2 += v1 ; v1 = rotl(v1,17) ; v1 ^= v2 ; v2 = rotl(v2,32)
    add  r13, r12
    mov  rax, r12
    rol  rax, 17
    mov  r12, rax
    xor  r12, r13
    rol  r13, 32
    ret

section .data
align 8
C0: dq 0x736f6d6570736575
C1: dq 0x646f72616e646f6d
C2: dq 0x6c7967656e657261
C3: dq 0x7465646279746573
sid_buf: times 96 db 0

section .text
; ============================================================================
; memcpy_len(dst=rdi, src=rsi, n=rdx) -- byte mover. Clobbers rax,rcx.
; ============================================================================
memcpy_len:
    xor  ecx, ecx
.mc:
    cmp  rcx, rdx
    jae  .mcd
    mov  al, [rsi+rcx]
    mov  [rdi+rcx], al
    inc  rcx
    jmp  .mc
.mcd:
    ret

; ============================================================================
; bip152_shortid(out6=rdi, hdr=rsi, nonce=rdx, wtxid=rcx)
;   Writes 6-byte LE short id to out6; returns the u64 in rax.
;   H=sha256(hdr||nonceLE8); k0=H[0:8],k1=H[8:16];
;   sid=siphash24_uint256(k0,k1,wtxid)&0xffffffffffff
; ============================================================================
global bip152_shortid
bip152_shortid:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 40
    mov  r12, rdi          ; out6
    mov  r13, rsi          ; hdr
    mov  r14, rdx          ; nonce
    mov  r15, rcx          ; wtxid
    ; NOTE: saved regs occupy rbp-8..rbp-48. Any 32-byte scratch (the digest)
    ; MUST live below rbp-48 — use rbp-72 (within the sub rsp,40 local area,
    ; rbp-88..rbp-49). Writing at rbp-32 previously clobbered the saved r14.
    ; sid_buf = hdr[80] || nonce LE8
    lea  rdi, [sid_buf]
    mov  rsi, r13
    mov  rdx, 80
    call memcpy_len
    lea  rdi, [sid_buf+80]
    mov  [rdi], r14
    ; sha256_full(digest@rbp-72, sid_buf, 88)
    lea  rdi, [rbp-72]
    lea  rsi, [sid_buf]
    mov  rdx, 88
    call sha256_full
    ; k0=digest[0:8] LE, k1=digest[8:16] LE
    mov  rdi, [rbp-72]
    mov  rsi, [rbp-64]
    mov  rdx, r15          ; msg = wtxid
    call siphash24_uint256
    and  rax, 0xffffffffffff
    ; write 6-byte LE
    mov  rcx, rax
    mov  byte [r12],   cl
    shr  rcx, 8
    mov  byte [r12+1], cl
    shr  rcx, 8
    mov  byte [r12+2], cl
    shr  rcx, 8
    mov  byte [r12+3], cl
    shr  rcx, 8
    mov  byte [r12+4], cl
    shr  rcx, 8
    mov  byte [r12+5], cl
    add  rsp, 40
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; p2p_sendcmpct(out=rdi, announce=rsi(u8), version=rdx(u64)) -> 9
;   payload = announce(u8) || version(u64 LE)
; ============================================================================
global p2p_sendcmpct
p2p_sendcmpct:
    mov  byte [rdi], sil
    mov  [rdi+1], rdx
    mov  rax, 9
    ret

; ============================================================================
; varint_put(dst=rdi, val=rsi) -> rax bytes written (1/3/5/9). Clobbers rcx.
; ============================================================================
varint_put:
    cmp  rsi, 0xfd
    jb   .v1
    cmp  rsi, 0xffff
    jbe  .v3
    cmp  rsi, 0xffffffff
    jbe  .v5
    mov  byte [rdi], 0xff
    mov  [rdi+1], rsi
    mov  rax, 9
    ret
.v5:
    mov  byte [rdi], 0xfe
    mov  dword [rdi+1], esi
    mov  rax, 5
    ret
.v3:
    mov  byte [rdi], 0xfd
    mov  word [rdi+1], si
    mov  rax, 3
    ret
.v1:
    mov  byte [rdi], sil
    mov  rax, 1
    ret

; ============================================================================
; p2p_getblocktxn_build(out=rdi, blockhash=rsi, indexes=rdx, n=rcx) -> len
;   BlockTransactionsRequest: blockhash(32) || count(varint) ||
;   indexes DifferenceFormatter-encoded: stored[i] = v - shift; shift = prev+1.
; ============================================================================
global p2p_getblocktxn_build
p2p_getblocktxn_build:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi          ; out
    mov  r13, rsi          ; blockhash
    mov  r14, rdx          ; indexes
    mov  rbx, rcx          ; n
    ; copy blockhash
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, 32
    call memcpy_len
    ; count varint
    lea  rdi, [r12+32]
    mov  rsi, rbx
    call varint_put
    lea  r13, [r12+32+rax] ; p = after count
    ; difference-encode: shift = 0
    xor  rdx, rdx          ; rdx = shift
    xor  ecx, ecx          ; i
.gloop:
    cmp  rcx, rbx
    jae  .gdone
    movzx rax, word [r14 + rcx*2]   ; v
    sub  rax, rdx                  ; stored = v - shift
    ; put varint
    mov  rdi, r13
    mov  rsi, rax
    push rcx
    push rdx
    push r14
    push rbx
    call varint_put
    pop  rbx
    pop  r14
    pop  rdx
    pop  rcx
    mov  r8, rax                    ; bytes written
    ; shift = v + 1
    movzx rax, word [r14 + rcx*2]
    add  rax, 1
    mov  rdx, rax
    add  r13, r8
    inc  rcx
    jmp  .gloop
.gdone:
    mov  rax, r13
    sub  rax, r12
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; p2p_blocktxn_build(out=rdi, blockhash=rsi, txs=rdx(const u8* const*),
;                    lens=rcx(const long*), n=r8) -> len
;   BlockTransactions: blockhash(32) || txn count(varint) || concat txs.
; ============================================================================
global p2p_blocktxn_build
p2p_blocktxn_build:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi          ; out
    mov  r13, rsi          ; blockhash
    mov  r14, rdx          ; txs
    mov  r15, rcx          ; lens
    mov  rbx, r8           ; n
    ; blockhash
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, 32
    call memcpy_len
    ; txn count varint
    lea  rdi, [r12+32]
    mov  rsi, rbx
    call varint_put
    lea  r13, [r12+32+rax]
    xor  ecx, ecx          ; i
.bloop:
    cmp  rcx, rbx
    jae  .bdone
    ; tx ptr = [r14 + rcx*8], len = [r15 + rcx*8]
    mov  rsi, [r14 + rcx*8]
    mov  rdx, [r15 + rcx*8]
    mov  rdi, r13
    push rcx
    push rbx
    push r14
    push r15
    call memcpy_len
    pop  r15
    pop  r14
    pop  rbx
    pop  rcx
    add  r13, [r15 + rcx*8]
    inc  rcx
    jmp  .bloop
.bdone:
    mov  rax, r13
    sub  rax, r12
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; cmpctblock_shorttxids_count(payload=rdi, plen=rsi) -> n or -1
;   Parses header(80)+nonce(8)+count(varint), validates bounds.
; ============================================================================
global cmpctblock_shorttxids_count
cmpctblock_shorttxids_count:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    mov  r12, rsi          ; plen
    cmp  rsi, 89
    jb   .err
    ; count varint at payload+88
    mov  al, [rdi+88]
    cmp  al, 0xfd
    jb   .c1
    cmp  al, 0xfe
    je   .err
    cmp  al, 0xfd
    jne  .err
    cmp  rsi, 91
    jb   .err
    movzx rbx, word [rdi+89]
    mov  r8, 3             ; varintlen
    jmp  .have
.c1:
    movzx rbx, byte [rdi+88]
    mov  r8, 1             ; varintlen
.have:
    ; need 88 + varintlen + n*6 <= plen
    mov  rax, rbx
    imul rax, 6
    add  rax, r8
    add  rax, 88
    cmp  rax, rsi
    ja   .err
    mov  rax, rbx
    pop  r12
    pop  rbx
    pop  rbp
    ret
.err:
    mov  rax, -1
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; cmpctblock_shorttxid(out6=rdi, payload=rsi, i=rdx) -> 1 ok / 0 out of range
;   Assumes count was validated; varint is 1 or 3 bytes (single-byte typical).
; ============================================================================
global cmpctblock_shorttxid
cmpctblock_shorttxid:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    mov  rbx, rdi          ; out6
    mov  r12, rsi          ; payload
    mov  r13, rdx          ; i
    ; parse count and varint len
    mov  al, [r12+88]
    xor  rcx, rcx          ; count
    mov  r8, 1             ; varintlen
    cmp  al, 0xfd
    jb   .cok
    mov  r8, 3
    movzx rcx, word [r12+89]
    jmp  .have
.cok:
    movzx rcx, byte [r12+88]
.have:
    cmp  r13, rcx
    jae  .err
    ; shorttxids start at 88+varintlen
    mov  rax, r13
    imul rax, 6
    add  rax, r8
    add  rax, 88
    add  rax, r12          ; addr of shortid i
    ; copy 6 bytes to out6
    mov  rdx, 6
    mov  rdi, rbx
    mov  rsi, rax
    xor  ecx, ecx
.hc:
    cmp  rcx, rdx
    jae  .hd
    mov  r9b, byte [rsi+rcx]
    mov  byte [rdi+rcx], r9b
    inc  rcx
    jmp  .hc
.hd:
    mov  rax, 1
    jmp  .ret
.err:
    xor  eax, eax
.ret:
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; Block tx enumeration helpers (used by the getblocktxn/blocktxn server path).
; A serialized block = header(80) || txcount(varint) || concat txs (each,
;   txlen = tx_parse info[0]; witness-bearing txs carry their witness).

; block_txcount(blockbuf=rdi, blen=rsi) -> # txs or -1
; ============================================================================
global block_txcount
block_txcount:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    mov  r12, rsi          ; blen
    cmp  rsi, 81
    jb   .err
    mov  al, [rdi+80]
    movzx rax, al
    cmp  al, 0xfd
    jb   .ok
    mov  rax, -1           ; only single-byte tx count supported here (blocks <253 txs)
    jmp  .ret
.ok:
    pop  r12
    pop  rbx
    pop  rbp
    ret
.err:
    mov  rax, -1
.ret:
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; block_tx_at(blockbuf=rdi, blen=rsi, index=rdx, out_ptr=rcx, out_len=r8)
;   -> 1 ok / 0 fail. Returns pointer+length of the index-th tx (witness
;   included, exactly as serialized in the block) via out_ptr/out_len.
;   Uses tx_parse (bitcoin_tx.asm) to find each tx's boundary.
; ============================================================================
extern tx_parse
global block_tx_at
block_tx_at:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x90         ; locals below saved regs (rbp-8..rbp-48):
                           ;   ntx  @ rbp-0x90, txinfo[64] @ rbp-0x80..rbp-0x41
                           ;   rsp=rbp-0x98, so rbp-0x90..rbp-0x09 is writable.
    mov  r12, rdi          ; blockbuf
    mov  r13, rsi          ; blen
    mov  r14, rdx          ; index
    mov  r15, rcx          ; out_ptr
    mov  rbx, r8           ; out_len
    ; header(80) + txcount varint(1 byte)
    cmp  r13, 82
    jb   .fail
    movzx rax, byte [r12+80]
    mov  [rbp-0x90], rax   ; ntx
    mov  qword [rbp-0x88], 0 ; i = 0  (loop counter, survives nested calls)
    lea  rcx, [r12+81]     ; cursor = first tx
    ; (rcx = cursor must survive the tx_parse call -> keep it in a local too)
    mov  [rbp-0x80+0x40], rcx ; keep cursor@rbp-0x40 (empty slot below txinfo)
.walk:
    mov  rax, [rbp-0x88]
    cmp  rax, qword [rbp-0x90]
    jae  .fail             ; i >= ntx
    ; remaining = block end - cursor
    mov  rdi, [rbp-0x40]
    mov  rax, r12
    add  rax, r13
    sub  rax, rdi
    cmp  rax, 9
    jb   .fail             ; insufficient room for a tx
    ; tx_parse(info@rbp-0x80, cursor, remaining) -> info[0]=txlen
    lea  rdi, [rbp-0x80]
    mov  rsi, [rbp-0x40]   ; cursor
    mov  rdx, rax          ; remaining
    call tx_parse
    test rax, rax
    jz   .fail
    mov  rax, [rbp-0x80]   ; txlen (txinfo[0])
    cmp  rax, 0
    jle  .fail
    ; is i == index?
    mov  rdx, [rbp-0x88]
    cmp  rdx, r14
    jne  .next
    ; yes: return ptr=cursor, len=txlen
    mov  rdx, [rbp-0x40]
    mov  [r15], rdx
    mov  [rbx], rax
    mov  rax, 1
    jmp  .ret
.next:
    ; cursor += txlen
    mov  rdx, [rbp-0x40]
    add  rdx, rax
    mov  [rbp-0x40], rdx
    inc  qword [rbp-0x88]
    jmp  .walk
.fail:
    xor  eax, eax
.ret:
    add  rsp, 0x90
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; tx_wtxid(out32=rdi, tx=rsi, txlen=rdx)
;   wtxid = sha256d(full witness serialization of tx) -- the hash BIP152 short
;   ids are computed over. (For non-witness txs this equals txid.)
; ============================================================================
extern sha256d
global tx_wtxid
tx_wtxid:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    mov  r12, rdi          ; out
    mov  r13, rsi          ; tx
    ; sha256d(out=r12, msg=tx=r13, len=rdx)
    mov  rdi, r12
    mov  rsi, r13
    ; rdx already = txlen (3rd param)
    call sha256d
    pop  r13
    pop  r12
    pop  rbp
    ret

; ============================================================================
; cmpctblock_build(out=rdi, blockbuf=rsi, blen=rdx, nonce=rcx) -> len or -1
;   Builds a BIP152 cmpctblock: header(80) || nonce(8 LE) || nshort(varint) ||
;   shortids(6B LE each) || nprefilled(varint=1) || index0(varint) || coinbase.
;   shorttxid[i] = bip152_shortid(hdr, nonce, wtxid(tx_{i+1}))
; ============================================================================
global cmpctblock_build
cmpctblock_build:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; saved regs: rbx@-8 r12@-16 r13@-24 r14@-32 r15@-40 (rbp-0x08..rbp-0x28).
    ; Locals must live BELOW rbp-0x28: use rbp-0x40..rbp-0x60.
    sub  rsp, 0x60
    mov  r12, rdi          ; out
    mov  r13, rsi          ; blockbuf
    mov  r14, rdx          ; blen
    mov  r15, rcx          ; nonce
    mov  [rbp-0x58], r14   ; blen (survives calls)
    ; header -> out
    lea  rdi, [r12]
    mov  rsi, r13
    mov  rdx, 80
    push rbx
    call memcpy_len
    pop  rbx
    ; nonce LE8
    mov  [r12+80], r15
    ; ntx = blockbuf[80] ; nshort = ntx-1 (single-byte varint, ntx<=253)
    movzx rax, byte [r13+80]
    mov  [rbp-0x50], rax   ; ntx
    lea  rax, [rax-1]
    mov  byte [r12+88], al
    lea  rax, [r12+89]     ; sid ptr
    mov  [rbp-0x48], rax
    mov  qword [rbp-0x40], 1  ; i = 1 (short-id tx index)
.cbloop:
    mov  rax, [rbp-0x40]
    cmp  rax, [rbp-0x50]
    jae  .cb_prefill
    ; block_tx_at(blockbuf, blen, i, &s_txptr_local, &s_txlen_local)
    mov  rdi, r13
    mov  rsi, [rbp-0x58]
    mov  rdx, rax
    lea  rcx, [s_txptr_local]
    lea  r8,  [s_txlen_local]
    push rbx
    call block_tx_at
    pop  rbx
    test rax, rax
    jz   .cb_fail
    ; tx_wtxid(sid_scrat, tx, len)
    lea  rdi, [sid_scrat]
    mov  rsi, [s_txptr_local]
    mov  rdx, [s_txlen_local]
    push rbx
    call tx_wtxid
    pop  rbx
    ; bip152_shortid(sid6, hdr(blockbuf), nonce, wtxid)
    lea  rdi, [sid6_scrat]
    mov  rsi, r13
    mov  rdx, r15
    lea  rcx, [sid_scrat]
    push rbx
    call bip152_shortid
    pop  rbx
    ; store 6 bytes
    mov  rdi, [rbp-0x48]
    lea  rsi, [sid6_scrat]
    mov  ecx, 6
.sidcp:
    test rcx, rcx
    jz   .siddn
    mov  al, [rsi]
    mov  [rdi], al
    inc  rsi
    inc  rdi
    dec  rcx
    jmp  .sidcp
.siddn:
    mov  [rbp-0x48], rdi
    inc  qword [rbp-0x40]
    jmp  .cbloop
.cb_prefill:
    ; nprefilled=1 ; index 0 ; coinbase tx
    mov  rdi, [rbp-0x48]
    mov  byte [rdi], 1
    mov  byte [rdi+1], 0
    lea  r15, [rdi+2]      ; coinbase dest (use r15; nonce no longer needed)
    ; block_tx_at(blockbuf, blen, 0, ...)
    mov  rdi, r13
    mov  rsi, [rbp-0x58]
    xor  edx, edx
    lea  rcx, [s_txptr_local]
    lea  r8,  [s_txlen_local]
    push rbx
    call block_tx_at
    pop  rbx
    test rax, rax
    jz   .cb_fail
    ; copy coinbase tx (len = s_txlen_local) to r15
    mov  rdi, r15
    mov  rsi, [s_txptr_local]
    mov  rdx, [s_txlen_local]
    push rbx
    call memcpy_len
    pop  rbx
    ; total = (sidptr+2+txlen) - out
    mov  rax, [rbp-0x48]
    add  rax, 2
    add  rax, [s_txlen_local]
    sub  rax, r12
    jmp  .cb_ret
.cb_fail:
    mov  rax, -1
.cb_ret:
    add  rsp, 0x60
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .data
align 8
sid_scrat: times 32 db 0
sid6_scrat: times 8 db 0
s_txptr_local: dq 0
s_txlen_local: dq 0

section .text
section .note.GNU-stack noalloc noexec nowrite progbits