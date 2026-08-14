; bitcoin_serve.asm
;   100% AI-authored x86-64 assembly.
;
; The server half of the node's P2P message handling. node_serve_loop reads a
; version/verack-acknowledged peer stream and answers each command using the
; other assembly primitives, so an inbound (server) connection is serviced
; entirely in machine code:
;
;   ping       -> pong (echo up to 8-byte nonce)
;   getaddr    -> addr (address book via amr_* + p2p_addr_v1)
;   getdata    -> block (hash looked up O(1) via bitcoin_idx, served via
;                        node_serve_block; MSG_BLOCK wire type check at +0)
;   getheaders -> headers (locator resolved via the hash index; 2000x81B page)
;   inv        -> ignored safely (inbound keep-up is the downloader's job)
;   verack     -> ignored
;
; Signature (SysV):
;   long node_serve_loop(int fd, int lfd, void* st, void* ht_idx,
;                        void* out_buf, long out_cap) -> # blocks served
;
; Uses static scratch buffers so the stack frame stays tiny.

default rel
    extern p2p_read
    extern p2p_write
    extern amr_init
    extern amr_count
    extern amr_get_i
    extern p2p_addr_v1
    extern idx_get
    extern node_serve_block
    extern node_log_event
    extern block_hash
    extern mpool_init
    extern mpool_put
    extern mpool_get
    extern mpool_count
    extern tx_txid
section .data
align 16
pl_buf:    times (8<<20) db 0     ; receive buffer
sb_buf:    times (8<<20) db 0     ; single block buffer
hp_buf:    times (2000*81+8) db 0 ; headers page buffer
cn_pong:   db "pong",0
cn_addr:   db "addr",0
cn_block:  db "block",0
cn_head:   db "headers",0
cn_inv:    db "inv",0
cn_tx:     db "tx",0
; ---- mempool for tx relay (static; initialized once in node_serve_loop) ----
; struct+slots: 40 + slots*48 ; use 1024 slots
MP_SLOTS equ 1024
mp_area:   times (40 + 1024*48 + 8) db 0
mp_blob:   times (2<<20) db 0           ; 2 MiB tx storage
mp_initdone: db 0
amr_ab:    times 64 db 0
ah_buf:    times (1000*30+8) db 0
src_buf:   times (1000*18) db 0
; ---- static per-connection state (NOT on the stack: the deep hashing callees
; may spill a large stack region on a loopback callback; keeping our loop state
; in statics makes it immune to that class of stack collision). ----
align 16
s_plen:   dq 0
s_fh:     dq 0
s_cmd:    times 16 db 0
s_cnt:    dq 0
s_ptr:    dq 0
s_p:      dq 0
s_n:      dq 0
s_served: dq 0
s_tip:    dq 0
s_from:   dq 0
s_htidx:  dq 0     ; stable copy of ht_idx (a callee clobbers r15; store it once)
s_txid:   times 32 db 0 ; inbound tx's computed BIP141 txid
s_st:     dq 0     ; stable copy of the store context (r14 also at risk)

section .text

global node_serve_loop
node_serve_loop:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x50          ; frame locals BELOW the 5-push save area [rbp-8..rbp-0x28].
                            ;   0x50 == 0 mod16 -> after 5 pushes (rsp5==8 mod16)
                            ;   RSP at nested calls == 8 mod16, the parity this
                            ;   codebase's asm callees (p2p_write cksum4 / the
                            ;   deep sha256d chain) require.
    ; locals:
    ;   [s_plen] plen
    ;   [s_fh] scratch fh/item-index
    ;   [s_cmd] cmd[16]
    ;   [s_p] p (headers page writer offset)
    ;   [s_cnt] itercount / getheaders tip
    ;   [s_ptr] getdata item pointer
    ;   [s_n] n-save (getheaders)
    ;   [s_served] served count
    mov  r12, rdi            ; fd
    mov  r13, rsi            ; lfd
    mov  r14, rdx            ; st
    mov  r15, rcx            ; ht_idx
    mov  [s_htidx], rcx      ; keep a stable copy (a downstream callee clobbers r15)
    mov  [s_st], rdx         ; stable copy of st
    mov  qword [s_served], 0 ; served count

    ; init the tx-relay mempool once (static; shared across connections)
    cmp  byte [mp_initdone], 1
    je   .mpready
    mov  rdi, mp_area
    mov  rsi, MP_SLOTS
    lea  rdx, [mp_blob]
    mov  rcx, (2<<20)
    call mpool_init
    mov  byte [mp_initdone], 1
.mpready:

    ; Outer-loop counter lives in r15. r15 is written ONLY here (entry); all
    ; handlers avoid it and reuse rbx as scratch (getdata item pointer etc.).
    ; r15 is callee-saved so the external calls (p2p_read, idx_get,
    ; node_serve_block, p2p_write) preserve it across the whole loop.
    mov  r15, 10000          ; outer loop bound
.outer:
    ; ---- read a message ----
    mov  qword [s_plen], 0
    mov  rdi, r12
    lea  rsi, [s_cmd]
    lea  rdx, [pl_buf]
    mov  rcx, (8<<20)
    lea  r8,  [s_plen]
    call p2p_read
    test rax, rax
    jle  .done
    mov  byte [s_cmd+11], 0

    ; ---- dispatch ----
    cmp  dword [s_cmd], 0x676e6970   ; "ping\0\0\0\0" dword0
    je   .do_ping
    cmp  dword [s_cmd], 0x61726576   ; "vera..."
    je   .do_verack
    cmp  dword [s_cmd], 0x61746567   ; "geta..." (getaddr)
    je   .maybe_getaddr
    cmp  dword [s_cmd], 0x64746567   ; "getd..." (getdata)
    je   .maybe_getdata
    cmp  dword [s_cmd], 0x68746567   ; "geth..." (getheaders)
    je   .maybe_getheaders
    cmp  dword [s_cmd], 0x62746567   ; "getb..." (getblocks)
    je   .maybe_getblocks
    cmp  dword [s_cmd], 0x00766e69   ; "inv"
    je   .do_inv
    cmp  dword [s_cmd], 0x00007874   ; "tx\0\0"
    je   .do_tx
    jmp  .next

.do_verack:
    jmp  .next

.do_ping:
    ; plen>=8 ? echo 8 : echo 0 (pong carries the peer's nonce -> echo all up to 8)
    mov  rax, [s_plen]
    cmp  rax, 8
    jae  .ping8
    xor  r8d, r8d
    jmp  .pingw
.ping8:
    mov  r8d, 8
.pingw:
    mov  rdi, r12
    lea  rsi, [cn_pong]
    mov  rdx, 4
    lea  rcx, [pl_buf]
    call p2p_write
    jmp  .next

.do_inv:
    ; inbound inv: acknowledged implicitly; keep-up is the downloader's job.
    jmp  .next

.do_tx:
    ; inbound tx: compute its BIP141 txid and store it in the mempool so we can
    ; relay it (answer later getdata(MSG_TX)). tx at pl_buf, len = s_plen.
    mov  rax, [s_plen]
    cmp  rax, 10            ; version(4)+1in+1out+locktime(4) min
    jb   .next
    ; tx_txid(s_txid, pl_buf, s_plen, hp_buf, cap)
    lea  rdi, [s_txid]
    lea  rsi, [pl_buf]
    mov  rdx, [s_plen]
    lea  rcx, [hp_buf]      ; unwitnessed serialization scratch (hp_buf idle here)
    mov  r8, (2000*81+8)
    call tx_txid
    test rax, rax
    jz   .next
    ; mpool_put(mp_area, s_txid, pl_buf, s_plen)
    mov  rdi, mp_area
    lea  rsi, [s_txid]
    lea  rdx, [pl_buf]
    mov  rcx, [s_plen]
    call mpool_put
    jmp  .next

.maybe_getaddr:
    ; "getaddr" -> dword0 "geta", index4..7 "ddr\0"
    cmp  dword [s_cmd+4], 0x00726464 ; "ddr\0"
    jne  .next
    ; ---- addr reply ----
    lea  rdi, [amr_ab]
    call amr_init
    test rax, rax
    jz   .next
    lea  rdi, [amr_ab]
    call amr_count
    mov  rdx, rax
    cmp  rdx, 1000
    jbe  .acnt
    mov  rdx, 1000
.acnt:
    xor  rax, rax            ; have = 0
    xor  rcx, rcx            ; i = 0
.aloop:
    cmp  rcx, rdx
    jae  .adone
    lea  rdi, [amr_ab]
    mov  rsi, rcx
    ; dst = src_buf + have*18  (scale 18 not encodable; compute rdx manually)
    lea  r9,  [rax + rax*8]   ; have*9
    shl  r9,  1               ; have*18
    lea  rdx, [src_buf + r9]
    ; save have/rcx across amr_get_i (callee-saved: rbx,r12-r15 only)
    mov  [s_p], rax
    mov  [s_cnt], rcx
    call amr_get_i
    mov  rax, [s_p]
    mov  rcx, [s_cnt]
    cmp  rax, 1
    jne  .anext
    inc  rax                 ; have++
.anext:
    inc  rcx
    jmp  .aloop
.adone:
    test rax, rax
    jz   .next
    ; p2p_addr_v1(ah_buf, src_buf, have)
    lea  rdi, [ah_buf]
    lea  rsi, [src_buf]
    mov  rdx, rax
    call p2p_addr_v1
    mov  r8d, eax           ; addr payload length (p2p_write arg5 = r8)
    ; p2p_write(fd,"addr",4, ah_buf, L)
    mov  rdi, r12
    lea  rsi, [cn_addr]
    mov  rdx, 4
    lea  rcx, [ah_buf]
    call p2p_write
    jmp  .next

.maybe_getdata:
    ; "getdata" -> dword0 "getd", index4..7 "ata\0"
    cmp  dword [s_cmd+4], 0x00617461 ; "ata\0"
    jne  .next
    mov  rax, [s_plen]
    cmp  rax, 37
    jb   .next
    ; cnt = pl[0] (single-byte varint)
    movzx rax, byte [pl_buf]
    mov  [s_cnt], rax     ; item counter
    lea  rax, [pl_buf+1]
    mov  [s_ptr], rax     ; item pointer (do NOT clobber the outer rbx counter)
.gd_loop:
    mov  rax, [s_cnt]
    test rax, rax
    jle  .next
    mov  rbx, [s_ptr]     ; item ptr (rbx is free here -- outer counter saved in the loop bound)
    ; type at rbx (u32 LE): 2=MSG_BLOCK -> serve block; 1=MSG_TX -> mempool tx
    mov  r9d, [rbx]
    cmp  r9d, 1
    je   .gd_tx
    cmp  r9d, 2
    jne  .gd_next
    ; hash at rbx+4; idx_get(ht_idx, hash, &fh)
    mov  [s_ptr], rbx
    mov  rdi, [s_htidx]      ; use the stable copy (a callee clobbers r15)
    lea  rsi, [rbx+4]
    lea  rdx, [s_fh]
    call idx_get
    mov  rbx, [s_ptr]
    test rax, rax
    jz   .gd_next
    ; node_serve_block(st, fh, sb_buf, cap)
    mov  [s_ptr], rbx
    mov  rdi, [s_st]         ; stable copy of st
    mov  rsi, [s_fh]
    lea  rdx, [sb_buf]
    mov  rcx, (8<<20)
    call node_serve_block
    mov  rbx, [s_ptr]
    test rax, rax
    jle  .gd_next
    mov  r8d, eax           ; block length (p2p_write arg5 = r8)
    ; p2p_write(fd,"block",5,sb_buf,len)
    mov  [s_ptr], rbx
    mov  rdi, r12
    lea  rsi, [cn_block]
    mov  rdx, 5
    lea  rcx, [sb_buf]
    call p2p_write
    mov  rbx, [s_ptr]
    ; served++
    add  qword [s_served], 1
    mov  rbx, [s_ptr]
    jmp  .gd_next

.gd_tx:
    ; txid at rbx+4; mpool_get(mp_area, txid, &s_n) -> ptr or 0
    mov  [s_ptr], rbx
    mov  rdi, mp_area
    lea  rsi, [rbx+4]
    lea  rdx, [s_n]          ; out_len slot
    call mpool_get
    mov  rbx, [s_ptr]
    test rax, rax
    jz   .gd_next
    ; p2p_write(fd,"tx",2, ptr, len)
    mov  [s_ptr], rbx
    mov  rdi, r12
    lea  rsi, [cn_tx]
    mov  rdx, 2
    mov  rcx, rax            ; tx bytes (mp_blob ptr)
    mov  r8, [s_n]           ; length
    push rbx
    call p2p_write
    pop  rbx
    add  qword [s_served], 1
    mov  rbx, [s_ptr]
    jmp  .gd_next
.gd_next:
    ; advance item pointer by 36 and decrement counter
    mov  rax, [s_ptr]
    add  rax, 36
    mov  [s_ptr], rax
    dec  qword [s_cnt]
    jmp  .gd_loop

.maybe_getheaders:
    ; "getheaders" = g e t h e a d e r s
    ;   "head" spans cmd[3..6], "ers\0" spans cmd[7..10].
    cmp  dword [s_cmd+3], 0x64616568 ; "head"
    jne  .next
    cmp  dword [s_cmd+7], 0x00737265 ; "ers\0"
    jne  .next
    ; locator hash at pl+5 -> resolve via idx
    mov  rax, [s_plen]
    cmp  rax, 5
    jb   .gh_zero
    lea  rsi, [pl_buf+5]
    ; idx_get(ht_idx, pl+5, &fh)
    mov  rdi, [s_htidx]      ; stable copy
    ; rsi already = pl+5
    lea  rdx, [s_fh]
    call idx_get
    test rax, rax
    jz   .gh_from0
    mov  rax, [s_fh]
    inc  rax                 ; from = fh+1
    jmp  .gh_havefrom
.gh_from0:
    xor  eax, eax            ; from = 0
.gh_havefrom:
    mov  [s_fh], rax     ; from
    jmp  .gh_build
.gh_zero:
    ; unknown locator / empty -> serve from genesis (headers with count 0 means
    ; "i have nothing"; but reference clients expect headers from the locator).
.gh_build:
    ; tip = st[24]
    mov  eax, [r14+24]
    mov  [s_cnt], rax     ; tip
    mov  rax, [s_fh]
    cmp  rax, [s_cnt]
    ja   .gh_empty
    ; Headers are written starting at hp_buf+3 (3 bytes reserved for the
    ; count varint, which is emitted at the end once n is known). p=3; n=0.
    mov  qword [s_p], 3 ; p
    mov  qword [s_n], 0 ; n   (kept in a static: immune to callee clobbering)
    mov  rax, [s_fh]
    mov  [s_plen], rax ; save starting 'from' for the post-serve log (loop advances s_fh)
.ghh_loop:
    ; loop using statics [s_fh] (height) and [s_n] (count). Callees
    ; (idx_get/node_serve_block/memcpy_len/p2p_write) clobber the volatile
    ; registers rax..r11, so the running height/count MUST live in statics.
    mov  rax, [s_fh]
    cmp  rax, [s_cnt]
    ja   .ghh_done
    mov  rax, [s_n]
    cmp  rax, 2000
    jae  .ghh_done
    ; node_serve_block(st, h, sb_buf, cap)
    mov  rdi, r14
    mov  rsi, [s_fh]
    lea  rdx, [sb_buf]
    mov  rcx, (8<<20)
    call node_serve_block
    test rax, rax
    jle  .ghh_done
    ; copy 80-byte header into hp_buf at p; then tx-count byte 0 at p+80
    ; memcpy_len(dst, src, len) reads its LENGTH from RDX (not r8). Passing the
    ; length in r8 here made it copy [s_p] bytes instead of 80 -> the write swept
    ; through hp_buf and past the .bss into the stdout/stderr copies (0x143e6a0),
    ; wiping libc's stdout/stderr globals and crashing main's printf once the
    ; loop had run a few headers. Must load the 80-header length into RDX.
    mov  rdx, [s_p]
    lea  rdi, [hp_buf + rdx]
    lea  rsi, [sb_buf]
    mov  rdx, 80             ; memcpy_len length argument (RDX)
    call memcpy_len
    mov  rdx, [s_p]
    mov  byte [hp_buf + rdx + 80], 0
    add  qword [s_p], 81
    mov  rax, [s_n]
    inc  rax
    mov  [s_n], rax
    mov  rax, [s_fh]
    inc  rax
    mov  [s_fh], rax
    jmp  .ghh_loop
.ghh_done:
    ; Count c = number of headers actually written = (s_p - 3) / 81.
    ; Derive it from the byte pointer (not the loop counter, which callees
    ; clobber) so the count field always matches the payload length.
    mov  rax, [s_p]
    sub  rax, 3
    xor  edx, edx
    mov  ecx, 81
    div  rcx                 ; rax = c
    mov  [s_n], rax          ; save n
    cmp  rax, 253
    jae  .gh_varint16
    ; c < 253 : single-byte varint. Headers sit at hp_buf+3; compact them down
    ; to hp_buf+1 (copy forward, dst<src so non-overlapping-safe) and set
    ; hp_buf[0]=c.
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rax            ; c*81 = bytes to move
    imul r12, 81
    mov  r13, 0              ; i
.gh_compact:
    cmp  r13, r12
    jae  .gh_compact_done
    mov  al, [hp_buf+3+r13]
    mov  [hp_buf+1+r13], al
    inc  r13
    jmp  .gh_compact
.gh_compact_done:
    mov  rax, [s_n]
    mov  byte [hp_buf], al
    mov  rax, [s_n]
    imul rax, 81
    add  rax, 1              ; final payload len = 1 + c*81
    mov  [s_p], rax
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    jmp  .gh_send
.gh_varint16:
    ; c in [253, 65535] : 0xFD + 2-byte little-endian. Headers already at +3.
    mov  byte [hp_buf], 0xFD
    mov  rax, [s_n]
    mov  byte [hp_buf+1], al
    shr  rax, 8
    mov  byte [hp_buf+2], al
    mov  rax, [s_n]
    imul rax, 81
    add  rax, 3              ; final payload len = 3 + c*81
    mov  [s_p], rax
.gh_send:
    ; p2p_write(fd,"headers",7,hp_buf,p)
    mov  r8d, [s_p]    ; headers payload length (p2p_write arg5 = r8)
    mov  rdi, r12
    lea  rsi, [cn_head]
    mov  rdx, 7
    lea  rcx, [hp_buf]
    call p2p_write
    ; node_log_event(lfd, 6, n, from, 0)
    mov  rdi, r13
    mov  rsi, 6
    mov  rdx, [s_n]
    mov  rcx, [s_plen]
    xor  r8, r8
    call node_log_event
    jmp  .next
.gh_empty:
    ; p2p_write(fd,"headers",7,"\x00",1)
    mov  byte [hp_buf], 0
    mov  r8d, 1             ; payload length 1
    mov  rdi, r12
    lea  rsi, [cn_head]
    mov  rdx, 7
    lea  rcx, [hp_buf]
    call p2p_write
    jmp  .next

.maybe_getblocks:
    ; "getblocks" = g e t b l o c k s. dword0 dispatch already guarantees "getb";
    ; confirm cmd[4..7]="lock" (getheaders has "ead\u...." there). Note we must
    ; compare all FOUR bytes: 'k' sits at cmd[7], so the LE dword is 0x6b636f6c.
    cmp  dword [s_cmd+4], 0x6b636f6c ; "lock"
    jne  .next
    ; payload: version(4) count(1) locator-hash(32) stop(32) ; locator at pl+5
    mov  rax, [s_plen]
    cmp  rax, 37
    jb   .gb_from0
    mov  rdi, [s_htidx]
    lea  rsi, [pl_buf+5]
    lea  rdx, [s_fh]
    call idx_get
    test rax, rax
    jz   .gb_from0
    mov  rax, [s_fh]
    inc  rax
    jmp  .gb_havefrom
.gb_from0:
    xor  eax, eax
.gb_havefrom:
    mov  [s_fh], rax        ; from
    ; tip = st[24]
    mov  eax, [r14+24]
    mov  [s_cnt], rax
    mov  rax, [s_fh]
    cmp  rax, [s_cnt]
    ja   .gb_empty
    ; build inv: reserve 3 bytes for count varint at hp_buf[0..2], entries at
    ; hp_buf[3..]. Each entry = type u32 (2=MSG_BLOCK) + hash32 (LE wire order).
    mov  qword [s_p], 3
    mov  qword [s_n], 0
.gbl_loop:
    mov  rax, [s_fh]
    cmp  rax, [s_cnt]
    ja   .gb_done
    mov  rax, [s_n]
    cmp  rax, 500
    jae  .gb_done
    ; node_serve_block(st, h, sb_buf, cap) -> rax = len
    mov  rdi, r14
    mov  rsi, [s_fh]
    lea  rdx, [sb_buf]
    mov  rcx, (8<<20)
    call node_serve_block
    test rax, rax
    jle  .gb_done
    ; block_hash(hh, sb_buf)
    lea  rdi, [sb_buf+0x200000]  ; scratch hash slot inside sb_buf (see below)
    lea  rsi, [sb_buf]
    call block_hash
    ; reverse the hash into hp_buf at offset [s_p]+4 (after the type u32)
    mov  rdx, [s_p]
    add  rdx, 4
    ; type = 2 (MSG_BLOCK) at hp_buf[rdx-4 .. rdx-1]
    mov  dword [hp_buf + rdx - 4], 2
    lea  r10, [sb_buf + 0x200000 + 31]  ; last byte of the hash output
    lea  r11, [hp_buf + rdx]            ; dest base (type u32 already written)
    xor  ecx, ecx
.gbl_rev:
    cmp  rcx, 32
    jae  .gbl_rev_done
    mov  r9, rcx
    neg  r9                  ; -rcx
    mov  al, [r10 + r9]      ; sb_buf+0x200000+31-rcx  (base + index)
    mov  [r11 + rcx], al     ; hp_buf+rdx+rcx
    inc  rcx
    jmp  .gbl_rev
.gbl_rev_done:
    add  qword [s_p], 36
    mov  rax, [s_n]
    inc  rax
    mov  [s_n], rax
    mov  rax, [s_fh]
    inc  rax
    mov  [s_fh], rax
    jmp  .gbl_loop
.gb_done:
    ; emit canonical count varint from [s_n]
    mov  rax, [s_n]
    cmp  rax, 253
    jae  .gb_varint16
    ; compact entries from hp_buf+3 down to hp_buf+1, count byte at [0]
    ; bytes = n*36
    imul rax, 36
    xor  rcx, rcx
.gb_comp:
    cmp  rcx, rax
    jae  .gb_comp_done
    mov  dl, [hp_buf + 3 + rcx]
    mov  [hp_buf + 1 + rcx], dl
    inc  rcx
    jmp  .gb_comp
.gb_comp_done:
    mov  rax, [s_n]
    mov  byte [hp_buf], al
    mov  rax, [s_n]
    imul rax, 36
    add  rax, 1
    mov  [s_p], rax        ; final len = 1 + n*36
    jmp  .gb_send
.gb_varint16:
    mov  byte [hp_buf], 0xFD
    mov  rax, [s_n]
    mov  byte [hp_buf+1], al
    shr  rax, 8
    mov  byte [hp_buf+2], al
    mov  rax, [s_n]
    imul rax, 36
    add  rax, 3
    mov  [s_p], rax        ; final len = 3 + n*36
.gb_send:
    ; p2p_write(fd,"inv",3,hp_buf,s_p)
    mov  r8d, [s_p]
    mov  rdi, r12
    lea  rsi, [cn_inv]
    mov  rdx, 3
    lea  rcx, [hp_buf]
    call p2p_write
    ; count served into s_served (like blocks served)
    mov  rax, [s_served]
    add  rax, [s_n]
    mov  [s_served], rax
    jmp  .next
.gb_empty:
    ; send empty inv (count 0)
    mov  byte [hp_buf], 0
    mov  r8d, 1
    mov  rdi, r12
    lea  rsi, [cn_inv]
    mov  rdx, 3
    lea  rcx, [hp_buf]
    call p2p_write
    jmp  .next

.next:
    dec  r15
    jg   .outer
.done:
    mov  rax, [s_served]
    add  rsp, 0x50
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; helper: memcpy_len(dst, src, n) -- byte mover
;   rdi=dst, rsi=src, rdx=n
memcpy_len:
    xor  ecx, ecx
.c:
    cmp  rcx, rdx
    jae  .cd
    mov  al, byte [rsi+rcx]
    mov  byte [rdi+rcx], al
    inc  rcx
    jmp  .c
.cd:
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
