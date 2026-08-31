; bitcoin_serve.asm
;   100% AI-authored x86-64 assembly.
;
; The server half of the node's P2P message handling. node_serve_loop reads a
; version/verack-acknowledged peer stream and answers each command using the
; other assembly primitives, so an inbound (server) connection is serviced
; entirely in machine code:
;
;   ping       -> pong (echo up to 8-byte nonce)
;   getaddr    -> addr / addrv2 (daemon/serve_addr.c, from the v2 book)
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

%define SERVE_TXID_CAP 80000   ; > 4,000,000/60, the wire max txs per block

default rel
    extern p2p_read
    extern p2p_write
    extern serve_getaddr
extern g_peer_wants_addrv2
    extern idx_get
    extern serve_inv_bounds
    extern serve_idx_topup
    extern serve_cfilters
    extern idx_put
    extern store_append
    extern block_strip_witness
    extern idxscan_append_locked
    extern store_validates_prevhash
    extern cons_verify
    extern node_serve_block
    extern node_log_event
    extern block_hash
    extern mpool_init
    extern mpool_put
    extern mpool_get
    extern mpool_count
    extern tx_dispatch_init
    extern tx_policy_init
    extern tx_accept_validate
    extern log_block_stored_inbound
    extern tx_txid
    extern bip152_shortid
    extern block_tx_at
    extern block_txcount
    extern p2p_blocktxn_build
    extern cmpctblock_build
    extern node_serve_block_by_hash
section .data
align 16

; ---------------------------------------------------------------------------
; Protocol-violation hook (audit 2026-08-29 finding 7).
;
; peer_misbehaving() existed with a 100-point threshold, a shared ban list and
; /32 auto-ban -- and ZERO call sites, so a peer could send malformed message
; after malformed message and the node kept talking to it. This is the first
; real caller.
;
; A function pointer rather than an extern for the same reason as the v2
; dispatch in bitcoin_net.asm: this object is linked into targets that do not
; link the daemon, and an undefined symbol would break all of them. NULL means
; "nobody registered", and the loop just drops the connection as before.
; ---------------------------------------------------------------------------
global g_serve_violation_hook
g_serve_violation_hook: dq 0      ; void (*)(const char* reason)
viol_oversize: db "oversized message announcement", 0
viol_invsz:    db "inv/getdata vector above MAX_INV_SZ", 0

pl_buf:    times (8<<20) db 0     ; receive buffer
sb_buf:    times (8<<20) db 0     ; single block buffer
hp_buf:    times (2000*81+8) db 0 ; headers page buffer
serve_txid_scratch: times SERVE_TXID_CAP*32 db 0  ; cons_verify scratch (own buffer)
cn_pong:   db "pong",0
cn_addr:   db "addr",0
cn_addrv2: db "addrv2",0
cn_block:  db "block",0
cn_notfnd: db "notfound",0
cn_head:   db "headers",0
cn_inv:    db "inv",0
cn_tx:     db "tx",0
cn_getdata: db "getdata",0
cn_getbtxn: db "getblocktxn",0
cn_btxn:   db "blocktxn",0
cn_cmpct:  db "cmpctblock",0
cn_sendhd: db "sendheaders",0
cn_feeflt: db "feefilter",0
; BIP152 output buffer (blocktxn / cmpctblock assembly) + per-connection state.
align 16
bt_buf:    times (8<<20) db 0     ; compact-block output buffer
; A getdata we cannot satisfy must be ANSWERED. Core replies `notfound`;
; this path used to say nothing at all, so the peer sat waiting for its own
; timeout on every miss -- and a peer that times out on us asks someone else
; next time. 50 entries is the inv/getdata cap Core enforces on the way in.
nf_buf:    times (1 + 50*36) db 0 ; notfound payload: count byte + 36B entries
s_cmpct_v2:  dq 0                 ; peer negotiated compact blocks (sendcmpct version 2)
s_cmpct_hb:  dq 0                 ; peer requested high-bandwidth mode (announce=1)
s_cmpct_nonce: dq 0               ; nonce used for the compact block we announced
s_shdr:    dq 0                   ; peer sent `sendheaders` -> announce new blocks with
                                  ;   a `headers` message instead of an `inv`
s_peerfee: dq 0                   ; peer's `feefilter` (min relay feerate, sat/kB); 0 = none.
s_myfee:   dq 1000                ; OUR min-relay-feerate (sat/kB) advertised to peers via
                                  ;   a `feefilter` message (1000 sat/kB = 1 sat/vB, Core default)
s_feesent: db 0                   ; have we sent our `feefilter` to this peer yet
s_addrsent: db 0                  ; getaddr answered once on this connection (Core: m_getaddr_recvd)
s_lasttip: dq 0                   ; remembered stored tip (height) for tip-watch announce
s_idxn:    dq 0                   ; # indexes parsed from getblocktxn
s_idxbuf:  times (512*2) db 0      ; getblocktxn requested tx indexes (u16 LE each)
s_diffshift: dq 0
s_blen_spill: dq 0                 ; preserved block length for blocktxn assembly
s_txptr:   dq 0                    ; block_tx_at output pointer
s_txlen:   dq 0                    ; block_tx_at output length
s_j:       dq 0                    ; loop counter j (blocktxn assembly)
; ---- mempool for tx relay (static; initialized once in node_serve_loop) ----
; struct+slots: 40 + slots*48 ; use 1024 slots
MP_SLOTS equ 1024
mp_area:   times (40 + 1024*48 + 8) db 0
mp_blob:   times (2<<20) db 0           ; 2 MiB tx storage -- FALLBACK only
mp_initdone: db 0
; ---- runtime-sized mempool (Core -maxmempool) ---------------------------
; The static buffers above cap the relay mempool at 2 MiB / 1024 slots, so
; -maxmempool (Core default 300 MB) could not be honoured at all. Rather than
; grow the statics -- which would cost that memory in every process whether
; used or not -- C may allocate a right-sized region and publish it here
; BEFORE node_serve_loop runs (daemon/mempool_cfg.c). If mp_ext_area is null
; the static fallback is used and behaviour is byte-identical to before, so
; every existing caller and test is unaffected.
extern mp_ext_area
extern mp_ext_blob
extern mp_ext_slots
extern mp_ext_blobcap
; MEMPOOL COHERENCE (2026-08-25): when the C-provided region is MAP_SHARED it
; is mpool_init'd ONCE pre-fork (mempool_cfg.c) and mp_ext_inited is 1 --
; re-running mpool_init here (per process, per lazy-init) would WIPE the
; shared pool every time an inbound child starts. Skip init, adopt the region.
extern mp_ext_inited
; resolved once at init to whichever region is in play; every later mempool
; call goes through this, so there is exactly one place that decides.
mp_cur:         dq 0
; ---- per-connection tx validation (daemon/tx_accept.c); same lazy-init-
; once-per-process shape as mp_initdone above ----
tx_dv_initdone: db 0
tx_dv_ok: db 0
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
s_nf:     dq 0        ; notfound entries accumulated for THIS getdata
s_ptr:    dq 0
s_ivn:    dq 0            ; inv/getdata entry count (from serve_inv_bounds)
s_ivo:    dq 0            ; offset of the first entry
s_p:      dq 0
s_abound: dq 0        ; getaddr reply: loop bound (min(book,1000)), kept in MEMORY
s_n:      dq 0
s_served: dq 0
s_tip:    dq 0
s_from:   dq 0
s_htidx:  dq 0     ; stable copy of ht_idx (a callee clobbers r15; store it once)
s_txid:   times 32 db 0 ; inbound tx's computed BIP141 txid
s_st:     dq 0     ; stable copy of the store context (r14 also at risk)
s_fd:     dq 0     ; stable copy of the peer fd (r12 at risk: cons_verify clobbers it)
s_lfd:    dq 0     ; stable copy of the log fd (r13 at risk)
s_lastheight: dq 0 ; height just returned by idxscan_append_locked in .do_block,
                    ; held here (not a register) so it survives the idx_put call
                    ; intact for the log_block_stored_inbound call right after

section .text

; ============================================================================
; serve_txdv_preinit() -> 1 if the tx-validation path is usable, else 0.
;   Runs the read-only UTXO snapshot + mempool policy init ONCE, intended to
;   be called by the parent BEFORE forking (see the note in node_serve_loop).
;   Idempotent: a second call is a no-op, and the per-connection guard skips
;   its own init once this has run.
; ============================================================================
global serve_txdv_preinit
serve_txdv_preinit:
    push rbp
    mov  rbp, rsp                 ; rsp%16==0 here, so the calls below are aligned
    cmp  byte [tx_dv_initdone], 1
    je   .pre_done
    call tx_dispatch_init
    mov  byte [tx_dv_ok], al
    call tx_policy_init
    and  al, byte [tx_dv_ok]
    mov  byte [tx_dv_ok], al
    mov  byte [tx_dv_initdone], 1
.pre_done:
    movzx eax, byte [tx_dv_ok]
    pop  rbp
    ret

global node_serve_loop
node_serve_loop:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x58          ; scratch reservation, sized to RESTORE SysV alignment.
                            ;   Entry RSP == 8 mod16; the 6 pushes above leave it
                            ;   at 8 mod16 again, so the reservation must be ODD
                            ;   mod 16 (0x58, not 0x50) to put RSP == 0 mod16 at
                            ;   every nested `call` -- exactly what node_announce_tip
                            ;   below does with its `sub rsp, 8`.
                            ;   This was 0x50, on the claim that the asm callees
                            ;   (p2p_write cksum4 / the sha256d chain) "require"
                            ;   8 mod16. They do not: every movdqa in sha256.asm /
                            ;   secp256k1_point.asm is register-to-register, with no
                            ;   16-byte-aligned stack operand anywhere. The C callees
                            ;   DO require it -- glibc's vsnprintf (reached from every
                            ;   daemon/log_ts.h fprintf) uses movaps on its stack
                            ;   frame, and a 8-mod-16 RSP at the call site makes that
                            ;   fault: #GP -> SIGSEGV with si_addr == NULL. That
                            ;   killed the serve child on the FIRST peer-pushed block
                            ;   (log_block_stored_inbound, .blk_chains). (2026-08-22)
                            ; NOTE: the frame is scratch only -- every "local" listed
                            ; below lives in .data, nothing here is rbp-relative, so
                            ; the size change moves no operand.
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
    mov  [s_fd], rdi         ; stable fd copy (cons_verify clobbers r12-r15)
    mov  [s_lfd], rsi        ; stable lfd copy
    mov  [s_htidx], rcx      ; keep a stable copy (a downstream callee clobbers r15)
    mov  [s_st], rdx         ; stable copy of st
    mov  qword [s_served], 0 ; served count

    ; init the tx-relay mempool once (static; shared across connections)
    cmp  byte [mp_initdone], 1
    je   .mpready
    mov  rax, [mp_ext_area]
    test rax, rax
    jnz  .mp_external
    ; --- static fallback: exactly the previous behaviour ---
    mov  rax, mp_area
    mov  [mp_cur], rax
    mov  rdi, rax
    mov  rsi, MP_SLOTS
    lea  rdx, [mp_blob]
    mov  rcx, (2<<20)
    call mpool_init
    jmp  .mp_inited
.mp_external:
    ; --- C-provided, -maxmempool sized ---
    mov  [mp_cur], rax
    cmp  qword [mp_ext_inited], 0
    jne  .mp_inited          ; shared region: init already ran pre-fork
    mov  rdi, rax
    mov  rsi, [mp_ext_slots]
    mov  rdx, [mp_ext_blob]
    mov  rcx, [mp_ext_blobcap]
    call mpool_init
.mp_inited:
    mov  byte [mp_initdone], 1
.mpready:
    ; init this connection's read-only UTXO snapshot + mempool policy state.
    ; NORMALLY ALREADY DONE: serve_txdv_preinit runs this once in the parent
    ; BEFORE the fork (daemon/main.c), so every inbound child inherits the
    ; snapshot copy-on-write instead of opening its own. This guard is the
    ; fallback for callers that never pre-init (the test harnesses).
    ;
    ; Why pre-fork: utxo_lsm_reload takes 60-83 s on the real 165M-entry set,
    ; and doing it HERE meant every inbound peer waited that long before we
    ; sent even a feefilter -- real peers hang up first, so inbound serving
    ; was effectively dead. Bitcoin Core opens its coins view once at startup
    ; (InitCoinsDB in node/chainstate.cpp) and shares it across peer threads;
    ; the shared mempool directly above already follows the same discipline
    ; via mp_ext_inited. This just gives the UTXO snapshot the same treatment.
    ; (2026-08-27)
    ; Non-fatal on failure -- .do_tx checks tx_dv_ready and falls back to
    ; dropping inbound tx (not accepting unvalidated ones) rather than
    ; taking the whole connection down.
    cmp  byte [tx_dv_initdone], 1
    je   .txdvready
    call tx_dispatch_init
    mov  byte [tx_dv_ok], al
    call tx_policy_init
    and  al, byte [tx_dv_ok]
    mov  byte [tx_dv_ok], al
    mov  byte [tx_dv_initdone], 1
.txdvready:

    ; ---- per-connection init: reset negotiation state, remember tip, and
    ; send the peer OUR `feefilter` (advertise min-relay-feerate so it skips
    ; low-fee relay to us). This is the outbound feefilter leg.
    mov  qword [s_shdr], 0
    mov  qword [s_peerfee], 0
    mov  byte [s_feesent], 0
    mov  byte [s_addrsent], 0
    mov  eax, [r14+24]           ; tip height (st[24])
    mov  [s_lasttip], rax
    ; feefilter_send(fd) -- 8-byte int64 LE min-relay-feerate (s_myfee)
    lea  rax, [hp_buf]
    mov  rdx, [s_myfee]
    mov  [hp_buf], rdx
    mov  rdi, r12
    lea  rsi, [cn_feeflt]
    mov  rdx, 9
    lea  rcx, [hp_buf]
    mov  r8d, 8
    call p2p_write
    mov  byte [s_feesent], 1

    ; r15 was written at entry and is no longer used as an iteration counter
    ; (see `.done` -- the loop is now unbounded, terminating only on connection
    ; close). Handlers avoid r15 and reuse rbx as scratch (getdata item pointer
    ; etc.); r15 is callee-saved so the external calls preserve it.
    mov  r15, 10000          ; (retained: reserved, unused bound)
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
    jle  .check_viol
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
    cmp  dword [s_cmd], 0x62746567   ; "getb..." (getblocks / getblocktxn)
    je   .maybe_getb
    cmp  dword [s_cmd], 0x63746567   ; "getc..." (getcfilters/-headers/-checkpt)
    je   .maybe_getcf
    cmp  dword [s_cmd], 0x00766e69   ; "inv"
    je   .do_inv
    cmp  dword [s_cmd], 0x00007874   ; "tx"
    je   .do_tx
    cmp  dword [s_cmd], 0x636f6c62   ; "bloc" ("block" command byte0..3, LE)
    je   .do_block
    cmp  dword [s_cmd], 0x646e6573   ; "send" (sendcmpct / sendheaders / sendaddrv2)
    je   .maybe_sendcmpct
    cmp  dword [s_cmd], 0x66656566   ; "feef" (feefilter)
    je   .maybe_feefilter
    cmp  dword [s_cmd], 0x69787477   ; "wtxi" (wtxidrelay) -- a handshake-only
    je   .done                       ;   message; after verack Core disconnects
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
    ; Inbound inv: for each MSG_BLOCK entry, if we don't already have it,
    ; send a getdata to fetch it (relay keep-up). inv payload:
    ;   count(varint) | (type u32 LE + hash32) x count   (36B per entry)
    ;
    ; The count used to be read as a SINGLE BYTE and the entries walked
    ; without consulting s_plen. A vector above 252 entries -- which Core
    ; sends routinely -- was therefore misparsed, and a SHORT message with a
    ; large count byte walked into whatever the previous, larger message had
    ; left in the 8 MB receive buffer, letting a peer steer getdata at hashes
    ; assembled from earlier traffic. serve_inv_bounds (daemon/serve_invbounds.c)
    ; now does the varint and the bounds; writing that in assembly would only
    ; trade one subtle parser for another.
    ;   rax =  1 ok, 0 malformed/short (drop), -1 over MAX_INV_SZ (score it)
    lea  rdi, [pl_buf]
    mov  rsi, [s_plen]
    lea  rdx, [s_ivn]
    lea  rcx, [s_ivo]
    call serve_inv_bounds
    ; SysV defines only EAX for an `int` return -- the upper half of RAX is
    ; undefined, so testing RAX here silently never matched -1. Sign-extend
    ; before comparing.
    movsxd rax, eax
    cmp  rax, -1
    je   .inv_toobig
    test rax, rax
    jle  .next               ; malformed or short: drop this message quietly
    mov  rax, [s_ivn]
    mov  [s_cnt], rax
    test rax, rax
    jle  .next
    lea  rax, [pl_buf]
    add  rax, [s_ivo]
    mov  [s_ptr], rax        ; entry pointer (stable slot; survives calls)
.inv_loop:
    mov  rax, [s_cnt]
    test rax, rax
    jle  .next
    mov  rbx, [s_ptr]
    mov  r9d, [rbx]          ; type
    cmp  r9d, 2              ; MSG_BLOCK only (skip tx inv for now)
    jne  .inv_next
    ; have it? idx_get(ht_idx, rbx+4, &s_fh)
    mov  [s_ptr], rbx
    mov  rdi, [s_htidx]
    lea  rsi, [rbx+4]
    lea  rdx, [s_fh]
    call idx_get
    mov  rbx, [s_ptr]
    test rax, rax
    jnz  .inv_next           ; already have it -> don't re-request
    ; build & send getdata: [count=1][type u32][hash32] = 37 bytes.
    ; MSG_WITNESS_BLOCK (0x40000002), not MSG_BLOCK: this is the steady-state
    ; path that fetches NEW tip blocks announced by inv, and with type 2 every
    ; block after the archive repair would have arrived stripped again.
    mov  byte  [src_buf], 1
    mov  dword [src_buf+1], 0x40000002
    ; copy hash (rbx+4) into src_buf+5 (memcpy_len length arg is RDX)
    mov  rdx, 32
    lea  rdi, [src_buf+5]
    lea  rsi, [rbx+4]
    push rbx
    push rbx                 ; 2nd push = padding: keep RSP 16-byte aligned
    call memcpy_len
    pop  rbx
    pop  rbx
    mov  [s_ptr], rbx
    mov  rdi, r12
    lea  rsi, [cn_getdata]
    mov  rdx, 7
    lea  rcx, [src_buf]
    mov  r8d, 37
    push rbx
    push rbx                 ; 2nd push = padding: keep RSP 16-byte aligned
    call p2p_write
    pop  rbx
    pop  rbx
.inv_next:
    mov  rbx, [s_ptr]
    add  rbx, 36
    mov  [s_ptr], rbx
    dec  qword [s_cnt]
    jmp  .inv_loop

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
    ; tx_accept_validate(mp_cur, s_txid, pl_buf, s_plen) -- full mempool
    ; policy (fee/RBF/ancestor-descendant limits) + whole-tx signature
    ; validation before storing for relay, replacing the previous
    ; unconditional mpool_put (which called it on every syntactically-
    ; minimal tx with zero validation).
    cmp  byte [tx_dv_ok], 1
    jne  .next               ; validation unavailable this connection -- drop, don't relay unvalidated
    mov  rdi, [mp_cur]
    lea  rsi, [s_txid]
    lea  rdx, [pl_buf]
    mov  rcx, [s_plen]
    call tx_accept_validate
    jmp  .next

.do_block:
    ; ---- inbound `block` message: the response to a getdata we sent from an
    ; inv (or a peer pushing a block directly). This is the receive/validate/
    ; store half of relay keep-up -- without it the serve loop relayed invs
    ; but never advanced its own store. Drain ONE block here (pl_buf).
    ; Guard 1: minimum block = 80-byte header + count byte.
    mov  rax, [s_plen]
    cmp  rax, 81
    jb   .next
    ; Guard 2: consensus validation. cons_verify(pl_buf, s_plen, scratch, cap)
    ; uses a 1MB reconstruction scratch below rbp internally; pass hp_buf
    ; (idle here) as the scratch source. Returns 1 = valid.
    lea  rdi, [pl_buf]
    mov  rsi, rax             ; s_plen
    lea  rdx, [serve_txid_scratch]        ; scratch
    ; 2026-08-24 (incident #33's audit): this passed (2000*81+8) = 162,008 --
    ; the headers-page BYTE size -- into cons_verify's 4th parameter, which
    ; is a txid COUNT. It licensed 162,008*32 = 5.18 MB of writes into
    ; hp_buf, a 162 KB buffer, i.e. an overflow for any block past ~5,062
    ; transactions (real mainnet blocks reach ~12,000). hp_buf is also the
    ; headers page buffer, so the scratch was aliasing live data either way;
    ; it now has its own.
    mov  rcx, SERVE_TXID_CAP  ; cap, IN TXIDS
    call cons_verify
    ; cons_verify does NOT preserve r12-r15 (it pushes only rbp/rbx), so it
    ; clobbered the serve loop's fd/ht/st live registers. Restore the ones the
    ; rest of the loop relies on from their stable static copies.
    mov  r12, [s_fd]
    mov  r13, [s_lfd]
    mov  r14, [s_st]
    test rax, rax
    jz   .next                ; invalid block -> ignore
    ; Guard 3: re-derive the block hash from its 80-byte header and require it
    ; to be unknown (not already in the hash index). If we already have it,
    ; this is a duplicate relay -- skip, no re-store.
    ; block_hash(out=sb_buf+0x200000, hdr=pl_buf). NOTE: pl_buf may be clobbered
    ; by later calls, so compute the hash BEFORE store_append/idx_put.
    lea  rdi, [sb_buf+0x200000]
    lea  rsi, [pl_buf]
    call block_hash
    ; already have it? idx_get(ht_idx, hash, &s_fh)
    mov  rdi, [s_htidx]
    lea  rsi, [sb_buf+0x200000]
    lea  rdx, [s_fh]
    call idx_get
    test rax, rax
    jnz  .next                ; duplicate -> skip
    ; Guard 4 (STAGE B): the block must actually EXTEND OUR TIP.
    ;
    ; Until now this path appended whatever a peer pushed, at "whatever the
    ; next height is", with no check that it chained to anything -- so a peer
    ; sending a block from a different chain (or a block far ahead of us) had
    ; it recorded at a height it does not belong to, silently producing a
    ; non-contiguous archive. Stage A built store_validates_prevhash for
    ; exactly this gate and nothing ever called it.
    ;
    ; This matters much more now that reorgs exist: an inbound child racing
    ; with a legitimate reorg in the download worker could otherwise append
    ; onto a chain that is mid-rewrite. (reorg_execute holding the append
    ; flock across its whole operation is the other half of that fix; this is
    ; the half that also protects the ordinary, non-reorg case.)
    ;
    ; store_validates_prevhash(st, header80) -> 1 match / 0 mismatch
    ;                                          / -1 empty store.
    ; 1  -> extends our tip, proceed.
    ; -1 -> store is empty, there is no tip to chain to, proceed (first block).
    ; 0  -> does not chain: DROP, matching this handler's existing
    ;       "duplicate -> skip" style (log and ignore, never disconnect the
    ;       peer -- a peer legitimately relaying a block we simply are not
    ;       caught up to yet is not misbehaviour, and the download worker's
    ;       own sync will fetch the gap in order).
    mov  rdi, [s_st]
    lea  rsi, [pl_buf]
    call store_validates_prevhash
    ; store_validates_prevhash -> store_get_tip_hash preserve only rbx/r12-r15
    ; per this codebase's convention, but the serve loop's live fd/lfd/st
    ; registers are restored from their stable statics here anyway, exactly as
    ; the cons_verify call above already does -- cheaper than reasoning about
    ; which callee happens to preserve what.
    mov  r12, [s_fd]
    mov  r13, [s_lfd]
    mov  r14, [s_st]
    test rax, rax
    jnz  .blk_chains          ; 1 (match) or -1 (empty store) -> accept
    ; node_log_event(lfd, 6=L_ERROR, 0, plen, 0) -- already-extern'd logger,
    ; so this adds no new link-time dependency to any binary using this file.
    mov  rdi, r13
    mov  rsi, 6
    xor  rdx, rdx
    mov  rcx, [s_plen]
    xor  r8, r8
    call node_log_event
    mov  r12, [s_fd]
    mov  r13, [s_lfd]
    mov  r14, [s_st]
    jmp  .next                ; does not chain to our tip -> drop
.blk_chains:
    ; idxscan_append_locked(st, hash, pl_buf, s_plen) -- an inbound peer can
    ; push a block directly (or in response to our own .do_inv-triggered
    ; getdata) in ANY forked serve child, concurrently with the download
    ; worker's own node_sync-driven appends in a SEPARATE process -- st+40 IS
    ; a valid flock fd here (main.c opens append.lock and sets it into
    ; store_buf before forking either the download worker or serve_mux's
    ; per-connection children, so every forked copy inherits it). Both
    ; concurrent writers now go through the same flock-guarded,
    ; atomic-height-under-lock primitive so neither can silently collide on
    ; or clobber the other's height slot.
    mov  rdi, [s_st]
    lea  rsi, [sb_buf+0x200000]
    lea  rdx, [pl_buf]
    mov  rcx, [s_plen]
    call idxscan_append_locked
    test rax, rax
    jle  .next
    mov  [s_lastheight], rax  ; survive the idx_put call in a static, not a register
    ; index it (freshly-stored block becomes serveable by hash O(1)):
    ; idx_put(ht_idx, hash, height=newtip). New tip = rax (store_append returns
    ; the appended position). idx_put(idx, hash, height).
    mov  rdi, [s_htidx]
    lea  rsi, [sb_buf+0x200000]
    mov  rdx, [s_lastheight]
    call idx_put
    ; log this inbound-relay disk write (daemon/tx_accept.c) -- the ONLY
    ; place a peer-pushed block (unsolicited or via our own .do_inv-triggered
    ; getdata) becomes visible in the log; the outbound download worker's own
    ; writes are logged separately in main.c's do_outbound_sync.
    lea  rdi, [sb_buf+0x200000]
    mov  rsi, [s_lastheight]
    mov  rdx, [s_plen]
    lea  rcx, [pl_buf]
    call log_block_stored_inbound
    ; bump the served/blocks counter + tip-watch will announce the new tip next
    ; iteration (s_lasttip is stale -> .next announces it exactly once).
    inc  qword [s_served]
    jmp  .next

.maybe_getaddr:
    ; "getaddr" -> dword0 "geta", index4..7 "ddr\0"
    cmp  dword [s_cmd+4], 0x00726464 ; "ddr\0"
    jne  .next
    ; Core answers getaddr ONCE per connection and ignores repeats
    ; (m_getaddr_recvd: "reduce resource waste").
    cmp  byte [s_addrsent], 0
    jne  .next
    mov  byte [s_addrsent], 1
    ; The reply is built in C from the version-2 book (daemon/serve_addr.c,
    ; every BIP155 network) -- this loop used to read the legacy IPv4-only
    ; book here. serve_getaddr(fd, wants_v2)
    mov  rdi, r12
    mov  rsi, [g_peer_wants_addrv2]
    call serve_getaddr
    jmp  .next

.maybe_getdata:
    ; "getdata" -> dword0 "getd", index4..7 "ata\0"
    cmp  dword [s_cmd+4], 0x00617461 ; "ata\0"
    jne  .next
    mov  rax, [s_plen]
    cmp  rax, 37
    jb   .next
    ; Fold in any height index.dat has gained since this process last looked.
    ; The hash index below was built at BOOT; new blocks are appended by the
    ; DOWNLOAD WORKER, a different process, so without this every block we
    ; downloaded during the run is a silent miss and this node never helps
    ; propagate recent blocks. Cheap when nothing is new (one stat), and done
    ; here rather than per connection so a long-lived peer cannot go stale.
    call serve_idx_topup
    mov  qword [s_nf], 0      ; no misses yet for this getdata
    ; cnt = pl[0] (single-byte varint)
    movzx rax, byte [pl_buf]
    mov  [s_cnt], rax     ; item counter
    lea  rax, [pl_buf+1]
    mov  [s_ptr], rax     ; item pointer (do NOT clobber the outer rbx counter)
.gd_loop:
    mov  rax, [s_cnt]
    test rax, rax
    jle  .gd_done
    mov  rbx, [s_ptr]     ; item ptr (rbx is free here -- outer counter saved in the loop bound)
    ; type at rbx (u32 LE): 2=MSG_BLOCK -> serve block; 1=MSG_TX -> mempool tx;
    ; 4=MSG_CMPCT_BLOCK -> serve a compact block (BIP152, requester negotiated).
    mov  r9d, [rbx]
    ; BIP144: modern peers request MSG_WITNESS_BLOCK (0x40000002) / MSG_WITNESS_TX
    ; (0x40000001). Mask the witness flag so they dispatch like the base types;
    ; the archive/mempool hold the full (witness) serialization, which is what a
    ; witness request wants. (A bare MSG_BLOCK from a pre-segwit peer would
    ; strictly want the stripped form -- not done; such peers no longer exist.)
    ; Before this, a MSG_WITNESS_BLOCK getdata matched nothing and was ignored --
    ; this node could not serve blocks to any current peer (2026-08-22).
    and  r9d, 0x3fffffff
    cmp  r9d, 1
    je   .gd_tx
    cmp  r9d, 4
    je   .gd_cmpct
    cmp  r9d, 2
    je   .gd_block
    jmp  .gd_next
.gd_cmpct:
    ; ---- serve a compact block (type 4) ----
    ; guard: peer must have negotiated sendcmpct v2
    cmp  qword [s_cmpct_v2], 1
    jne  .gd_miss
    ; hash at rbx+4 -> resolve to height
    mov  [s_ptr], rbx
    mov  rdi, [s_htidx]
    lea  rsi, [rbx+4]
    lea  rdx, [s_fh]
    call idx_get
    mov  rbx, [s_ptr]
    test rax, rax
    jz   .gd_miss
    ; load block into sb_buf
    mov  [s_ptr], rbx
    mov  rdi, [s_st]
    mov  rsi, [s_fh]
    lea  rdx, [sb_buf]
    mov  rcx, (8<<20)
    call node_serve_block
    mov  rbx, [s_ptr]
    test rax, rax
    jle  .gd_miss
    mov  [s_blen_spill], rax
    ; choose/rotate the nonce (fixed seed is fine for deterministic tests)
    mov  rcx, [s_cmpct_nonce]
    test rcx, rcx
    jnz  .gc_nonce_ok
    mov  rcx, 0x0123456789abcdef
    mov  [s_cmpct_nonce], rcx
.gc_nonce_ok:
    ; cmpctblock_build(bt_buf, sb_buf, blen, nonce)
    mov  [s_ptr], rbx
    lea  rdi, [bt_buf]
    lea  rsi, [sb_buf]
    mov  rdx, [s_blen_spill]
    call cmpctblock_build
    mov  rbx, [s_ptr]
    test rax, rax
    jle  .gd_miss
    mov  r8d, eax           ; cmpctblock length
    ; p2p_write(fd, "cmpctblock", 10, bt_buf, len)
    mov  [s_ptr], rbx
    mov  rdi, r12
    lea  rsi, [cn_cmpct]
    mov  rdx, 10
    lea  rcx, [bt_buf]
    call p2p_write
    mov  rbx, [s_ptr]
    add  qword [s_served], 1
    jmp  .gd_next
    ; ---- serve a full block (type 2) ----
.gd_block:
    ; hash at rbx+4; idx_get(ht_idx, hash, &fh)
    mov  [s_ptr], rbx
    mov  rdi, [s_htidx]      ; use the stable copy (a callee clobbers r15)
    lea  rsi, [rbx+4]
    lea  rdx, [s_fh]
    call idx_get
    mov  rbx, [s_ptr]
    test rax, rax
    jz   .gd_miss
    ; node_serve_block(st, fh, sb_buf, cap)
    mov  [s_ptr], rbx
    mov  rdi, [s_st]         ; stable copy of st
    mov  rsi, [s_fh]
    lea  rdx, [sb_buf]
    mov  rcx, (8<<20)
    call node_serve_block
    mov  rbx, [s_ptr]
    test rax, rax
    jle  .gd_miss
    ; BIP144: a bare MSG_BLOCK (witness flag 0x40000000 CLEAR) from a strict
    ; pre-segwit peer wants the STRIPPED serialization -- it cannot parse the
    ; segwit marker/flag bytes in the full form. The type u32 is still at
    ; [rbx]; if the witness bit is set (MSG_WITNESS_BLOCK) send sb_buf as is,
    ; else strip into bt_buf (free inside this arm) and send that. Length
    ; from node_serve_block is in eax.
    mov  ecx, [rbx]
    test ecx, 0x40000000
    jnz  .gdb_send_full         ; witness requested: full block
    ; block_strip_witness(sb_buf, len, bt_buf, 8<<20) -> stripped len / 0
    mov  [s_ptr], rbx
    lea  rdi, [sb_buf]
    movsxd rsi, eax
    lea  rdx, [bt_buf]
    mov  rcx, (8<<20)
    call block_strip_witness
    mov  rbx, [s_ptr]
    test rax, rax
    jle  .gd_miss               ; strip failed -> serve nothing (never a wrong form)
    mov  r8d, eax
    mov  [s_ptr], rbx
    mov  rdi, r12
    lea  rsi, [cn_block]
    mov  rdx, 5
    lea  rcx, [bt_buf]
    call p2p_write
    mov  rbx, [s_ptr]
    add  qword [s_served], 1
    jmp  .gd_next
.gdb_send_full:
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
    ; txid at rbx+4; mpool_get(mp_cur, txid, &s_n) -> ptr or 0
    mov  [s_ptr], rbx
    mov  rdi, [mp_cur]
    lea  rsi, [rbx+4]
    lea  rdx, [s_n]          ; out_len slot
    call mpool_get
    mov  rbx, [s_ptr]
    test rax, rax
    jz   .gd_miss
    ; p2p_write(fd,"tx",2, ptr, len)
    mov  [s_ptr], rbx
    mov  rdi, r12
    lea  rsi, [cn_tx]
    mov  rdx, 2
    mov  rcx, rax            ; tx bytes (mp_blob ptr)
    mov  r8, [s_n]           ; length
    push rbx
    push rbx                 ; 2nd push = padding: keep RSP 16-byte aligned
    call p2p_write
    pop  rbx
    pop  rbx
    add  qword [s_served], 1
    mov  rbx, [s_ptr]
    jmp  .gd_next
.gd_miss:
    ; Could not serve this entry: copy its 36 bytes into the notfound reply.
    ; rbx points at the entry (type u32 + 32B hash) -- exactly the shape
    ; notfound carries, so it is copied verbatim rather than rebuilt.
    mov  rax, [s_nf]
    cmp  rax, 50
    jae  .gd_next                 ; reply is full; the rest are simply dropped
    lea  rdi, [nf_buf+1]
    imul rcx, rax, 36
    add  rdi, rcx
    mov  rsi, rbx
    mov  rcx, 36
    push rbx
    rep  movsb
    pop  rbx
    inc  qword [s_nf]
    jmp  .gd_next

.gd_done:
    ; every entry handled -- tell the peer about the ones we could not serve
    mov  rax, [s_nf]
    test rax, rax
    jz   .next
    mov  byte [nf_buf], al        ; count (<=50, so a single-byte varint)
    imul r8, rax, 36
    inc  r8                       ; payload length = 1 + n*36
    ; p2p_write(fd,"notfound",8,nf_buf,len)
    mov  rdi, r12
    lea  rsi, [cn_notfnd]
    mov  rdx, 8
    lea  rcx, [nf_buf]
    call p2p_write
    jmp  .next

.gd_next:
    ; advance item pointer by 36 and decrement counter
    mov  rax, [s_ptr]
    add  rax, 36
    mov  [s_ptr], rax
    dec  qword [s_cnt]
    jmp  .gd_loop

.maybe_getcf:
    ; BIP157 compact filters. The index has existed and been proven
    ; byte-identical to Core's for some time; none of these three messages
    ; was in this dispatch, so a light client asking us got silence.
    ; Distinguish on cmd[4..7]: "filt" / "head" / "chec".
    mov  r9d, dword [s_cmd+4]
    xor  r8d, r8d                  ; kind 0 = getcfilters
    cmp  r9d, 0x746c6966           ; "filt" (getcf|ilt|ers)
    je   .gcf_go
    ; NOTE the offsets: after "getc" the next four bytes are "fhea" and
    ; "fche", not "head"/"chec" -- getcfilters matched and the other two did
    ; not, which is exactly what the probe reported.
    mov  r8d, 1                    ; kind 1 = getcfheaders ("getcf|hea|ders")
    cmp  r9d, 0x61656866           ; "fhea"
    je   .gcf_go
    mov  r8d, 2                    ; kind 2 = getcfcheckpt ("getcf|che|ckpt")
    cmp  r9d, 0x65686366           ; "fche"
    jne  .next
.gcf_go:
    ; serve_cfilters(fd, kind, pl_buf, plen)
    mov  rdi, r12
    mov  esi, r8d
    lea  rdx, [pl_buf]
    mov  rcx, [s_plen]
    call serve_cfilters
    jmp  .next

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

.maybe_getb:
    ; "getb..." splits into "getblocks" (cmd[4..7]=="lock" then cmd[8..11]==0)
    ; and "getblocktxn" (cmd[4..7]=="lock", cmd[8..11]=="txn\0" -> 0x006e7874).
    ; Check the "txn\0" suffix at cmd[8..11] first.
    cmp  dword [s_cmd+8], 0x006e7874 ; "txn\0"
    je   .do_getblocktxn
    ; else must be the classic getblocks -> require "lock" at cmd[4..7]
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

.maybe_sendcmpct:
    ; "send..." split: sendheaders / sendcmpct share dword0 "send".
    ;   cmd[4]=='h' -> sendheaders : peer wants new blocks announced as a
    ;     headers message instead of an inv (payload: none).
    ;   cmd[4]=='c' && cmd[5]=='m' -> sendcmpct : BIP152 negotiation.
    cmp  byte [s_cmd+4], 'h'
    je   .do_sendheaders
    ; sendaddrv2 is handshake-only (BIP155: before verack). This loop only
    ; runs after verack, so one arriving here is a protocol violation; Core
    ; disconnects ("sendaddrv2 received after verack"), and so do we -- an
    ; offer we could not honour would be silently misleading. (2026-08-28)
    cmp  byte [s_cmd+4], 'a'
    je   .done
    cmp  byte [s_cmd+4], 'c'
    jne  .next
    cmp  byte [s_cmd+5], 'm'
    jne  .next
    ; payload = announce(u8) || version(u64 LE), 9 bytes
    mov  rax, [s_plen]
    cmp  rax, 9
    jb   .next
    mov  al, [pl_buf]          ; announce (high-bandwidth flag)
    mov  rdx, [pl_buf+1]       ; version
    cmp  rdx, 2
    jne  .next                 ; only support version 2 (BIP152 witness)
    mov  qword [s_cmpct_v2], 1
    movzx rax, byte [pl_buf]
    test rax, rax
    jz   .sc_low
    mov  qword [s_cmpct_hb], 1
    jmp  .next
.sc_low:
    mov  qword [s_cmpct_hb], 0
    jmp  .next

.do_sendheaders:
    ; sendheaders: peer wants new blocks advertised with a `headers` message
    ; rather than an `inv`, cutting relay traffic (one header instead of one
    ; 36-byte inv entry). Empty payload; record the flag so the tip-watch
    ; announcer honors it.
    mov  qword [s_shdr], 1
    jmp  .next

.maybe_feefilter:
    ; "feefilter": confirm cmd[4..7]=="ilt\0" (dword after "feef").
    cmp  dword [s_cmd+4], 0x00746c69 ; "ilt\0"
    jne  .next
    ; payload = int64 LE min-relay-feerate (sat/kB), 8 bytes. We skip relaying
    ; txs to this peer whose feerate is below it.
    mov  rax, [s_plen]
    cmp  rax, 8
    jb   .next
    mov  rax, [pl_buf]           ; int64 LE feerate
    mov  [s_peerfee], rax
    jmp  .next

.do_getblocktxn:
    ; payload: blockhash(32) || count(varint) || indexes (DifferenceFormatter
    ; encoded: stored[i]=idx-shift; shift=idx+1). We serve a blocktxn reply with
    ; exactly the requested txs (witness included) from the stored block.
    mov  rax, [s_plen]
    cmp  rax, 33
    jb   .next
    ; load the requested block by hash into sb_buf
    ; node_serve_block_by_hash(st, hash, out, cap) -> len
    mov  rdi, [s_st]
    lea  rsi, [pl_buf]
    lea  rdx, [sb_buf]
    mov  rcx, (8<<20)
    call node_serve_block_by_hash
    mov  [s_blen_spill], rax   ; block length (preserved)
    test rax, rax
    jle  .next
    ; parse indexes (DifferenceFormatter) from pl_buf+33...
    mov  qword [s_idxn], 0
    mov  qword [s_diffshift], 0
    ; count varint at pl_buf+32
    lea  rbx, [pl_buf+32]      ; cursor (rbx is free, outer counter in r15/rbp)
    xor  ecx, ecx
    mov  cl, byte [rbx]
    cmp  cl, 0xfd
    jae  .gbtx_bigcnt
    inc  rbx
    jmp  .gbtx_cnthave
.gbtx_bigcnt:
    cmp  cl, 0xfd
    jne  .gbkt_done            ; unsupported varint form -> bail (send nothing)
    movzx rcx, word [rbx+1]
    add  rbx, 3
.gbtx_cnthave:
    ; rcx = number of indexes. Parse each diff varint.
.gbtx_idxloop:
    test rcx, rcx
    jz   .gbkt_build
    ; parse a varint diff value at rbx
    xor  edx, edx
    mov  dl, byte [rbx]
    cmp  dl, 0xfd
    jb   .gbtx_d1
    cmp  dl, 0xfd
    jne  .gbkt_done
    movzx rdx, word [rbx+1]
    add  rbx, 3
    jmp  .gbtx_dhave
.gbtx_d1:
    inc  rbx
.gbtx_dhave:
    ; index = shift + diff
    mov  rax, [s_diffshift]
    add  rax, rdx
    ; store index (u16) in s_idxbuf[ idxn*2 ]
    mov  rdx, [s_idxn]
    mov  word [s_idxbuf + rdx*2], ax
    inc  qword [s_idxn]
    ; shift = index + 1
    inc  rax
    mov  [s_diffshift], rax
    dec  rcx
    jmp  .gbtx_idxloop
.gbkt_build:
    ; Build blocktxn into bt_buf = blockhash(32) + count(varint) + concat txs.
    ; blockhash = original request's pl_buf[0:32] (echoed back)
    lea  rdi, [bt_buf]
    lea  rsi, [pl_buf]
    mov  rdx, 32
    call memcpy_len
    ; count varint from s_idxn
    lea  rdi, [bt_buf+32]
    mov  rsi, [s_idxn]
    call varint_put
    ; running write offset = 32 + countbytes
    add  rax, 32
    mov  [s_p], rax
    ; for each requested index j, copy that tx from sb_buf into bt_buf
    mov  qword [s_cnt], 0     ; j = 0
.gbtx_txloop:
    mov  rax, [s_cnt]
    cmp  rax, [s_idxn]
    jae  .gbkt_send
    ; block_tx_at(sb_buf, blen, idx, out_ptr=rcx, out_len=r8)
    ;   out_ptr -> s_fh (slot), out_len -> s_blen (slot); args in regs
    movzx rdx, word [s_idxbuf + rax*2]   ; index
    lea  rdi, [sb_buf]                    ; blockbuf
    mov  rsi, [s_blen_spill]              ; blen  (preserved block length)
    lea  rcx, [s_txptr]                   ; out_ptr
    lea  r8,  [s_txlen]                   ; out_len
    ; save loop vars (caller-saved across block_tx_at + memcpy_len)
    mov  rax, [s_cnt]
    mov  [s_j], rax
    call block_tx_at
    test rax, rax
    jz   .gbkt_done
    ; dst = bt_buf + s_p ; src = s_txptr ; n = s_txlen
    mov  rax, [s_p]
    lea  rdi, [bt_buf + rax]
    mov  rsi, [s_txptr]
    mov  rdx, [s_txlen]
    push rbx
    push rbx                 ; 2nd push = padding: keep RSP 16-byte aligned
    call memcpy_len
    pop  rbx
    pop  rbx
    ; advance offset
    mov  rax, [s_p]
    add  rax, [s_txlen]
    mov  [s_p], rax
    ; next j
    mov  rax, [s_j]
    inc  rax
    mov  [s_cnt], rax
    jmp  .gbtx_txloop
.gbkt_send:
    ; p2p_write(fd, "blocktxn", 8, bt_buf, len)
    mov  rdi, r12
    lea  rsi, [cn_btxn]
    mov  rdx, 8
    lea  rcx, [bt_buf]
    mov  r8d, [s_p]
    call p2p_write
    ; served++
    add  qword [s_served], 1
    jmp  .next
.gbkt_done:
    jmp  .next

.next:
    ; ---- tip-watch: if the stored tip advanced past what we last announced,
    ; advertise the newly-tipped block to the connected peer. Honored form:
    ; `inv`(MSG_BLOCK) by default, or a `headers` message when the peer
    ; negotiated `sendheaders` (BIP130). Updates s_lasttip so each new tip is
    ; announced exactly once.
    mov  eax, [r14+24]        ; tip height (st[24])
    mov  [s_cnt], rax
    mov  rax, [s_lasttip]
    cmp  rax, [s_cnt]
    jge  .tw_done             ; no advance -> nothing to announce
    ; announce the newly-tipped block (height = s_cnt)
    ; node_announce_tip(fd, st, ht_idx, use_headers)
    mov  rdi, r12             ; fd
    mov  rsi, [s_st]          ; st
    mov  rdx, [s_htidx]       ; ht_idx (stable copy)
    mov  rcx, [s_shdr]        ; use_headers: 1 if sendheaders negotiated
    call node_announce_tip
    mov  rax, [s_cnt]
    mov  [s_lasttip], rax
.tw_done:
    ; LONG-RUNNING: do not count down to an exit. Real termination is handled
    ; only by connection close / error (p2p_read <= 0 jumps straight to `.done`).
    ; This lets the node serve + keep current continuously instead of exiting
    ; after a fixed iteration budget.
    jmp  .outer
; A -3 from p2p_read means the peer announced a message above
; P2P_MAX_MSG -- a protocol violation, not an ordinary disconnect. Score it
; before dropping, so a peer that does it repeatedly earns a ban instead of
; simply reconnecting. Anything else falls through unchanged.
; An inv/getdata vector above MAX_INV_SZ is a protocol violation, scored the
; way Core scores it ("inv message size = %u"). Report, then drop.
.inv_toobig:
    mov  rax, [g_serve_violation_hook]
    test rax, rax
    je   .next
    lea  rdi, [viol_invsz]
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    call rax
    mov  rsp, rbp
    pop  rbp
    jmp  .next

.check_viol:
    cmp  rax, -3
    jne  .done
    mov  r13, rax                 ; preserve the return value across the call
    mov  rax, [g_serve_violation_hook]
    test rax, rax
    je   .viol_done
    lea  rdi, [viol_oversize]
    push rbp
    mov  rbp, rsp
    and  rsp, -16                 ; C callee: align explicitly (see net.asm)
    call rax
    mov  rsp, rbp
    pop  rbp
.viol_done:
    mov  rax, r13
.done:
    mov  rax, [s_served]
    add  rsp, 0x58
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; node_announce_tip(int fd, void* st, void* ht_idx, long use_headers) -> long
;   Advertise the node's current tip block to a connected peer, the proactive
;   relay half of the serve loop. Honouases BIP130 sendheaders: when
;   `use_headers` is nonzero the tip is announced as a `headers` message
;   (one 80-byte header + tx-count 0) instead of an `inv`(MSG_BLOCK) entry.
;   Modeled on the wire output a reference client expects byte-for-byte:
;     inv:     [count=1][type u32 LE=2][hash32]           (37 bytes)
;     headers: [count varint=1][hdr80][tx-count 0]        (82 bytes)
;   Returns 1 on success (announcement written), 0 on failure (no tip / load
;   error). Preserves all callee-saved registers.
; ============================================================================
global node_announce_tip
node_announce_tip:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8               ; keep 16-byte stack alignment for calls
    mov  r12, rdi             ; fd
    mov  r13, rsi             ; st
    mov  r14, rdx             ; ht_idx (unused here; block_hash only needs header)
    ; use_headers (rcx) -> local slot [rbp-0x30]. A deep callee below
    ; (node_serve_block / hashing) clobbers r15 and caller-saved regs, so keep
    ; the mode in a stack slot rather than a live register.
    mov  [rbp-0x30], rcx      ; use_headers
    ; tip height = *(int*)(st+24)
    mov  eax, [r13+24]
    test eax, eax
    js   .at_fail             ; no tip
    mov  ebx, eax             ; height (ebx, callee-saved)
    ; node_serve_block(st, h, sb_buf, cap) -> rax = length
    mov  rdi, r13
    mov  esi, ebx
    lea  rdx, [sb_buf]
    mov  rcx, (8<<20)
    call node_serve_block
    test rax, rax
    jle  .at_fail
    cmp  rax, 80
    jb   .at_fail
    ; ---- headers form (sendheaders negotiated) ----
    mov  rax, [rbp-0x30]      ; use_headers (restore after deep callee)
    test rax, rax
    jz   .at_inv
    ; hp_buf = [count varint=0x01][hdr80][tx-count 0x00]
    mov  byte [hp_buf], 1
    ; memcpy_len(dst=hp_buf+1, src=sb_buf, n=80) -- length in RDX
    lea  rdi, [hp_buf+1]
    lea  rsi, [sb_buf]
    mov  rdx, 80
    call memcpy_len
    mov  byte [hp_buf+81], 0        ; tx-count 0
    mov  rdi, r12
    lea  rsi, [cn_head]
    mov  rdx, 7
    lea  rcx, [hp_buf]
    mov  r8d, 82
    call p2p_write
    test rax, rax
    jle  .at_fail
    mov  rax, 1
    jmp  .at_done
.at_inv:
    ; ---- inv form ----
    ; block_hash(out=hp_buf+6+? ...) use sb_buf+0x200000 scratch like getblocks
    ; block_hash(hh, sb_buf) -- 80-byte header hash
    lea  rdi, [sb_buf+0x200000]
    lea  rsi, [sb_buf]
    call block_hash
    ; build inv: hp_buf[0]=count 1, hp_buf[1..4]=type u32 LE=2, hp_buf[5..36]=hashLE
    mov  byte [hp_buf], 1
    mov  dword [hp_buf+1], 2
    ; reverse the 32-byte hash (internal order at sb_buf+0x200000..+31) into
    ; hp_buf+5 in LE wire order. Use base+index (2 MB displacement not encodable
    ; with a scaled register index directly).
    lea  r10, [sb_buf+0x200000+31]  ; src base (last hash byte)
    lea  r11, [hp_buf+5]            ; dst base
    xor  ecx, ecx
.at_rev:
    cmp  rcx, 32
    jae  .at_rev_done
    mov  r9, rcx
    neg  r9
    mov  al, [r10+r9]
    mov  [r11+rcx], al
    inc  rcx
    jmp  .at_rev
.at_rev_done:
    mov  rdi, r12
    lea  rsi, [cn_inv]
    mov  rdx, 3
    lea  rcx, [hp_buf]
    mov  r8d, 37
    call p2p_write
    test rax, rax
    jle  .at_fail
    mov  rax, 1
    jmp  .at_done
.at_fail:
    xor  eax, eax
.at_done:
    add  rsp, 8
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

; helper: varint_put(dst=rdi, val=rsi) -> rax bytes written (1/3/5/9)
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

section .note.GNU-stack noalloc noexec nowrite progbits
