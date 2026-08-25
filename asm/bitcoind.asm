; ============================================================================
; bitcoind.asm -- node daemon orchestration. 100% AI-authored x86-64 assembly.
;
; Functions (each operating on an already-connected/framed peer socket fd):
;
;   long node_make_version(u8* out)   -> length of a version payload built into
;        `out` (caller buffer >= 110 bytes).  Modern version: protocol 70016,
;        NODE_NETWORK, 26-byte addr_recv, 26-byte addr_from, nonce, user-agent
;        string, start_height=0, relay=1.  Layout locked via live-peer oracle.
;
;   int  node_handshake(int fd)  -> 1 ok / 0.  Sends `version`, drains inbound
;        messages until we see the peer's `verack`, then sends our `verack`.
;        (Responds to `ping` with `pong`.)
;
; Depends on (all verified asm): p2p_* builders (bitcoin_p2p.asm), net framing
;   (bitcoin_net.asm).
; ============================================================================
%include "version.inc"   ; single source of truth: app version, UA, protocol version
default rel
%define SYNC_TXID_CAP 80000          ; > 4,000,000 / 60, the wire maximum
                                     ; number of txs a valid block can carry
section .text

extern p2p_write
extern p2p_read
extern p2p_getheaders
extern p2p_getdata_block
extern p2p_headers_count
extern block_hash
extern cons_verify
extern store_append
extern idxscan_append_locked
extern store_get_at
extern store_get_file_fd
extern hst_append
extern hst_get_at
extern hst_count

global node_make_version
node_make_version:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    mov  r12, rdi           ; out (cursor base)
    ; protocol version -- from the single source of truth (version.inc)
    mov  dword [r12], NODE_PROTOCOL_VER
    ; services = NODE_NETWORK(1), timestamp
    mov  qword [r12+4], 1
    mov  qword [r12+12], 1700000000
    ; addr_recv[26] at +20: zero, then port at +44
    lea  rdi, [r12+20]
    xor  eax, eax
    mov  rcx, 26
    rep  stosb
    mov  word [r12+44], 0x8d20     ; port 8333 big-endian bytes 20 8d
    ; addr_from[26] at +46: zero, then port at +70
    lea  rdi, [r12+46]
    mov  rcx, 26
    rep  stosb
    mov  word [r12+70], 0x8d20
    ; nonce at +72  (build in rax: an imm64 mem-store truncates to 32 bits!)
    mov  rax, 0x1122334455667788
    mov  [r12+72], rax
    ; user_agent varstr at +80: len byte + UA bytes. Length is DERIVED at
    ; assembly time from version.inc (%strlen), so it can never drift from the
    ; string itself.
    mov  byte [r12+80], NODE_UA_LEN
    lea  rsi, [rel ua]
    lea  rdi, [r12+81]
    mov  rcx, NODE_UA_LEN
    rep  movsb
    ; start_height u32 then relay byte (cursor-relative: after 81+UA_LEN)
    lea  rdi, [r12+81+NODE_UA_LEN]
    mov  dword [rdi], 0
    mov  byte [rdi+4], 1
    ; total length = 81 + UA_LEN + 4 + 1 -- derived, no hardcoded total
    mov  rax, 81 + NODE_UA_LEN + 5
    pop  r12
    pop  rbx
    pop  rbp
    ret

global node_handshake
node_handshake:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x338        ; locals ALL below save area (rbp-8..-40):
                           ; version payload @ rbp-0xa0 (>=112B: 81+UA26+5)
                           ; cmd[12]      @ rbp-0xe0 (-0xe0..-0xd5)
                           ; plen(4)      @ rbp-0xc8
                           ; payload buf  @ rbp-0x2e0 (cap 0x100=256)
                           ;
                           ; LAYOUT IS LOAD-BEARING (2026-08-25). The old
                           ; frame had TWO overlaps of the incident-#11/#31
                           ; class: plen@-0xd8 sat INSIDE cmd[8..11], and the
                           ; payload buf @-0x140 cap 0x80 spanned -0x140..
                           ; -0xc1 -- placing cmd (and plen) at payload
                           ; offsets 96/104. Any peer version payload LONGER
                           ; than 96 bytes (every real Core peer: 102-125B;
                           ; only short lab payloads fit) overwrote cmd with
                           ; its own tail, the "version" compare failed, and
                           ; the capture below never ran -- blank [dl]
                           ; outbound log fields and zeroed getpeerinfo
                           ; version/subver/services ever since the UA grew.
                           ; The cap is 256 now: a version message of
                           ; 129..256 bytes used to fail the WHOLE handshake
                           ; (p2p_read -2 -> .fail), silently dropping any
                           ; peer with a long UA. 0x338 also restores 16-byte
                           ; RSP alignment at the calls (0x28+0x338 = 0x360).
    mov  r12, rdi           ; fd
    ; build version payload
    lea  rdi, [rbp-0xa0]
    call node_make_version
    mov  r13, rax
    ; send version
    mov  rdi, r12
    lea  rsi, [rel _version]
    mov  rdx, 7
    lea  rcx, [rbp-0xa0]
    mov  r8, r13
    call p2p_write
    cmp  rax, 24
    jl   .fail
.read:
    ; p2p_read(fd, cmd[12], payload, cap, &plen)
    mov  rdi, r12
    lea  rsi, [rbp-0xe0]    ; cmd
    lea  rdx, [rbp-0x2e0]   ; payload (256B, clear of cmd/plen -- see above)
    mov  ecx, 0x100
    lea  r8, [rbp-0xc8]     ; plen (4 bytes, OUTSIDE cmd)
    call p2p_read
    cmp  rax, 0
    jle  .fail
    ; --- is it "version"? capture the peer's payload for logging only (we
    ; already sent ours before the loop; no reply needed here) ---
    lea  rdi, [rbp-0xe0]
    lea  rsi, [rel _version]
    mov  ecx, 7
    repe cmpsb
    jne  .nh_not_version
    mov  eax, dword [rbp-0xc8]  ; plen is a u32 -- the old 8-byte load
                                ; dragged in 4 adjacent garbage bytes
    cmp  rax, 256
    jbe  .nh_len_ok
    mov  rax, 256
.nh_len_ok:
    mov  [rel g_peer_version_len], rax
    mov  rcx, rax
    lea  rdi, [rel g_peer_version_payload]
    lea  rsi, [rbp-0x2e0]
    rep  movsb
.nh_not_version:
    ; --- is it "verack"? ---
    lea  rdi, [rbp-0xe0]
    lea  rsi, [rel _verack]
    mov  ecx, 6
    repe cmpsb
    je   .send_verack
    ; --- is it "ping"? ---
    lea  rdi, [rbp-0xe0]
    lea  rsi, [rel _ping]
    mov  ecx, 4
    repe cmpsb
    jne  .read
    ; echo pong
    mov  rdi, r12
    lea  rsi, [rel _pong]
    mov  rdx, 4
    lea  rcx, [rbp-0x2e0]
    mov  r8d, 8
    call p2p_write
    jmp  .read
.send_verack:
    mov  rdi, r12
    lea  rsi, [rel _verack]
    mov  rdx, 6
    xor  ecx, ecx
    xor  r8d, r8d
    call p2p_write
    mov  eax, 1
    jmp  .ret
.fail:
    mov  eax, 0
.ret:
    add  rsp, 0x338
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; node_accept_handshake(fd) -> 1 ok / 0
;   SERVER / INBOUND role handshake, the peer side of node_handshake. A genuine
;   inbound peer (a full node connecting OUT to us) sends ITS `version` FIRST and
;   waits for us to reply with our own `version` + `verack`, then sends its
;   `verack`. This is what the original serve path was missing: it used
;   node_handshake (the OUTBOUND/initiator role, which sends OUR version first),
;   so an inbound peer's version went unanswered and the handshake hung.
;   Sequence here:
;     loop: p2p_read -> ping: echo pong; "version": send our version + verack,
;           then wait for the peer's verack (echo ping->pong, ignore chatter);
;           "verack": done.
;   Drains/ignores sendheaders/sendaddrv2/addr/inv chatter just like the drain
;   loops, so it never stalls on protocol msgs.
;   Both roles now exist: node_handshake for outbound (daemon sync/follow/ibd),
;   node_accept_handshake for inbound (daemon serve).
; ============================================================================
global node_accept_handshake
node_accept_handshake:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x400        ; 5 pushes (0x28) + 0x400 = 0x428 -> RSP 8 mod 16 at
                           ; every call (matches the node_* call parity). Locals
                           ; ALL below the save area (rbp-8..-40):
                           ; cmd[12]        @ rbp-0x48
                           ; plen(4)        @ rbp-0x54
                           ; our version[128] @ rbp-0x180
                           ; recv[256]      @ rbp-0x300
    mov  r12, rdi          ; fd (callee-saved)
.read_peer_version:
    ; wait for the peer's `version`
.loop:
    mov  rdi, r12
    lea  rsi, [rbp-0x48]   ; cmd
    lea  rdx, [rbp-0x300]  ; payload
    mov  ecx, 256
    lea  r8,  [rbp-0x54]   ; plen
    call p2p_read
    cmp  rax, 0
    jle  .fail
    ; is it "version"?
    lea  rdi, [rbp-0x48]
    lea  rsi, [rel _version]
    mov  ecx, 7
    repe cmpsb
    je   .got_version
    ; is it "ping"? -> echo pong, keep waiting
    lea  rdi, [rbp-0x48]
    lea  rsi, [rel _ping]
    mov  ecx, 4
    repe cmpsb
    jne  .loop
    mov  rdi, r12
    lea  rsi, [rel _pong]
    mov  rdx, 4
    lea  rcx, [rbp-0x300]
    mov  r8d, 8
    call p2p_write
    jmp  .loop
.got_version:
    ; capture the peer's raw version payload (side-effect only; actual
    ; field parsing happens in C -- see g_peer_version_payload's comment)
    mov  eax, dword [rbp-0x54]  ; plen u32 (8-byte load read garbage)
    cmp  rax, 256
    jbe  .gv_len_ok
    mov  rax, 256
.gv_len_ok:
    mov  [rel g_peer_version_len], rax
    mov  rcx, rax
    lea  rdi, [rel g_peer_version_payload]
    lea  rsi, [rbp-0x300]
    rep  movsb
    ; build our version reply
    lea  rdi, [rbp-0x180]
    call node_make_version
    mov  r13, rax          ; payload len (128) -- callee-saved
    ; send our version
    mov  rdi, r12
    lea  rsi, [rel _version]
    mov  rdx, 7
    lea  rcx, [rbp-0x180]
    mov  r8, r13
    call p2p_write
    cmp  rax, 24
    jl   .fail
    ; send our verack
    mov  rdi, r12
    lea  rsi, [rel _verack]
    mov  rdx, 6
    xor  ecx, ecx
    xor  r8d, r8d
    call p2p_write
    ; wait for the peer's verack
.read_peer_verack:
    mov  rdi, r12
    lea  rsi, [rbp-0x48]
    lea  rdx, [rbp-0x300]
    mov  ecx, 256
    lea  r8,  [rbp-0x54]
    call p2p_read
    cmp  rax, 0
    jle  .fail
    ; is it "verack"?
    lea  rdi, [rbp-0x48]
    lea  rsi, [rel _verack]
    mov  ecx, 6
    repe cmpsb
    je   .ok
    ; ping? echo pong
    lea  rdi, [rbp-0x48]
    lea  rsi, [rel _ping]
    mov  ecx, 4
    repe cmpsb
    jne  .read_peer_verack
    mov  rdi, r12
    lea  rsi, [rel _pong]
    mov  rdx, 4
    lea  rcx, [rbp-0x300]
    mov  r8d, 8
    call p2p_write
    jmp  .read_peer_verack
.ok:
    mov  eax, 1
    jmp  .ret
.fail:
    mov  eax, 0
.ret:
    add  rsp, 0x400
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; STAGE B: node_sync now has TWO entry points.
;
;   node_sync(fd, st*, locator32, buf, buflen, out_count*)
;       The ORIGINAL 6-argument signature, byte-for-byte behaviour preserved
;       for every pre-existing caller (tests/test_bitcoind_sync.c,
;       tests/test_keepup.c, daemon/main.c's follow/ibd/serve_mux paths, ...).
;       Now implemented as a thin shim over node_sync_multi with count=1.
;
;   node_sync_multi(fd, st*, locator*, loc_count, buf, buflen, out_count*)
;       The real body. `locator` is loc_count*32 contiguous hash bytes (the
;       doubling-gap ancestor list daemon/locator_build.c produces), clamped
;       to [1,32]. This is what makes FORK DISCOVERY possible at all: with a
;       single-hash locator, a peer whose chain diverged below our tip
;       recognises NONE of our locator and replies from ITS genesis (or with
;       nothing usable); with the real multi-hash locator it finds the newest
;       ancestor it shares with us and starts there.
;
;   After the first successfully stored block the internal loc_count is reset
;   to 1, because from that point the locator local holds exactly one hash
;   (the block just stored) -- the same locator-advance the original code did,
;   just with the count kept consistent with it.
;
; node_sync_multi(fd, st*, locator, loc_count, buf, buflen, out_count*)
;   Headers-first Initial Block Download for a small chain. Loop:
;     request getheaders from the tip locator; parse headers; for each header
;     request the block (getdata), receive `block`, validate (cons_verify), store
;     (store_append); advance the locator to the last-stored block hash. Repeat
;     until headers returns zero (chain tip).  *out_count = blocks stored.
;   NOTE: this is the minimal correct form; a real node tracks more, but this
;   exercises the full download->validate->store path in machine code.
;   Returns 1 ok / 0 error.
;
; Frame: rbx=fd r12=st r13=loc r14=buf r15=out_count (all callee-saved)
;   locals below save area (rbp-8..-40):
;     rbp-0x48 buflen(qw), rbp-0x50 hcount(dw), rbp-0x54 plen(dw),
;     rbp-0x58 varint(dw), rbp-0x5c getdata_len(dw), rbp-0x60 out_count(qw),
;     rbp-0x68 loop_i(dw), rbp-0x70 blockhash[32], rbp-0x90 getdata[37],
;     rbp-0xc0 getheaders[69], rbp-0xf0 stop[32], rbp-0x110 cmd[12],
;     rbp-0xae8 block-hash-precompute[64*32] (headers path),
;     rbp-0x1308 txid_scratch[64*32] (cons_verify path)
;
;   BUG FIXED: txid_scratch used to sit at rbp-0x2e8, immediately after the
;   block-hash-precompute array -- but 0x2e8 (744 bytes) of headroom before
;   rbp is nowhere near enough for a 64*32=2048-byte buffer. Any real block
;   with more than ~23 transactions (i.e. essentially every real mainnet
;   block) overflowed straight through the saved rbx/r12-r15/rbp and the
;   return address on THIS frame, corrupting them with txid bytes and
;   crashing on the next `ret` out of node_sync -- reliably, deterministically,
;   on the very first real block with a real transaction count. The local
;   fake-peer tests that exercised this path only ever sent a handful of
;   near-empty blocks (well under 23 tx), which is why it went uncaught.
;   Moved txid_scratch to fresh space at the (enlarged) frame's own edge,
;   fully clear of both rbp and the block-hash-precompute array, without
;   touching any other local's offset.
;   sub rsp, 0x1b08 (8 mod16; 6 pushes -> RSP 0 mod16 at every nested call)
;
;   STAGE B FRAME ADDITIONS. The getheaders payload used to be built at
;   rbp-0x140, where it had only 0x45 (69) bytes of clearance before the
;   stop-hash local at rbp-0xf0 -- exactly the size of a ONE-hash getheaders
;   message and not one byte more. A 32-hash locator serialises to
;   5 + 32*32 + 32 = 1061 (0x425) bytes, which from rbp-0x140 would have run
;   0x2e5 bytes PAST rbp, straight through the entire save area and the
;   return address. The payload buffer is therefore moved into the deep,
;   otherwise-unused tail of this frame, and loc_count gets its own qword
;   there too:
;     rbp-0x1b04 hdr-drain retry counter (dword, pre-existing)
;     rbp-0x1b00 blk-drain retry counter (dword, pre-existing)
;     rbp-0x1af8 loc_count (qword, NEW)
;     rbp-0x1af0 getheaders payload[1061] (NEW) -> spans [-0x1af0, -0x16cb)
;   RSP is rbp-0x1b30 (5 pushes + 0x1b08), so -0x1b04 is the deepest local and
;   is in bounds; the payload's top (-0x16cb) stays 0x3c3 bytes clear of
;   txid_scratch's base at -0x1308. rbp-0x140 is now unused.
; ============================================================================
; ---- node_sync: 6-arg compatibility shim (count = 1) ----------------------
;   Shifts the register arguments and passes out_count as the 7th (stack)
;   argument node_sync_multi expects at [rbp+16].
;   Alignment: entry RSP%16==8; push rbp -> 0; sub 16 -> 0; so node_sync_multi
;   is entered with RSP%16==8, the standard post-call state its own frame
;   arithmetic assumes.
global node_sync
node_sync:
    push rbp
    mov  rbp, rsp
    sub  rsp, 16
    mov  rax, r9            ; out_count* (arg6) -> 7th arg slot
    mov  [rsp], rax
    mov  r9, r8             ; buflen   (arg5) -> arg6
    mov  r8, rcx            ; buf      (arg4) -> arg5
    mov  ecx, 1             ; loc_count = 1   -> arg4
    call node_sync_multi
    add  rsp, 16
    pop  rbp
    ret

global node_sync_multi
node_sync_multi:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x1b08       ; frame: scratch@-0x1308 (cons_verify), block hashes
                           ; array@-0xae8 (64 x 32B) so headers stay usable even
                           ; after the block receive overwrites buf. 0x1b08==8
                           ; mod16, after 6 pushes -> RSP 0 mod16 at all calls.
    mov  rbx, rdi           ; fd
    mov  r12, rsi           ; st
    mov  [rbp-0x78], rdx    ; locator kept in a STACK LOCAL (r13 is leaked by a
                            ; deep callee in this hash chain -- do not trust it)
    ; ---- loc_count, clamped to [1,32] (the locator payload buffer below is
    ; sized for exactly 32 hashes; p2p_getheaders itself would accept up to
    ; 252, so the clamp must happen HERE, not there) ----
    cmp  rcx, 1
    jge  .lc_lo_ok
    mov  rcx, 1
.lc_lo_ok:
    cmp  rcx, 32
    jle  .lc_hi_ok
    mov  rcx, 32
.lc_hi_ok:
    mov  [rbp-0x1af8], rcx
    mov  r14, r8            ; buf
    mov  [rbp-0x48], r9     ; buflen (QWORD; write BEFORE out_count to avoid overlap)
    mov  rax, [rbp+16]      ; out_count ptr (7th arg, on the stack)
    mov  [rbp-0x60], rax
    mov  r15, [rbp-0x60]    ; r15 = out_count ptr (callee-saved)
    mov  qword [r15], 0
    mov  dword [rbp-0x68], 0    ; loop index i = 0
    ; zero the 32-byte stop hash
    lea  rdi, [rbp-0xf0]
    xor  eax, eax
    mov  rcx, 32
    rep  stosb
.sync_loop:
    ; ---- request headers ----
    lea  rdi, [rbp-0x1af0]  ; payload buffer (1061B capacity; see frame note)
    mov  rsi, [rbp-0x78]    ; locator (from stack local)
    mov  edx, [rbp-0x1af8]  ; loc_count (clamped to [1,32] at entry)
    lea  rcx, [rbp-0xf0]
    call p2p_getheaders
    test rax, rax
    jg .fchk1
    mov  dword [rel sync_fail_code], 1
    jmp  .fail
    .fchk1:
    mov  r8, rax            ; headers payload len (5+count*32+32) = plen to send
    mov  rdi, rbx
    lea  rsi, [rel _getheaders]
    mov  rdx, 10
    lea  rcx, [rbp-0x1af0]
    call p2p_write
    cmp  rax, 24
    jge .fchk2
    mov  dword [rel sync_fail_code], 2
    jmp  .fail
    .fchk2:
    ; ---- receive headers, draining ANY interleaved relay chatter a live seed
    ; sends post-verack (addr/sendheaders/feefilter/inv/version/ping). The fake
    ; loopback peer never interleaves these, so the original strict "first read
    ; must be headers -> else .fail" only worked in test. Against real mainnet
    ; the first post-getheaders read is often an `addr`/`inv`, which must be
    ; drained -- echo ping->pong, ignore everything else, re-read.
    ;
    ; BUG FIXED: a single read TIMEOUT (p2p_read returning -1, from the 3s
    ; SO_RCVTIMEO on this socket) used to be treated identically to a real
    ; connection failure -- immediately abandoning the whole getheaders
    ; attempt. Debug instrumentation against real mainnet peers showed
    ; -1 returns landing ~3.0s apart consistently (i.e. genuine per-read
    ; timeouts, not a dead socket): a busy peer sends inv/ping chatter in
    ; sparse bursts with multi-second gaps, so ANY single quiet moment
    ; during the drain was enough to make us give up and re-dial from
    ; scratch on the next rotation -- we would never sit through a gap
    ; long enough to actually receive the real headers response, no matter
    ; how healthy the connection was. -1 (timeout/transient error) now
    ; retries, bounded, instead of failing immediately; 0 (EOF/short-read)
    ; and -2 (truncated) are unchanged -- those mean the connection itself
    ; is genuinely done, retrying would be pointless.
    mov  dword [rbp-0x1b04], 0    ; hdr-drain retry counter (fresh unused
                                    ; space in the enlarged frame; reset once
                                    ; per getheaders attempt, i.e. every
                                    ; .sync_loop re-entry)
.hdr_drain:
    mov  rdi, rbx
    lea  rsi, [rbp-0x160]   ; cmd
    mov  rdx, r14
    mov  ecx, [rbp-0x48]    ; cap
    lea  r8, [rbp-0x54]     ; plen
    call p2p_read
    cmp  rax, -1
    jne  .hdr_not_timeout
    inc  dword [rbp-0x1b04]
    ; 2026-08-24 (incident #33 root-cause-2 investigation): was 20 (~60s).
    ; An independent Python getheaders probe against the same public peers
    ; this node fails on showed every peer that WILL serve headers answers in
    ; 150-1065 ms; the ones that fail send tx-relay chatter or go silent and
    ; never send headers at all -- i.e. `where=3` is a non-serving peer, not a
    ; slow one. 60 s of patience for a peer that answers in ~1 s just makes the
    ; node slow to rotate off a dead leg after boot (each failing pass costs
    ; the full budget, and a leg is dropped only after 3 passes). 8 timeouts
    ; (~24s) is still far beyond any real headers latency while cutting the
    ; dead-leg cost ~2.5x. Chatter (rax>0) does not increment this counter, so
    ; this only bounds GENUINE silence; the block-drain counter is left at 20
    ; because a large block transfer legitimately involves longer quiet gaps.
    cmp  dword [rbp-0x1b04], 8
    jb .fchk3
    mov  dword [rel sync_fail_code], 3
    jmp  .fail                      ; before truly giving up on this pass
    .fchk3:
    jmp  .hdr_drain                 ; truly giving up on this getheaders pass
.hdr_not_timeout:
    cmp  rax, 0
    jg .fchk4
    mov  dword [rel sync_fail_code], 4
    jmp  .fail
    .fchk4:
    lea  rdi, [rbp-0x160]
    lea  rsi, [rel _headers]
    mov  ecx, 7
    repe cmpsb
    je   .have_headers
    ; not headers: echo pong if ping, else just ignore & re-read
    lea  rdi, [rbp-0x160]
    lea  rsi, [rel _ping]
    mov  ecx, 4
    repe cmpsb
    jne  .hdr_drain
    mov  rdi, rbx
    lea  rsi, [rel _pong]
    mov  rdx, 4
    mov  rcx, r14
    mov  r8d, 8
    call p2p_write
    jmp  .hdr_drain
.have_headers:
    ; ---- headers count ----
    mov  rdi, r14
    mov  esi, [rbp-0x54]
    call p2p_headers_count
    mov  [rbp-0x50], eax    ; hcount (processing cap)
    mov  [rbp-0x4c], eax    ; hcount_real (raw; for varint offset calc below)
    test eax, eax
    jz   .done
    ; varint bytes = plen - hcount_real*81  (real count, NOT the 64-cap -- the
    ; page may hold up to 2000 headers in the buffer even though we only
    ; process/store the first 64 this pass; offset must point at header 0)
    mov  eax, [rbp-0x4c]
    imul rax, 81
    mov  r8d, [rbp-0x54]    ; plen is a DWORD -- 32-bit load!
    sub  r8, rax
    mov  [rbp-0x58], r8d
    ; CAP the PROCESSING count to the allocated prehash array (64 x 32B at
    ; rbp-0xae8). A live mainnet seed returns up to 2000 headers per getheaders
    ; page; the prehash loop writes hash[i] at rbp-0xae8 + i*32, so processing
    ; >64 would overflow that array upward and stomp the locator ([rbp-0x78])
    ; + save area -> SIGSEGV. The fake 8-block peer never sent >64, hiding this.
    ; Clamping to 64 keeps the verified array bound; node_sync re-requests from
    ; the advanced locator to fetch the remainder.
    mov  eax, [rbp-0x50]
    cmp  eax, 64
    jbe  .hc_ok
    mov  eax, 64
    mov  [rbp-0x50], eax
.hc_ok:
    mov  dword [rbp-0x68], 0
    ; PRECOMPUTE all block hashes from headers into rbp-0xae8 + i*32 while the
    ; headers are still in buf (the later block receive overwrites buf, so we
    ; can't re-derive header1's hash after block0 lands).
.prehash:
    mov  eax, [rbp-0x68]
    cmp  eax, [rbp-0x50]
    jae  .prehash_done
    ; src = buf + varint + i*81
    mov  eax, [rbp-0x58]
    mov  ecx, [rbp-0x68]
    imul rcx, 81
    add  rax, rcx
    lea  rsi, [r14+rax]
    ; dst = rbp-0xae8 + i*32
    mov  ecx, [rbp-0x68]
    imul rcx, 32
    lea  rdi, [rbp-0xae8]
    add  rdi, rcx
    call block_hash
    inc  dword [rbp-0x68]
    jmp  .prehash
.prehash_done:
    mov  dword [rbp-0x68], 0
.header_loop:
    mov  eax, [rbp-0x68]    ; i
    mov  r9d, eax
    cmp  eax, [rbp-0x50]    ; i vs hcount
    jae  .sync_loop_next
    ; use the precomputed hash at rbp-0xae8 + i*32 for getdata
    mov  ecx, [rbp-0x68]
    imul rcx, 32
    lea  rsi, [rbp-0xae8]
    add  rsi, rcx
    ; rsi already = precomputed block hash (rbp-0xae8 + i*32). Copy it into
    ; the blockhash buffer -0xa0 (so the later store_append can use it), then
    ; build getdata straight from it.
    push rsi
    lea  rdi, [rbp-0xa0]
    mov  rcx, 32
    rep  movsb
    pop  rsi
    ; build getdata (buffer at -0xd0)
    lea  rdi, [rbp-0xd0]
    lea  rsi, [rbp-0xa0]
    call p2p_getdata_block
    mov  [rbp-0x5c], eax
    ; send getdata
    mov  rdi, rbx
    lea  rsi, [rel _getdata]
    mov  rdx, 7
    lea  rcx, [rbp-0xd0]
    mov  r8d, [rbp-0x5c]
    call p2p_write
    cmp  rax, 24
    jge .fchk5
    mov  dword [rel sync_fail_code], 5
    jmp  .fail
    .fchk5:
    ; ---- receive block, draining interleaved relay chatter (live seeds send
    ; addr/inv/ping/sendheaders between our getdata and the block reply; the
    ; fake peer never did, so the original strict read broke live). Echo ping->
    ; pong, ignore other non-`block` msgs, re-read.
    ; Same fix as .hdr_drain: a single read timeout (-1) retries (bounded)
    ; rather than immediately abandoning the block fetch -- see the .hdr_drain
    ; comment above for why (busy real peers pause between chatter bursts).
    mov  dword [rbp-0x1b00], 0    ; blk-drain retry counter (separate 4 bytes
                                    ; from the hdr-drain one at -0x1b04)
.blk_drain:
    mov  rdi, rbx
    lea  rsi, [rbp-0x160]
    mov  rdx, r14
    mov  ecx, [rbp-0x48]
    lea  r8, [rbp-0x54]
    call p2p_read
    cmp  rax, -1
    jne  .blk_not_timeout
    inc  dword [rbp-0x1b00]
    cmp  dword [rbp-0x1b00], 20
    jb .fchk6
    mov  dword [rel sync_fail_code], 6
    jmp  .fail
    .fchk6:
    jmp  .blk_drain
.blk_not_timeout:
    cmp  rax, 0
    jg .fchk7
    mov  dword [rel sync_fail_code], 7
    jmp  .fail
    .fchk7:
    lea  rdi, [rbp-0x160]
    lea  rsi, [rel _block]
    mov  ecx, 5
    repe cmpsb
    je   .have_block
    ; not block: echo pong if ping, else ignore & re-read
    lea  rdi, [rbp-0x160]
    lea  rsi, [rel _ping]
    mov  ecx, 4
    repe cmpsb
    jne  .blk_drain
    mov  rdi, rbx
    lea  rsi, [rel _pong]
    mov  rdx, 4
    mov  rcx, r14
    mov  r8d, 8
    call p2p_write
    jmp  .blk_drain
.have_block:
    ; ---- validate ----
    mov  rdi, r14
    mov  esi, [rbp-0x54]
    ; INCIDENT #33 (2026-08-24): this passed the frame-local txid_scratch with
    ; cap=64, and cons_verify's 4th argument is the scratch capacity IN TXIDS
    ; -- so steady-state sync could not validate any block with more than 64
    ; transactions. Every block at the chain tip has thousands, so
    ; node_sync_multi returned 0 on every modern block, AFTER downloading and
    ; storing it; do_outbound_sync then took its ok!=1 early-return and threw
    ; the work away. The node advanced its tip only at boot (the dlc catch-up
    ; path passes a correctly-sized scratch), and the failure was silent at
    ; both ends. Found by driving node_sync_multi against the scratch Core
    ; oracle: ok=0 with cnt=51,727 -- the first block over 64 txs, at height
    ; ~51,726, is exactly where it stopped.
    ;
    ; A frame-local scratch cannot be made big enough: the bound is
    ; MAX_BLOCK_SERIALIZED_SIZE / smallest-tx ~= 4,000,000/60 ~= 66,666
    ; txids, i.e. >2 MB. It moves to .bss, which is per-process and therefore
    ; still safe for the forked serve children (COW).
    lea  rdx, [rel sync_txid_scratch]
    mov  ecx, SYNC_TXID_CAP
    call cons_verify
    test eax, eax
    jnz .fchk8
    mov  dword [rel sync_fail_code], 8
    jmp  .fail
    .fchk8:
    ; ---- store ----
    ; idxscan_append_locked (not plain store_append): in `serve` mode this
    ; process (the download worker) is not the only writer -- an inbound
    ; peer's forked serve child can also append via .do_block. Both paths
    ; now go through the flock-guarded, atomic-height-under-lock primitive
    ; so neither can silently collide on or clobber the other's height slot.
    ; Same (st,hash,raw,len) signature and return convention as store_append,
    ; so no other change is needed at this call site. Harmless/no-op locking
    ; overhead in `sync`/`ibd` modes, where st+40 is never set to a flock fd.
    mov  rdi, r12
    lea  rsi, [rbp-0xa0]
    mov  rdx, r14
    mov  ecx, [rbp-0x54]    ; blen is a DWORD -- 32-bit load!
    call idxscan_append_locked
    cmp  rax, -1
    je   .app_err
    cmp  rax, -2
    jne  .fchk9
    ; -2: not-tip-linked (incident #46's linkage gate) -- a sibling writer
    ; landed this block first, or the peer served a stale/competing block.
    ; Not a leg failure in the ordinary sense, but ending the pass here is
    ; correct either way: the locator is stale, and the next rotation
    ; rebuilds it from the true tip. Distinct fail code so the log
    ; distinguishes "append error" from "stale duplicate refused".
    mov  dword [rel sync_fail_code], 10
    jmp  .fail
    .app_err:
    mov  dword [rel sync_fail_code], 9
    jmp  .fail
    .fchk9:
    ; locator = stored block hash (a SINGLE hash from here on -- so the count
    ; must drop to 1 to match, or the next getheaders would re-send stale
    ; ancestor hashes from the caller's original multi-hash buffer behind it)
    lea  rsi, [rbp-0xa0]
    mov  rdi, [rbp-0x78]    ; locator (from stack local)
    mov  rcx, 32
    rep  movsb
    mov  qword [rbp-0x1af8], 1
    inc  qword [r15]
    inc  dword [rbp-0x68]
    jmp  .header_loop
.sync_loop_next:
    jmp  .sync_loop
.done:
    mov  eax, 1
    add  rsp, 0x1b08
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
.fail:
    mov  eax, 0
    add  rsp, 0x1b08
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; node_serve_block(st, height, out_buf, cap) -> block length, or -1
;   Serve a stored block from a MULTI-FILE store: store_get_at returns
;   (data_pos, data_size, file_no); open blk%05d.dat for file_no, seek to
;   data_pos+8 (skip the frame header), read data_size bytes into out_buf.
; ============================================================================
global node_serve_block
; CALLEE-SAVED SAVE AREA IS *ABOVE* RBP: the pushes precede `push rbp`, so
;   rbx r12 r13 r14 r15 are saved at [rbp+0x08 ...] and every [rbp-N] local is inside this
;   function's own 0x48 reservation. Previously the pushes followed
;   `mov rbp,rsp`, which put the save area at [rbp-0x08 ...] -- underneath the
;   locals listed below -- so the epilogue's pops handed the CALLER the saved data_size instead of r15.
;   ALIGNMENT IS UNCHANGED: same pushes, same reservation, only reordered, so
;   RSP has the same value mod 16 at every instruction after the prologue.
node_serve_block:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x48          ; meta[24]@-0x48, saved pos/size qwords @-0x30/-0x28
    mov  r12, rdi           ; st (callee-saved, preserved by store_* calls)
    mov  r13, rdx           ; out_buf
    mov  r14, rcx           ; cap
    ; store_get_at(st, height, &meta@-0x48) -> pos, size, file_no
    mov  rdi, r12
    mov  rsi, rsi           ; height
    lea  rdx, [rbp-0x48]
    call store_get_at
    cmp  rax, 1
    jne  .fail
    mov  rax, [rbp-0x48]    ; data_pos
    mov  [rbp-0x30], rax    ; save pos across the open-file call
    mov  rax, [rbp-0x48+8]  ; data_size
    mov  [rbp-0x28], rax    ; save size across the open-file call
    mov  eax, [rbp-0x48+16] ; file_no
    mov  r15, rax           ; file_no (callee-saved)
    cmp  qword [rbp-0x28], r14
    ja   .fail              ; cap too small
    ; open the correct block file for file_no -> sets st->cur_blk_fd, returns fd
    mov  rdi, r12
    mov  esi, r15d
    call store_get_file_fd
    test rax, rax
    jl   .fail
    ; read from fd=rax: lseek(pos+8), read(size) into out_buf
    mov  rbx, rax           ; fd (callee-saved)
    mov  rdi, rbx
    mov  rax, [rbp-0x30]
    add  rax, 8
    mov  rsi, rax
    xor  edx, edx
    mov  eax, 8             ; lseek
    syscall
    test rax, rax
    jl   .fail
    mov  rdi, rbx
    mov  rsi, r13
    mov  rdx, [rbp-0x28]    ; size
    mov  eax, 0             ; read
    syscall
    cmp  rax, [rbp-0x28]
    jne  .fail
    mov  rax, [rbp-0x28]    ; return block length
    add  rsp, 0x48
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.fail:
    mov  rax, -1
    add  rsp, 0x48
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; node_serve_block_by_hash(st, hash32, out_buf, cap) -> block length, or -1
;   COMPLIANT block serve: a peer's `getdata` carries a block HASH. Scan the
;   stored chain (heights 0..tip), compute each stored block's header hash, and
;   serve the exact block whose hash matches `hash32`. This answers real getdata
;   requests with the precise requested block.  Returns the block length, or -1
;   if height is out of range, cap too small, or no block matched.
; ============================================================================
global node_serve_block_by_hash
; CALLEE-SAVED SAVE AREA IS *ABOVE* RBP: the pushes precede `push rbp`, so
;   rbx/r12/r13/r14/r15 are saved at [rbp+0x08 .. rbp+0x28] and every [rbp-N]
;   local is inside this function's own reservation. Previously the pushes
;   followed `mov rbp,rsp`, putting saved r15 at rbp-0x28 -- only 24 bytes above
;   the 32-byte hash buffer at [rbp-0x40], which block_hash fills completely. The top
;   8 bytes of that hash landed on saved r15. Flagged by
;   scripts/abi_callee_saved_audit.py as 24 bytes of headroom for a 32-byte
;   write.
;   ALIGNMENT IS UNCHANGED: same six pushes, same reservation, only reordered.
node_serve_block_by_hash:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x208       ; 8 mod16 -> nested calls land at RSP ≡ 8 (mod 16), the
                          ; parity that provably works for the deep
                          ; block_hash->sha256d->sha256_full chain (node_sync and
                          ; cons_verify both call at ≡8; a ≡0 caller crashes it).
    mov  r12, rdi           ; st
    mov  r13, rsi           ; hash32 (requested)
    mov  r14, rdx           ; out_buf
    mov  r15, rcx           ; cap
    ; tip height = *(int*)(st+24)
    mov  eax, [r12+24]
    test eax, eax
    js   .nomatch
    mov  [rbp-0x4c], eax    ; tip (dword local; r9 is caller-saved/C-clobbered)
    ; loop index in rbx (callee-saved across node_serve_block/block_hash)
    mov  ebx, 0
.loop:
    mov  eax, [rbp-0x4c]
    cmp  ebx, eax
    ja   .nomatch
    mov  rdi, r12
    mov  rsi, rbx
    mov  rdx, r14
    mov  rcx, r15
    call node_serve_block
    test rax, rax
    jle  .next
    lea  rdi, [rbp-0x40]    ; hashbuf[32]
    mov  rsi, r14
    call block_hash
    lea  rsi, [rbp-0x40]
    mov  rdi, r13
    mov  rcx, 32
    repe cmpsb
    je   .matched
.next:
    inc  ebx
    jmp  .loop
.matched:
    mov  rdi, r12
    mov  rsi, rbx
    mov  rdx, r14
    mov  rcx, r15
    call node_serve_block
    test rax, rax
    jle  .nomatch
    add  rsp, 0x208
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.nomatch:
    mov  rax, -1
    add  rsp, 0x208
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; node_drain(fd, st, buf, buflen) -> eax = # blocks stored (or -1 on hard err)
;   Distributed-download per-peer loop: drains a live peer until it closes,
;   downloading+storing whatever it announces. For each message:
;     ping       -> pong (echo nonce)
;     inv        -> for each MSG_BLOCK hash: getdata, receive `block`, validate
;                   with asm cons_verify, store with asm store_append. A real
;                   peer announces new/recent blocks via inv, so this is the
;                   live-relay half of a multi-peer downloader.
;   Everything else (sendheaders/addr/etc.) is drained and ignored, so we never
;   stall on peer chatter the way a naive single p2p_read does.
;   This is the per-connection loop the 8-peer orchestrator forks.
;   clobbers: caller-saved. Preserves rbx/r12-r15.
; ============================================================================
global node_drain
; CALLEE-SAVED SAVE AREA IS *ABOVE* RBP: the pushes precede `push rbp`, so
;   rbx r12 r13 r14 r15 are saved at [rbp+0x08 ...] and every [rbp-N] local is inside this
;   function's own 0x108 reservation. Previously the pushes followed
;   `mov rbp,rsp`, which put the save area at [rbp-0x08 ...] -- underneath the
;   locals listed below -- so the epilogue's pops handed the CALLER buflen/plen/idx instead of r14/r15.
;   ALIGNMENT IS UNCHANGED: same pushes, same reservation, only reordered, so
;   RSP has the same value mod 16 at every instruction after the prologue.
node_drain:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x108           ; 6 pushes (0x30) + 0x108 = 0x138 == 8 mod16 -> calls
                              ; aligned. Locals below rbp-0x28 down to -0x130:
                              ; buflen@-0x20, plen@-0x24, idx@-0x28, cmd@-0x40,
                              ; getdata-msg@-0x60, blockhash-out@-0x100.
    mov  rbx, rdi            ; fd
    mov  r12, rsi            ; st
    mov  r13, rdx            ; buf (receive buffer)
    mov  [rbp-0x20], rcx     ; buflen
    xor  r14d, r14d          ; r14 = block count (callee-saved)
.drain_loop:
    ; p2p_read(fd, cmd@rbp-0x40, buf, cap, &plen@rbp-0x24)
    mov  rdi, rbx
    lea  rsi, [rbp-0x40]
    mov  rdx, r13
    mov  ecx, [rbp-0x20]
    lea  r8, [rbp-0x24]
    call p2p_read
    test rax, rax
    jle  .done                ; eof/err
    lea  rdi, [rbp-0x40]
    lea  rsi, [rel _ping]
    mov  ecx, 4
    repe cmpsb
    jne  .not_ping
    ; pong echo
    mov  rdi, rbx
    lea  rsi, [rel _pong]
    mov  rdx, 4
    mov  rcx, r13
    mov  r8d, 8
    call p2p_write
    jmp  .drain_loop
.not_ping:
    lea  rdi, [rbp-0x40]
    lea  rsi, [rel _inv]
    mov  ecx, 3
    repe cmpsb
    jne  .drain_loop          ; drain/ignore other messages
    ; inv: payload[0]=count(1B varint); items at +1 step 36: [type u32 LE][hash32]
    mov  eax, [rbp-0x24]
    cmp  eax, 5
    jl   .drain_loop
    xor  eax, eax
    movzx eax, byte [r13]
    mov  r15d, eax            ; item count in callee-saved r15
    cmp  r15d, 1
    jb   .drain_loop
    mov  dword [rbp-0x28], 0  ; item index in a stack local (caller-saved regs unsafe)
.inv_loop:
    mov  eax, [rbp-0x28]
    cmp  eax, r15d
    jae  .drain_loop
    ; item ptr = r13 + 1 + (index*36)
    lea  r9, [r13+1]
    mov  edx, eax
    imul edx, edx, 36
    add  r9, rdx              ; r9 = item ptr (caller-saved, recompute after any call)
    mov  edx, [r9]            ; type (u32 LE)
    cmp  edx, 2               ; MSG_BLOCK
    jne  .inv_next
    ; build getdata(payload) for hash at r9+4 into [rbp-0x60]
    lea  rdi, [rbp-0x60]
    lea  rsi, [r9+4]
    call p2p_getdata_block
    mov  r8d, eax             ; 4th arg: payload len
    mov  rdi, rbx
    lea  rsi, [rel _getdata]
    mov  edx, 7
    lea  rcx, [rbp-0x60]
    call p2p_write            ; (fd, cmd, 7, payload@-0x60, len)
    ; receive `block` message into buf
    mov  rdi, rbx
    lea  rsi, [rbp-0x40]
    mov  rdx, r13
    mov  ecx, [rbp-0x20]
    lea  r8, [rbp-0x24]
    call p2p_read
    test rax, rax
    jle  .inv_next
    lea  rdi, [rbp-0x40]
    lea  rsi, [rel _block]
    mov  ecx, 5
    repe cmpsb
    jne  .inv_next
    ; validate: cons_verify(buf @r13, plen, scratch, cap)
    ; 2026-08-24 (incident #33's audit): this reserved 0x400 = 1024 bytes of
    ; stack scratch -- room for 32 txids -- and then told cons_verify the cap
    ; was 256, i.e. 8192 bytes. Any block with more than 32 transactions
    ; wrote up to 7 KB past the scratch, over this function's own locals,
    ; saved registers and return address, on data supplied by a peer. Same
    ; units confusion as node_sync_multi's cap=64, one step further along:
    ; there the wrong cap REJECTED valid blocks, here it CORRUPTS THE STACK.
    ; Uses the shared .bss scratch and its matching cap, like node_sync_multi.
    mov  rdi, r13
    mov  esi, [rbp-0x24]
    lea  rdx, [rel drain_txid_scratch]
    mov  ecx, SYNC_TXID_CAP
    call cons_verify
    test eax, eax
    jz   .inv_next
    ; block_hash(out@rbp-0x100, buf)
    lea  rdi, [rbp-0x100]
    mov  rsi, r13
    call block_hash
    ; store_append(st, hash@rbp-0x100, buf, plen)
    mov  rdi, r12
    lea  rsi, [rbp-0x100]
    mov  rdx, r13
    mov  ecx, [rbp-0x24]
    call store_append
    cmp  rax, -1
    je   .inv_next
    inc  r14d                 ; block stored
.inv_next:
    inc  dword [rbp-0x28]
    jmp  .inv_loop
.done:
    mov  eax, r14d
    add  rsp, 0x108
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; node_fetch_headers(fd, locator32, count, stop32, out_buf, &out_count) -> eax
;   Robust headers-first fetch for a real peer: sends getheaders(locator), then
;   DRAINS peer chatter (ping->pong, ignores sendheaders/addr/inv) until a
;   `headers` message arrives; copies the header bytes into out_buf and reports
;   the header entry count via *out_count. Returns 1 ok / 0 on error.
;   This is the primitive a persistent header-chain download needs; it tolerates
;   the chatter that naive node_sync stalls on.
; ============================================================================
global node_fetch_headers
node_fetch_headers:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x188          ; 6 pushes (0x30) + 0x188 = 0x1b8 == 8 mod16 -> aligned
                             ; Locals cover down to -0x180 (getheaders-msg).
                             ; GOLDEN-RULE AUDIT (2026-08-11 fix): the len_out
                             ; local was at rbp-0x20, INSIDE the 5-push callee-
                             ; saved save area (rbx-8/r12-16/r13-24/r14-32/r15-40),
                             ; so p2p_read wrote the message length over the saved
                             ; r14 slot and the epilogue pop r14 restored garbage
                             ; into the caller's r14 (broke node_ibd_headers, which
                             ; keeps page_buf in r14). Moved to rbp-0x98 (below).
    mov  rbx, rdi            ; fd
    mov  [rbp-0x50], rsi     ; locator32 (qword, NON-overlapping)
    mov  r15d, edx           ; count (locator hashes; usually 1)
    mov  [rbp-0x60], rcx     ; stop32 (qword pointer)
    mov  r12, r8             ; out_buf
    mov  r13, r9             ; out_count ptr
    ; ---- build + send getheaders ----
    lea  rdi, [rbp-0x180]
    mov  rsi, [rbp-0x50]
    mov  edx, r15d
    mov  rcx, [rbp-0x60]
    call p2p_getheaders      ; -> eax = payload len (69)
    mov  r8d, eax
    mov  rdi, rbx
    lea  rsi, [rel _getheaders]
    mov  edx, 10
    lea  rcx, [rbp-0x180]
    call p2p_write
    cmp  rax, 24
    jl   .fail
    ; Bound the drain: a live seed streams sendheaders/addr/inv/sendcmpct/
    ; feefilter etc. and may NOT send a `headers` reply for a locator it
    ; considers already-known, so an unbounded wait hangs forever (the
    ; 2026-08-15 live-IBD finding). Cap + return an error so a caller can
    ; never block indefinitely. Synthetic loopback peers reply within a few
    ; iterations, so this bound (64) is unreachable in tests.
    mov  rax, 64
    mov  [rbp-0x70], rax
.do_read:
    dec  qword [rbp-0x70]
    js   .fail                ; drained too much chatter -> no headers reply
    mov  rdi, rbx            ; fd
    lea  rsi, [rbp-0x80]     ; cmd buffer (12 bytes, no overlap)
    mov  rdx, r12            ; payload -> out_buf
    mov  ecx, 2000000        ; cap (caller must supply >= 2MB out_buf)
    lea  r8, [rbp-0x98]
    call p2p_read
    test rax, rax
    jle  .fail
    lea  rdi, [rbp-0x80]
    lea  rsi, [rel _ping]
    mov  ecx, 4
    repe cmpsb
    jne  .not_ping
    mov  rdi, rbx
    lea  rsi, [rel _pong]
    mov  edx, 4
    mov  rcx, r12
    mov  r8d, 8
    call p2p_write
    jmp  .do_read
.not_ping:
    lea  rdi, [rbp-0x80]
    lea  rsi, [rel _headers]
    mov  ecx, 7
    repe cmpsb
    jne  .do_read            ; sendheaders/addr/inv: drain, keep waiting
    ; got `headers`: report the entry count
    mov  rdi, r12
    mov  esi, [rbp-0x98]
    call p2p_headers_count
    test eax, eax
    jl   .fail
    mov  [r13], rax          ; *out_count = count
    mov  eax, 1
    jmp  .ret
.fail:
    mov  eax, 0
.ret:
    add  rsp, 0x188
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; node_ibd_headers(fd, hst*, locator32, page_buf, buflen) -> eax total
;   Paged headers-first IBD download into a PERSISTENT header store.
;   Repeatedly calls node_fetch_headers at the "running locator" (the hash the
;   peer should chain the next page from), verifies chain continuity for every
;   header in the page, computes each header's block_hash, and hst_appends the
;   (header, block_hash) pair. The running locator then advances to the last
;   appended header's hash. Stops when a page returns 0 headers (reached tip)
;   or a short page (< 2000). Returns total headers appended this call, or -1
;   on a hard error (fetch fail / continuity break / append fail).
;
;   Args:
;     rdi fd
;     rsi hst*            (bitcoin_headers.asm store state)
;     rdx locator32       mutable 32-byte buffer: initial locator on entry;
;                         updated to the tip hash on return
;     rcx page_buf        >= 2MB scratch for one headers page (like node_fetch_headers)
;     r8  buflen          cap of page_buf (must be >= 2,000,000)
;   Returns eax = total headers appended this call, or -1.
;
;   Frame: 5 callee pushes (rbx,r12-r15) -> save area rbp-0x08..-0x28. RSP after
;   pushes is rbp-0x28 (8 mod16); sub rsp,0xa8 (8 mod16) lands RSP 0 mod16 for
;   every nested call. ALL locals live below the save area:
;     last_hash[32] @ rbp-0x50
;     hout[32]      @ rbp-0x70
;     pgcount qword @ rbp-0x78
;     entoff  qword @ rbp-0x80
;     total   qword @ rbp-0x88
;     i       qword @ rbp-0x90
;     stop[32]      @ rbp-0xb0   (all zeros; valid buffer for p2p_getheaders)
;   i/counters live in stack slots so deep callees (block_hash->sha256d->
;   sha256_full) cannot clobber them; fd/hst/locator/page_buf/buflen live in
;   callee-saved registers (all preserved by every callee we invoke).
; ============================================================================
global node_ibd_headers
node_ibd_headers:
    push rbp
    mov  rbp, rsp
    push rbx                ; -0x08
    push r12                ; -0x10
    push r13                ; -0x18
    push r14                ; -0x20
    push r15                ; -0x28
    sub  rsp, 0xa8          ; 5 pushes + 0xa8 -> RSP 0 mod16 (see header)
    mov  rbx, rdi           ; fd
    mov  r12, rsi           ; hst
    mov  r13, rdx           ; locator32 (running locator, mutable)
    mov  r14, rcx           ; page_buf
    mov  r15, r8            ; buflen (cap)
    mov  qword [rbp-0x88], 0    ; total = 0
    mov  qword [rbp-0x78], 0    ; pgcount = 0
    mov  qword [rbp-0x98], 0    ; pages_fetched = 0 (live-peer loop bound)
    ; zero the stop[32] local (pull toward tip = all-zero stop hash)
    xor  eax, eax
    mov  qword [rbp-0xb0], rax
    mov  qword [rbp-0xa8], rax
    mov  qword [rbp-0xa0], rax
    mov  qword [rbp-0x98], rax

    ; ---- seed last_hash = running locator (chain start) ----
    lea  rdi, [rbp-0x50]
    mov  rsi, r13
    mov  ecx, 32
    rep  movsb

.page_loop:
    ; Safety bound on page count so a live peer that never returns a short
    ; page (or ignores our advancing locator) cannot busy-loop forever:
    ; a max of 4096 pages (~8.2M headers, well past mainnet's 790k tip). A
    ; cooperative peer reaches the tip long before this; the bound only ever
    ; trips against a misbehaving/streaming live seed (2026-08-15 finding).
    inc  qword [rbp-0x98]    ; pages_fetched++
    cmp  qword [rbp-0x98], 4096
    jg   .done
    ; ---- fetch one page at running locator ----
    mov  rdi, rbx            ; fd
    mov  rsi, r13            ; locator
    mov  edx, 1              ; count = 1 locator hash
    lea  rcx, [rbp-0xb0]     ; stop = zeros local
    mov  r8,  r14            ; page_buf
    lea  r9,  [rbp-0x78]     ; &pgcount
    call node_fetch_headers
    test eax, eax
    jz   .done               ; fetch failed -> stop (treat as clean end)
    mov  rax, [rbp-0x78]
    test rax, rax
    jz   .done               ; 0 headers -> reached tip
    mov  qword [rbp-0x90], 0 ; i = 0

    ; ---- entry base offset from the count varint ----
    movzx eax, byte [r14]
    mov  qword [rbp-0x80], 1
    cmp  al, 0xfd
    je   .cfd
    cmp  al, 0xfe
    je   .cfe
    cmp  al, 0xff
    je   .cff
    jmp  .base_done
.cfd:
    mov  qword [rbp-0x80], 3
    jmp  .base_done
.cfe:
    mov  qword [rbp-0x80], 5
    jmp  .base_done
.cff:
    mov  qword [rbp-0x80], 9
.base_done:

.entry_loop:
    ; if (i >= pgcount) goto page_done
    mov  rax, [rbp-0x90]
    mov  rcx, [rbp-0x78]
    cmp  rax, rcx
    jae  .page_done
    ; hdr_ptr = page_buf + entoff + i*81   (in r8)
    mov  r8, [rbp-0x80]      ; entoff
    mov  r9, rax
    imul r9, 81
    add  r8, r9
    add  r8, r14             ; r8 = &hdr(i)
    ; ---- continuity: hdr.prevhash (hdr+4) == last_hash ----.
    ; EXCEPT for absolutely the first header of the whole download (total==0 &&
    ; i==0): the genesis locator is the synthetic all-zero hash, but real block 1's
    ; prevhash is the GENESIS hash (000000000019d668...), not zero -- so the very
    ; first link cannot be compared against the zero locator. Real-mainnet IBD was
    ; failing here (synthetic test chains use a zero-prev block 0 and never showed
    ; it). Skip the compare for that one first header only; every later header
    ; still must chain exactly (catches an evil peer swapping any middle block).
    mov  rax, [rbp-0x88]    ; total
    test rax, rax
    jnz  .do_cont
    mov  rax, [rbp-0x90]    ; i
    test rax, rax
    jnz  .do_cont
    jmp  .skip_cont
.do_cont:
    lea  rdi, [r8+4]
    lea  rsi, [rbp-0x50]
    mov  ecx, 32
    repe cmpsb
    jne  .fail               ; chain break
.skip_cont:
    ; ---- compute block_hash(hdr) into hout (r8 preserved across call) ----
    lea  rdi, [rbp-0x70]
    mov  rsi, r8
    call block_hash
    ; r8 (hdr ptr) MUST survive block_hash -> keep it, but ensure: reload from
    ; formula since block_hash preserves r8? Not guaranteed. Recompute r8:
    mov  r8, [rbp-0x80]
    mov  rax, [rbp-0x90]
    mov  r9, rax
    imul r9, 81
    add  r8, r9
    add  r8, r14             ; r8 = &hdr(i) again
    ; ---- hst_append(hst, hdr, hout) ----
    mov  rdi, r12            ; hst
    mov  rsi, r8             ; hdr
    lea  rdx, [rbp-0x70]     ; hout
    call hst_append
    test rax, rax
    js   .fail               ; append failed
    inc  qword [rbp-0x88]    ; total++
    ; ---- last_hash = hout ----
    lea  rdi, [rbp-0x50]
    lea  rsi, [rbp-0x70]
    mov  ecx, 32
    rep  movsb
    ; ---- i++ ----
    inc  qword [rbp-0x90]
    jmp  .entry_loop

.page_done:
    ; ---- advance running locator = last appended hash (== last_hash) ----
    mov  rdi, r13
    lea  rsi, [rbp-0x50]
    mov  ecx, 32
    rep  movsb
    ; ---- short page (< 2000) => reached tip ----
    mov  rax, [rbp-0x78]
    cmp  rax, 2000
    jl   .done
    jmp  .page_loop

.done:
    mov  rax, [rbp-0x88]
    jmp  .ret
.fail:
    mov  rax, -1
.ret:
    add  rsp, 0xa8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; node_ibd_blocks(fd, st*, hst*, start_h, buf, buflen) -> eax #blocks stored
;   Block-body download driven OFF the PERSISTED header chain (bitcoin_headers.asm
;   store `hst`), stored into the block store (bitcoin_store.asm `st`). This is
;   the "download the blocks behind the header chain" half of full IBD: for every
;   stored header from index `start_h` to the tip, it
;     1. reads the header entry (hst_get_at) to get its block_hash (rec[80..112]),
;     2. getdata(block_hash) -> receives the `block` (draining ping->pong chatter),
;     3. validates with cons_verify,
;     4. RE-derives block_hash(received block) and requires it to EQUAL the stored
;        header's block_hash (guards against a peer serving the wrong block),
;     5. store_append(st, hash, buf, plen).
;   Returns eax = number of blocks stored this call, or -1 on any hard error
;   (bad block / hash mismatch / store failure / socket error).
;
;   Args: rdi fd, rsi st*, rdx hst*, rcx start_h (0-based), r8 buf, r9 buflen.
;
;   Frame: 5 callee pushes (rbx,r12-r15) -> save area rbp-0x08..-0x28. RSP after
;   pushes is rbp-0x28 (8 mod16); sub rsp,0x648 (8 mod16) lands RSP 0 mod16 for
;   every nested call. ALL locals live below the save area:
;     hst      qword @ rbp-0x30   (header-store ptr -- a stack local, NOT r13;
;                                  r13 is leaked by the deep block_hash chain, so
;                                  keep every cross-call value in slots/regs we
;                                  KNOW survive; see node_sync's locator lesson)
;     i        qword @ rbp-0x38
;     count    qword @ rbp-0x40
;     total    qword @ rbp-0x48
;     plen     dword @ rbp-0x60
;     rec[112]       @ rbp-0xd0   (hdr[0..80] ++ block_hash[80..112])
;     cmd[12]        @ rbp-0xe0
;     getdata[40]    @ rbp-0x110  (p2p_getdata_block emits 37; padded)
;     blockhash[32]  @ rbp-0x140
;     cons scratch   @ rbp-0x540   (0x400 bytes, below all other locals)
;   Loop-critic values live in stack slots or callee-saved regs so the deep
;   block_hash->sha256d->sha256_full chain cannot clobber them.
; ============================================================================
global node_ibd_blocks
node_ibd_blocks:
    push rbp
    mov  rbp, rsp
    push rbx                ; -0x08
    push r12                ; -0x10
    push r13                ; -0x18
    push r14                ; -0x20
    push r15                ; -0x28
    sub  rsp, 0x648         ; 5 pushes + 0x648 -> RSP 0 mod16 (see header)
    mov  rbx, rdi           ; fd
    mov  r12, rsi           ; st (block store)
    mov  [rbp-0x30], rdx    ; hst (header store) in a STACK LOCAL (see header)
    mov  [rbp-0x38], rcx    ; i = start_h
    mov  r14, r8            ; buf
    mov  r15, r9            ; buflen
    mov  qword [rbp-0x48], 0 ; total = 0
    ; count = hst_count(hst)
    mov  rdi, [rbp-0x30]
    call hst_count
    mov  [rbp-0x40], rax    ; count

.block_loop:
    ; while (i < count)
    mov  rax, [rbp-0x38]
    mov  rcx, [rbp-0x40]
    cmp  rax, rcx
    jae  .done
    ; hst_get_at(hst, i, rec@rbp-0xd0)
    mov  rdi, [rbp-0x30]    ; reload hst from the stack slot (r13 not trusted)
    mov  rsi, rax           ; i
    lea  rdx, [rbp-0xd0]
    call hst_get_at
    test eax, eax
    jle  .fail              ; out-of-range/err -> treat as hard error
    ; build getdata(block_hash = rec+80) into getdata@rbp-0x110
    lea  rdi, [rbp-0x110]
    lea  rsi, [rbp-0xd0+80]
    call p2p_getdata_block
    mov  r8d, eax           ; payload len
    mov  rdi, rbx
    lea  rsi, [rel _getdata]
    mov  edx, 7
    lea  rcx, [rbp-0x110]
    call p2p_write
    cmp  rax, 24
    jl   .fail
    ; ---- receive until `block`, draining ping->pong and other chatter ----
.receive:
    mov  rdi, rbx
    lea  rsi, [rbp-0xe0]    ; cmd
    mov  rdx, r14           ; buf
    mov  ecx, r15d          ; buflen (cap)
    lea  r8, [rbp-0x60]     ; &plen
    call p2p_read
    test rax, rax
    jle  .fail              ; eof/err
    lea  rdi, [rbp-0xe0]
    lea  rsi, [rel _ping]
    mov  ecx, 4
    repe cmpsb
    jne  .not_ping
    ; ping -> pong echo
    mov  rdi, rbx
    lea  rsi, [rel _pong]
    mov  edx, 4
    mov  rcx, r14
    mov  r8d, 8
    call p2p_write
    jmp  .receive
.not_ping:
    lea  rdi, [rbp-0xe0]
    lea  rsi, [rel _block]
    mov  ecx, 5
    repe cmpsb
    jne  .receive           ; not the block we want -> drain and keep reading
    ; got `block`: validate with cons_verify(buf, plen, scratch@rbp-0x540, cap)
    mov  rdi, r14
    mov  esi, [rbp-0x60]
    ; 2026-08-24: was scratch=[rbp-0x540] with cap=256. The frame is 0x648
    ; total, so at most 0x540/32 = 42 txids fit below rbp and a 256-txid cap
    ; (8192 bytes) runs past rbp into the caller's frame. Same fix.
    lea  rdx, [rel ibd_txid_scratch]
    mov  ecx, SYNC_TXID_CAP
    call cons_verify
    test eax, eax
    jz   .fail              ; invalid block body
    ; block_hash(received block) -> blockhash@rbp-0x140
    lea  rdi, [rbp-0x140]
    mov  rsi, r14
    call block_hash
    ; require it to equal the stored header block_hash (rec+80)
    lea  rdi, [rbp-0x140]
    lea  rsi, [rbp-0xd0+80]
    mov  ecx, 32
    repe cmpsb
    jne  .fail              ; peer served the wrong block
    ; store_append(st, blockhash, buf, plen)
    mov  rdi, r12
    lea  rsi, [rbp-0x140]
    mov  rdx, r14
    mov  ecx, [rbp-0x60]
    call store_append
    cmp  rax, -1
    je   .fail
    inc  qword [rbp-0x48]   ; total++
    ; i++
    inc  qword [rbp-0x38]
    jmp  .block_loop

.done:
    mov  rax, [rbp-0x48]
    jmp  .ret
.fail:
    mov  rax, -1
.ret:
    add  rsp, 0x648
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; node_ibd_blocks_x(fd, st*, hst*, start_h, end_h, buf, buflen, scratch, scratch_cap)
;                                             -> eax #blocks stored (or -1)
;   HARDENED, all-asm block-body receive loop over the PERSISTED header chain
;   (extended from node_ibd_blocks for real mainnet data + parallel workers):
;     - caller-supplied cons_verify scratch + cap (node_ibd_blocks used a fixed
;       0x400 scratch / cap 256, far too small for dense modern blocks).
;     - an explicit [start_h, end_h] HEIGHT RANGE so a worker can be told to
;       process only its shard of the header store; loop runs i = start_h..end_h.
;     - drains ping->pong AND ignores all other non-`block` chatter
;       (sendcmpct/sendheaders/sendaddrv2/wtxidrelay/feefilter/inv) so it never
;       stalls on a live peer's announcement traffic.
;     - getdata/recv/cons_verify/re-derived-hash-guard/store_append per block
;       (identical crypto tail to node_ibd_blocks, all asm).
;   Returns the number stored, or -1 on a hard error/peer-close (the CALLER
;   reconnects a fresh peer and re-invokes starting at the height after what the
;   store already holds, so a mid-range peer drop resumes cleanly).
;
;   Args: rdi fd, rsi st*, rdx hst*, rcx start_h, r8 end_h, r9 buf,
;         [rbp+16] buflen, [rbp+24] scratch*, [rbp+32] scratch_cap (stack args)
;
;   Frame: 5 pushes -> save area rbp-8..-0x28. sub rsp,0x148 (0x28+0x148=0x170,
;   8 mod16; matches the node_* call parity). Locals BELOW save area:
;     hst        qword @ rbp-0x30   (stack local; r13 is leaked by hash chain)
;     start_h    qword @ rbp-0x38
;     end_h      qword @ rbp-0x40
;     i          qword @ rbp-0x48
;     total      qword @ rbp-0x50
;     scratch    qword @ rbp-0x58
;     scratch_cap dword @ rbp-0x60
;     plen       dword @ rbp-0x64
;     cmd[12]          @ rbp-0x70
;     getdata[40]      @ rbp-0xa0
;     blockhash[32]    @ rbp-0xc0
;     rec[112]         @ rbp-0x140 (hdr[0..80] ++ block_hash[80..112])
; ============================================================================
global node_ibd_blocks_x
node_ibd_blocks_x:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x280          ; rec@-0x140 (112B), prevrec@-0x1b0 (112B),
                             ; skip budget @-0x258; +0x280 keeps RSP aligned
    mov  rbx, rdi           ; fd
    mov  r12, rsi           ; st (block store)
    mov  [rbp-0x30], rdx    ; hst (stack local)
    mov  [rbp-0x38], rcx    ; start_h
    mov  [rbp-0x40], r8     ; end_h
    mov  r14, r9            ; buf
    mov  rax, [rbp+16]
    mov  r15, rax           ; buflen
    mov  rax, [rbp+24]
    mov  [rbp-0x58], rax    ; scratch (stack local)
    mov  eax, [rbp+32]
    mov  [rbp-0x60], eax    ; scratch_cap
    mov  qword [rbp-0x50], 0        ; total = 0
    mov  qword [rbp-0x258], 0       ; skip budget = 0 (out-of-order drain guard)
    ; i = start_h
    mov  rax, [rbp-0x38]
    mov  [rbp-0x48], rax
.block_loop_x:
    ; while (i <= end_h)
    mov  rax, [rbp-0x48]
    mov  rcx, [rbp-0x40]
    cmp  rax, rcx
    ja   .done
    ; hst_get_at(hst, i, rec@rbp-0x140); skip if out of range (0-height beyond tip)
    mov  rdi, [rbp-0x30]
    mov  rsi, rax
    lea  rdx, [rbp-0x140]
    call hst_get_at
    test eax, eax
    jle  .done              ; out-of-range -> no more headers, stop cleanly
    ; build getdata(block_hash = rec+80) into getdata@rbp-0xa0
    lea  rdi, [rbp-0xa0]
    lea  rsi, [rbp-0x140+80]
    call p2p_getdata_block
    mov  r8d, eax
    mov  rdi, rbx
    lea  rsi, [rel _getdata]
    mov  edx, 7
    lea  rcx, [rbp-0xa0]
    call p2p_write
    cmp  rax, 24
    jl   .fail
.receive_x:
    ; p2p_read(fd, cmd@-0x70, buf, buflen, &plen@-0x64)
    mov  rdi, rbx
    lea  rsi, [rbp-0x70]
    mov  rdx, r14
    mov  ecx, r15d
    lea  r8,  [rbp-0x64]
    call p2p_read
    test rax, rax
    jle  .fail              ; peer closed/eof -> caller reconnects + resumes
    ; ping? -> echo pong, keep waiting
    lea  rdi, [rbp-0x70]
    lea  rsi, [rel _ping]
    mov  ecx, 4
    repe cmpsb
    jne  .not_ping_x
    mov  rdi, rbx
    lea  rsi, [rel _pong]
    mov  edx, 4
    mov  rcx, r14
    mov  r8d, 8
    call p2p_write
    jmp  .receive_x
.not_ping_x:
    ; block? else drain (ignore chatter) and keep reading
    lea  rdi, [rbp-0x70]
    lea  rsi, [rel _block]
    mov  ecx, 5
    repe cmpsb
    jne  .receive_x
    ; ---- got `block`: validate with the CALLER scratch ----
    mov  rdi, r14
    mov  esi, [rbp-0x64]
    mov  rdx, [rbp-0x58]
    mov  ecx, [rbp-0x60]
    call cons_verify
    test eax, eax
    jz   .fail              ; invalid block body
    ; block_hash(received) -> blockhash@-0xc0; the received block is only the
    ; block for the CURRENT height if it matches rec+80 (stored header hash).
    lea  rdi, [rbp-0xc0]
    mov  rsi, r14
    call block_hash
    lea  rdi, [rbp-0xc0]
    lea  rsi, [rbp-0x140+80]
    mov  ecx, 32
    repe cmpsb
    jne  .skip_block_x        ; out-of-order/late block: drain it, keep waiting
    ; ---- CHAIN-LINK GUARD (node_ibd_blocks_x): prevents storing a block at the
    ; wrong local height (root cause of duplicate hashes). The incoming block's
    ; prevhash (buf[4..36]) MUST equal the stored header hash at local height i-1.
    ; For i==start_h (shard's first local height) the prior real header is outside
    ; this shard's header store, so the check is skipped; for every resume step
    ; (i>start_h) it is enforced, so a repeated/out-of-order block can never be
    ; appended under two heights. ----
    mov  rax, [rbp-0x48]    ; i
    mov  rcx, [rbp-0x38]    ; start_h
    cmp  rax, rcx
    je   .chain_ok
    ; prevrec@rbp-0x1b0 = hst_get_at(hst, i-1)
    mov  rdi, [rbp-0x30]
    lea  rsi, [rax-1]
    lea  rdx, [rbp-0x1b0]
    call hst_get_at
    test eax, eax
    jle  .fail              ; prior header missing -> cannot trust, drop
    ; require buf+4 .. buf+36 == prevrec+80 .. prevrec+112
    lea  rdi, [r14+4]
    lea  rsi, [rbp-0x1b0+80]
    mov  ecx, 32
    repe cmpsb
    jne  .fail              ; block does NOT chain from the previous local height
.chain_ok:
    ; store_append(st, blockhash, buf, plen)
    mov  rdi, r12
    lea  rsi, [rbp-0xc0]
    mov  rdx, r14
    mov  ecx, [rbp-0x64]
    call store_append
    cmp  rax, -1
    je   .fail
    inc  qword [rbp-0x50]   ; total++
    inc  qword [rbp-0x48]   ; i++
    jmp  .block_loop_x
.skip_block_x:
    ; Out-of-order / late block that doesn't match the CURRENT height: drain it
    ; (do NOT store, do NOT kill the connection) and keep waiting for the block
    ; we asked for. Under concurrent load peers may deliver a nearby block first.
    ; Guard with a bounded budget so a genuinely useless peer still times out.
    inc  qword [rbp-0x258]
    cmp  qword [rbp-0x258], 64
    ja   .fail              ; too many wasted deliveries -> reconnect
    jmp  .receive_x
.done:
    mov  rax, [rbp-0x50]
    jmp  .ret
.fail:
    mov  rax, -1
.ret:
    add  rsp, 0x280
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; node_ibd_blocks_s(fd, st*, hst*, lo_real, nloc, buf, buflen, scratch, cap)
;   SAME receive/validate loop as node_ibd_blocks_x, but each block is written
;   via CONCURRENT-SAFE store_append_shared(st, lo_real+i, hash, buf, plen), so
;   many workers write DIRECTLY into ONE shared store (single directory), with
;   no per-worker shard dirs. hst holds nloc LOCAL headers for real heights
;   [lo_real .. lo_real+nloc-1].
;   Frame mirrors node_ibd_blocks_x (0x280 stack, locals below save area).
; ============================================================================
extern store_append_shared
global node_ibd_blocks_s
node_ibd_blocks_s:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x280
    mov  rbx, rdi           ; fd
    mov  r12, rsi           ; st
    mov  [rbp-0x30], rdx    ; hst (local)
    mov  [rbp-0x38], rcx    ; lo_real
    mov  [rbp-0x40], r8     ; nloc
    mov  r14, r9            ; buf
    mov  rax, [rbp+16]
    mov  r15, rax           ; buflen
    mov  rax, [rbp+24]
    mov  [rbp-0x58], rax    ; scratch
    mov  eax, [rbp+32]
    mov  [rbp-0x60], eax    ; scratch_cap
    mov  qword [rbp-0x50], 0        ; total = 0
    mov  qword [rbp-0x48], 0        ; i (local) = 0
    mov  qword [rbp-0x258], 0       ; skip budget
.loop_s:
    mov  rax, [rbp-0x48]
    mov  rcx, [rbp-0x40]
    cmp  rax, rcx
    jae  .done_s
    ; hst_get_at(hst, i, rec@-0x140)
    mov  rdi, [rbp-0x30]
    mov  rsi, rax
    lea  rdx, [rbp-0x140]
    call hst_get_at
    test eax, eax
    jle  .done_s
    lea  rdi, [rbp-0xa0]
    lea  rsi, [rbp-0x140+80]
    call p2p_getdata_block
    mov  r8d, eax
    mov  rdi, rbx
    lea  rsi, [rel _getdata]
    mov  edx, 7
    lea  rcx, [rbp-0xa0]
    call p2p_write
    cmp  rax, 24
    jl   .fail_s
.receive_s:
    mov  rdi, rbx
    lea  rsi, [rbp-0x70]
    mov  rdx, r14
    mov  ecx, r15d
    lea  r8,  [rbp-0x64]
    call p2p_read
    test rax, rax
    jle  .fail_s
    lea  rdi, [rbp-0x70]
    lea  rsi, [rel _ping]
    mov  ecx, 4
    repe cmpsb
    jne  .not_ping_s
    mov  rdi, rbx
    lea  rsi, [rel _pong]
    mov  edx, 4
    mov  rcx, r14
    mov  r8d, 8
    call p2p_write
    jmp  .receive_s
.not_ping_s:
    lea  rdi, [rbp-0x70]
    lea  rsi, [rel _block]
    mov  ecx, 5
    repe cmpsb
    jne  .receive_s
    mov  rdi, r14
    mov  esi, [rbp-0x64]
    mov  rdx, [rbp-0x58]
    mov  ecx, [rbp-0x60]
    call cons_verify
    test eax, eax
    jz   .fail_s
    lea  rdi, [rbp-0xc0]
    mov  rsi, r14
    call block_hash
    lea  rdi, [rbp-0xc0]
    lea  rsi, [rbp-0x140+80]
    mov  ecx, 32
    repe cmpsb
    jne  .skip_block_s
    ; chain-link guard (i>0): block prevhash == hdr hash at local i-1
    cmp  qword [rbp-0x48], 0
    je   .chain_ok_s
    mov  rdi, [rbp-0x30]
    mov  rax, [rbp-0x48]
    lea  rsi, [rax-1]
    lea  rdx, [rbp-0x1b0]
    call hst_get_at
    test eax, eax
    jle  .fail_s
    lea  rdi, [r14+4]
    lea  rsi, [rbp-0x1b0+80]
    mov  ecx, 32
    repe cmpsb
    jne  .fail_s
.chain_ok_s:
    ; store_append_shared(st, lo_real + i, blockhash, buf, plen)
    mov  rax, [rbp-0x38]
    add  rax, [rbp-0x48]    ; real_height
    mov  rdi, r12
    mov  rsi, rax           ; height
    lea  rdx, [rbp-0xc0]    ; hash
    mov  rcx, r14           ; raw
    mov  r8d, [rbp-0x64]    ; len (zero-extended)
    call store_append_shared
    cmp  rax, -1
    je   .fail_s
    inc  qword [rbp-0x50]
    inc  qword [rbp-0x48]
    jmp  .loop_s
.skip_block_s:
    inc  qword [rbp-0x258]
    cmp  qword [rbp-0x258], 64
    ja   .fail_s
    jmp  .receive_s
.done_s:
    mov  rax, [rbp-0x50]
    jmp  .ret_s
.fail_s:
    mov  rax, -1
.ret_s:
    add  rsp, 0x280
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; node_ibd(fd, st*, hst*, buf, buflen) -> eax = # blocks stored (or -1)
;   FULL headers-first Initial Block Download as ONE assembly pass over a single
;   peer connection, stitching the two verified halves:
;     1. node_ibd_headers(fd, hst, locator=0, buf, buflen)  -- download the whole
;        header chain in 2000-header pages and PERSIST it into the header store
;        (advancing the locator from genesis to the tip).
;     2. node_ibd_blocks(fd, st, hst, 0, buf, buflen)      -- walk every stored
;        header, getdata its block body, cons_verify + re-hash-guard, and
;        store_append into the block store.
;   Returns the number of block bodies stored, or -1 if either half fails.
;
;   Args: rdi fd, rsi st* (block store), rdx hst* (header store),
;         rcx buf (>= 2MB, shared by both halves), r8 buflen.
;
;   Frame: 5 callee pushes (rbx,r12-r15) -> save area rbp-0x08..-0x28. RSP after
;   pushes is rbp-0x28 (8 mod16); sub rsp,0x68 (8 mod16) lands RSP 0 mod16 for
;   every nested call. Locals (below -0x28):
;     st       qword @ rbp-0x30
;     hst      qword @ rbp-0x38   (stack local -- r13 is leaked by the hash chain)
;     loc[32]  qword x4 @ rbp-0x60 (zeroed genesis locator)
; ============================================================================
global node_ibd
node_ibd:
    push rbp
    mov  rbp, rsp
    push rbx                ; -0x08
    push r12                ; -0x10
    push r13                ; -0x18
    push r14                ; -0x20
    push r15                ; -0x28
    sub  rsp, 0x68          ; 5 pushes + 0x68 -> RSP 0 mod16 (see header)
    mov  rbx, rdi           ; fd
    mov  [rbp-0x30], rsi    ; st  (block store)
    mov  [rbp-0x38], rdx    ; hst (header store)
    mov  r14, rcx           ; buf
    mov  r15, r8            ; buflen
    ; zero the genesis locator[32] @ rbp-0x60
    xor  eax, eax
    mov  qword [rbp-0x60], rax
    mov  qword [rbp-0x58], rax
    mov  qword [rbp-0x50], rax
    mov  qword [rbp-0x48], rax

    ; ---- phase 1: persistent headers-first download ----
    mov  rdi, rbx           ; fd
    mov  rsi, [rbp-0x38]    ; hst
    lea  rdx, [rbp-0x60]    ; locator (=0, genesis)
    mov  rcx, r14           ; buf
    mov  r8,  r15           ; buflen
    call node_ibd_headers
    cmp  rax, -1
    je   .fail              ; header phase error

    ; ---- phase 2: block bodies off the persisted header chain ----
    mov  rdi, rbx           ; fd
    mov  rsi, [rbp-0x30]    ; st
    mov  rdx, [rbp-0x38]    ; hst
    xor  ecx, ecx           ; start_h = 0
    mov  r8,  r14           ; buf
    mov  r9,  r15           ; buflen
    call node_ibd_blocks
    jmp  .done              ; eax = #blocks stored (or -1 from that call)

.fail:
    mov  rax, -1
.done:
    add  rsp, 0x68
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .bss
align 32
sync_txid_scratch: resb SYNC_TXID_CAP*32   ; node_sync_multi's cons_verify scratch
global sync_fail_code
drain_txid_scratch: resb SYNC_TXID_CAP*32  ; node_drain's cons_verify scratch
ibd_txid_scratch:   resb SYNC_TXID_CAP*32  ; node_ibd_blocks' cons_verify scratch
sync_fail_code: resd 1                     ; which .fail exit node_sync_multi took   ; node_sync_multi's cons_verify scratch

section .data
align 16
ua: db NODE_UA_STRING   ; user-agent from version.inc (length derived via %strlen)

; ---- last-seen peer `version` payload, captured (not parsed) by both
; node_handshake and node_accept_handshake the moment they see a "version"
; command from the other side -- raw bytes only, zero interpretation here.
; Actual field extraction (services/protocol/UA/height, general Bitcoin
; varint-length UA) happens in C (daemon/main.c) for safety/simplicity;
; this is just a plain memcpy'd snapshot. Per-connection process only (each
; inbound serve child and the single outbound download worker are separate
; processes), so a single set of globals is safe -- no cross-connection
; clobbering. Purely additive: existing handshake control flow/behavior is
; unchanged either way, this is a side-effect capture only. */
global g_peer_version_payload
global g_peer_version_len
g_peer_version_payload: times 256 db 0
g_peer_version_len:     dq 0

section .rodata
_version: db "version",0
_verack:  db "verack",0
_ping:    db "ping",0
_pong:    db "pong",0
_getheaders: db "getheaders",0
_headers: db "headers",0
_getdata: db "getdata",0
_block:   db "block",0
_inv:     db "inv",0

section .note.GNU-stack noalloc noexec nowrite progbits
