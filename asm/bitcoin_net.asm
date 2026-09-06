; ============================================================================
; bitcoin_net.asm -- POSIX sockets + Bitcoin P2P message framing (raw syscalls).
;   100% AI-authored x86-64 assembly.
;
;   Layer boundaries:
;     - Sockets/tcp use raw Linux syscalls (no libc for the data path).
;     - The P2P frame cksum = sha256d(payload)[0..4) (calls sha256d from
;       bitcoin_hash.asm).
;     - DNS name -> address is delegated to libc getaddrinfo (the OS resolver);
;       everything else is raw machine code.
;
;   Wire frame (from the live peer oracle):
;     magic[4]=f9 be b4 d9 | command[12] | length[4 LE] | checksum[4] | payload
;
;   Exported API (System V AMD64):
;     long fd_write_all(int fd, const void* buf, size_t n)   -> n or -1
;     long fd_read_full (int fd, void* buf, size_t n)        -> n on success,
;                                                              or < n on eof,
;                                                              -1 on error
;     int  fd_close(int fd)
;     int  tcp_connect_ip(u32 ip_le, u16 port_be)            -> fd or -1
;     long p2p_frame(u8* out, const char* cmd, u32 cmdlen,
;                    const void* payload, u32 plen)          -> 24+plen (bytes)
;     long p2p_write(int fd, const char* cmd, u32 cmdlen,
;                    const void* payload, u32 plen)          -> total sent or -1
;     int  p2p_read(int fd, char cmd_out[12], void* payload,
;                   u32 cap, u32* plen_out)                  -> 1 ok / 0 eof /
;                                                              -1 err / -2 trunc
;
;   NOTE: payload buffers for p2p_read must be >= cap. If the announced length
;   exceeds cap the excess is drained from the socket (so framing stays aligned)
;   and -2 is returned after reporting the announced length.
; ============================================================================
default rel

extern sha256d

; ----------------------------------------------------------------------------
; net_magic -- the 4-byte network message-start, as the little-endian dword
; that lands in the frame verbatim. Statically MAINNET (f9 be b4 d9), so every
; existing tool and test that never selects a chain behaves exactly as before.
; chainparams_select() (daemon/chainparams.c) overwrites it for regtest
; (fa bf b5 da) BEFORE any socket is opened; it is never written again, so the
; unsynchronized reads below are safe.
; ----------------------------------------------------------------------------
section .data
global net_magic
net_magic: dd 0xd9b4bef9

; ---------------------------------------------------------------------------
; BIP324 v2 transport dispatch.
;
; p2p_read/p2p_write are called from roughly sixty files and several hundred
; call sites, so v2 cannot be plumbed through by giving every caller a
; transport handle. Instead the dispatch lives HERE, keyed by file
; descriptor: an fd that has completed a v2 handshake is flagged in
; g_v2_active, and the two hooks below are filled in by the v2 module.
;
; A build that never links the v2 module leaves the hooks NULL and the table
; zero, so p2p_read/p2p_write behave exactly as they always have -- no link
; dependency is created, which is why this is a table in this object rather
; than a C wrapper that would have to be added to sixty link lines.
;
; The flag is checked before the hook so the v1 path costs one compare and one
; branch, not an indirect call.
; ---------------------------------------------------------------------------
; Core's MAX_PROTOCOL_MESSAGE_LENGTH (net.h): 4 * 1000 * 1000. Core also
; compares against MAX_SIZE (0x02000000), but that is the larger of the two,
; so this single bound is the effective one -- and it is the same limit the
; BIP324 path enforces (BIP324_MAX_MESSAGE_LEN).
P2P_MAX_MSG equ 4000000

V2_FD_MAX equ 4096
global g_v2_hook_write
global g_v2_hook_read
global g_v2_active
g_v2_hook_write: dq 0          ; long (*)(int fd, const char* cmd, u32 cmdlen,
                               ;         const void* payload, u32 plen)
g_v2_hook_read:  dq 0          ; int  (*)(int fd, char cmd_out[12], void* payload,
                               ;         u32 cap, u32* plen_out)
g_v2_active: times V2_FD_MAX db 0

section .text

; ============================================================================
; fd_write_all(fd, buf, n) -> total written or -1
; ============================================================================
global fd_write_all
fd_write_all:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi            ; fd
    mov  r13, rsi            ; buf
    mov  r14, rdx            ; n
    xor  rbx, rbx            ; done
.wa:
    cmp  rbx, r14
    jae  .done
    ; ---- bound the write: poll({fd, POLLOUT}, 1, 10000) first. A peer that
    ; stops reading (a dead Tor circuit, a stalled subscriber, the other end
    ; of an IPC pair busy elsewhere) otherwise holds a blocking write() for
    ; ever, and nothing above this function can interrupt it. SO_SNDTIMEO
    ; covers the sockets tcp_connect_ip creates; this covers every fd.
    ; 0 = timed out, <0 = error/EINTR: both are a failed write (-1).
    sub  rsp, 16
    mov  dword [rsp], r12d   ; pollfd.fd
    mov  word  [rsp+4], 4    ; pollfd.events = POLLOUT
    mov  word  [rsp+6], 0    ; pollfd.revents
    mov  rdi, rsp
    mov  esi, 1              ; nfds
    mov  edx, 10000          ; timeout ms
    mov  eax, 7              ; poll
    syscall
    add  rsp, 16
    test rax, rax
    jle  .fail
    mov  rdi, r12
    lea  rsi, [r13+rbx]
    mov  rdx, r14
    sub  rdx, rbx
    mov  eax, 1              ; write
    syscall
    test rax, rax
    jg   .ok
.fail:
    mov  rax, -1
    jmp  .ret
.ok:
    add  rbx, rax
    jmp  .wa
.done:
    mov  rax, rbx
.ret:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; fd_read_full(fd, buf, n) -> bytes read (< n only on eof), or -1 on error
; ============================================================================
global fd_read_full
fd_read_full:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi            ; fd
    mov  r13, rsi            ; buf
    mov  r14, rdx            ; n
    xor  rbx, rbx            ; got
.ra:
    cmp  rbx, r14
    jae  .done
    mov  rdi, r12
    lea  rsi, [r13+rbx]
    mov  rdx, r14
    sub  rdx, rbx
    mov  eax, 0              ; read
    syscall
    test rax, rax
    jg   .ok
    je   .eof
    mov  rax, -1
    jmp  .ret
.ok:
    add  rbx, rax
    jmp  .ra
.eof:
    mov  rax, rbx
.ret:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
.done:
    mov  rax, rbx
    jmp  .ret

; ============================================================================
; fd_close(fd)
; ============================================================================
global fd_close
fd_close:
    mov  eax, 3              ; close
    syscall
    ret

; ============================================================================
; tcp_connect_ip(ip_le, port_be) -> fd or -1
;   ip_le   = ipv4 address as a native little-endian u32 (i.e. the value you get
;             from sin_addr.s_addr / the dotted quad parsed to network order).
;   port_be = port in big-endian (htons).
; ============================================================================
global tcp_connect_ip
tcp_connect_ip:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    push rbx
    mov  r12d, edi          ; ip
    mov  r13w, si           ; port
    ; socket(AF_INET=2, SOCK_STREAM=1, 0)
    mov  edi, 2
    mov  esi, 1
    xor  edx, edx
    mov  eax, 41
    syscall
    test rax, rax
    jl   .ret
    mov  rbx, rax           ; fd
    ; ---- set SO_RCVTIMEO (10s) so blocking reads FAIL FAST on an idle peer
    ; instead of hanging forever. The IBD/headers paths (node_fetch_headers,
    ; node_ibd_blocks, node_sync) rely on p2p_read returning on idle; without a
    ; socket timeout a live seed that stops replying blocks the whole node
    ; indefinitely (2026-08-15 live-IBD finding). 10s is generous vs synthetic
    ; loopback tests (which reply instantly and are unaffected) yet bounds any
    ; real-peer stall. setsockopt(fd, SOL_SOCKET=1, SO_RCVTIMEO=20, &tv{10,0}, 16)
    sub  rsp, 0x20          ; scratch below save area (rsp = rbp-0x40)
    xor  eax, eax
    mov  qword [rsp],   10  ; tv_sec  = 10
    mov  qword [rsp+8], 0   ; tv_usec = 0
    mov  rdi, rbx           ; fd
    mov  esi, 1             ; SOL_SOCKET
    mov  edx, 20            ; SO_RCVTIMEO
    lea  r10, [rsp]         ; &timeval -- syscall arg4 is R10, not RCX (RCX is clobbered by SYSCALL)
    mov  r8, 16             ; optlen
    mov  eax, 54            ; setsockopt
    syscall
    ; ---- and SO_SNDTIMEO (21) with the same 10s: on Linux it bounds the
    ; blocking connect() below. Without it a peer that swallows SYNs (a
    ; blackholed address, a host behind a dropped route) holds connect() for
    ; the kernel's full retry schedule -- about two minutes -- and every dial
    ; site that is not inside the SIGALRM dial budget wedges the download
    ; worker for that long per address: heartbeat silent, zero outbound
    ; peers, SIGTERM unanswered (2026-08-31 21:20 and 2026-09-01 00:31,
    ; both worker backtraces ending in tcp_connect_ip). A bounded connect
    ; fails with EINPROGRESS, which every caller treats as a failed dial.
    mov  rdi, rbx           ; fd
    mov  esi, 1             ; SOL_SOCKET
    mov  edx, 21            ; SO_SNDTIMEO
    lea  r10, [rsp]         ; &timeval (still {10,0}); R10 = syscall arg4
    mov  r8, 16             ; optlen
    mov  eax, 54            ; setsockopt
    syscall
    add  rsp, 0x20
    ; (ignore setsockopt errors; the timeouts are best-effort)
    ; sockaddr_in on stack (16 bytes) BELOW save area
    sub  rsp, 0x40            ; rsp = rbp-0x40 ; sockaddr at rbp-0x40..-0x31
    xor  eax, eax
    lea  rdi, [rsp]
    mov  rcx, 16
    rep  stosb               ; zero 16 bytes
    mov  word [rsp+0], 2        ; AF_INET
    mov  word [rsp+2], r13w     ; port
    mov  dword [rsp+4], r12d    ; ip
    mov  rdi, rbx
    mov  rsi, rsp
    mov  edx, 16
    mov  eax, 42            ; connect
    syscall
    add  rsp, 0x40
    test rax, rax
    jl   .close
    mov  rax, rbx
    jmp  .ret
.close:
    mov  r14, rax           ; keep -errno before close
    mov  rdi, rbx
    mov  eax, 3
    syscall
    mov  rax, r14           ; return the raw -errno for diagnosis
.ret:
    pop  rbx
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

; ============================================================================
; cksum4(out4, payload, plen): writes sha256d(payload)[0:4] to out4
; ============================================================================
cksum4:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    sub  rsp, 0x48          ; digest[32] at rbp-0x48..rbp-0x29 (BELOW save area
                            ; rbp-0x08..rbp-0x20)
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    lea  rdi, [rbp-0x48]
    mov  rsi, r13
    mov  rdx, r14
    call sha256d
    mov  eax, [rbp-0x48]
    mov  [r12], eax
    add  rsp, 0x48
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

; ============================================================================
; p2p_frame(out, cmd, cmdlen, payload, plen) -> 24+plen
;   SysV: rdi=out rsi=cmd rdx=cmdlen rcx=payload r8=plen
; ============================================================================
global p2p_frame
p2p_frame:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    push r15
    push rbx
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbx, r8
    ; out[0..4] magic (runtime chain-selected; see net_magic above)
    mov  eax, [net_magic]
    mov  [r12], eax
    ; out[4..16] command (zero then copy <=12)
    lea  rdi, [r12+4]
    xor  eax, eax
    mov  rcx, 12
    rep  stosb
    mov  rcx, r14
    cmp  rcx, 12
    jbe  .cok
    mov  rcx, 12
.cok:
    lea  rdi, [r12+4]
    mov  rsi, r13
    rep  movsb
    ; out[16..20] length
    mov  [r12+16], ebx
    ; out[20..24] checksum
    lea  rdi, [r12+20]
    mov  rsi, r15
    mov  rdx, rbx
    call cksum4
    ; out[24..] payload
    lea  rdi, [r12+24]
    mov  rsi, r15
    mov  rcx, rbx
    rep  movsb
    mov  rax, rbx
    add  rax, 24
    pop  rbx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

; ============================================================================
; p2p_write(fd, cmd, cmdlen, payload, plen) -> total sent or -1
;   SysV: rdi=fd rsi=cmd rdx=cmdlen rcx=payload r8=plen
;   Writes 24-byte header then payload in two syscalls (no big intermediate copy).
; ============================================================================
global p2p_write
p2p_write:
    ; v2 dispatch (see g_v2_active above); falls through to v1 untouched
    cmp  edi, V2_FD_MAX
    jae  .v1
    mov  eax, edi
    ; RIP-relative, not absolute: several test targets link this object into a
    ; PIE binary, and an absolute R_X86_64_32S reloc against .data cannot be
    ; used there ("recompile with -fPIE"). r10 is caller-saved and is not an
    ; argument register, so borrowing it disturbs nothing.
    lea  r10, [rel g_v2_active]
    cmp  byte [r10 + rax], 0
    je   .v1
    mov  rax, [rel g_v2_hook_write]
    test rax, rax
    je   .v1
    ; The hook is a C function, and this entry is reached at BOTH stack
    ; parities (the auditor calls p2p_read/p2p_write multi-entry). A tail jmp
    ; would hand C whatever alignment we happened to arrive with, and C may
    ; spill SSE registers to the stack. So align explicitly and make a real
    ; call: rsp is forced to 0 mod 16, the call pushes 8, and the callee sees
    ; the 8 that SysV promises it. Arguments are already in place and rax is
    ; the return value, so nothing else moves.
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    call rax
    mov  rsp, rbp
    pop  rbp
    ret
.v1:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    push r15
    push rbx
    sub  rsp, 0x68          ; frame locals BELOW save area (rbp-0x08..-0x40);
                            ; 0x68==8 mod 16 keeps RSP 0 mod 16 at nested calls
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbx, r8
    ; header buffer at rbp-0x58 .. rbp-0x41 (24 bytes)
    mov  eax, [net_magic]
    mov  [rbp-0x58], eax
    lea  rdi, [rbp-0x54]
    xor  eax, eax
    mov  rcx, 12
    rep  stosb
    mov  rcx, r14
    cmp  rcx, 12
    jbe  .cok
    mov  rcx, 12
.cok:
    lea  rdi, [rbp-0x54]
    mov  rsi, r13
    rep  movsb
    mov  [rbp-0x48], ebx
    lea  rdi, [rbp-0x44]
    mov  rsi, r15
    mov  rdx, rbx
    call cksum4
    ; send header
    mov  rdi, r12
    lea  rsi, [rbp-0x58]
    mov  rdx, 24
    call fd_write_all
    cmp  rax, 24
    jne  .fail
    ; send payload
    mov  rdi, r12
    mov  rsi, r15
    mov  rdx, rbx
    call fd_write_all
    cmp  rax, rbx
    jne  .fail
    mov  rax, rbx
    add  rax, 24
    jmp  .ret
.fail:
    mov  rax, -1
.ret:
    add  rsp, 0x68
    pop  rbx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

; ============================================================================
; p2p_read(fd, cmd_out[12], payload, cap, plen_out) -> 1 ok / 0 eof / -1 err / -2 trunc
;   SysV: rdi=fd rsi=cmd_out rdx=payload rcx=cap r8=plen_out
;   Frame stack locals (BELOW the save area):
;     rbp-0x18 .. rbp+0x8 : 24-byte header
;     rbp-0x20            : announced length (u32)
;     rbp-0x24            : tocopy          (u32)
;     rbp-0x30            : 8-byte drain scratch
;   Callee-saved: r12=fd r13=cmd_out r14=payload r15=cap rbx=plen_out
; ============================================================================
global p2p_read
p2p_read:
    ; v2 dispatch (see g_v2_active above); falls through to v1 untouched
    cmp  edi, V2_FD_MAX
    jae  .v1
    mov  eax, edi
    ; RIP-relative, not absolute: several test targets link this object into a
    ; PIE binary, and an absolute R_X86_64_32S reloc against .data cannot be
    ; used there ("recompile with -fPIE"). r10 is caller-saved and is not an
    ; argument register, so borrowing it disturbs nothing.
    lea  r10, [rel g_v2_active]
    cmp  byte [r10 + rax], 0
    je   .v1
    mov  rax, [rel g_v2_hook_read]
    test rax, rax
    je   .v1
    ; The hook is a C function, and this entry is reached at BOTH stack
    ; parities (the auditor calls p2p_read/p2p_write multi-entry). A tail jmp
    ; would hand C whatever alignment we happened to arrive with, and C may
    ; spill SSE registers to the stack. So align explicitly and make a real
    ; call: rsp is forced to 0 mod 16, the call pushes 8, and the callee sees
    ; the 8 that SysV promises it. Arguments are already in place and rax is
    ; the return value, so nothing else moves.
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    call rax
    mov  rsp, rbp
    pop  rbp
    ret
.v1:
    push rbp
    mov  rbp, rsp
    push r12
    push r13
    push r14
    push r15
    push rbx
    sub  rsp, 0xd8          ; locals BELOW save area (rbp-0x08..-0x40):
                            ; hdr[24]@-0x58, announced@-0x64, tocopy@-0x68,
                            ; drain scratch[64]@-0xc0.  0xd8==8 mod 16 -> RSP 0 mod 16
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbx, r8

    ; --- read 24-byte header ---
    mov  rdi, r12
    lea  rsi, [rbp-0x58]
    mov  rdx, 24
    call fd_read_full
    cmp  rax, 24
    jne  .eof_or_err

    ; --- verify magic (runtime chain-selected; see net_magic above) ---
    mov  eax, [rbp-0x58]
    cmp  eax, [net_magic]
    jne  .eof_or_err

    ; --- copy command (12B) to cmd_out ---
    mov  rdi, r13
    lea  rsi, [rbp-0x54]
    mov  rcx, 12
    rep  movsb

    ; --- announced length ---
    mov  eax, [rbp-0x48]
    ; SECURITY (audit 2026-08-29 finding 6): reject an oversized announcement
    ; before acting on it. Core rejects at exactly this point --
    ; net.cpp: `hdr.nMessageSize > MAX_SIZE || > MAX_PROTOCOL_MESSAGE_LENGTH`
    ; -- and the note beside that check cites the 2024-07-03 disclosure where
    ; the missing test let a peer make a node allocate 32 MiB per connection.
    ;
    ; Here the damage is unbounded WORK rather than memory: callers cap their
    ; own buffers, so a huge `announced` cannot overflow anything, but the
    ; drain loop below reads the excess 64 bytes at a time. A peer announcing
    ; 0xFFFFFFFF makes the forked serve child grind through ~4 GB of socket
    ; reads, holding a connection slot for as long as it cares to feed us.
    ;
    ; Returns -3, distinct from -2 (truncated) so the caller can score the
    ; peer for misbehaviour rather than treat it as an ordinary short read.
    cmp  eax, P2P_MAX_MSG
    ja   .oversize
    mov  [rbp-0x64], eax       ; announced

    ; --- tocopy = min(announced, cap) ---
    mov  ecx, r15d
    cmp  eax, ecx
    jbe  .small
    mov  eax, r15d
.small:
    mov  [rbp-0x68], eax       ; tocopy

    ; --- read tocopy payload bytes ---
    test eax, eax
    jz   .no_copy
    mov  rdi, r12
    mov  rsi, r14
    mov  edx, [rbp-0x68]
    call fd_read_full
    ; recompute tocopy to compare with what we asked for
    mov  eax, [rbp-0x64]
    mov  ecx, r15d
    cmp  eax, ecx
    jbe  .small2
    mov  eax, r15d
.small2:
    cmp  eax, [rbp-0x68]
    jne  .eof_or_err           ; short read
.no_copy:

    ; ---- NET-11 (audit 2026-09-03): VERIFY THE PAYLOAD CHECKSUM ----
    ; The header's checksum[4] at rbp-0x44 was read into the frame and never
    ; compared with sha256d(payload)[0:4], so a corrupted or deliberately
    ; mis-checksummed message was processed as if it were sound. Core's
    ; V1Transport::GetMessage rejects it ("Checksum mismatch") and disconnects,
    ; so a mismatch here goes to .eof_or_err -- the same exit a bad magic
    ; takes, which is exactly the audit's suggestion.
    ;
    ; ONLY when the whole payload was kept. If `announced` exceeded the
    ; caller's cap the excess is drained below and never lands in the buffer,
    ; and a digest over the prefix would be a guaranteed false mismatch; the
    ; message is already reported as truncated in that case.
    ;
    ; An EMPTY payload is checked too, not skipped: Core verifies the
    ; sha256d("") prefix on verack and friends, and a peer sending garbage
    ; there is as wrong as one sending garbage anywhere else.
    ;
    ; cksum4 lives in this same file (it is what p2p_write uses to PRODUCE the
    ; field) and sha256d was already an extern here, so this adds no link
    ; dependency to any of the sixty-odd targets that carry bitcoin_net.o --
    ; the concern that shaped the v2 dispatch table above.
    ;
    ; The 4-byte output sits at rbp-0x60, an already-reserved gap between
    ; tocopy@-0x68 and hdr[24]@-0x58, so the frame and its alignment are
    ; unchanged. cksum4 preserves r12-r14 itself and sha256d honours the SysV
    ; callee-saved set (proven by the callee-saved-check audit), so fd, cmd,
    ; payload, cap and plen_out all survive the call.
    mov  eax, [rbp-0x64]       ; announced
    cmp  eax, r15d             ; cap
    ja   .cksum_done           ; truncated -- cannot verify what we did not keep
    lea  rdi, [rbp-0x60]
    mov  rsi, r14
    mov  edx, eax
    call cksum4
    mov  eax, [rbp-0x60]
    cmp  eax, [rbp-0x44]
    jne  .eof_or_err           ; Core: "Checksum mismatch" -> drop the peer
.cksum_done:

    ; --- drain excess (announced - tocopy) if any ---
    mov  eax, [rbp-0x64]       ; announced
    mov  ecx, [rbp-0x68]       ; tocopy
    cmp  eax, ecx
    jbe  .no_drain             ; announced <= tocopy -> nothing to drain
    sub  eax, ecx              ; remaining to drain
.drain:
    test eax, eax
    jz   .no_drain
    ; requested = min(remaining, 64)
    mov  edx, eax
    cmp  edx, 64
    jbe  .dr_amt
    mov  edx, 64
.dr_amt:
    ; save remaining and requested on the stack across the call
    push rax                  ; [rsp+8]=remaining ; [rsp]=requested
    push rdx                  ; [rsp]=requested
    mov  rdi, r12
    lea  rsi, [rbp-0xc0]
    mov  rdx, [rsp]           ; ask for exactly `requested` bytes
    call fd_read_full         ; rax = actual bytes read
    pop  rcx                  ; requested (discard)
    pop  rdx                  ; remaining
    test rax, rax
    jle  .no_drain            ; peer closed / error -> stop draining here
    sub  rdx, rax             ; remaining -= actual read
    mov  rax, rdx
    jmp  .drain
.no_drain:

    ; --- report announced length ---
    mov  eax, [rbp-0x64]
    mov  [rbx], eax

    ; --- return code ---
    mov  eax, [rbp-0x64]
    mov  ecx, [rbp-0x68]
    cmp  eax, ecx
    ja   .trunc
    mov  rax, 1
    jmp  .ret
.trunc:
    mov  rax, -2
    jmp  .ret

.oversize:
    mov  rax, -3               ; announced length above P2P_MAX_MSG
    jmp  .ret
.eof_or_err:
    test rax, rax
    js   .err
    mov  rax, 0                ; eof (or short read)
    jmp  .ret
.err:
    mov  rax, -1
.ret:
    add  rsp, 0xd8
    pop  rbx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
