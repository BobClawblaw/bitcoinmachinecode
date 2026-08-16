; ============================================================================
; bitcoin_store_fast.asm -- fast block READ path for bitcoin_store.asm.
;   100% AI-authored x86-64 assembly (NASM ELF64).
;
; WHY
;   The existing read path costs SIX syscalls per block:
;       store_get_at        : lseek(idx_fd) + read(48)
;       store_get_file_fd   : close(cur_blk_fd) + open(blk%05u.dat)
;       node_serve_block    : lseek(blk_fd)  + read(size)
;   The close/open pair is the worst of it: open_file unconditionally closes
;   whatever block file is open and reopens by name, with no "is it already
;   this file?" check. Serving 1,000 consecutive blocks out of one 128 MiB
;   blk file therefore performs 1,000 path lookups and 1,000 close/open pairs
;   for no reason.
;
;   This module drops the same work to TWO syscalls (pread index, pread body),
;   and to ONE when the caller supplies a cached index record.
;
; HOW
;   1. A small direct-mapped cache of READ-ONLY file descriptors lives in the
;      caller's store struct. Consecutive blocks in the same blk file reuse the
;      same fd with zero syscalls.
;   2. pread/pwrite-style positioned I/O replaces lseek+read. Besides halving
;      the syscall count this removes the shared file-offset entirely, which is
;      what makes the read path safe to call from several threads at once --
;      the current lseek+read pair races on st->cur_blk_fd's offset the moment
;      two peers are served concurrently.
;   3. The WRITE path (store_append / open_file / st->cur_blk_fd) is left
;      completely untouched. Read fds are a separate, read-only pool, so an
;      appending writer and concurrent readers never share a descriptor.
;
; FD-CACHE LAYOUT (inside the caller-supplied store struct)
;   bitcoin_store.asm uses offsets +0..+52. Every caller in the tree allocates
;   at least 256 bytes for the struct (the smallest are test_ibd_blocks.c's
;   stb2/stb3[256]), so the cache is placed at +64..+127 -- clear of the
;   existing fields and clear of the 256-byte floor.
;
;     +64 + slot*8 : dword file_no
;     +68 + slot*8 : dword fd  (-1 == empty)
;     slot = file_no & 7, i.e. direct-mapped, 8 entries.
;
;   Direct-mapped rather than LRU on purpose: block serving is overwhelmingly
;   sequential within a file, so a one-entry cache would already hit ~100% of
;   the time; eight entries additionally cover a scattered working set without
;   any replacement bookkeeping, and hard-bound the descriptor count at 8 so
;   this can never reintroduce the EMFILE exhaustion documented in open_file.
;
;   store_init zeroes... does NOT zero this region (callers may pass an
;   uninitialised stack buffer), so store_rd_init MUST be called before use.
;   store_read_at self-initialises via a magic word at +56 to stay safe even
;   if a caller forgets.
;
; EXPORTS
;   void store_rd_init(void* st)
;        Reset the read-fd cache (closes any cached fds). Safe to call twice.
;   int  store_rd_fd(void* st, unsigned file_no)          -> fd or -errno
;        Cached read-only descriptor for blk%05u.dat.
;   long store_read_at(void* st, unsigned long height, void* buf, unsigned long cap)
;        -> block size in bytes, or  -2 out-of-range / -3 pruned / -1 error
;           / -4 cap too small.  Reads the raw block payload into buf.
;   long store_read_meta(void* st, unsigned long height, unsigned long meta[3],
;                        void* buf, unsigned long cap)
;        -> same, but ALSO returns pos/size/file_no, and skips the index read
;           when meta[1] (size) is already non-zero -- lets a caller that walks
;           heights sequentially amortise the index lookup to ONE syscall.
;   void store_rd_advise(void* st, unsigned long height, unsigned long nblocks)
;        posix_fadvise(WILLNEED) over the byte range covering nblocks starting
;        at height, so the kernel reads ahead while the caller is still busy.
;   void store_rd_close(void* st)
;        Close all cached read fds (shutdown / post-prune invalidation).
;
; ABI: System V AMD64. rbx/r12-r15 preserved. Every `sub rsp, N` uses
;   N == 8 (mod 16) after the 5 callee pushes, matching the convention used
;   throughout bitcoin_store.asm, so RSP is 16-byte aligned at nested calls.
; ============================================================================

default rel
section .text

extern fmt_blkname
extern store_get_at
extern store_prune

FDC_OFF     equ 64            ; byte offset of the fd cache inside st
FDC_SLOTS   equ 8
FDC_MASK    equ 7
FDC_MAGIC   equ 0x5244464300000001   ; "RDFC" + version, stored at st+56

SYS_read        equ 0
SYS_open        equ 2
SYS_close       equ 3
SYS_pread64     equ 17
SYS_fadvise64   equ 221

O_RDONLY    equ 0
O_CLOEXEC   equ 0o2000000

FADV_WILLNEED equ 3

; ============================================================================
; store_rd_init(st)  -- reset the read-fd cache, closing anything cached.
;   Idempotent. Writes the magic so store_read_at knows the cache is live.
; ============================================================================
global store_rd_init
store_rd_init:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x18

    mov  r12, rdi                 ; st
    ; If the magic is already present the slots hold real fds -- close them
    ; before clearing, or we leak. If it is absent the region is uninitialised
    ; garbage and must NOT be interpreted as descriptors.
    mov  rax, FDC_MAGIC
    cmp  [r12+56], rax
    jne  .fresh

    xor  r13, r13                 ; slot = 0
.closeloop:
    mov  rax, r13
    shl  rax, 3
    lea  rbx, [r12 + FDC_OFF]
    add  rbx, rax                 ; &slot
    mov  eax, [rbx+4]             ; fd
    cmp  eax, 0
    jl   .closenext
    mov  edi, eax
    mov  eax, SYS_close
    syscall
.closenext:
    inc  r13
    cmp  r13, FDC_SLOTS
    jb   .closeloop

.fresh:
    ; clear all slots: file_no = 0, fd = -1
    xor  r13, r13
.clrloop:
    mov  rax, r13
    shl  rax, 3
    lea  rbx, [r12 + FDC_OFF]
    add  rbx, rax
    mov  dword [rbx+0], 0
    mov  dword [rbx+4], -1
    inc  r13
    cmp  r13, FDC_SLOTS
    jb   .clrloop

    mov  rax, FDC_MAGIC
    mov  [r12+56], rax

    add  rsp, 0x18
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; store_rd_close(st) -- close every cached read fd and clear the cache.
;   MUST be called after store_prune(), which unlinks blk files: a cached fd
;   would otherwise pin the deleted inode and keep serving stale bytes.
; ============================================================================
global store_rd_close
store_rd_close:
    jmp  store_rd_init            ; same work: close-then-clear

; ============================================================================
; store_rd_fd(st, file_no) -> fd (>=0) or negative errno
;   Direct-mapped cache lookup; opens O_RDONLY|O_CLOEXEC on miss.
; ============================================================================
global store_rd_fd
store_rd_fd:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x38                ; name[16] @ rbp-0x50 (below the save area)

    mov  r12, rdi                 ; st
    mov  r13d, esi                ; file_no

    ; lazily initialise if the caller never called store_rd_init
    mov  rax, FDC_MAGIC
    cmp  [r12+56], rax
    je   .ready
    mov  rdi, r12
    call store_rd_init
    mov  rdi, r12                 ; (store_rd_init preserves r12/r13 anyway)
.ready:
    ; slot = file_no & FDC_MASK ; rbx = &slot
    mov  eax, r13d
    and  eax, FDC_MASK
    shl  rax, 3
    lea  rbx, [r12 + FDC_OFF]
    add  rbx, rax

    ; hit?  slot.fd >= 0  AND  slot.file_no == file_no
    mov  eax, [rbx+4]
    cmp  eax, 0
    jl   .miss
    mov  ecx, [rbx+0]
    cmp  ecx, r13d
    jne  .evict
    ; ---- HIT: zero syscalls ----
    movsxd rax, eax
    jmp  .ret

.evict:
    ; occupied by a different file -> close it first (bounded fd usage)
    mov  edi, eax
    mov  eax, SYS_close
    syscall
    mov  dword [rbx+4], -1

.miss:
    lea  rdi, [rbp-0x50]
    mov  esi, r13d
    call fmt_blkname              ; "blk%05u.dat" + NUL
    lea  rdi, [rbp-0x50]
    mov  esi, O_RDONLY | O_CLOEXEC
    xor  edx, edx
    mov  eax, SYS_open
    syscall
    test rax, rax
    jl   .ret                     ; propagate -errno, leave slot empty
    ; install
    mov  [rbx+0], r13d            ; file_no
    mov  [rbx+4], eax             ; fd (low 32 bits; fds are ints)

.ret:
    add  rsp, 0x38
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; store_read_meta(st, height, meta[3], buf, cap) -> size or negative
;   meta[0]=data_pos meta[1]=data_size meta[2]=file_no
;   If meta[1] != 0 on entry the index lookup is SKIPPED and the supplied meta
;   is trusted -- this is the one-syscall path for a caller that already knows
;   where the block lives (e.g. it just called store_get_at, or it is walking
;   a contiguous range and caching records itself).
;   Otherwise store_get_at fills meta first.
; ============================================================================
global store_read_meta
store_read_meta:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x18

    mov  r12, rdi                 ; st
    mov  r13, rsi                 ; height
    mov  r14, rdx                 ; meta*
    mov  r15, rcx                 ; buf
    mov  [rbp-0x30], r8           ; cap

    ; meta[1] (size) already known?
    mov  rax, [r14+8]
    test rax, rax
    jnz  .have_meta

    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    call store_get_at             ; 1 syscall (pread) after the store patch
    cmp  rax, 1
    jne  .passthru                ; propagate -1 / -2 / -3 verbatim

.have_meta:
    mov  rax, [r14+8]             ; size
    cmp  rax, [rbp-0x30]          ; cap
    ja   .toobig

    ; fd = store_rd_fd(st, meta[2])
    mov  rdi, r12
    mov  esi, [r14+16]
    call store_rd_fd
    test rax, rax
    jl   .err
    mov  ebx, eax                 ; fd

    ; pread(fd, buf, size, pos+8)   -- +8 skips the [len][magic] frame header
    mov  edi, ebx
    mov  rsi, r15
    mov  rdx, [r14+8]             ; size
    mov  r10, [r14+0]             ; pos
    add  r10, 8
    mov  eax, SYS_pread64
    syscall
    cmp  rax, [r14+8]
    jne  .err
    ; rax already == size
    jmp  .ret

.passthru:
    ; rax holds store_get_at's negative status (-1/-2/-3)
    jmp  .ret
.toobig:
    mov  rax, -4
    jmp  .ret
.err:
    mov  rax, -1
.ret:
    add  rsp, 0x18
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; store_read_at(st, height, buf, cap) -> size or negative
;   Convenience wrapper: local meta, always does the index lookup.
;   Two syscalls total on a warm fd cache (pread index, pread body).
; ============================================================================
global store_read_at
store_read_at:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x38                ; meta[3] @ rbp-0x50

    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx                 ; buf
    mov  r15, rcx                 ; cap

    ; zero meta so store_read_meta performs the index lookup
    mov  qword [rbp-0x50+0], 0
    mov  qword [rbp-0x50+8], 0
    mov  qword [rbp-0x50+16], 0

    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rbp-0x50]
    mov  rcx, r14
    mov  r8,  r15
    call store_read_meta

    add  rsp, 0x38
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ============================================================================
; store_rd_advise(st, height, nblocks)
;   Ask the kernel to read ahead the byte span covering [height, height+n).
;   Cheap (one fadvise) and lets the page cache fill while the caller is still
;   hashing/serving earlier blocks. Best-effort: all errors ignored.
;   Only advises the span inside the FIRST file involved; a range spanning a
;   file rollover simply advises the head of it, which is the part needed soon.
; ============================================================================
global store_rd_advise
store_rd_advise:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x78                ; m0[3] @ rbp-0x50, m1[3] @ rbp-0x70

    mov  r12, rdi                 ; st
    mov  r13, rsi                 ; height
    mov  r14, rdx                 ; nblocks
    test r14, r14
    jz   .ret

    ; meta for the first block
    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rbp-0x50]
    call store_get_at
    cmp  rax, 1
    jne  .ret

    ; meta for the last block of the run
    lea  rax, [r13 + r14 - 1]
    mov  rdi, r12
    mov  rsi, rax
    lea  rdx, [rbp-0x70]
    call store_get_at
    cmp  rax, 1
    jne  .single

    ; same file? if not, fall back to advising just the first block's file
    mov  eax, [rbp-0x50+16]
    cmp  eax, [rbp-0x70+16]
    jne  .single

    ; len = (last.pos + last.size + 8) - first.pos
    mov  rax, [rbp-0x70+0]
    add  rax, [rbp-0x70+8]
    add  rax, 8
    sub  rax, [rbp-0x50+0]
    mov  [rbp-0x58], rax
    jmp  .advise

.single:
    mov  rax, [rbp-0x50+8]
    add  rax, 8
    mov  [rbp-0x58], rax

.advise:
    mov  rdi, r12
    mov  esi, [rbp-0x50+16]       ; file_no
    call store_rd_fd
    test rax, rax
    jl   .ret
    mov  edi, eax                 ; fd
    mov  rsi, [rbp-0x50+0]        ; offset
    mov  rdx, [rbp-0x58]          ; len
    mov  r10d, FADV_WILLNEED
    mov  eax, SYS_fadvise64
    syscall                       ; best-effort; ignore result

.ret:
    add  rsp, 0x78
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret


; ============================================================================
; ZERO-COPY PATH -- mmap-backed block access.
;
; WHY THIS EXISTS
;   store_read_at cut the syscall count from six to two, but benchmarking on a
;   warm page cache showed only ~1.1x: at ~8 GB/s the cost is dominated by the
;   memcpy of the block payload, not by syscall entry. Real mainnet blocks
;   average >1 MB, so the copy is ~99% of the work and shaving syscalls can
;   never buy much. The only way to go materially faster is to not copy.
;
;   mmap gives the caller a pointer straight into the page cache. cons_verify,
;   sha256d, merkle_root and the serve path can all consume that pointer
;   directly, so a "read" becomes an address computation. For the wire path,
;   writev(hdr, {ptr,len}) or sendfile then copies once (kernel->socket)
;   instead of twice (kernel->user->socket).
;
; MAPPING CACHE (store struct offsets +128..+255; struct MUST be >= 256 bytes,
;   which every caller in the tree already satisfies)
;     +128 + slot*32 +0  : dword file_no
;     +128 + slot*32 +4  : dword fd        (-1 empty)
;     +128 + slot*32 +8  : qword addr      (0 = unmapped)
;     +128 + slot*32 +16 : qword maplen
;     +128 + slot*32 +24 : qword reserved
;   slot = file_no & 3, four entries = up to 512 MiB of mapped blk files.
;
; APPEND SAFETY
;   A blk file grows under an appending writer. The mapping is sized from
;   fstat at map time; if a later request needs bytes past maplen the entry is
;   remapped at the current size. A shorter-than-needed mapping is therefore
;   never read past -- which matters because touching a mapped page beyond EOF
;   raises SIGBUS rather than returning an error.
; ============================================================================

MAP_OFF     equ 128
MAP_SLOTS   equ 4
MAP_MASK    equ 3
MAP_MAGIC   equ 0x4d415000000001    ; at st+120

SYS_mmap    equ 9
SYS_munmap  equ 11
SYS_fstat   equ 5
SYS_madvise equ 28

PROT_READ    equ 1
MAP_PRIVATE  equ 2
MAP_NORESERVE equ 0x4000
MADV_WILLNEED equ 3

; ----------------------------------------------------------------------------
; store_map_init(st) -- reset the mapping cache (unmapping anything live).
; ----------------------------------------------------------------------------
global store_map_init
store_map_init:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x18
    mov  r12, rdi

    mov  rax, MAP_MAGIC
    cmp  [r12+120], rax
    jne  .fresh
    xor  r13, r13
.uloop:
    mov  rax, r13
    shl  rax, 5
    lea  rbx, [r12 + MAP_OFF]
    add  rbx, rax
    mov  rax, [rbx+8]             ; addr
    test rax, rax
    jz   .ufd
    mov  rdi, rax
    mov  rsi, [rbx+16]            ; maplen
    mov  eax, SYS_munmap
    syscall
.ufd:
    mov  eax, [rbx+4]             ; fd
    cmp  eax, 0
    jl   .unext
    mov  edi, eax
    mov  eax, SYS_close
    syscall
.unext:
    inc  r13
    cmp  r13, MAP_SLOTS
    jb   .uloop
.fresh:
    xor  r13, r13
.cloop:
    mov  rax, r13
    shl  rax, 5
    lea  rbx, [r12 + MAP_OFF]
    add  rbx, rax
    mov  dword [rbx+0], 0
    mov  dword [rbx+4], -1
    mov  qword [rbx+8], 0
    mov  qword [rbx+16], 0
    mov  qword [rbx+24], 0
    inc  r13
    cmp  r13, MAP_SLOTS
    jb   .cloop
    mov  rax, MAP_MAGIC
    mov  [r12+120], rax

    add  rsp, 0x18
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

global store_map_close
store_map_close:
    jmp  store_map_init

; ----------------------------------------------------------------------------
; map_file(st, file_no, need_end) -> base addr in rax (0 on failure)
;   need_end = highest byte offset the caller will touch; the mapping is grown
;   (remapped) if it does not already cover it.
;   rdi=st, esi=file_no, rdx=need_end
; ----------------------------------------------------------------------------
map_file:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0xc8                ; statbuf[144] @ rbp-0xc0, name[16] @ rbp-0xd0
    mov  r12, rdi                 ; st
    mov  r13d, esi                ; file_no
    mov  r14, rdx                 ; need_end

    mov  rax, MAP_MAGIC
    cmp  [r12+120], rax
    je   .ready
    mov  rdi, r12
    call store_map_init
.ready:
    mov  eax, r13d
    and  eax, MAP_MASK
    shl  rax, 5
    lea  rbx, [r12 + MAP_OFF]
    add  rbx, rax                 ; rbx = &slot

    ; same file AND mapping already covers need_end -> HIT, zero syscalls
    mov  ecx, [rbx+0]
    cmp  ecx, r13d
    jne  .replace
    mov  rax, [rbx+8]
    test rax, rax
    jz   .replace
    mov  rcx, [rbx+16]
    cmp  r14, rcx
    ja   .grow                    ; right file, mapping too short
    jmp  .out                     ; rax already = base

.replace:
    ; different file in this slot: tear it down completely
    mov  rax, [rbx+8]
    test rax, rax
    jz   .repfd
    mov  rdi, rax
    mov  rsi, [rbx+16]
    mov  eax, SYS_munmap
    syscall
    mov  qword [rbx+8], 0
.repfd:
    mov  eax, [rbx+4]
    cmp  eax, 0
    jl   .opennew
    mov  edi, eax
    mov  eax, SYS_close
    syscall
    mov  dword [rbx+4], -1
.opennew:
    ; reuse the read-fd cache's opener semantics but keep a dedicated fd here,
    ; so an eviction in the pread cache cannot pull the mapping's fd away.
    lea  rdi, [rbp-0xd0]
    mov  esi, r13d
    call fmt_blkname
    lea  rdi, [rbp-0xd0]
    mov  esi, O_RDONLY | O_CLOEXEC
    xor  edx, edx
    mov  eax, SYS_open
    syscall
    test rax, rax
    jl   .fail
    mov  [rbx+4], eax
    mov  dword [rbx+0], r13d
    jmp  .domap

.grow:
    ; right file, mapping too short: drop the old mapping, keep the fd
    mov  rdi, [rbx+8]
    mov  rsi, [rbx+16]
    mov  eax, SYS_munmap
    syscall
    mov  qword [rbx+8], 0

.domap:
    ; maplen = current file size (fstat), must be >= need_end
    mov  edi, [rbx+4]
    lea  rsi, [rbp-0xc0]
    mov  eax, SYS_fstat
    syscall
    test rax, rax
    jl   .fail
    mov  rax, [rbp-0xc0+48]       ; st_size
    cmp  rax, r14
    jb   .fail                    ; file shorter than the caller needs
    mov  r15, rax                 ; maplen

    ; mmap(NULL, maplen, PROT_READ, MAP_PRIVATE|MAP_NORESERVE, fd, 0)
    xor  edi, edi
    mov  rsi, r15
    mov  edx, PROT_READ
    mov  r10d, MAP_PRIVATE | MAP_NORESERVE
    mov  r8d, [rbx+4]
    xor  r9d, r9d
    mov  eax, SYS_mmap
    syscall
    cmp  rax, -4095
    jae  .fail                    ; mmap returns -errno in [-4095,-1]
    mov  [rbx+8], rax
    mov  [rbx+16], r15
.out:
    jmp  .ret
.fail:
    xor  eax, eax
.ret:
    add  rsp, 0xc8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; store_map_at(st, height, out[2]) -> const u8* block payload (0 on failure)
;   out[0] = size, out[1] = file_no.
;   ZERO copies, and zero syscalls once the file is mapped: the return value
;   points straight into the page cache. The pointer stays valid until the
;   slot is reused (another file_no hashing to the same slot) or the mapping
;   is grown, so consume it before the next store_map_at on a different file.
; ----------------------------------------------------------------------------
global store_map_at
store_map_at:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x38                ; meta[3] @ rbp-0x50
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx                 ; out[2]

    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rbp-0x50]
    call store_get_at
    cmp  rax, 1
    jne  .fail

    ; need_end = pos + 8 + size
    mov  r15, [rbp-0x50+0]        ; pos
    mov  rax, r15
    add  rax, 8
    add  rax, [rbp-0x50+8]        ; + size
    mov  rdi, r12
    mov  esi, [rbp-0x50+16]       ; file_no
    mov  rdx, rax
    call map_file
    test rax, rax
    jz   .fail

    add  rax, r15
    add  rax, 8                   ; skip [len][magic] frame header
    test r14, r14
    jz   .ret
    mov  rcx, [rbp-0x50+8]
    mov  [r14+0], rcx             ; size
    mov  rcx, [rbp-0x50+16]
    mov  [r14+8], rcx             ; file_no
    jmp  .ret
.fail:
    xor  eax, eax
    test r14, r14
    jz   .ret
    mov  qword [r14+0], 0
    mov  qword [r14+8], 0
.ret:
    add  rsp, 0x38
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ----------------------------------------------------------------------------
; store_map_advise(st, height, nblocks) -- madvise(WILLNEED) across a run of
;   blocks so the kernel faults them in ahead of a sequential walk.
; ----------------------------------------------------------------------------
global store_map_advise
store_map_advise:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x38
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    test r14, r14
    jz   .ret

    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rbp-0x50]
    call store_map_at             ; maps the file and gives us the base ptr
    test rax, rax
    jz   .ret
    mov  rbx, rax                 ; ptr to first block
    ; span ~= nblocks * size(first) -- an estimate is fine for readahead
    mov  rax, [rbp-0x50+0]
    imul rax, r14
    mov  rdi, rbx
    mov  rsi, rax
    mov  edx, MADV_WILLNEED
    mov  eax, SYS_madvise
    syscall
.ret:
    add  rsp, 0x38
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret


; ----------------------------------------------------------------------------
; store_prune_safe(st, prune_height) -> whatever store_prune returns
;   store_prune UNLINKS blk files and compacts the boundary file. A cached read
;   fd or live mmap would keep the deleted inode alive and keep serving stale
;   bytes from it, so both caches are invalidated first.
;   Provided as a wrapper rather than a hook inside store_prune so that
;   bitcoin_store.o keeps zero link dependency on this module -- existing
;   binaries that never read fast do not have to link it.
; ----------------------------------------------------------------------------
global store_prune_safe
store_prune_safe:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x18
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, r12
    call store_rd_close
    mov  rdi, r12
    call store_map_close
    mov  rdi, r12
    mov  rsi, r13
    call store_prune
    add  rsp, 0x18
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
