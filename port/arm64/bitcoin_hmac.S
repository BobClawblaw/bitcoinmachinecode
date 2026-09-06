/* bitcoin_hmac.S -- AArch64 port of asm/bitcoin_hmac.asm (AAPCS64).
 *   void hmac_sha512(u8 out[64], const u8* key, i64 keylen,
 *                    const u8* msg, i64 msglen)
 * Dep: sha512_full (sha512.S).
 *
 * ---- CRY-4 (audit 2026-09-03): kpad and tmp were .bss, i.e. ONE buffer
 * shared by every caller in the process. Two threads computing an HMAC
 * concurrently overwrote each other's key block and concatenation scratch and
 * both returned wrong MACs, silently -- the same class of defect as the
 * schnorr false-reject incident, and latent here only because every caller
 * happens to run under rpc_server.c's g_exec_lock. Nothing enforced that, and
 * BIP32/BIP39 derivation from a worker thread would have produced wrong child
 * keys.
 *
 * Both now live in hmac_sha512's own frame, so each call has its own. They
 * are still zeroised before return (WAL-3): stack memory outlives the call
 * just as .bss does, and the key block is a BIP32 chain code or the mnemonic
 * itself.
 */
    .text

    .global hmac_sha512
    .type hmac_sha512,%function
hmac_sha512:
    stp  x29,x30,[sp,#-16]!
    stp  x19,x20,[sp,#-16]!
    stp  x21,x22,[sp,#-16]!
    stp  x23,x24,[sp,#-16]!
    stp  x25,x26,[sp,#-16]!
    mov  x29,sp
    /* CRY-4: kpad (128) at [x29,#-0x128] and tmp (1160) at [x29,#-0x5B0]
     * now live in this frame -- each call gets its own. The reservation is
     * 0x5B0 (1456, a multiple of 16) so SP keeps its alignment at the
     * sha512_full call sites AND sits exactly at tmp's base: on ARM there
     * are no call-site pushes to cover the gap the way the x86's 0x590 plus
     * its per-site pushes do, and memory below SP is not owned -- a callee
     * frame there would overwrite the scratch. */
    sub  sp,sp,#0x5B0
    mov  x19,x0                 /* out   */
    mov  x20,x1                 /* key   */
    mov  x21,x2                 /* keylen (later effective) */
    mov  x22,x3                 /* msg   */
    mov  x23,x4                 /* msglen */

    /* ---- effective key: if keylen > 128, K = SHA512(key) (64 B) ---- */
    cmp  x21,#128
    b.le .keyok
    sub  x7,x29,#0x5B0
    mov  x0,x7                  /* out = tmp */
    mov  x1,x20
    mov  x2,x21
    bl   sha512_full
    mov  x21,#64                /* effective keylen = 64 */
    sub  x7,x29,#0x5B0
    mov  x20,x7                 /* effective key = tmp digest */
.keyok:

    sub  x24,x29,#0x128         /* x24 = kpad base (in-frame) */
    sub  x25,x29,#0x5B0         /* x25 = tmp base (in-frame) */

    /* ---- K' = effective key right-padded to 128 into kpad ---- */
    mov  x10,#0
.hkcp:
    cmp  x10,x21
    b.hs .hkcp_done
    ldrb w11,[x20,x10]
    strb w11,[x24,x10]
    add  x10,x10,#1
    b    .hkcp
.hkcp_done:
.hkz:
    cmp  x10,#128
    b.hs .hkz_done
    strb wzr,[x24,x10]
    add  x10,x10,#1
    b    .hkz
.hkz_done:

    /* ---- INNER: tmp[0..127] = K' XOR ipad(0x36); tmp[128..] = msg ---- */
    mov  x10,#0
.hxip:
    cmp  x10,#128
    b.hs .hxip_done
    ldrb w11,[x24,x10]
    mov  w12,#0x36
    eor  w11,w11,w12
    strb w11,[x25,x10]
    add  x10,x10,#1
    b    .hxip
.hxip_done:
    mov  x10,#0
.hmcp:
    cmp  x10,x23
    b.hs .hmcp_done
    ldrb w11,[x22,x10]
    add  x12,x25,#128
    strb w11,[x12,x10]
    add  x10,x10,#1
    b    .hmcp
.hmcp_done:
    /* inner_len = 128 + msglen ; inner digest = sha512_full(tmp, tmp, inner_len) */
    add  x2,x23,#128
    mov  x0,x25
    mov  x1,x25
    bl   sha512_full
    /* stash inner digest tmp[0..63] -> tmp[192..255] */
    mov  x10,#0
.hstash:
    cmp  x10,#64
    b.hs .hstash_done
    ldrb w11,[x25,x10]
    add  x13,x25,#192
    strb w11,[x13,x10]
    add  x10,x10,#1
    b    .hstash
.hstash_done:
    /* ---- OUTER: tmp[0..127] = K' XOR opad(0x5c) ---- */
    mov  x10,#0
.hxop:
    cmp  x10,#128
    b.hs .hxop_done
    ldrb w11,[x24,x10]
    mov  w12,#0x5c
    eor  w11,w11,w12
    strb w11,[x25,x10]
    add  x10,x10,#1
    b    .hxop
.hxop_done:
    /* copy tmp[192..255] -> tmp[128..191] */
    mov  x10,#0
.hicp:
    cmp  x10,#64
    b.hs .hicp_done
    add  x13,x25,#192
    ldrb w11,[x13,x10]
    add  x14,x25,#128
    strb w11,[x14,x10]
    add  x10,x10,#1
    b    .hicp
.hicp_done:
    /* out = sha512_full(out, tmp, 192) */
    mov  x0,x19
    mov  x1,x25
    mov  x2,#192
    bl   sha512_full

    /* ---- CRY-4 (audit 2026-09-03): zeroise the secret-derived scratch ----
     *
     * kpad holds the padded HMAC KEY -- a BIP32 parent chain code on the
     * derivation path, the mnemonic itself under BIP39's PBKDF2 -- and
     * tmp[192..255] holds the inner digest. Both survived the call's frame
     * (stack memory outlives the call just as .bss did), and any
     * memory-disclosure bug elsewhere in the daemon reads them straight out.
     * Core's equivalents live in the CHMAC_SHA512 object and go through
     * memory_cleanse.
     *
     * Only kpad and the key-block prefix of tmp are cleared. The rest of tmp
     * is message bytes, which are not secret here, and clearing the whole
     * 1160 bytes on every HMAC would cost real time in PBKDF2's 2,048
     * iterations. All registers used are caller-saved and already dead. */
    mov  x10,#0
.hzk:
    cmp  x10,#128
    b.hs .hzk_done
    strb wzr,[x24,x10]
    add  x10,x10,#1
    b    .hzk
.hzk_done:
    mov  x10,#0
.hzt:
    cmp  x10,#256               /* key block (128) + stashed inner digest */
    b.hs .hzt_done
    strb wzr,[x25,x10]
    add  x10,x10,#1
    b    .hzt
.hzt_done:

    add  sp,sp,#0x5B0           /* CRY-4: must match the reservation */
    ldp  x25,x26,[sp],#16
    ldp  x23,x24,[sp],#16
    ldp  x21,x22,[sp],#16
    ldp  x19,x20,[sp],#16
    ldp  x29,x30,[sp],#16
    ret
    .size hmac_sha512,.-hmac_sha512

    .section .note.GNU-stack,"",@progbits
