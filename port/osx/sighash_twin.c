/* ============================================================================
 * sighash_twin.c -- legacy SignatureHash builders for the macOS/AArch64 port.
 * Functional twin of asm/bitcoin_sighash.asm (branch bmc_osx).
 *
 *   int  sighash_all(u8 out32[32], const u8 *tx, u64 txlen, u64 input_index,
 *                    const u8 *script, u64 script_len, u8 *preimg, u64 cap);
 *   int  legacy_sighash(u8 out32[32], const u8* tx, u64 txlen, u64 nIn,
 *                       const u8* scriptCode, u64 scLen, int32_t hashtype,
 *                       u8* preimg, u64 cap);
 *   u64  script_find_and_delete(u8* dst, u64 dstcap, const u8* src, u64 srclen,
 *                               const u8* needle, u64 needlelen);
 *   u64  script_op_len(const u8* pos, const u8* end);
 *   u64  script_push_encode(u8* dst, u64 dstcap, const u8* data, u64 datalen);
 *   __thread u8 legacy_sighash_scfbuf[20000];
 *
 * Shipped as a C twin (escape-hatch rule #2): the x86 module carries a
 * thread-local .tbss scratch (legacy_sighash_scfbuf, the parallel-verification
 * fix of 2026-08-19) and dense cursor arithmetic; __thread + C gives the
 * identical semantics without hand-rolling Mach-O TLS in asm.  Revisit for
 * perf after p3 if it ever matters.
 *
 * Every bound check / non-check of the x86 is transcribed as-is, including
 * the raw unchecked copies the module's callers never feed hostile txs
 * through (documented in the asm header).  Fail returns are 0; the
 * find-and-delete/push-encode overflow sentinel is UINT64_MAX.
 * ==========================================================================*/
#include <stdint.h>
#include <string.h>

typedef uint64_t u64;
typedef uint32_t u32;

extern void sha256d(unsigned char out[32], const void *msg, unsigned long long len);

__thread unsigned char legacy_sighash_scfbuf[20000];

/* parse_varint: CompactSize at *cur (against end).  Returns the value and
 * advances *cur past what was consumed; 0 on any over-run (ambiguous with a
 * genuine 0 exactly as on x86 -- callers reject 0 where it matters).
 * Advance order matches the asm: the prefix byte is consumed before the
 * width-overrun check, the value bytes are not consumed on failure. */
static u64 parse_varint(const unsigned char **cur, const unsigned char *end){
    const unsigned char *p = *cur;
    if (p >= end) return 0;
    unsigned b = *p++;
    if (b < 0xfd){ *cur = p; return b; }
    u64 width = (b == 0xfe) ? 4 : (b == 0xff) ? 8 : 2;
    if ((u64)(end - p) < width){ *cur = p; return 0; }
    u64 v = 0;
    for (u64 i = 0; i < width; i++) v |= (u64)p[i] << (8*i);   /* LE */
    *cur = p + width;
    return v;
}

/* write_varint: emit CompactSize of v at p (no cap check -- callers bound);
 * returns the advanced cursor.  1/0xfd+2/0xfe+4/0xff+8 forms, LE values. */
static unsigned char *write_varint(unsigned char *p, u64 v){
    if (v <= 0xfc){ *p++ = (unsigned char)v; }
    else if (v <= 0xffff){ *p++ = 0xfd; p[0]=v&0xff; p[1]=(v>>8)&0xff; p+=2; }
    else if (v <= 0xffffffffULL){
        *p++ = 0xfe; p[0]=v&0xff; p[1]=(v>>8)&0xff; p[2]=(v>>16)&0xff; p[3]=(v>>24)&0xff; p+=4;
    } else {
        *p++ = 0xff; for (int i=0;i<8;i++) p[i]=(unsigned char)(v>>(8*i)); p+=8;
    }
    return p;
}

/* copy_bytes: n bytes src->dst, advancing both (caller ensures bounds). */
static void copy_bytes(unsigned char **dst, const unsigned char **src, u64 n){
    memcpy(*dst, *src, n);
    *dst += n; *src += n;
}

/* script_op_len: byte length of the one script unit at pos, or 0. */
u64 script_op_len(const unsigned char *pos, const unsigned char *end){
    if (pos >= end) return 0;
    unsigned op = *pos;
    u64 unit;
    if (op < 0x4c)      unit = 1 + (u64)op;
    else if (op == 0x4c){
        if ((u64)(end - pos) < 2) return 0;
        unit = 2 + (u64)pos[1];
    } else if (op == 0x4d){
        if ((u64)(end - pos) < 3) return 0;
        unit = 3 + (u64)(pos[1] | ((u64)pos[2] << 8));
    } else if (op == 0x4e){
        if ((u64)(end - pos) < 5) return 0;
        unit = 5 + (u64)(pos[1] | ((u64)pos[2] << 8) | ((u64)pos[3] << 16) | ((u64)pos[4] << 24));
    } else unit = 1;
    if (pos + unit > end) return 0;
    return unit;
}

/* script_find_and_delete: Core's FindAndDelete; UINT64_MAX sentinel on cap. */
u64 script_find_and_delete(unsigned char *dst, u64 dstcap,
                           const unsigned char *src, u64 srclen,
                           const unsigned char *needle, u64 needlelen){
    const unsigned char *pc = src, *end = src + srclen;
    unsigned char *out = dst, *outend = dst + dstcap;
    for(;;){
        /* consume consecutive raw needle matches (deleted, not copied) */
        while (needlelen &&
               (u64)(end - pc) >= needlelen &&
               memcmp(pc, needle, needlelen) == 0)
            pc += needlelen;
        if (pc == end) break;
        u64 unit = script_op_len(pc, end);
        if (unit == 0){
            /* malformed trailing bytes: copy the raw remainder verbatim */
            u64 rem = (u64)(end - pc);
            if ((u64)(outend - out) < rem) return 0xFFFFFFFFFFFFFFFFULL;
            memcpy(out, pc, rem);
            out += rem;
            break;
        }
        if ((u64)(outend - out) < unit) return 0xFFFFFFFFFFFFFFFFULL;
        memcpy(out, pc, unit);
        out += unit; pc += unit;
    }
    return (u64)(out - dst);
}

/* script_push_encode: minimal CScript::operator<<(bytes); UINT64_MAX on cap. */
u64 script_push_encode(unsigned char *dst, u64 dstcap,
                       const unsigned char *data, u64 datalen){
    unsigned char *p;
    if (datalen < 0x4c){
        if (dstcap < datalen + 1) return 0xFFFFFFFFFFFFFFFFULL;
        dst[0] = (unsigned char)datalen;
        p = dst + 1;
    } else if (datalen <= 0xff){
        if (dstcap < datalen + 2) return 0xFFFFFFFFFFFFFFFFULL;
        dst[0] = 0x4c; dst[1] = (unsigned char)datalen;
        p = dst + 2;
    } else if (datalen <= 0xffff){
        if (dstcap < datalen + 3) return 0xFFFFFFFFFFFFFFFFULL;
        dst[0] = 0x4d; dst[1] = datalen & 0xff; dst[2] = (datalen >> 8) & 0xff;
        p = dst + 3;
    } else {
        if (dstcap < datalen + 5) return 0xFFFFFFFFFFFFFFFFULL;
        dst[0] = 0x4e;
        dst[1] = datalen & 0xff; dst[2] = (datalen >> 8) & 0xff;
        dst[3] = (datalen >> 16) & 0xff; dst[4] = (datalen >> 24) & 0xff;
        p = dst + 5;
    }
    memcpy(p, data, datalen);
    return (u64)((p + datalen) - dst);
}

/* legacy_locate_nout: walk version+n_in+all inputs to nOut without writing.
 * Returns nOut and sets *ok; also rejects nIn >= n_in.  The n_out varint is
 * pre-validated for length so a 0 return there can only mean genuine 0. */
static u64 legacy_locate_nout(const unsigned char *tx, const unsigned char *txend,
                              u64 nIn, int *ok){
    const unsigned char *p = tx + 4;
    u64 n_in = parse_varint(&p, txend);
    if (n_in == 0 || nIn >= n_in){ *ok = 0; return 0; }
    for (u64 i = 0; i < n_in; i++){
        p += 36;                                   /* prevout+index */
        if (p > txend){ *ok = 0; return 0; }
        u64 sl = parse_varint(&p, txend);
        p += sl;
        if (p > txend){ *ok = 0; return 0; }
        p += 4;                                    /* sequence */
        if (p > txend){ *ok = 0; return 0; }
    }
    if (p >= txend){ *ok = 0; return 0; }
    unsigned b = *p;
    u64 need = (b < 0xfd) ? 1 : (b == 0xfd) ? 3 : (b == 0xfe) ? 5 : 9;
    if ((u64)(txend - p) < need){ *ok = 0; return 0; }
    *ok = 1;
    return parse_varint(&p, txend);
}

/* ---------------------------------------------------------------- sighash_all */
int sighash_all(unsigned char out32[32], const unsigned char *tx, u64 txlen,
                u64 input_index, const unsigned char *script, u64 script_len,
                unsigned char *preimg, u64 cap){
    const unsigned char *txcur, *txend = tx + txlen;
    unsigned char *p, *pend = preimg + cap;
    u64 n_in, i;

    if (txlen < 10) return 0;

    txcur = tx + 4;
    n_in = parse_varint(&txcur, txend);
    if (n_in == 0) return 0;
    if (input_index >= n_in) return 0;

    p = preimg;

    /* version(4) raw */
    if ((u64)(pend - p) < 4) return 0;
    memcpy(p, tx, 4); p += 4;

    /* varint n_in (the asm does not re-check the cursor after this write) */
    p = write_varint(p, n_in);

    for (i = 0; i < n_in; i++){
        /* prevout(32)+index(4) raw */
        copy_bytes(&p, &txcur, 36);

        /* skip the raw scriptSig; a length that overruns the tx is rejected */
        u64 sl = parse_varint(&txcur, txend);
        txcur += sl;
        if (txcur > txend) return 0;

        if (i == input_index){
            p = write_varint(p, script_len);
            if (p > pend) return 0;             /* FINDING 2b cap */
            copy_bytes(&p, &script, script_len);
        } else {
            if ((u64)(pend - p) < 1) return 0;
            *p++ = 0;
        }

        /* sequence(4) raw (asm copies without re-checking either cursor) */
        copy_bytes(&p, &txcur, 4);
    }

    /* tail [txcur..txend) verbatim (asm: raw difference, unchecked) */
    copy_bytes(&p, &txcur, (u64)(txend - txcur));

    /* hashtype(4) = 1 */
    if ((u64)(pend - p) < 4) return 0;
    { u32 one = 1; memcpy(p, &one, 4); p += 4; }

    sha256d(out32, preimg, (u64)(p - preimg));
    return 1;
}

/* -------------------------------------------------------------- legacy_sighash */
int legacy_sighash(unsigned char out32[32], const unsigned char *tx, u64 txlen,
                   u64 nIn, const unsigned char *scriptCode, u64 scLen,
                   int32_t hashtype, unsigned char *preimg, u64 cap){
    const unsigned char *txend = tx + txlen;
    unsigned char *pcur, *pend = preimg + cap;
    u32 ht = (u32)hashtype;
    int fSingle = ((ht & 0x1f) == 3);
    int fNone   = ((ht & 0x1f) == 2);
    int fACP    = (ht & 0x80) != 0;
    u64 n_in, n_out, i, j;

    if (txlen < 10) return 0;

    const unsigned char *txcur = tx + 4;
    n_in = parse_varint(&txcur, txend);
    if (n_in == 0) return 0;
    if (nIn >= n_in) return 0;

    /* SIGHASH_SINGLE out-of-range pre-check (Core evaluates before building) */
    if (fSingle){
        int ok;
        u64 n_out_pre = legacy_locate_nout(tx, txend, nIn, &ok);
        if (!ok) return 0;
        if (nIn >= n_out_pre){
            memset(out32, 0, 32);
            out32[0] = 1;
            return 1;
        }
    }

    /* codeseparator-strip scriptCode into the per-thread scratch buffer */
    {
        static const unsigned char cs_needle[1] = { 0xab };
        u64 scF_len = script_find_and_delete(legacy_sighash_scfbuf, 20000,
                                             scriptCode, scLen, cs_needle, 1);
        if (scF_len == 0xFFFFFFFFFFFFFFFFULL) return 0;
        /* scF_len lives across the loop; C keeps it in a local */
        u64 scf_len = scF_len;

        pcur = preimg;

        /* version(4) raw */
        if ((u64)(pend - pcur) < 4) return 0;
        memcpy(pcur, tx, 4); pcur += 4;

        /* nInputs varint: fACP ? 1 : n_in */
        pcur = write_varint(pcur, fACP ? 1 : n_in);
        if (pcur > pend) return 0;

        /* input loop: i=0..n_in-1, ALWAYS walk the raw tx forward */
        const unsigned char *walk = txcur;
        for (i = 0; i < n_in; i++){
            const unsigned char *prevout_ptr = walk;
            walk += 36;
            if (walk > txend) return 0;
            u64 sl = parse_varint(&walk, txend);
            walk += sl;
            if (walk > txend) return 0;
            const unsigned char *seq_ptr = walk;
            walk += 4;
            if (walk > txend) return 0;

            if (i == nIn){
                /* the signed input: ALWAYS emitted */
                if ((u64)(pend - pcur) < 36) return 0;
                memcpy(pcur, prevout_ptr, 36); pcur += 36;
                pcur = write_varint(pcur, scf_len);
                if (pcur > pend) return 0;
                if ((u64)(pend - pcur) < scf_len) return 0;
                memcpy(pcur, legacy_sighash_scfbuf, scf_len); pcur += scf_len;
                if ((u64)(pend - pcur) < 4) return 0;
                memcpy(pcur, seq_ptr, 4); pcur += 4;
            } else {
                if (fACP) continue;          /* other inputs not emitted at all */
                if ((u64)(pend - pcur) < 36) return 0;
                memcpy(pcur, prevout_ptr, 36); pcur += 36;
                if ((u64)(pend - pcur) < 1) return 0;
                *pcur++ = 0;
                if ((u64)(pend - pcur) < 4) return 0;
                if (fSingle || fNone){
                    u32 zero = 0;
                    memcpy(pcur, &zero, 4); pcur += 4;
                } else {
                    memcpy(pcur, seq_ptr, 4); pcur += 4;
                }
            }
        }

        /* n_out (raw side; parse result unvalidated exactly as the asm) */
        u64 sl_nout = parse_varint(&walk, txend);
        n_out = sl_nout;

        /* nOutputs varint to emit */
        u64 n_emit = fNone ? 0 : fSingle ? (nIn + 1) : n_out;
        pcur = write_varint(pcur, n_emit);
        if (pcur > pend) return 0;

        /* output loop: j=0..n_out-1, ALWAYS walk the raw side */
        for (j = 0; j < n_out; j++){
            const unsigned char *val_ptr = walk;
            walk += 8;
            if (walk > txend) return 0;
            u64 spk_len = parse_varint(&walk, txend);
            const unsigned char *spk_ptr = walk;
            walk += spk_len;
            if (walk > txend) return 0;

            if (fNone) continue;
            if (fSingle && j < nIn){
                if ((u64)(pend - pcur) < 9) return 0;
                memset(pcur, 0xff, 8); pcur[8] = 0; pcur += 9;
                continue;
            }
            if (fSingle && j > nIn) continue;
            /* real emit (not fSingle, or fSingle && j == nIn) */
            if ((u64)(pend - pcur) < 8) return 0;
            memcpy(pcur, val_ptr, 8); pcur += 8;
            pcur = write_varint(pcur, spk_len);
            if (pcur > pend) return 0;
            if ((u64)(pend - pcur) < spk_len) return 0;
            memcpy(pcur, spk_ptr, spk_len); pcur += spk_len;
        }

        /* locktime(4 raw) */
        if (walk + 4 > txend) return 0;
        if ((u64)(pend - pcur) < 4) return 0;
        memcpy(pcur, walk, 4); pcur += 4;

        /* hashtype(4): the full passed-in bit pattern, raw LE */
        if ((u64)(pend - pcur) < 4) return 0;
        memcpy(pcur, &ht, 4); pcur += 4;

        sha256d(out32, preimg, (u64)(pcur - preimg));
        return 1;
    }
}
