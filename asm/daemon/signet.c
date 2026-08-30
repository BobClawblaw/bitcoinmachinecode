/* daemon/signet.c -- BIP325 signet block solutions. See signet.h.
 *
 * Layer 1 of the feature: locating the witness commitment and splitting the
 * signet solution out of it. Everything above (the synthetic to_spend/to_sign
 * transactions, the modified merkle root, and the script verification that
 * actually decides the block) builds on exactly these bytes, so this is
 * pinned on its own before anything depends on it.
 */
#include <string.h>
#include "signet.h"

/* Core's MINIMUM_WITNESS_COMMITMENT: OP_RETURN, a 36-byte push, the 4-byte
 * tag and a 32-byte hash. */
#define MIN_WITNESS_COMMITMENT 38

int signet_commitment_index(const unsigned char* const* spks,
                            const unsigned long* spk_lens, long nout){
    int idx = -1;
    if (!spks || !spk_lens) return -1;
    for (long o = 0; o < nout; o++){
        const unsigned char* s = spks[o];
        if (!s || spk_lens[o] < MIN_WITNESS_COMMITMENT) continue;
        if (s[0] == 0x6a /* OP_RETURN */ && s[1] == 0x24 &&
            s[2] == 0xaa && s[3] == 0x21 && s[4] == 0xa9 && s[5] == 0xed)
            idx = (int)o;      /* deliberately no break: the LAST one wins */
    }
    return idx;
}

/* One script opcode. Returns the number of bytes consumed, 0 at the end, or
 * -1 on a truncated push. `*data`/`*dlen` describe the pushed bytes when the
 * opcode is a push, otherwise dlen is 0. */
static long script_next(const unsigned char* s, unsigned long len, unsigned long pos,
                        const unsigned char** data, unsigned long* dlen){
    *data = 0; *dlen = 0;
    if (pos >= len) return 0;
    unsigned char op = s[pos];
    unsigned long need = 0, off = pos + 1;
    if (op <= 75){ need = op; }
    else if (op == 0x4c){ if (off + 1 > len) return -1; need = s[off]; off += 1; }
    else if (op == 0x4d){ if (off + 2 > len) return -1;
        need = (unsigned long)s[off] | ((unsigned long)s[off+1] << 8); off += 2; }
    else if (op == 0x4e){ if (off + 4 > len) return -1;
        need = (unsigned long)s[off] | ((unsigned long)s[off+1] << 8) |
               ((unsigned long)s[off+2] << 16) | ((unsigned long)s[off+3] << 24); off += 4; }
    else return 1;                       /* a bare opcode, one byte */
    if (need > len - off) return -1;     /* truncated push */
    *data = s + off; *dlen = need;
    return (long)(off + need - pos);
}

/* Emit a minimal push of `n` bytes, the way Core's CScript operator<< does.
 * The encoding must match, because the stripped script is hashed into the
 * modified merkle root -- a different but equivalent encoding yields a
 * different root and every signature check downstream fails. */
static long push_bytes(unsigned char* out, unsigned long cap, unsigned long o,
                       const unsigned char* d, unsigned long n){
    unsigned long need = n + (n < 76 ? 1 : n <= 0xff ? 2 : n <= 0xffff ? 3 : 5);
    if (o + need > cap) return -1;
    if (n < 76) out[o++] = (unsigned char)n;
    else if (n <= 0xff){ out[o++] = 0x4c; out[o++] = (unsigned char)n; }
    else if (n <= 0xffff){ out[o++] = 0x4d; out[o++] = (unsigned char)n; out[o++] = (unsigned char)(n >> 8); }
    else { out[o++] = 0x4e; for (int i = 0; i < 4; i++) out[o++] = (unsigned char)(n >> (8*i)); }
    if (n) memcpy(out + o, d, n);
    return (long)(o + n);
}

int signet_extract_solution(const unsigned char* spk, unsigned long spk_len,
                            unsigned char* out_solution, unsigned long* out_solution_len,
                            unsigned char* out_stripped, unsigned long* out_stripped_len,
                            unsigned long cap){
    static const unsigned char HDR[4] = { SIGNET_HEADER_0, SIGNET_HEADER_1,
                                          SIGNET_HEADER_2, SIGNET_HEADER_3 };
    if (!spk) return -1;
    unsigned long pos = 0, wo = 0;
    int found = 0;
    if (out_solution_len) *out_solution_len = 0;

    while (pos < spk_len){
        const unsigned char* d; unsigned long dl;
        long used = script_next(spk, spk_len, pos, &d, &dl);
        if (used < 0) return -1;
        if (used == 0) break;

        if (dl > 0){
            /* The push counts only if it carries the header AND data after
             * it -- a bare 4-byte header push is not a solution. */
            if (!found && dl > sizeof HDR && !memcmp(d, HDR, sizeof HDR)){
                unsigned long sl = dl - sizeof HDR;
                if (out_solution){
                    if (sl > cap) return -1;
                    memcpy(out_solution, d + sizeof HDR, sl);
                }
                if (out_solution_len) *out_solution_len = sl;
                found = 1;
                /* re-emit the header push, shortened -- Core truncates in
                 * place rather than dropping the push */
                long r = push_bytes(out_stripped, cap, wo, d, sizeof HDR);
                if (r < 0) return -1;
                wo = (unsigned long)r;
            } else {
                long r = push_bytes(out_stripped, cap, wo, d, dl);
                if (r < 0) return -1;
                wo = (unsigned long)r;
            }
        } else {
            if (wo + 1 > cap) return -1;
            if (out_stripped) out_stripped[wo] = spk[pos];
            wo++;
        }
        pos += (unsigned long)used;
    }

    /* Core only replaces the script when a header was found; otherwise the
     * caller keeps the original bytes. Reporting the rebuilt script either
     * way would be a subtly different thing to hash. */
    if (out_stripped_len) *out_stripped_len = found ? wo : spk_len;
    if (!found && out_stripped && spk_len <= cap) memcpy(out_stripped, spk, spk_len);
    return found;
}
