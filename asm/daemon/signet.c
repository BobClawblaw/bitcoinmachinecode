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

int signet_is_commitment_spk(const unsigned char* s, unsigned long len){
    return s && len >= MIN_WITNESS_COMMITMENT &&
           s[0] == 0x6a /* OP_RETURN */ && s[1] == 0x24 &&
           s[2] == 0xaa && s[3] == 0x21 && s[4] == 0xa9 && s[5] == 0xed;
}

int signet_commitment_index(const unsigned char* const* spks,
                            const unsigned long* spk_lens, long nout){
    int idx = -1;
    if (!spks || !spk_lens) return -1;
    for (long o = 0; o < nout; o++)
        if (signet_is_commitment_spk(spks[o], spk_lens[o]))
            idx = (int)o;      /* deliberately no break: the LAST one wins */
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
        /* VAL-13 (audit 2026-09-03): a truncated push used to be a hard
         * reject (-1 -> "bad-signet-commitment-malformed"). Core's
         * FetchAndClearCommitmentSection loops `while (GetOp(...))`: a
         * failing GetOp simply ENDS the loop, and if a header was already
         * found the truncated tail is dropped from the replacement script --
         * the signature is validated over the truncated form. A signer whose
         * commitment output ends with a dangling `4d ff ff` after a valid
         * solution push therefore produces a block Core accepts and this node
         * rejected. Stop here, exactly as GetOp does; `wo` already holds
         * only the ops that parsed, which IS Core's replacement. */
        if (used < 0) break;
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

/* ======================================================================
 * Layer 2 -- the BIP325 synthetic transactions.
 * ====================================================================== */

/* The consensus merkle and hash primitives, not private copies. Using a
 * second implementation here would mean the thing under test is not the
 * thing that runs. merkle_root reduces IN PLACE (bitcoin_hash.asm). */
extern void merkle_root(unsigned char out[32], unsigned char* hashes,
                        unsigned long n);
extern void sha256_full(unsigned char out[32], const unsigned char* msg,
                        long long len);

void signet_txid(unsigned char out32[32], const unsigned char* tx,
                 unsigned long txlen){
    unsigned char h[32];
    sha256_full(h, tx, (long long)txlen);
    sha256_full(out32, h, 32);
}

void signet_merkle_root(unsigned char out32[32], unsigned char* leaves,
                        unsigned long nleaves){
    merkle_root(out32, leaves, nleaves);
}

/* ---- CompactSize. Local on purpose: this file links standalone (its test
 * pulls in only the merkle and sha256 objects), and the readers elsewhere in
 * the tree are all static to their own translation units. ---- */

static int cs_size(unsigned long n){
    if (n < 0xfdUL)       return 1;
    if (n <= 0xffffUL)    return 3;
    if (n <= 0xffffffffUL) return 5;
    return 9;
}

static unsigned long put_cs(unsigned char* d, unsigned long n){
    if (n < 0xfdUL){ d[0] = (unsigned char)n; return 1; }
    if (n <= 0xffffUL){ d[0] = 0xfd; d[1] = (unsigned char)n;
                        d[2] = (unsigned char)(n >> 8); return 3; }
    if (n <= 0xffffffffUL){ d[0] = 0xfe;
        for (int i = 0; i < 4; i++) d[1+i] = (unsigned char)(n >> (8*i));
        return 5; }
    d[0] = 0xff;
    for (int i = 0; i < 8; i++) d[1+i] = (unsigned char)(n >> (8*i));
    return 9;
}

/* Canonical CompactSize read. `*ok` goes 0 on truncation OR on a value spelled
 * in more bytes than it needs -- Core's ReadCompactSize throws
 * "non-canonical ReadCompactSize()" for exactly that, and a length prefix with
 * several spellings is an ambiguity to refuse, not to normalise. */
static unsigned long read_cs(const unsigned char** p, const unsigned char* end,
                             int* ok){
    const unsigned char* b = *p;
    if (b >= end){ *ok = 0; return 0; }
    unsigned char f = *b++;
    if (f < 0xfd){ *p = b; return f; }
    int extra = (f == 0xfd) ? 2 : (f == 0xfe ? 4 : 8);
    if (end - b < extra){ *ok = 0; return 0; }
    unsigned long v = 0, min;
    for (int i = 0; i < extra; i++) v |= (unsigned long)b[i] << (8*i);
    b += extra;
    min = (f == 0xfd) ? 0xfdUL : (f == 0xfe ? 0x10000UL : 0x100000000UL);
    if (v < min){ *ok = 0; return 0; }
    *p = b;
    return v;
}

static unsigned long w32le(unsigned char* d, unsigned int v){
    for (int i = 0; i < 4; i++) d[i] = (unsigned char)(v >> (8*i));
    return 4;
}
static unsigned long w64le(unsigned char* d, unsigned long long v){
    for (int i = 0; i < 8; i++) d[i] = (unsigned char)(v >> (8*i));
    return 8;
}

int signet_parse_solution(const unsigned char* sol, unsigned long sol_len,
                          signet_solution_t* out){
    if (!out) return -1;
    out->script_sig = 0; out->script_sig_len = 0; out->nwit = 0;
    if (!sol && sol_len) return -1;

    const unsigned char* p = sol;
    const unsigned char* end = sol + sol_len;
    int ok = 1;

    unsigned long ssl = read_cs(&p, end, &ok);
    if (!ok || (unsigned long)(end - p) < ssl) return -1;
    out->script_sig = p; out->script_sig_len = ssl;
    p += ssl;

    unsigned long n = read_cs(&p, end, &ok);
    if (!ok) return -1;
    if (n > SIGNET_MAX_WIT) return -1;
    for (unsigned long i = 0; i < n; i++){
        unsigned long l = read_cs(&p, end, &ok);
        if (!ok || (unsigned long)(end - p) < l) return -1;
        out->wit[i] = p; out->witlen[i] = l;
        p += l;
    }
    out->nwit = n;

    /* Core: `if (!v.empty()) return std::nullopt;` -- leftover bytes are a
     * hard parse failure. Tolerating them would accept blocks Core rejects. */
    if (p != end) return -1;
    return 0;
}

/* block_data is always exactly 72 bytes (4 + 32 + 32 + 4), which is below
 * OP_PUSHDATA1 (76), so CScript::operator<< always emits the one-byte direct
 * push. Spelled as a constant with the reasoning rather than a general
 * minimal-push routine whose other branches could never be reached or
 * tested. */
#define SIGNET_BLOCK_DATA_LEN 72

long signet_build_to_spend(unsigned char* out, unsigned long cap,
                           int nversion, const unsigned char prev32[32],
                           const unsigned char signet_merkle32[32],
                           unsigned int ntime,
                           const unsigned char* challenge,
                           unsigned long challenge_len){
    if (!out || !prev32 || !signet_merkle32 || (!challenge && challenge_len))
        return -1;
    /* scriptSig = OP_0 <72 bytes> */
    const unsigned long ssl = 1 + 1 + SIGNET_BLOCK_DATA_LEN;
    unsigned long need = 4                          /* version */
                       + 1                          /* vin count */
                       + 36                         /* null outpoint */
                       + cs_size(ssl) + ssl
                       + 4                          /* sequence */
                       + 1                          /* vout count */
                       + 8                          /* value */
                       + cs_size(challenge_len) + challenge_len
                       + 4;                         /* locktime */
    if (cap < need) return -1;

    unsigned char* d = out;
    d += w32le(d, 0);                               /* version 0 */
    *d++ = 0x01;
    for (int i = 0; i < 32; i++) *d++ = 0x00;       /* null prevout hash */
    d += w32le(d, 0xffffffffu);                     /* COutPoint::NULL_INDEX */
    d += put_cs(d, ssl);
    *d++ = 0x00;                                    /* OP_0 */
    *d++ = (unsigned char)SIGNET_BLOCK_DATA_LEN;    /* direct push of 72 */
    d += w32le(d, (unsigned int)nversion);
    for (int i = 0; i < 32; i++) *d++ = prev32[i];
    for (int i = 0; i < 32; i++) *d++ = signet_merkle32[i];
    d += w32le(d, ntime);
    d += w32le(d, 0);                               /* sequence 0 */
    *d++ = 0x01;
    d += w64le(d, 0);                               /* value 0 */
    d += put_cs(d, challenge_len);
    for (unsigned long i = 0; i < challenge_len; i++) *d++ = challenge[i];
    d += w32le(d, 0);                               /* locktime 0 */
    return (long)(d - out);
}

long signet_build_to_sign(unsigned char* out, unsigned long cap,
                          const unsigned char to_spend_txid32[32],
                          const signet_solution_t* sol){
    if (!out || !to_spend_txid32 || !sol) return -1;
    if (sol->nwit > SIGNET_MAX_WIT) return -1;

    /* CTransaction::Serialize writes the witness marker/flag iff HasWitness(),
     * so an empty stack yields a plain legacy serialisation -- which is what
     * the trivial-challenge (OP_TRUE, no solution) case produces. */
    const int use_wit = sol->nwit > 0;
    unsigned long wbytes = 0;
    if (use_wit){
        wbytes = cs_size(sol->nwit);
        for (unsigned long i = 0; i < sol->nwit; i++)
            wbytes += cs_size(sol->witlen[i]) + sol->witlen[i];
    }
    unsigned long need = 4
                       + (use_wit ? 2u : 0u)
                       + 1 + 36
                       + cs_size(sol->script_sig_len) + sol->script_sig_len
                       + 4
                       + 1 + 8 + 1 + 1          /* one output: 0 / OP_RETURN */
                       + wbytes
                       + 4;
    if (cap < need) return -1;

    unsigned char* d = out;
    d += w32le(d, 0);
    if (use_wit){ *d++ = 0x00; *d++ = 0x01; }
    *d++ = 0x01;
    for (int i = 0; i < 32; i++) *d++ = to_spend_txid32[i];
    d += w32le(d, 0);                               /* to_spend output 0 */
    d += put_cs(d, sol->script_sig_len);
    for (unsigned long i = 0; i < sol->script_sig_len; i++)
        *d++ = sol->script_sig[i];
    d += w32le(d, 0);                               /* sequence 0 */
    *d++ = 0x01;
    d += w64le(d, 0);
    *d++ = 0x01; *d++ = 0x6a;                       /* scriptPubKey OP_RETURN */
    if (use_wit){
        d += put_cs(d, sol->nwit);
        for (unsigned long i = 0; i < sol->nwit; i++){
            d += put_cs(d, sol->witlen[i]);
            for (unsigned long j = 0; j < sol->witlen[i]; j++)
                *d++ = sol->wit[i][j];
        }
    }
    d += w32le(d, 0);                               /* locktime 0 */
    return (long)(d - out);
}
