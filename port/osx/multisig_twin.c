/* multisig_twin.c -- C twin of asm/bitcoin_multisig.asm for the osx port.
 *
 *   int p2sh_hash(const u8 *script, ulong script_len, u8 out20[20])
 *       RIPEMD160(SHA256(script)); 1, or 0 for an empty script.
 *   int multisig_verify(const u8 *scriptSig, ulong sigLen,
 *                       const u8 *pubKey, ulong pubLen,
 *                       const u8 *tx, ulong txLen, ulong inputIndex,
 *                       u8 *work, ulong workCap,
 *                       const u8 *prevOutScript, ulong prevOutScriptLen)
 *       One signer of an OP_CHECKMULTISIG: walk the scriptSig's pushes
 *       (<len byte><data>), find the push equal to pubKey, take the push
 *       BEFORE it as its DER signature + hashtype, and verify it against the
 *       legacy SIGHASH_ALL digest with prevOutScript as the signing script.
 *       1 valid / 0 otherwise (hashtype must be exactly SIGHASH_ALL).
 *
 * An early standalone module: consensus multisig is the interpreter's
 * OP_CHECKMULTISIG; only tests/test_multisig (and the ABI bench) call this.
 * Until 2026-09-26 the Mac had no counterpart and test_multisig could not run.
 *
 * One divergence from the asm, on MALFORMED input only: the asm compares a
 * candidate push against pubKey without checking the push fits inside the
 * scriptSig, reading past its end when a length byte overruns; the twin
 * requires the push to fit. Every well-formed scriptSig answers the same.
 */
#include <stdint.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

extern void sha256_full(u8 *out, const u8 *in, unsigned long len);
extern void ripemd160(unsigned char out[20], const void *in, long long len);
extern int  sighash_all(unsigned char out32[32], const unsigned char *tx, u64 txlen,
                        u64 input_index, const unsigned char *script, u64 script_len,
                        unsigned char *preimg, u64 cap);
extern int  der_parse_sig(const unsigned char *sig, unsigned long long slen,
                          u64 r[4], u64 s[4], u32 *hashtype);
extern void be_to_limbs(u64 out[4], const unsigned char *bytes, unsigned long long len);
extern int  pubkey_parse(const unsigned char *pub, unsigned long plen, u64 qx[4], u64 qy[4]);
extern int  ecdsa_verify(const u64 z[4], const u64 r[4], const u64 s[4],
                         const u64 qx[4], const u64 qy[4]);

int p2sh_hash(const u8 *script, unsigned long script_len, u8 out20[20])
{
    u8 h[32];
    if (!script_len) return 0;
    sha256_full(h, script, script_len);
    ripemd160(out20, h, 32);
    return 1;
}

int multisig_verify(const u8 *ss, unsigned long ss_len,
                    const u8 *pub, unsigned long pub_len,
                    const u8 *tx, unsigned long tx_len, unsigned long input_index,
                    u8 *work, unsigned long work_cap,
                    const u8 *prev_script, unsigned long prev_script_len)
{
    /* step 1: the push equal to pubKey, and the push before it */
    const u8 *p = ss, *end = ss + ss_len, *sig = 0;
    unsigned long sig_len = 0, prev_len = 0;
    const u8 *prev = 0;
    int found = 0;
    while (p < end){
        unsigned long n = *p++;
        if (n > (unsigned long)(end - p)) return 0;     /* the push must fit (the asm does not check) */
        if (n == pub_len && !memcmp(p, pub, n)){ sig = prev; sig_len = prev_len; found = 1; break; }
        prev = p; prev_len = n; p += n;
    }
    if (!found) return 0;

    /* step 2: the legacy SIGHASH_ALL digest (prevOutScript signs) */
    u8 digest[32];
    if (!sighash_all(digest, tx, tx_len, input_index, prev_script, prev_script_len, work, work_cap)) return 0;

    /* step 3: DER without the trailing hashtype byte (IR-2, as Core), which must be ALL */
    if (!sig_len) return 0;
    u64 r[4], s[4]; u32 ht_slot = 0;
    if (!der_parse_sig(sig, sig_len - 1, r, s, &ht_slot)) return 0;
    if (sig[sig_len - 1] != 1) return 0;

    /* steps 4-6 */
    u64 z[4], qx[4], qy[4];
    be_to_limbs(z, digest, 32);
    if (!pubkey_parse(pub, pub_len, qx, qy)) return 0;
    return ecdsa_verify(z, r, s, qx, qy) ? 1 : 0;
}
