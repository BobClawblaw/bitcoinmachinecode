/* musig2.h -- BIP327 MuSig2 in plain C over the node's own secp256k1
 * field/point/scalar kernels (the same ones bip340_sign.c uses; no
 * thread-local scratch, so it links into any thread and never pulls
 * secp256k1_taproot.o into an RPC binary).
 *
 * Scope: KeyAgg (with the "second key" rule), ApplyTweak (plain and x-only),
 * NonceGen (BIP327 secure derivation), NonceAgg, GetSessionValues, Sign
 * (partial), PartialSigVerify, PartialSigAgg. Proven on libsecp256k1's copy
 * of the BIP's vectors (tests/test_musig2.c).
 *
 * Byte conventions match the BIP: pubkeys are 33-byte compressed; a
 * pubnonce is two compressed points (66 bytes) and an aggnonce likewise
 * with 33 zero bytes meaning the point at infinity; secnonce is
 * k1 || k2 || pk (97 bytes); partial sigs are 32-byte scalars; the final
 * signature is 64 bytes BIP340. All scalars/coordinates big-endian.
 *
 * ---- descriptor integration (BIP390 musig(), for descriptor.c) ----------
 * `musig(KEY,KEY,...)` is only valid as the KEY of tr() (internal key or
 * inside a leaf's pk()/multi_a()); nested musig() and musig() inside an
 * origin `[...]` are errors. Each KEY is a plain 33-byte key or a BIP32
 * (xpub[/path]) key WITHOUT its own `/ *` (star child) or `/<a;b>` when the musig() itself
 * carries derivation. Two shapes:
 *   1. musig(K1,...,Kn)            -> agg = musig2_key_agg(K1..Kn) (keys in
 *      the WRITTEN order; the BIP sorts nothing -- the descriptor writer
 *      chooses the order, and the aggregate depends on it), x-only = the
 *      32-byte xbytes(Q) used as the tr() key.
 *   2. musig(K1,...,Kn)/NUM/... then the star child or /<a;b> -> the aggregate becomes a
 *      SYNTHETIC xpub: depth 0, fingerprint 0, child 0, chaincode
 *      868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965,
 *      pubkey = the plain 33-byte aggregate; then ordinary unhardened
 *      CKDpub steps (hardened steps are an error, as is deriving both the
 *      participants and the aggregate). The PSBT records the participants
 *      under PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS keyed by the UNDERIVED
 *      aggregate and a PSBT_IN_TAP_BIP32_DERIVATION for the derived key
 *      whose fingerprint is hash160(agg)[0..4] with the musig() path --
 *      the signer recovers the per-step BIP32 tweaks from that (see
 *      musig2_psbt in rpc_commands.c).
 *   Participant keys keep their own origins/paths inside musig(); when a
 *   participant KEY is ranged (ends in the star child), the whole musig() is ranged and
 *   every participant is derived at the same index before aggregation.
 * descr_to_string must reproduce the musig() text verbatim (with private
 * keys for the with_priv form); the checksum covers the whole expression.
 * The Core tests for this are src/test/descriptor_tests.cpp ("musig").
 */
#ifndef MUSIG2_H
#define MUSIG2_H
#include <stdint.h>

#define MUSIG2_MAX_KEYS 32

typedef struct {
    uint64_t Qx[4], Qy[4];         /* aggregate key after tweaks, affine limbs (never infinity) */
    uint64_t gacc[4], tacc[4];      /* BIP327 accumulators */
    unsigned char L[32];            /* TaggedHash("KeyAgg list", pk_1 || ... || pk_n) */
    unsigned char pk2[33];          /* the second distinct key (coefficient 1), or 33 zero bytes */
    unsigned char pks[MUSIG2_MAX_KEYS][33];
    int n;
} musig2_keyagg_t;

typedef struct {
    uint64_t b[4], e[4];            /* nonce coefficient and challenge */
    uint64_t Rx[4], Ry[4];          /* the final nonce point (G if the aggregate was infinity) */
} musig2_session_t;

/* KeyAgg over n compressed keys in the given order -> 1, or 0 for an invalid
 * key, n out of [1, MUSIG2_MAX_KEYS], or an aggregate at infinity. */
int musig2_key_agg(musig2_keyagg_t* ka, const unsigned char (*pks)[33], int n);
/* ApplyTweak(t, is_xonly) -> 1, or 0 for t >= n or a result at infinity. */
int musig2_tweak(musig2_keyagg_t* ka, const unsigned char t[32], int is_xonly);
void musig2_agg_xonly(unsigned char out[32], const musig2_keyagg_t* ka);
void musig2_agg_plain(unsigned char out[33], const musig2_keyagg_t* ka);

/* NonceGen: rand32 is fresh randomness; sk may be NULL (then rand is used
 * directly); pk is our compressed key (required); aggpk32 may be NULL; msg
 * NULL means "no message" (distinct from an empty one); extra may be NULL.
 * -> 1, or 0 for a zero nonce (negligible) or an oversize message. */
int musig2_nonce_gen(unsigned char secnonce[97], unsigned char pubnonce[66],
                     const unsigned char rand32[32], const unsigned char* sk,
                     const unsigned char pk[33], const unsigned char* aggpk32,
                     const unsigned char* msg, unsigned long msglen,
                     const unsigned char* extra, unsigned long extralen);
/* 1 if both points of a pubnonce are valid (non-infinity) curve points. */
int musig2_pubnonce_valid(const unsigned char pn[66]);
/* NonceAgg -> 1, or 0 if any pubnonce is invalid (an infinity sum is fine and
 * encoded as 33 zero bytes). */
int musig2_nonce_agg(unsigned char aggnonce[66], const unsigned char (*pns)[66], int n);
/* GetSessionValues over the (tweaked) aggregate -> 1, or 0 for a malformed
 * aggnonce or an oversize message. */
int musig2_session(musig2_session_t* s, const musig2_keyagg_t* ka,
                   const unsigned char aggnonce[66], const unsigned char* msg, unsigned long msglen);
/* Sign -> 1 with the 32-byte partial signature, or 0 for a bad secnonce/key,
 * a key that is not a participant, or a partial signature that fails its own
 * verification. The caller must never reuse a secnonce. */
int musig2_partial_sign(unsigned char psig[32], const unsigned char secnonce[97],
                        const unsigned char sk[32], const musig2_keyagg_t* ka,
                        const musig2_session_t* s);
/* PartialSigVerify(psig, pubnonce, pk) -> 1 valid / 0 invalid or malformed. */
int musig2_partial_sig_verify(const unsigned char psig[32], const unsigned char pubnonce[66],
                              const unsigned char pk[33], const musig2_keyagg_t* ka,
                              const musig2_session_t* s);
/* PartialSigAgg -> 1 with the 64-byte BIP340 signature, or 0 for a partial
 * signature that is not a valid scalar. */
int musig2_partial_sig_agg(unsigned char sig[64], const musig2_session_t* s,
                           const musig2_keyagg_t* ka, const unsigned char (*psigs)[32], int n);
#endif
