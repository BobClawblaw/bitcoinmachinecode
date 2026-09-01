/* miniscript_sign.h -- witnesses for miniscript-locked inputs.
 *
 * The raw signer (signrawtransactionwithkey, and through it walletprocesspsbt
 * / descriptorprocesspsbt) hands a witnessScript it does not recognise here
 * together with the sighash it already computed, the keys it holds, the
 * preimages the PSBT carried and the spending transaction's timelock fields.
 * The script is decoded as miniscript, the non-malleable satisfaction is
 * built with the signatures/preimages available, and the witness items come
 * back varint-prefixed, bottom first (the raw signer's own witness format;
 * it appends the script itself). Tapscript leaves get the same service for
 * the script-path signer: items only, BIP340 signatures. */
#ifndef BMC_MINISCRIPT_SIGN_H
#define BMC_MINISCRIPT_SIGN_H
#include <stddef.h>

#define MS_PRE_MAX 16
typedef struct {
    int n;
    unsigned char hash[MS_PRE_MAX][32]; int hlen[MS_PRE_MAX];   /* 20 or 32 */
    unsigned char pre[MS_PRE_MAX][32];
} ms_preimages_t;

/* P2WSH: witnessScript ws[0..wl), BIP143 sighash z for it, hashtype byte,
 * this input's nSequence and the tx nLockTime, the signer's key table
 * (compressed pubkeys; ncomp[k] = 1 compressed), the preimages.
 * Returns 1 with the items in wit (witlen bytes, wititems items -- NOT
 * including the witnessScript), 0 if ws is not a miniscript (the caller keeps
 * its own diagnostics), -1 when it is one but cannot be satisfied (*err). */
int ms_sign_witness_v0(const unsigned char* ws, size_t wl, const unsigned char z[32], int hashtype,
                       unsigned seq, unsigned long locktime,
                       unsigned char (*kpriv)[32], unsigned char (*kpub)[33], const int* ncomp, int nkeys,
                       const unsigned char (*pubs)[33], int npubs,          /* pubkeys known without a private key (pk_h resolution) */
                       const ms_preimages_t* pre,
                       unsigned char* wit, unsigned long witcap, unsigned long* witlen, int* wititems, const char** err);

/* Tapscript leaf: same contract with the BIP341 leaf sighash z; hashtype 0
 * gives 64-byte signatures. Keys are matched x-only. */
int ms_sign_witness_tapleaf(const unsigned char* leaf, size_t ll, const unsigned char z[32], int hashtype,
                            unsigned seq, unsigned long locktime,
                            unsigned char (*kpriv)[32], unsigned char (*kpub)[33], int nkeys,
                            const unsigned char (*pubs)[33], int npubs,
                            const ms_preimages_t* pre,
                            unsigned char* wit, unsigned long witcap, unsigned long* witlen, int* wititems, const char** err);
#endif
