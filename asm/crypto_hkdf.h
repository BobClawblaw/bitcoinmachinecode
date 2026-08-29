/* crypto_hkdf.h -- HMAC-SHA256 and RFC 5869 HKDF.
 *
 * The HMAC was originally a static helper inside rpc_server.c for -rpcauth.
 * BIP324's handshake needs the same primitive, so it lives here rather than
 * being written twice -- two copies of a keyed hash is exactly the shape that
 * ends with one of them quietly diverging. */
#ifndef BMC_CRYPTO_HKDF_H
#define BMC_CRYPTO_HKDF_H
void hmac_sha256(unsigned char out[32], const unsigned char* key, unsigned long keylen,
                 const unsigned char* msg, unsigned long msglen);
/* RFC 5869. salt/info may be NULL with length 0. outlen <= 255*32. */
void hkdf_sha256(unsigned char* out, unsigned long outlen,
                 const unsigned char* ikm,  unsigned long ikmlen,
                 const unsigned char* salt, unsigned long saltlen,
                 const unsigned char* info, unsigned long infolen);
/* the two halves separately -- BIP324 extracts once and expands several times */
void hkdf_sha256_extract(unsigned char prk[32],
                         const unsigned char* salt, unsigned long saltlen,
                         const unsigned char* ikm,  unsigned long ikmlen);
void hkdf_sha256_expand(unsigned char* out, unsigned long outlen,
                        const unsigned char prk[32],
                        const unsigned char* info, unsigned long infolen);
#endif
