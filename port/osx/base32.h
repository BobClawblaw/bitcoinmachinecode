/* base32.h -- RFC 4648 base32 (lowercase, no padding), the alphabet Tor v3
 * onion addresses and I2P .b32.i2p names are written in. NOT bech32 (which
 * has its own charset and checksum) -- that already exists in bech32.asm. */
#ifndef BMC_BASE32_H
#define BMC_BASE32_H
/* out must hold ceil(len*8/5) + 1 bytes; returns the string length */
long base32_encode(char* out, const unsigned char* in, long len);
/* decodes a lowercase-or-uppercase string of exactly `slen` chars (no '=');
 * returns the byte count, or -1 on a bad character or a length that leaves
 * more than 4 unused bits. out must hold slen*5/8 bytes. */
long base32_decode(unsigned char* out, const char* s, long slen);
#endif
