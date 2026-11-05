/* base32.c -- RFC 4648 base32, lowercase, unpadded (see base32.h). */
#include "base32.h"
static const char ALPHA[33] = "abcdefghijklmnopqrstuvwxyz234567";
long base32_encode(char* out, const unsigned char* in, long len){
    long o = 0; unsigned acc = 0; int bits = 0;
    for (long i = 0; i < len; i++){
        acc = (acc << 8) | in[i]; bits += 8;
        while (bits >= 5){ bits -= 5; out[o++] = ALPHA[(acc >> bits) & 31]; }
    }
    if (bits > 0) out[o++] = ALPHA[(acc << (5 - bits)) & 31];
    out[o] = 0;
    return o;
}
long base32_decode(unsigned char* out, const char* s, long slen){
    long o = 0; unsigned acc = 0; int bits = 0;
    for (long i = 0; i < slen; i++){
        char c = s[i]; int v;
        if (c >= 'a' && c <= 'z') v = c - 'a';
        else if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= '2' && c <= '7') v = c - '2' + 26;
        else return -1;
        acc = (acc << 5) | (unsigned)v; bits += 5;
        if (bits >= 8){ bits -= 8; out[o++] = (unsigned char)((acc >> bits) & 0xff); }
    }
    /* leftover bits must be padding of fewer than 5 bits, all zero -- Core's
     * DecodeBase32 rejects the rest as malformed */
    if (bits >= 5 || (acc & ((1u << bits) - 1)) != 0) return -1;
    return o;
}
