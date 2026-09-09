/* Differential driver: runs port/osx/bitcoin_hash.S functions over vector
 * files produced by the Python oracle, writes results back for comparison.
 * Usage: dvh <vectors.bin> <results.bin>
 * Vector file format (all little-endian): sequence of records
 *   u32 op; u32 len; len bytes payload (op: 0=sha256d,1=block_hash,2=diff_target,
 *   3=pow_check,4=sha256d64(pairs),5=merkle_root(n*32))
 * Result file: for each record, 32-byte out (or u32 ret for ops 3,5).
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

void sha256d(uint8_t *out, const void *msg, int64_t len);
void block_hash(uint8_t *out, const uint8_t *hdr);
void diff_target(uint8_t *target, uint32_t bits);
int pow_check(const uint8_t *hdr);
void sha256d64(uint8_t *out, const uint8_t *in, uint64_t pairs);
int merkle_root(uint8_t *out, void *hashes, uint64_t n);

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: dvh vectors results\n"); return 2; }
    FILE *fv = fopen(argv[1], "rb");
    FILE *fr = fopen(argv[2], "wb");
    if (!fv || !fr) { perror("open"); return 2; }
    uint8_t *payload = malloc(1 << 22);
    uint32_t op, len;
    while (fread(&op, 4, 1, fv) == 1 && fread(&len, 4, 1, fv) == 1) {
        if (fread(payload, 1, len, fv) != len) break;
        if (op == 0) { uint8_t o[32]; sha256d(o, payload, len); fwrite(o, 1, 32, fr); }
        else if (op == 1) { uint8_t o[32]; block_hash(o, payload); fwrite(o, 1, 32, fr); }
        else if (op == 2) { uint32_t bits; memcpy(&bits, payload, 4); uint8_t o[32];
                            diff_target(o, bits); fwrite(o, 1, 32, fr); }
        else if (op == 3) { int r = pow_check(payload); fwrite(&r, 4, 1, fr); }
        else if (op == 4) { uint64_t pairs; memcpy(&pairs, payload, 8);
                            /* contract: out[32i] = sha256d(in[64i..64i+63]);
                               in stride 64, out stride 32 */
                            uint8_t *in = payload + 8; uint8_t *o = malloc(pairs * 32);
                            sha256d64(o, in, pairs); fwrite(o, 1, pairs * 32, fr); free(o); }
        else if (op == 5) { uint8_t o[32]; int r = merkle_root(o, payload, len / 32);
                            fwrite(o, 1, 32, fr); fwrite(&r, 4, 1, fr); }
    }
    fclose(fv); fclose(fr); free(payload);
    return 0;
}
