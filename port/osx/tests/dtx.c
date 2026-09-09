/* Differential driver for tx_parse/tx_txid (mirrors port/osx/tests/dvh.c style).
 * Reads vectors.bin records: (u32 op, u32 len, payload)
 *   op 0: tx_parse   payload=raw tx  -> out: u32 ok, 64 bytes info
 *   op 1: tx_txid    payload=raw tx  -> out: u32 ok, 32 bytes txid
 * Writes results.bin.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

int tx_parse(unsigned long long info[8], const void *tx, unsigned long txlen);
int tx_txid(unsigned char out[32], const void *tx, unsigned long txlen,
            unsigned char *buf, unsigned long buflen);

static unsigned char txbuf[1 << 20];

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: dtx vectors results\n"); return 2; }
    FILE *fv = fopen(argv[1], "rb");
    FILE *fr = fopen(argv[2], "wb");
    if (!fv || !fr) { perror("open"); return 2; }
    uint8_t *payload = malloc(1 << 22);
    uint32_t op, len;
    while (fread(&op, 4, 1, fv) == 1 && fread(&len, 4, 1, fv) == 1) {
        if (fread(payload, 1, len, fv) != len) break;
        if (op == 0) {
            unsigned long long info[8];
            memset(info, 0xCD, sizeof info);
            int ok = tx_parse(info, payload, len);
            fwrite(&ok, 4, 1, fr);
            fwrite(info, 8, 8, fr);
        } else if (op == 1) {
            unsigned char out[32];
            memset(out, 0xCD, 32);
            int ok = tx_txid(out, payload, len, txbuf, sizeof txbuf);
            fwrite(&ok, 4, 1, fr);
            fwrite(out, 1, 32, fr);
        }
    }
    fclose(fv); fclose(fr); free(payload);
    return 0;
}
