/* test_schnorr.c -- drive secp256k1_schnorr.asm (BIP340 Schnorr verify) against
 * the official BIP340 test vectors from the bitcoin/bips repository
 * (bip-0340/test-vectors.csv).
 *
 * schnorr_verify(sig, pub_xonly, msg, msglen) returns 1 for a valid BIP340
 * signature, else 0. Rows with a secret key are signer tests; we only check
 * the "verification result" column. Messages may be any length (the CSV
 * includes 0/1/17/100-byte variants), so we compute msglen from the hex.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

extern int schnorr_verify(const uint8_t* sig, const uint8_t* pk, const uint8_t* msg, int msglen);

static int g_fails = 0;
static int g_checks = 0;

/* Parse a CSV line into an array of field strings, preserving empty fields.
 * The input 'buf' is a mutable NUL-terminated copy of the line; the array
 * 'fields' receives pointers into it. Returns the field count. */
static int split_csv(char* line, char** fields, int maxf){
    int n = 0;
    char* p = line;
    if (line[0]==0) return 0;
    while (n < maxf) {
        fields[n++] = p;
        char* c = strchr(p, ',');
        if (!c) break;
        *c = 0;
        p = c + 1;
    }
    return n;
}

static int hex2b(const char* h, uint8_t* out){
    if (!h) return 0;
    int n = 0;
    while (h[0] && h[1]) {
        unsigned v;
        if (sscanf(h, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
        h += 2;
    }
    return n;
}

static void run_rows(char* data){
    char* save = NULL;
    int lineno = 0;
    char* line = strtok_r(data, "\n", &save);
    while (line) {
        lineno++;
        if (lineno == 1) { line = strtok_r(NULL, "\n", &save); continue; } /* header */
        size_t l = strlen(line);
        while (l && (line[l-1]=='\r'||line[l-1]=='\n')) line[--l]=0;
        if (!line[0]) { line = strtok_r(NULL, "\n", &save); continue; }

        char* f[8] = {0};
        int nf = split_csv(line, f, 8);
        /* columns: 0 index,1 sk,2 pk,3 aux,4 msg,5 sig,6 result,7 comment */
        if (nf < 7) { line = strtok_r(NULL, "\n", &save); continue; }

        uint8_t pk[32], msg[256], sig[64];
        int want;
        int pklen = hex2b(f[2], pk);
        if (pklen != 32) { line = strtok_r(NULL, "\n", &save); continue; }
        int msglen = hex2b(f[4], msg);
        if (hex2b(f[5], sig) != 64) { line = strtok_r(NULL, "\n", &save); continue; }
        want = (strncmp(f[6], "TRUE", 4)==0) ? 1 : 0;

        int got = schnorr_verify(sig, pk, msg, msglen);
        g_checks++;
        if (got != want) {
            g_fails++;
            printf("  MISMATCH row %d index=%s msglen=%d want=%d got=%d\n",
                   lineno, f[0], msglen, want, got);
        }
        line = strtok_r(NULL, "\n", &save);
    }
}

int main(int argc, char** argv){
    if (argc < 2) {
        printf("usage: test_schnorr <test-vectors.csv>\n");
        return 2;
    }
    FILE* fp = fopen(argv[1], "rb");
    if (!fp) { perror("open"); return 2; }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char* buf = malloc(sz+1);
    if (fread(buf, 1, sz, fp) != (size_t)sz) { perror("read"); return 2; }
    buf[sz] = 0;
    fclose(fp);

    run_rows(buf);
    printf("BIP340 vectors: %d checks, %d failures\n", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
