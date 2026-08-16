/* test_wallet_txlog.c -- transaction-journal unit test.
 *
 * Verifies the persistent wallet transaction history primitive:
 *   - txlog_append_sent writes a versioned, own-format "BMCTX v1" record
 *     (txid hex, amount, fee, dest h160, inputs, rawlen) to a 0600 journal.
 *   - txlog_list renders it back; the journal is APPEND-ONLY (a second append
 *     does not clobber the first).
 *   - txlog_path_for derives "<wallet>.txlog" (mirroring the .pass convention).
 *
 * This backs the CLI `history` / `listtransactions` commands.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern char* txlog_path_for(const char* wallet_path, char* buf, int cap);
extern int txlog_append_sent(const char* wallet_path, const unsigned char txid[32],
                             long long amount, long long fee,
                             const unsigned char dest_h160[20],
                             unsigned long inputs_used, long rawlen);
extern int txlog_list(const char* path, char* out, int cap);

static int failures = 0;
static void ck(const char* lbl, int got, int exp){
    if (got == exp) printf("PASS %s\n", lbl);
    else { printf("FAIL %s got=%d exp=%d\n", lbl, got, exp); failures++; }
}
static void ck_contains(const char* lbl, const char* hay, const char* needle, int should){
    int found = strstr(hay, needle) != NULL;
    if (found == should) printf("PASS %s\n", lbl);
    else { printf("FAIL %s (needle '%s' %s)\n", lbl, needle, should?"missing":"unexpectedly present"); failures++; }
}

int main(void){
    const char* wal = "/tmp/wtxlog_test_wallet.dat";
    const char* jp  = "/tmp/wtxlog_test_wallet.dat.txlog";
    remove(jp);
    unlink(jp);

    unsigned char txid[32];
    for (int i=0;i<32;i++) txid[i]=(unsigned char)i;
    unsigned char dest[20];
    for (int i=0;i<20;i++) dest[i]=(unsigned char)(0xa0+i);

    /* path derivation mirrors the .pass convention */
    char pb[256];
    txlog_path_for(wal, pb, sizeof pb);
    ck("txlog_path_for derives <wallet>.txlog", strcmp(pb, jp)==0, 1);

    /* append is versioned, own-format, 0600 */
    ck("append_sent succeeds", txlog_append_sent(wal, txid, 5000, 100, dest, 1, 226), 0);
    struct stat st;
    stat(jp, &st);
    ck("journal perms are 0600", ((st.st_mode & 0777) == 0600), 1);
    char out[4096]; out[0]=0;
    ck("list succeeds", txlog_list(jp, out, sizeof out), 0);
    ck_contains("list has header", out, "amount-sat", 1);
    ck_contains("list has the txid", out, "000102030405060708090a0b0c0d0e0f", 1); /* hex of bytes 0x00..0x0f */
    ck_contains("list has amount", out, "5000", 1);
    ck_contains("list has dest", out, "a0a1a2a3a4a5a6a7a8a9", 1);

    /* append-only: a second write must not clobber */
    unsigned char txid2[32]; for (int i=0;i<32;i++) txid2[i]=(unsigned char)(0x80+i);
    unsigned char dest2[20]; for (int i=0;i<20;i++) dest2[i]=(unsigned char)(0x40+i);
    txlog_append_sent(wal, txid2, 300, 50, dest2, 2, 222);
    char out2[4096]; out2[0]=0;
    txlog_list(jp, out2, sizeof out2);
    ck_contains("append-only keeps first txid", out2, "000102030405060708090a0b0c0d0e0f", 1);
    ck_contains("append-only adds second txid", out2, "8081828384858687", 1);

    /* list of a missing path is empty-but-ok, not an error */
    char out3[4096]; 
    ck("list of missing file -> ok(0)", txlog_list("/tmp/definitely_missing.txlog", out3, sizeof out3), 0);

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
