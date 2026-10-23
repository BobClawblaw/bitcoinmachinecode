/* tests/test_wallet_enc_durability.c -- CRY-8 (audit 2026-10-23):
 * encryptwallet makes the sealed container's rename durable before it
 * unlinks the plaintext store.
 *
 * wenc_encrypt wrote bmcwallet.enc.tmp, fsynced it, renamed it to
 * bmcwallet.enc, verified it, then unlinked bmcwallet.dat -- with no fsync of
 * the directory between the rename and the unlink. A filesystem may persist
 * the two directory updates in either order, so a crash between them can
 * leave the unlink on disk and not the rename: no plaintext store and no
 * container, i.e. no wallet.
 *
 * The test wraps rename, fsync and unlink (-Wl,--wrap) and records the order
 * of the calls wenc_encrypt and wenc_change make: a directory fsync must come
 * after the container's rename and before the plaintext unlink; and after
 * walletpassphrasechange's rename. The control is that the calls are seen at
 * all and the container opens. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

typedef unsigned char u8;
extern int  wenc_boot(const char* dir);
extern int  wenc_encrypt(const char* mn, const char* mn_pass, const char* wallet_pass, long wplen);
extern int  wenc_change(const char* oldp, long ol, const char* newp, long nl);
extern int  wenc_unlock(const char* pass, long plen, long seconds);

/* wallet_enc_state.c derives the seed on unlock; the derivation is not what
 * this test is about, so a stand-in keeps the link small */
long wallet_mnemonic_seed(u8 seed[64], const char* mn, const char* pass, long passlen){
    (void)mn; (void)pass; (void)passlen; memset(seed, 0x5a, 64); return 64;
}

#define MAXEV 64
static char g_ev[MAXEV][96]; static int g_nev;
static void ev(const char* kind, const char* what){
    if (g_nev < MAXEV) snprintf(g_ev[g_nev++], sizeof g_ev[0], "%s %s", kind, what);
}
int __real_rename(const char* a, const char* b);
int __real_fsync(int fd);
int __real_unlink(const char* p);
int __wrap_rename(const char* a, const char* b){
    const char* base = strrchr(b, '/'); ev("rename", base ? base + 1 : b);
    return __real_rename(a, b);
}
int __wrap_fsync(int fd){
    struct stat sb; ev("fsync", fstat(fd, &sb) == 0 && S_ISDIR(sb.st_mode) ? "dir" : "file");
    return __real_fsync(fd);
}
int __wrap_unlink(const char* p){
    const char* base = strrchr(p, '/'); ev("unlink", base ? base + 1 : p);
    return __real_unlink(p);
}
static int find(const char* e, int from){
    for (int i = from; i < g_nev; i++) if (!strcmp(g_ev[i], e)) return i;
    return -1;
}

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }

int main(void){
    char tmpl[] = "/tmp/wencdur.XXXXXX"; char* d = mkdtemp(tmpl);
    if (!d || chdir(d) != 0){ printf("FAIL: tmpdir\n"); return 1; }
    FILE* f = fopen("bmcwallet.dat", "w"); fputs("BMCWAL v1\nabandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n", f); fclose(f);
    ck("no container yet (boot adopts nothing, records the directory)", wenc_boot(d) == 0);

    printf("== encryptwallet ==\n");
    g_nev = 0;
    ck("wenc_encrypt succeeds", wenc_encrypt("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", "pw-cry8", 7) == 1);
    for (int i = 0; i < g_nev; i++) printf("    %s\n", g_ev[i]);
    int r = find("rename bmcwallet.enc", 0);
    int u = find("unlink bmcwallet.dat", 0);
    ck("the container was renamed into place", r >= 0);
    ck("the plaintext store was unlinked", u > r);
    int dsync = find("fsync dir", r < 0 ? 0 : r);
    ck("CRY-8 a directory fsync comes after the rename and BEFORE the unlink", r >= 0 && dsync > r && dsync < u);
    ck("the plaintext store is gone", access("bmcwallet.dat", F_OK) != 0);
    ck("control: the container opens", wenc_unlock("pw-cry8", 7, 0) == 1);

    printf("== walletpassphrasechange ==\n");
    g_nev = 0;
    ck("wenc_change succeeds", wenc_change("pw-cry8", 7, "pw-new", 6) == 1);
    r = find("rename bmcwallet.enc", 0);
    ck("CRY-8 a directory fsync follows the re-wrap's rename", r >= 0 && find("fsync dir", r) > r);
    ck("control: the new passphrase opens it", wenc_unlock("pw-new", 6, 0) == 1);

    unlink("bmcwallet.enc"); if (chdir("/") == 0) rmdir(d);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
