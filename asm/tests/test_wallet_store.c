/* tests/test_wallet_store.c -- security audit 2026-09-02 finding N4: the
 * mnemonic file ("BMCWAL") and the extra-key secret blob ("BMCHDK") used a
 * 2048-iteration PBKDF2 with an empty salt, a custom CTR cipher and a custom
 * tag, long after the live descriptor wallet had moved to Core's
 * BytesToKeySHA512AES (100000 iterations, random salt) + AES-256-CBC
 * (daemon/wallet_crypter.c, "BMCWENC1"). Both now write the strong container
 * ("BMCWAL v3" / "format=wcrypt") and never the legacy shape again; legacy
 * files still open, and a successful open rewrites them upgraded, in place.
 * The legacy fixtures under tests/fixtures/ were written by the pre-change
 * code with passphrase "correct horse". */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern int wallet_store_create(const char* path, const char* mnemonic, const char* pass);
extern int wallet_store_load(const char* path, char* mnemonic_out, int cap, char* pass_out, int pcap);
extern int wallet_secret_write(const char* path, const char* magic, const char* plaintext, const char* pass);
extern int wallet_secret_read(const char* path, const char* magic, char* out, int cap, const char* pass);
static int failures = 0;
static void ck(const char* l, int c){ if (c) printf("PASS %s\n", l); else { printf("FAIL %s\n", l); failures++; } }
static int file_has(const char* path, const char* needle){
    FILE* f = fopen(path, "r"); if (!f) return 0; static char buf[65536]; size_t n = fread(buf, 1, sizeof buf - 1, f); fclose(f); buf[n] = 0;
    return strstr(buf, needle) != NULL;
}
static int copy_file(const char* from, const char* to){
    FILE* a = fopen(from, "r"); if (!a) return 0; FILE* b = fopen(to, "w"); if (!b){ fclose(a); return 0; }
    static char buf[65536]; size_t n; while ((n = fread(buf, 1, sizeof buf, a)) > 0) fwrite(buf, 1, n, b); fclose(a); fclose(b); return 1;
}
int main(void){
    const char* MN = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char* XPRV = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    char fix_v2[1024], fix_hdk[1024]; char cwd[512]; if (!getcwd(cwd, sizeof cwd)) return 1;
    snprintf(fix_v2, sizeof fix_v2, "%s/tests/fixtures/wallet_store_legacy_v2.wal", cwd);
    snprintf(fix_hdk, sizeof fix_hdk, "%s/tests/fixtures/wallet_store_legacy_hdk.dat", cwd);
    char tmpl[] = "/tmp/wstoreXXXXXX"; char* dir = mkdtemp(tmpl); if (!dir || chdir(dir) != 0){ printf("FAIL tmpdir\n"); return 1; }
    unsetenv("BMC_WALLET_PASS");
    char mn[512], pass[128];
    printf("---- mnemonic file: new writes are the strong container ----\n");
    ck("create with a passphrase", wallet_store_create("w.dat", MN, "hunter2") == 0);
    ck("file is BMCWAL v3", file_has("w.dat", "BMCWAL v3"));
    ck("...sealed with wcrypt", file_has("w.dat", "format=wcrypt"));
    ck("...and NOT the legacy shape", !file_has("w.dat", "ctr-sha512") && !file_has("w.dat", "BMCWAL v2"));
    ck("...the mnemonic is not in the file", !file_has("w.dat", "abandon"));
    snprintf(pass, sizeof pass, "hunter2"); mn[0] = 0;
    ck("load with the passphrase", wallet_store_load("w.dat", mn, sizeof mn, pass, sizeof pass) == 0 && !strcmp(mn, MN));
    snprintf(pass, sizeof pass, "wrong"); mn[0] = 0;
    ck("wrong passphrase -> -1", wallet_store_load("w.dat", mn, sizeof mn, pass, sizeof pass) == -1 && mn[0] == 0);
    pass[0] = 0;
    ck("no passphrase -> -1", wallet_store_load("w.dat", mn, sizeof mn, pass, sizeof pass) == -1);
    setenv("BMC_WALLET_PASS", "hunter2", 1); pass[0] = 0; mn[0] = 0;
    ck("passphrase from BMC_WALLET_PASS", wallet_store_load("w.dat", mn, sizeof mn, pass, sizeof pass) == 0 && !strcmp(mn, MN));
    unsetenv("BMC_WALLET_PASS");
    ck("plaintext create (no passphrase) is v1", wallet_store_create("p.dat", MN, "") == 0 && file_has("p.dat", "BMCWAL v1"));
    pass[0] = 0; ck("...and loads", wallet_store_load("p.dat", mn, sizeof mn, pass, sizeof pass) == 0 && !strcmp(mn, MN));
    printf("---- legacy BMCWAL v2 fixture: opens, then is upgraded in place ----\n");
    ck("fixture copied", copy_file(fix_v2, "legacy.dat"));
    ck("fixture is v2 (2048-iteration KDF)", file_has("legacy.dat", "BMCWAL v2") && file_has("legacy.dat", "ctr-sha512"));
    snprintf(pass, sizeof pass, "wrong"); mn[0] = 0;
    ck("wrong passphrase on legacy -> -1", wallet_store_load("legacy.dat", mn, sizeof mn, pass, sizeof pass) == -1);
    ck("...and the file is untouched", file_has("legacy.dat", "BMCWAL v2"));
    snprintf(pass, sizeof pass, "correct horse"); mn[0] = 0;
    ck("right passphrase opens the legacy file", wallet_store_load("legacy.dat", mn, sizeof mn, pass, sizeof pass) == 0 && !strcmp(mn, MN));
    ck("...which is now v3", file_has("legacy.dat", "BMCWAL v3") && file_has("legacy.dat", "format=wcrypt") && !file_has("legacy.dat", "ctr-sha512"));
    snprintf(pass, sizeof pass, "correct horse"); mn[0] = 0;
    ck("...and opens again through the strong path", wallet_store_load("legacy.dat", mn, sizeof mn, pass, sizeof pass) == 0 && !strcmp(mn, MN));
    ck("no .tmp left behind", access("legacy.dat.tmp", F_OK) != 0);
    printf("---- secret blob (addhdkey's xprv store) ----\n");
    char out[512];
    ck("write refuses an empty passphrase", wallet_secret_write("k.dat", "BMCHDK v1", XPRV, "") == -1);
    ck("write with a passphrase", wallet_secret_write("k.dat", "BMCHDK v1", XPRV, "hunter2") == 0);
    ck("blob is sealed, not legacy", file_has("k.dat", "format=wcrypt") && !file_has("k.dat", "ctr-sha512") && !file_has("k.dat", "xprv"));
    out[0] = 0; ck("read with the passphrase", wallet_secret_read("k.dat", "BMCHDK v1", out, sizeof out, "hunter2") == 0 && !strcmp(out, XPRV));
    ck("wrong passphrase -> -1", wallet_secret_read("k.dat", "BMCHDK v1", out, sizeof out, "nope") == -1);
    ck("wrong magic -> -1", wallet_secret_read("k.dat", "BMCOTHER v1", out, sizeof out, "hunter2") == -1);
    ck("legacy hdk fixture copied", copy_file(fix_hdk, "lk.dat"));
    ck("legacy blob opens", wallet_secret_read("lk.dat", "BMCHDK v1", out, sizeof out, "correct horse") == 0 && !strcmp(out, XPRV));
    ck("...and is upgraded in place", file_has("lk.dat", "format=wcrypt") && !file_has("lk.dat", "ctr-sha512"));
    ck("...and opens again sealed", wallet_secret_read("lk.dat", "BMCHDK v1", out, sizeof out, "correct horse") == 0 && !strcmp(out, XPRV));
    printf("%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL PASS", failures);
    return failures ? 1 : 0;
}
