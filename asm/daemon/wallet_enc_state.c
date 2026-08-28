/* daemon/wallet_enc_state.c -- the runtime lock/unlock state for wallet
 * encryption, driving encryptwallet / walletpassphrase /
 * walletpassphrasechange / walletlock.
 *
 * Owns: the on-disk encrypted container (bmcwallet.enc), a decrypted-seed
 * buffer that exists ONLY while unlocked, and the unlock expiry. When the
 * store is encrypted the live RPC wallet seed is NULL (locked); unlocking
 * derives the seed from the mnemonic and installs it via a setter the daemon
 * registers, for a caller-chosen number of seconds; locking (explicit, or
 * lazily on expiry) clears it and re-NULLs the live seed. Not encrypted =>
 * this module is inert and the plaintext wallet loads as before.
 *
 * Single process (the serve parent's RPC), single wallet, so a module-global
 * state is the right shape -- no locking beyond the lazy expiry check every
 * seed access already makes.
 */
#include <stdio.h>
#include "log_ts.h"   /* timestamped fprintf(stderr), like every other daemon line */
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

typedef unsigned char u8;

extern long wcrypt_seal(const char* pass, long passlen, const u8* seed, long seedlen, u8* out, long cap);
extern long wcrypt_open(const char* pass, long passlen, const u8* blob, long len, u8* seed_out, long cap);
extern long wcrypt_rewrap(const char* oldp, long oldlen, const char* newp, long newlen,
                          const u8* blob, long len, u8* out, long cap);
extern int  wcrypt_is_encrypted(const u8* blob, long len);
/* the wallet's BIP39 mnemonic -> 64-byte seed (bitcoin_bip39.asm via wallet) */
extern long wallet_mnemonic_seed(u8 seed[64], const char* mn, const char* pass, long passlen);

#define WENC_FILE   "bmcwallet.enc"
#define WENC_MNMAX  768

static int   g_encrypted;              /* an encrypted store exists */
static u8    g_blob[8192]; static long g_bloblen;
static u8    g_seed[64]; static int g_unlocked;
static long  g_unlock_until;           /* unix seconds; 0 = no timer */
static char  g_enc_dir[512];           /* datadir for the .enc path */

/* the daemon installs this so unlock/lock can flip the live RPC wallet's
 * seed pointer (NULL = locked). */
static void (*g_set_live_seed)(const u8*);
void wenc_set_seed_installer(void (*fn)(const u8*)){ g_set_live_seed = fn; }

/* The daemon installs this so encryptwallet can fetch the loaded wallet's
 * mnemonic (+ its bip39 passphrase) to seal. Kept here, not in main.c, so the
 * RPC layer and unit tests resolve wenc_current_mnemonic without linking the
 * daemon entry point. NULL provider (e.g. tests that never encrypt) => 0. */
static int (*g_mn_provider)(char*, long, char*, long);
void wenc_set_mnemonic_provider(int (*fn)(char*, long, char*, long)){ g_mn_provider = fn; }
int wenc_current_mnemonic(char* out, long cap, char* pass_out, long pcap){
    return g_mn_provider ? g_mn_provider(out, cap, pass_out, pcap) : 0;
}

static void wenc_path(char* out, long cap){
    if (g_enc_dir[0]) snprintf(out, (size_t)cap, "%s/%s", g_enc_dir, WENC_FILE);
    else snprintf(out, (size_t)cap, "%s", WENC_FILE);
}

/* Boot: if an encrypted container exists in `dir`, adopt it (locked). The
 * daemon calls this INSTEAD of loading a plaintext seed when it finds one. */
int wenc_boot(const char* dir){
    snprintf(g_enc_dir, sizeof g_enc_dir, "%s", dir ? dir : "");
    char p[600]; wenc_path(p, sizeof p);
    int fd = open(p, O_RDONLY);
    if (fd < 0) return 0;
    long n = read(fd, g_blob, sizeof g_blob);
    close(fd);
    if (n <= 0 || !wcrypt_is_encrypted(g_blob, n)) return 0;
    g_bloblen = n; g_encrypted = 1; g_unlocked = 0;
    fprintf(stderr, "[wallet] encrypted store present -- locked (walletpassphrase to unlock)\n");
    return 1;
}

int  wenc_is_encrypted(void){ return g_encrypted; }

/* the live seed IF unlocked and unexpired; NULL otherwise (also re-locks) */
const u8* wenc_seed(void){
    if (!g_encrypted || !g_unlocked) return 0;
    if (g_unlock_until && (long)time(NULL) >= g_unlock_until){
        memset(g_seed, 0, sizeof g_seed);
        g_unlocked = 0;
        if (g_set_live_seed) g_set_live_seed(0);
        return 0;
    }
    return g_seed;
}

/* Encrypt a currently-plaintext wallet. `mn` is the loaded mnemonic (its
 * own passphrase-derived seed is what the wallet uses; we store the
 * mnemonic so unlock can re-derive it). Writes bmcwallet.enc atomically,
 * removes the plaintext store, and leaves the wallet LOCKED. Returns 1 ok. */
int wenc_encrypt(const char* mn, const char* mn_pass, const char* wallet_pass, long wplen){
    static u8 seal[8192];
    /* store the mnemonic bytes (plus its own bip39 passphrase, if any, as a
     * newline-joined pair) so unlock reconstructs the exact seed */
    static char payload[WENC_MNMAX*2];
    long pl = snprintf(payload, sizeof payload, "%s\n%s", mn, mn_pass ? mn_pass : "");
    long n = wcrypt_seal(wallet_pass, wplen, (const u8*)payload, pl, seal, sizeof seal);
    memset(payload, 0, sizeof payload);
    if (n < 0) return 0;
    char p[600]; wenc_path(p, sizeof p);
    char tmp[640]; snprintf(tmp, sizeof tmp, "%s.tmp", p);
    int fd = open(tmp, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) return 0;
    if (write(fd, seal, n) != n || fsync(fd) != 0){ close(fd); return 0; }
    close(fd);
    if (rename(tmp, p) != 0) return 0;
    /* remove the plaintext store (both candidate locations) */
    { char d1[600]; snprintf(d1, sizeof d1, "%s/bmcwallet.dat", g_enc_dir[0]?g_enc_dir:"."); unlink(d1);
      unlink("bmcwallet.dat"); }
    memcpy(g_blob, seal, n); g_bloblen = n;
    g_encrypted = 1; g_unlocked = 0;
    memset(g_seed, 0, sizeof g_seed);
    if (g_set_live_seed) g_set_live_seed(0);
    return 1;
}

/* Unlock for `seconds`. Returns 1 ok, 0 wrong passphrase. */
int wenc_unlock(const char* pass, long plen, long seconds){
    if (!g_encrypted) return -1;
    static u8 payload[WENC_MNMAX*2];
    long pl = wcrypt_open(pass, plen, g_blob, g_bloblen, payload, sizeof payload);
    if (pl <= 0){ memset(payload,0,sizeof payload); return 0; }
    payload[pl] = 0;
    /* payload = "mnemonic\npassphrase" */
    char* nl = memchr(payload, '\n', pl);
    const char* mn = (char*)payload;
    const char* mp = nl ? nl + 1 : "";
    if (nl) *nl = 0;
    wallet_mnemonic_seed(g_seed, mn, mp[0] ? mp : 0, mp[0] ? (long)strlen(mp) : 0);
    memset(payload, 0, sizeof payload);
    g_unlocked = 1;
    g_unlock_until = seconds > 0 ? (long)time(NULL) + seconds : 0;
    if (g_set_live_seed) g_set_live_seed(g_seed);
    return 1;
}

void wenc_lock(void){
    memset(g_seed, 0, sizeof g_seed);
    g_unlocked = 0; g_unlock_until = 0;
    if (g_set_live_seed) g_set_live_seed(0);
}

/* Change passphrase (re-wrap only). Returns 1 ok, 0 old wrong. */
int wenc_change(const char* oldp, long ol, const char* newp, long nl){
    if (!g_encrypted) return -1;
    static u8 nb[8192];
    long n = wcrypt_rewrap(oldp, ol, newp, nl, g_blob, g_bloblen, nb, sizeof nb);
    if (n <= 0) return 0;
    char p[600]; wenc_path(p, sizeof p);
    char tmp[640]; snprintf(tmp, sizeof tmp, "%s.tmp", p);
    int fd = open(tmp, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) return 0;
    if (write(fd, nb, n) != n || fsync(fd) != 0){ close(fd); return 0; }
    close(fd);
    if (rename(tmp, p) != 0) return 0;
    memcpy(g_blob, nb, n); g_bloblen = n;
    return 1;
}
