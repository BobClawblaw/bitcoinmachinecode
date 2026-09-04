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
#include "secure_zero.h"   /* WAL-3: a memset the optimiser may not delete */
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
/* WAL-3 (audit 2026-09-03): once encryptwallet has sealed the mnemonic and
 * verified the container, the daemon's plaintext copy is no longer the source
 * of truth -- wenc_unlock re-derives everything from the container -- and it
 * must not outlive the sealing. It used to sit in main.c statics for the life
 * of the process, so a node the operator believed locked still served the
 * mnemonic and its BIP39 passphrase through the provider, and both were
 * readable from /proc/<pid>/mem. Injected the same way the provider is, so
 * this module keeps no knowledge of where the daemon holds them. */
static void (*g_mn_forget)(void);
void wenc_set_mnemonic_forget(void (*fn)(void)){ g_mn_forget = fn; }

/* WAL-3 (rest): g_seed holds the unlocked wallet's seed for as long as the
 * wallet is unlocked, so it gets the same treatment as the daemon's own
 * copies -- out of swap, out of core files. Called once from main.c, which
 * reports the result; this module has no logging of its own to lose. */
int wenc_lock_secrets(void){
    return secure_lock(g_seed, sizeof g_seed);
}
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
    /* kept only until the container has been verified below, then wiped */
    static char payload_check[WENC_MNMAX*2];
    memcpy(payload_check, payload, (size_t)(pl < (long)sizeof payload_check ? pl : (long)sizeof payload_check));
    secure_zero(payload, sizeof payload);
    if (n < 0) return 0;
    char p[600]; wenc_path(p, sizeof p);
    char tmp[640]; snprintf(tmp, sizeof tmp, "%s.tmp", p);
    int fd = open(tmp, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    if (fd < 0) return 0;
    if (write(fd, seal, n) != n || fsync(fd) != 0){ close(fd); return 0; }
    close(fd);
    if (rename(tmp, p) != 0) return 0;

    /* VERIFY BEFORE DESTROYING (audit follow-up 2026-08-29).
     *
     * The plaintext store used to be unlinked the moment the container was
     * renamed into place, on the strength of the write having returned
     * success. That is the wrong order: everything after the rename -- a
     * corrupt seal, an unreadable file, a passphrase that does not actually
     * open what we just wrote -- would leave the operator with no wallet at
     * all, because the only readable copy had already been removed.
     *
     * So the container is re-opened from disk and unsealed with the same
     * passphrase, and the recovered payload compared against what went in.
     * Only if that round-trips is the plaintext store removed. If it does
     * not, the container is discarded and the plaintext store is left exactly
     * where it was: the caller sees a failure and still has a wallet. */
    { static u8 back[8192]; static char got[WENC_MNMAX*2];
      int ok = 0;
      int vfd = open(p, O_RDONLY);
      if (vfd >= 0){
          long bn = (long)read(vfd, back, sizeof back);
          close(vfd);
          if (bn == n && !memcmp(back, seal, (size_t)n)){
              long gl = wcrypt_open(wallet_pass, wplen, back, bn, (u8*)got, sizeof got);
              if (gl == pl && !memcmp(got, payload_check, (size_t)pl)) ok = 1;
          }
      }
      secure_zero(got, sizeof got);
      secure_zero(back, sizeof back);
      if (!ok){
          unlink(p);                       /* discard the unverified container */
          secure_zero(payload_check, sizeof payload_check);
          return 0;                        /* plaintext store deliberately kept */
      } }

    /* verified -- now the plaintext store can go (both candidate locations) */
    { char d1[600]; snprintf(d1, sizeof d1, "%s/bmcwallet.dat", g_enc_dir[0]?g_enc_dir:"."); unlink(d1);
      unlink("bmcwallet.dat"); }
    secure_zero(payload_check, sizeof payload_check);
    memcpy(g_blob, seal, n); g_bloblen = n;
    g_encrypted = 1; g_unlocked = 0;
    secure_zero(g_seed, sizeof g_seed);
    /* WAL-3: `seal` is ciphertext and may stay, but everything upstream of it
     * must go. The plaintext store is unlinked above; the daemon's in-memory
     * copy of the mnemonic goes here, at the one point where the container is
     * proven to open. */
    if (g_mn_forget) g_mn_forget();
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
    /* ---- WAL-16 (audit 2026-09-03): prove the plaintext before installing it
     *
     * The container's integrity field is a plain SHA-256 over the file, which
     * anyone with write access can recompute, and wrong-passphrase detection
     * is the PKCS#7 pad of the 48-byte wrapped master key. The SEED ciphertext
     * itself is only pad-checked, so flipped bits there decrypt to garbage
     * that passes (probability ~1/256 per try, or always when the last block
     * is untouched), wenc_unlock derived a seed from that garbage, and the
     * wallet then generated addresses nobody holds the keys for -- silent
     * fund loss, reported as a successful unlock.
     *
     * The stored plaintext is a BIP39 mnemonic, which carries its own
     * checksum, so validating it is a cheap MAC over the part that matters.
     * This cannot lock anyone out of a genuine wallet: bip39_parse verifies
     * the checksum on every path that can put a mnemonic into the store, so a
     * mnemonic that got in validates coming out.
     *
     * Core's analogue is DecryptKey checking that the decrypted key
     * reproduces the stored pubkey. A real HMAC over the container, keyed
     * from the master key, would be better still and needs a format change. */
    { extern int bip39_validate(const char* mnemonic);
      if (bip39_validate(mn) <= 0){
          fprintf(stderr,
              "[wallet]  UNLOCK REFUSED: the passphrase was accepted but the decrypted\n"
              "[wallet]           mnemonic fails its own BIP39 checksum, so " WENC_FILE " has\n"
              "[wallet]           been altered or corrupted. Deriving from it would produce\n"
              "[wallet]           addresses whose keys nobody holds. Restore from a backup.\n");
          secure_zero(payload, sizeof payload);
          return 0;
      } }
    wallet_mnemonic_seed(g_seed, mn, mp[0] ? mp : 0, mp[0] ? (long)strlen(mp) : 0);
    secure_zero(payload, sizeof payload);
    g_unlocked = 1;
    g_unlock_until = seconds > 0 ? (long)time(NULL) + seconds : 0;
    if (g_set_live_seed) g_set_live_seed(g_seed);
    return 1;
}

void wenc_lock(void){
    secure_zero(g_seed, sizeof g_seed);
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
