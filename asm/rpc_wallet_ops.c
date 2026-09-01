/* rpc_wallet_ops.c -- Core's Wallet RPC category beyond the query subset.
 *
 * rpc_commands.c owns the wallet methods that read derived keys, the UTXO
 * list and the send journal (getnewaddress, listunspent, getbalance,
 * listtransactions, gettransaction, getwalletinfo, getbalances, the PSBT
 * family). This module adds the rest of Core's Wallet category: labels,
 * wallet inventory, output locks, message signing, descriptor reporting, the
 * encryption-state methods, and the lifecycle methods this node cannot honour.
 *
 * It follows the same rule the network methods do. Every method here is
 * either
 *   (a) backed by real wallet state, or
 *   (b) an EXACT reproduction of the answer Core gives in this node's
 *       situation (an unencrypted wallet, no rescan in flight), or
 *   (c) an explicit -1 refusal naming what is missing.
 * None of them returns a plausible-looking value it did not compute. A
 * `backupwallet` that reports success without writing a file, or a `setban`
 * that reports success without banning, leaves the caller worse off than an
 * error would -- they now believe something false.
 *
 * The shapes were taken off a running Core oracle (v31.99, 2026-08-25), not
 * from memory: getaddressesbylabel's {address:{purpose}} map and its -11,
 * signmessage's -5/-3/-4 ladder, walletlock/walletpassphrase's -15 text,
 * listwalletdir's {wallets:[{name,warnings}]}, and abortrescan's bare false.
 */

#include "daemon/wallet_pass.h"   /* wallet passphrase source (audit finding 2) */
#include "rpc_wallet_ops.h"
#include "rpc_chain.h"
/* rpc_node_mempool_rawtx (bumpfee reads the original out of the pool).
 * Included for the PROTOTYPE, not convenience: without it the call was
 * implicit, so the compiler assumed int for a long-returning function
 * and the declaration in rpc_node.h was dead -- a signature change on
 * either side would not have been caught. */
#include "rpc_node.h"
#include "daemon/chainparams.h"   /* extended-key version bytes per chain */
#include "wallet_scan.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- wallet_core / wallet_labels / descriptor externs -------------------- */
extern int  wallet_validate_address(const char* str, int* type_, unsigned char* version,
                                    unsigned char h160[20], unsigned char prog32[32]);
extern int  msg_sign_core(const unsigned char priv_be[32], const char* message, char sig_b64[96]);
extern int  bip32_derive_path(unsigned char k[32], unsigned char c[32],
                              const unsigned char* seed, long seedlen,
                              const unsigned* indexes, long n);
extern int  bip32_extkey_serialize(unsigned char ser[78], int is_priv, unsigned char depth,
                                   const unsigned char parent_fp[4], unsigned child,
                                   const unsigned char c[32], const unsigned char* key, long keylen);
extern void base58check_encode(char* out, const unsigned char* payload, long long paylen);
extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char priv_be[32]);
extern void hash160(unsigned char out[20], const void* in, long long len);

extern int lbl_validate(const char* label);
extern int lbl_get(const char* path, const char* addr, char* out, int cap);
extern int lbl_set(const char* path, const char* addr, const char* label);
extern int lbl_count(const char* path);
extern int lbl_get_i(const char* path, int i, char* addr, int addrcap, char* label, int labelcap);

/* wallet_validate_address's type enum, mirrored from wallet_core.c. */
enum { WOP_ADDR_INVALID = 0, WOP_ADDR_P2PKH, WOP_ADDR_P2WPKH,
       WOP_ADDR_P2SH, WOP_ADDR_P2WSH, WOP_ADDR_P2TR, WOP_ADDR_UNKNOWN };

/* ---- paths --------------------------------------------------------------
 * The daemon may run from the datadir or from its parent; every wallet
 * reader in this tree probes the same two candidates, so these do too
 * rather than inventing a third convention. */
#define WOP_LABELS_REL  "labels.dat"
#define WOP_WALLET_REL  "bmcwallet.dat"

#define WOP_WALLET_NAME "bmcwallet"   /* the default wallet's display name */

/* ==== multi-wallet state (single-ACTIVE-wallet model) ====================
 * Core can serve many loaded wallets at once, routed by /wallet/<name>
 * endpoints. This node's wallet machinery (seed slot, label store, scan
 * journal, caches) is single-instance, so exactly ONE wallet is active at a
 * time: createwallet/loadwallet switch to it, unloadwallet leaves none.
 * That divergence is stated in the loadwallet error when a second concurrent
 * load is attempted, not hidden.
 *
 * g_aw_state: 0 = boot default (the legacy store, loaded by the daemon at
 * startup when present); 1 = an explicitly loaded wallet (g_aw_name); 2 =
 * explicitly none (after unloadwallet). */
static char g_aw_name[64];
static int  g_aw_state;
static int  g_aw_watchonly;          /* active wallet has no keys, only
                                        imported descriptors */
static void (*g_aw_install_seed)(const unsigned char*);   /* daemon-registered */
void rpc_wops_set_seed_installer(void (*fn)(const unsigned char*)){ g_aw_install_seed = fn; }

const char* rpc_wops_active_wallet_name(void){
    if (g_aw_state == 2) return NULL;
    return g_aw_state == 1 ? g_aw_name : WOP_WALLET_NAME;
}
int rpc_wops_watchonly(void){ return g_aw_watchonly; }

/* Reject anything that could escape the wallets/ directory. Core's rule
 * (util/string.h + wallet.cpp): letters, digits and a safe punctuation set,
 * no path separators, no leading dot. */
static int wop_name_ok(const char* n){
    if (!n || !*n || strlen(n) >= sizeof g_aw_name) return 0;
    if (n[0] == '.') return 0;
    for (const char* p = n; *p; p++)
        if (!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||
              *p=='-'||*p=='_'||*p=='.')) return 0;
    return 1;
}

#define WOP_WATCH_REL  "bmcwallet.watch"     /* watch-only shell marker  */
#define WOP_DESCS_REL  "descriptors.dat"     /* imported descriptors     */
/* header of an exportwatchonlywallet file: what lets restorewallet tell an
 * exported watch-only wallet from a seed backup and install the right kind */
#define WOP_WATCH_EXPORT_MAGIC "BMCWATCHEXPORT v1"

/* forward decl: the ACTIVE wallet may scope wallet files into a subdir */
static const char* wop_wallet_prefix(void);
/* Core -walletdir (set by main.c via rpc_wops_set_walletdir; empty = legacy layout) */
static char g_walletdir[256];

static const char* wop_path(const char* rel, char* buf, size_t cap){
    const char* wp = wop_wallet_prefix();
    if (g_walletdir[0]){ snprintf(buf, cap, "%s/%s%s", g_walletdir, wp, rel); return buf; }
    snprintf(buf, cap, "data/%s%s", wp, rel);
    struct stat sb;
    if (stat(buf, &sb) == 0) return buf;
    snprintf(buf, cap, "%s%s", wp, rel);
    if (stat(buf, &sb) == 0) return buf;
    /* Neither exists yet. Writers need a path anyway: prefer data/ when that
     * directory is present, else the cwd -- the same choice the CLI makes. */
    if (stat("data", &sb) == 0 && S_ISDIR(sb.st_mode)) snprintf(buf, cap, "data/%s%s", wp, rel);
    else snprintf(buf, cap, "%s%s", wp, rel);
    return buf;
}
/* Extended-key version bytes for the ACTIVE chain, stamped over what
 * bip32_extkey_serialize emits. That routine hardcodes mainnet's pair in
 * assembly, so every xpub this node produced was a mainnet xpub -- which
 * Core's descriptor parser rejects outright on regtest or testnet4 ("key
 * ... is not valid"). Patching the four bytes here keeps the asm untouched
 * and puts the chain rule where the other chain rules already live. */
/* WEAK: several test targets link this object without chainparams.o, the
 * same reason tx_wtxid is weak in rpc_node.c. A build without it falls back
 * to mainnet's pair below, which is what those targets mean anyway. */
extern const chainparams_t* g_chainp __attribute__((weak));

static void wop_stamp_extkey_version(unsigned char ser[78], int want_priv){
    unsigned int v = 0;
    if (&g_chainp && g_chainp)
        v = want_priv ? g_chainp->xprv_version : g_chainp->xpub_version;
    if (!v) v = want_priv ? 0x0488ADE4u : 0x0488B21Eu;   /* mainnet default */
    ser[0] = (unsigned char)(v >> 24); ser[1] = (unsigned char)(v >> 16);
    ser[2] = (unsigned char)(v >> 8);  ser[3] = (unsigned char)v;
}

/* ==== added HD keys (addhdkey) ===========================================
 * Core's addhdkey adds a BIP32 extended PRIVATE key to the wallet, to be
 * used later by createwalletdescriptor. Getting this right needed three
 * things, and skipping any of them makes the feature a hazard rather than a
 * gap:
 *
 *  1. THE KEY MUST BE PROTECTED AS THE SEED IS. An xprv in plaintext beside
 *     a passphrase-encrypted mnemonic would silently become the weakest
 *     thing in the wallet directory. It goes through wallet_secret_write,
 *     which reuses the mnemonic's own KDF, cipher and tag.
 *
 *  2. RECORDS MUST SAY WHICH KEY THEY BELONG TO. The scan identified a key
 *     by (keyidx, branch) alone. Two HD keys collide on that immediately --
 *     both have an index 0 receive key -- so an output paying key B would
 *     resolve to key A's address, and the wallet would build a spend against
 *     the wrong scriptPubKey. That is why the record format gained an hdkey
 *     byte (BMCWSCN4) rather than this being a pure RPC addition.
 *
 *  3. THE SIGNER MUST HOLD THEM. signrawtransactionwithwallet offers every
 *     window key and lets the matcher pick; an added key whose private half
 *     never reached that list would produce coins the wallet reports as
 *     spendable and then cannot sign.
 *
 * PATH CONVENTION: an added key is treated as an ACCOUNT node, and addresses
 * come from <i>/<branch> beneath it -- the same tail this wallet derives
 * under m/84'/0'/0', so one convention covers both. */
#define WOP_HDKEYS_REL  "walletkeys.dat"
#define WOP_HDK_MAGIC   "BMCHDK v1"
#define WOP_MAX_HDKEYS  8            /* hdkey 0 is the seed; 1..7 added */

extern int  wallet_secret_write(const char* path, const char* magic,
                                const char* plaintext, const char* pass);
extern int  wallet_secret_read(const char* path, const char* magic,
                               char* out, int cap, const char* pass);
extern int  wallet_base58check_decode(unsigned char* out, long cap, long* outlen,
                                      const char* str);
extern int  bip32_ckd_priv(unsigned char k[32], unsigned char c[32],
                           const unsigned char kpar[32], const unsigned char cpar[32],
                           unsigned index);

static char g_hdk[WOP_MAX_HDKEYS][128];   /* xprv strings; [0] unused (the seed) */
static int  g_hdk_n = -1;                 /* count of ADDED keys, -1 = not loaded */

/* The wallet passphrase. One lookup, shared with the boot path, so the two
 * cannot disagree about which secret protects this wallet --
 * daemon/wallet_pass.c. <store>.pass is deliberately NOT consulted here any
 * more (audit 2026-08-29 finding 2). */
static int wop_wallet_pass(char* out, size_t cap){
    return wallet_pass_load(out, (int)cap, 0);
}

static int wop_hdkeys_load(void){
    if (g_hdk_n >= 0) return g_hdk_n;
    g_hdk_n = 0;
    char pass[256];
    if (!wop_wallet_pass(pass, sizeof pass)) return 0;
    char pb[512]; struct stat sb;
    const char* path = wop_path(WOP_HDKEYS_REL, pb, sizeof pb);
    if (stat(path, &sb) != 0){ memset(pass, 0, sizeof pass); return 0; }
    static char blob[WOP_MAX_HDKEYS * 128 + 64];
    int rc = wallet_secret_read(path, WOP_HDK_MAGIC, blob, (int)sizeof blob, pass);
    memset(pass, 0, sizeof pass);
    if (rc != 0) return 0;                 /* wrong passphrase or tampered */
    char* save = NULL;
    for (char* t = strtok_r(blob, "\n", &save); t && g_hdk_n < WOP_MAX_HDKEYS - 1;
         t = strtok_r(NULL, "\n", &save))
        if (t[0]) snprintf(g_hdk[++g_hdk_n], sizeof g_hdk[0], "%s", t);
    memset(blob, 0, sizeof blob);
    return g_hdk_n;
}

static int wop_hdkeys_save(void){
    char pass[256];
    if (!wop_wallet_pass(pass, sizeof pass)) return 0;
    static char blob[WOP_MAX_HDKEYS * 128 + 64];
    blob[0] = 0;
    for (int i = 1; i <= g_hdk_n; i++){
        strncat(blob, g_hdk[i], sizeof blob - strlen(blob) - 2);
        strncat(blob, "\n", sizeof blob - strlen(blob) - 1);
    }
    char pb[512];
    int rc = wallet_secret_write(wop_path(WOP_HDKEYS_REL, pb, sizeof pb),
                                 WOP_HDK_MAGIC, blob, pass);
    memset(pass, 0, sizeof pass);
    memset(blob, 0, sizeof blob);
    return rc == 0;
}

/* xprv -> (key, chaincode). Returns 1 on a well-formed mainnet xprv. */
static int wop_hdk_parse(const char* xprv, unsigned char k[32], unsigned char c[32]){
    unsigned char dec[128]; long dl = 0;
    if (!wallet_base58check_decode(dec, (long)sizeof dec, &dl, xprv)) return 0;
    if (dl != 78) return 0;
    /* A PRIVATE extended key, on either version pair -- mainnet xprv
     * (0488ADE4) or the test-chain tprv (04358394). A key that is not
     * private cannot sign, and accepting one would create exactly the
     * unspendable-but-reported-spendable coins this design is avoiding. */
    { unsigned int v = ((unsigned)dec[0]<<24)|((unsigned)dec[1]<<16)|
                       ((unsigned)dec[2]<<8)|dec[3];
      if (v != 0x0488ADE4u && v != 0x04358394u) return 0; }
    if (dec[45] != 0x00) return 0;               /* private keys are 0x00-prefixed */
    memcpy(c, dec + 13, 32);
    memcpy(k, dec + 46, 32);
    return 1;
}

/* the xpub string for an added key, as gethdkeys reports it */
static int wop_hdk_xpub(const char* xprv, char out[128]){
    unsigned char dec[128]; long dl = 0;
    if (!wallet_base58check_decode(dec, (long)sizeof dec, &dl, xprv) || dl != 78) return 0;
    unsigned char pub[33];
    scalar_to_pubkey(pub, dec + 46);
    unsigned char ser[78];
    /* is_priv = 0: the PUBLIC form. gethdkeys reports xpubs, never xprvs --
     * this node does not serve private key material over RPC. */
    bip32_extkey_serialize(ser, 0, dec[4], dec + 5,
                           (unsigned)((dec[9]<<24)|(dec[10]<<16)|(dec[11]<<8)|dec[12]),
                           dec + 13, pub, 33);
    wop_stamp_extkey_version(ser, 0);
    base58check_encode(out, ser, 78);
    return out[0] != 0;
}

/* the private key at <idx>/<branch> under added key `hdk` (1-based) */
static int wop_hdk_derive(int hdk, unsigned idx, int branch, unsigned char out[32]){
    if (hdk < 1 || hdk > g_hdk_n) return 0;
    unsigned char k[32], c[32], k1[32], c1[32], c2[32];
    if (!wop_hdk_parse(g_hdk[hdk], k, c)) return 0;
    if (bip32_ckd_priv(k1, c1, k, c, idx) != 1) return 0;
    /* c2, not c1, for the second step's OUTPUT chaincode: passing the same
     * buffer as both output and parent aliases them, and whether that
     * survives depends on the order the callee happens to write in. It
     * silently produced the wrong key here -- the added key's addresses did
     * not match what Core derived from the same xpub. */
    if (bip32_ckd_priv(out, c2, k1, c1, (unsigned)branch) != 1) return 0;
    return 1;
}

int rpc_wops_hdkey_count(void){ return wop_hdkeys_load(); }

/* Every private key an ADDED hd key contributes over the signing window.
 * signrawtransactionwithwallet appends these to the seed's, because a key
 * the wallet watches but cannot sign for is worse than one it never had. */
int rpc_wops_hdkey_privkeys(unsigned char (*out)[32], int cap, unsigned window){
    int n = wop_hdkeys_load(), m = 0;
    for (int h = 1; h <= n; h++)
        for (unsigned i = 0; i < window && m < cap; i++)
            for (int b = 0; b <= 1 && m < cap; b++)
                if (wop_hdk_derive(h, i, b, out[m])) m++;
    return m;
}

/* ==== wallet flags =======================================================
 * Core has exactly one MUTABLE wallet flag, avoid_reuse, and setwalletflag
 * exists to toggle it. A flag that is stored and then ignored would be worse
 * than refusing the call: the caller would be told the wallet now avoids
 * reusing addresses when it does not. So this is wired all the way through
 * -- persisted here, honoured by coin selection in wf_coins, and reported by
 * getwalletinfo and listunspent. */
#define WOP_FLAGS_REL "walletflags.dat"
static int g_wop_avoid_reuse = -1;        /* -1 = not loaded */

static int wop_avoid_reuse_load(void){
    if (g_wop_avoid_reuse >= 0) return g_wop_avoid_reuse;
    g_wop_avoid_reuse = 0;
    char pb[512]; FILE* f = fopen(wop_path(WOP_FLAGS_REL, pb, sizeof pb), "r");
    if (!f) return 0;
    char line[128];
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "avoid_reuse=", 12)) g_wop_avoid_reuse = (line[12] == '1');
    fclose(f);
    return g_wop_avoid_reuse;
}
int rpc_wops_avoid_reuse(void){ return wop_avoid_reuse_load(); }

static int wop_avoid_reuse_save(int on){
    char pb[512]; FILE* f = fopen(wop_path(WOP_FLAGS_REL, pb, sizeof pb), "w");
    if (!f) return 0;
    fprintf(f, "avoid_reuse=%d\n", on ? 1 : 0);
    if (fflush(f) != 0 || fsync(fileno(f)) != 0){ fclose(f); return 0; }
    fclose(f);
    g_wop_avoid_reuse = on ? 1 : 0;
    return 1;
}

/* Core IsSpentKey: a destination counts as USED once any output paying it
 * has been spent. Reusing such an address links the new payment to the old
 * one on chain, which is what avoid_reuse exists to prevent. */
static int wop_key_is_reused(const wscan_rec* recs, long n,
                             unsigned keyidx, unsigned char branch){
    for (long i = 0; i < n; i++){
        if (recs[i].kind != 0) continue;
        if (recs[i].keyidx != keyidx || recs[i].branch != branch) continue;
        for (long j = 0; j < n; j++)
            if (recs[j].kind == 1 && recs[j].vout == recs[i].vout &&
                !memcmp(recs[j].prev_txid, recs[i].txid, 32)) return 1;
    }
    return 0;
}

static int wop_exists(const char* rel){
    char b[512]; struct stat sb;
    const char* wp = wop_wallet_prefix();
    snprintf(b, sizeof b, "data/%s%s", wp, rel); if (stat(b, &sb) == 0) return 1;
    snprintf(b, sizeof b, "%s%s", wp, rel);      return stat(b, &sb) == 0;
}
/* "" for the default wallet; "wallets/<name>/" for a named one. A static
 * buffer is fine: single RPC thread, and the prefix changes only inside
 * load/create which run on that thread. */
/* Core -walletdir: the directory every wallet file lives under. Empty =
 * the legacy layout (the chain directory, or data/ beneath it). Set by
 * main.c from the config so this file carries no node_config dependency. */
void rpc_wops_set_walletdir(const char* d){ snprintf(g_walletdir, sizeof g_walletdir, "%s", d ? d : ""); }
const char* rpc_wops_walletdir(void){ return g_walletdir; }
static const char* wop_wallet_prefix(void){
    static char pfx[96];
    if (g_aw_state == 1 && g_aw_name[0]){
        snprintf(pfx, sizeof pfx, "wallets/%s/", g_aw_name);
        return pfx;
    }
    return "";
}

/* The DEFAULT wallet's name. Named wallets (multi-wallet, 2026-08-27) live
 * under wallets/<name>/ beneath the same data root; the default wallet stays
 * at the legacy root path so production is untouched. */


/* ---- small helpers ------------------------------------------------------ */
static int wop_err(long* ec, const char** em, long code, const char* msg){
    *ec = code; *em = msg; return 0;
}
static const char* wop_str_arg(const rj_val* p, size_t i){
    if (!p || p->typ != RJ_ARR || p->nitems <= i) return NULL;
    return p->items[i]->typ == RJ_STR ? p->items[i]->str : NULL;
}

/* Core renders amounts through ValueFromAmount; rpc_commands.c owns the
 * exact formatter and exports it. */
extern void rpc_amounts(long long sats, char* out, size_t outcap);

/* ==== labels =============================================================
 * Core's model: every wallet address has exactly one label (default ""),
 * and one label may name many addresses. wallet_labels.c stores that
 * inversion; see its header for why the pre-existing wallet_book.c could
 * not be reused. */

static int cmd_setlabel(const rj_val* params, long* ec, const char** em, rj_val** res){
    const char* addr = wop_str_arg(params, 0);
    const char* label = wop_str_arg(params, 1);
    if (!addr)  return wop_err(ec, em, -8, "Invalid or missing address");
    if (!label) return wop_err(ec, em, -8, "Invalid or missing label");
    int t; unsigned char v, h[20], p32[32];
    if (!wallet_validate_address(addr, &t, &v, h, p32) ||
        t < WOP_ADDR_P2PKH || t > WOP_ADDR_P2TR)
        return wop_err(ec, em, -5, "Invalid Bitcoin address");
    if (!lbl_validate(label))
        return wop_err(ec, em, -8, "Label must be at most 255 bytes and contain no newline");
    char pb[512];
    if (lbl_set(wop_path(WOP_LABELS_REL, pb, sizeof pb), addr, label) != 0)
        return wop_err(ec, em, -4, "Could not write the label store");
    *res = rj_null();
    return 1;
}

static int cmd_listlabels(const rj_val* params, rj_val** res){
    (void)params;   /* Core's "purpose" filter: every label here is receive */
    char pb[512]; const char* path = wop_path(WOP_LABELS_REL, pb, sizeof pb);
    int n = lbl_count(path);
    /* unique + sorted, as Core returns them (it walks a std::set) */
    char (*seen)[256] = NULL; int ns = 0;
    if (n > 0) seen = malloc((size_t)n * sizeof *seen);
    for (int i = 0; i < n && seen; i++){
        char a[128], l[256];
        if (!lbl_get_i(path, i, a, sizeof a, l, sizeof l)) continue;
        int dup = 0;
        for (int j = 0; j < ns; j++) if (!strcmp(seen[j], l)){ dup = 1; break; }
        if (!dup) snprintf(seen[ns++], 256, "%s", l);
    }
    for (int i = 1; i < ns; i++){          /* insertion sort; ns is tiny */
        char key[256]; snprintf(key, sizeof key, "%s", seen[i]);
        int j = i - 1;
        while (j >= 0 && strcmp(seen[j], key) > 0){ memcpy(seen[j+1], seen[j], 256); j--; }
        snprintf(seen[j+1], 256, "%s", key);
    }
    rj_val* arr = rj_arr();
    for (int i = 0; i < ns; i++) rj_arr_push(arr, rj_str(seen[i]));
    free(seen);
    *res = arr;
    return 1;
}

static int cmd_getaddressesbylabel(const rj_val* params, long* ec, const char** em, rj_val** res){
    const char* want = wop_str_arg(params, 0);
    if (!want) return wop_err(ec, em, -8, "Invalid or missing label");
    char pb[512]; const char* path = wop_path(WOP_LABELS_REL, pb, sizeof pb);
    int n = lbl_count(path), hits = 0;
    rj_val* o = rj_obj();
    for (int i = 0; i < n; i++){
        char a[128], l[256];
        if (!lbl_get_i(path, i, a, sizeof a, l, sizeof l)) continue;
        if (strcmp(l, want)) continue;
        rj_val* e = rj_obj();
        /* purpose: this wallet has no send/receive purpose distinction --
         * every labelled address is one it can receive to. */
        rj_obj_set(e, "purpose", rj_str("receive"));
        rj_obj_set(o, a, e);
        hits++;
    }
    if (!hits){
        rj_free(o);
        /* Core: RPC_WALLET_INVALID_LABEL_NAME, "No addresses with label <x>" */
        static char msg[320];
        snprintf(msg, sizeof msg, "No addresses with label %s", want);
        return wop_err(ec, em, -11, msg);
    }
    *res = o;
    return 1;
}

/* ==== wallet inventory =================================================== */

static int cmd_listwallets(rj_val** res){
    rj_val* arr = rj_arr();
    /* Core lists LOADED wallets. Exactly one can be active here (see the
     * multi-wallet state note above); after unloadwallet the list is empty. */
    const char* n = rpc_wops_active_wallet_name();
    if (n && (g_aw_state == 1 || wop_exists(WOP_WALLET_REL)))
        rj_arr_push(arr, rj_str(n));
    *res = arr;
    return 1;
}

static int cmd_listwalletdir(rj_val** res){
    rj_val* arr = rj_arr();
    /* the default wallet at the legacy root path... */
    { char b[512]; struct stat sb;
      if (g_walletdir[0]) snprintf(b, sizeof b, "%s/%s", g_walletdir, WOP_WALLET_REL);
      else snprintf(b, sizeof b, "data/%s", WOP_WALLET_REL);
      int have = stat(b, &sb) == 0;
      if (!have && !g_walletdir[0]){ snprintf(b, sizeof b, "%s", WOP_WALLET_REL); have = stat(b, &sb) == 0; }
      if (have){
          rj_val* e = rj_obj();
          rj_obj_set(e, "name", rj_str(WOP_WALLET_NAME));
          rj_obj_set(e, "warnings", rj_arr());
          rj_arr_push(arr, e);
      } }
    /* ...plus every named wallet under wallets/ (key store or watch shell) */
    { char wdr[600]; snprintf(wdr, sizeof wdr, "%s/wallets", g_walletdir[0] ? g_walletdir : "data");
      const char* roots[2] = { g_walletdir[0] ? wdr : "data/wallets", g_walletdir[0] ? wdr : "wallets" };
      for (int r = 0; r < (g_walletdir[0] ? 1 : 2); r++){
          DIR* d = opendir(roots[r]); if (!d) continue;
          struct dirent* de;
          while ((de = readdir(d))){
              if (de->d_name[0] == '.') continue;
              char b[600]; struct stat sb;
              snprintf(b, sizeof b, "%s/%s/%s", roots[r], de->d_name, WOP_WALLET_REL);
              int have = stat(b, &sb) == 0;
              if (!have){ snprintf(b, sizeof b, "%s/%s/%s", roots[r], de->d_name, WOP_WATCH_REL);
                          have = stat(b, &sb) == 0; }
              if (!have) continue;
              /* don't double-report a wallet visible under both roots */
              int dup = 0;
              for (unsigned long i = 0; i < arr->nitems; i++){
                  rj_val* nm = rj_obj_get(arr->items[i], "name");
                  if (nm && nm->str && !strcmp(nm->str, de->d_name)){ dup = 1; break; }
              }
              if (dup) continue;
              rj_val* e = rj_obj();
              rj_obj_set(e, "name", rj_str(de->d_name));
              rj_obj_set(e, "warnings", rj_arr());
              rj_arr_push(arr, e);
          }
          closedir(d);
      } }
    rj_val* o = rj_obj();
    rj_obj_set(o, "wallets", arr);
    *res = o;
    return 1;
}

/* ==== wallet lifecycle (createwallet / loadwallet / unloadwallet /
 *      restorewallet), 2026-08-27 ========================================= */
extern int  wallet_store_create(const char* path, const char* mnemonic, const char* pass);
extern int  wallet_store_load(const char* path, char* mnemonic_out, int cap,
                              char* pass_out, int pcap);
extern int  wallet_mnemonic_seed(unsigned char seed[64], const char* mn,
                                 const char* pass, long passlen);
extern int  wallet_mnemonic_generate(char out[256]);   /* wallet_core.c, 1 = ok */
static void wop_watch_keys_invalidate(void);
static void wop_records_invalidate(void);
static void wop_keyset_invalidate(void);

/* Make wallets/<name>/ under whichever root wop_path would write to. */
static int wop_wallet_mkdir(const char* name, char* dir, size_t cap){
    struct stat sb;
    const char* root = g_walletdir[0] ? g_walletdir
                     : (stat("data", &sb) == 0 && S_ISDIR(sb.st_mode)) ? "data" : ".";
    char b[600];
    snprintf(b, sizeof b, "%s/wallets", root);       mkdir(b, 0700);
    snprintf(b, sizeof b, "%s/wallets/%s", root, name); mkdir(b, 0700);
    if (stat(b, &sb) != 0 || !S_ISDIR(sb.st_mode)) return 0;
    snprintf(dir, cap, "%s", b);
    return 1;
}
static int wop_named_store_path(const char* name, const char* rel, char* buf, size_t cap){
    char b[600]; struct stat sb;
    if (g_walletdir[0]){
        snprintf(b, sizeof b, "%s/wallets/%s/%s", g_walletdir, name, rel);
        if (stat(b, &sb) == 0){ snprintf(buf, cap, "%s", b); return 1; }
        return 0;
    }
    snprintf(b, sizeof b, "data/wallets/%s/%s", name, rel);
    if (stat(b, &sb) == 0){ snprintf(buf, cap, "%s", b); return 1; }
    snprintf(b, sizeof b, "wallets/%s/%s", name, rel);
    if (stat(b, &sb) == 0){ snprintf(buf, cap, "%s", b); return 1; }
    return 0;
}

/* Switch the active wallet, deriving + installing the seed (or clearing it
 * for a watch-only shell). Resets every per-wallet cache. Returns 1, or 0
 * with ec/em set. */
static int wop_activate(const char* name, long* ec, const char** em){
    static char perr[256];
    int is_default = (!name || !*name || !strcmp(name, WOP_WALLET_NAME));
    char store[640]; int watch = 0;
    if (is_default){
        char b[512]; struct stat sb;
        snprintf(b, sizeof b, "data/%s", WOP_WALLET_REL);
        if (stat(b, &sb) != 0){ snprintf(b, sizeof b, "%s", WOP_WALLET_REL);
                                 if (stat(b, &sb) != 0){
            *ec = -18; *em = "Requested wallet does not exist or is not loaded"; return 0; } }
        snprintf(store, sizeof store, "%s", b);
    } else {
        if (!wop_name_ok(name)) { *ec = -8; *em = "Invalid wallet name"; return 0; }
        if (wop_named_store_path(name, WOP_WALLET_REL, store, sizeof store)) watch = 0;
        else if (wop_named_store_path(name, WOP_WATCH_REL, store, sizeof store)) watch = 1;
        else { *ec = -18; *em = "Requested wallet does not exist or is not loaded"; return 0; }
    }
    if (!g_aw_install_seed){
        *ec = -4; *em = "wallet switching is unavailable: no seed installer registered "
                        "(the standalone RPC daemon serves the boot wallet only)"; return 0; }
    if (!watch){
        static char mn[768], pass[256];
        pass[0] = 0;
        /* audit finding 2 -- see daemon/wallet_pass.c */
        wallet_pass_load(pass, (int)sizeof pass, 0);
        if (wallet_store_load(store, mn, (int)sizeof mn, pass, (int)sizeof pass) != 0){
            memset(mn, 0, sizeof mn); memset(pass, 0, sizeof pass);
            snprintf(perr, sizeof perr, "Wallet file verification failed. Failed to load "
                     "wallet store %s (encrypted? set BMC_WALLET_PASS or walletpassfile=)", store);
            *ec = -18; *em = perr; return 0;
        }
        static unsigned char seed[64];
        wallet_mnemonic_seed(seed, mn, pass[0] ? pass : NULL, pass[0] ? (long)strlen(pass) : 0);
        memset(mn, 0, sizeof mn); memset(pass, 0, sizeof pass);
        g_aw_install_seed(seed);
        memset(seed, 0, sizeof seed);
        g_aw_watchonly = 0;
    } else {
        g_aw_install_seed(NULL);       /* no keys: watch-only */
        g_aw_watchonly = 1;
    }
    if (is_default){ g_aw_state = 0; g_aw_name[0] = 0; }
    else { g_aw_state = 1; snprintf(g_aw_name, sizeof g_aw_name, "%s", name); }
    wop_records_invalidate();
    wop_watch_keys_invalidate();
    return 1;
}

static int cmd_loadwallet(const rj_val* params, long* ec, const char** em, rj_val** res){
    const char* name = wop_str_arg(params, 0);
    if (!name) return wop_err(ec, em, -8, "loadwallet requires a wallet name");
    if (!wop_activate(name, ec, em)) return 0;
    rj_val* o = rj_obj();
    rj_obj_set(o, "name", rj_str(rpc_wops_active_wallet_name()));
    rj_val* w = rj_arr();
    rj_arr_push(w, rj_str("this node serves ONE active wallet at a time; loading "
                          "a wallet switches to it (Core would keep both loaded)"));
    rj_obj_set(o, "warnings", w);
    *res = o;
    return 1;
}

static int cmd_unloadwallet(const rj_val* params, long* ec, const char** em, rj_val** res){
    const char* cur = rpc_wops_active_wallet_name();
    if (!cur || (g_aw_state == 0 && !wop_exists(WOP_WALLET_REL)))
        return wop_err(ec, em, -18, "Requested wallet does not exist or is not loaded");
    const char* name = wop_str_arg(params, 0);
    if (name && *name && strcmp(name, cur))
        return wop_err(ec, em, -18, "Requested wallet does not exist or is not loaded");
    if (!g_aw_install_seed)
        return wop_err(ec, em, -4, "wallet switching is unavailable: no seed installer registered");
    g_aw_install_seed(NULL);
    g_aw_state = 2; g_aw_name[0] = 0; g_aw_watchonly = 0;
    wop_records_invalidate();
    wop_watch_keys_invalidate();
    rj_val* o = rj_obj();
    rj_obj_set(o, "warnings", rj_arr());
    *res = o;
    return 1;
}

static int cmd_createwallet(const rj_val* params, long* ec, const char** em, rj_val** res){
    static char perr[192];
    const char* name = wop_str_arg(params, 0);
    if (!name || !*name) return wop_err(ec, em, -8, "createwallet requires a wallet name");
    if (!wop_name_ok(name) || !strcmp(name, WOP_WALLET_NAME))
        return wop_err(ec, em, -8, "Invalid wallet name");
    if (!g_aw_install_seed)
        return wop_err(ec, em, -4, "wallet switching is unavailable: no seed installer "
                       "registered (the standalone RPC daemon serves the boot wallet only)");
    int disable_priv = 0, blank = 0;
    if (params->nitems >= 2 && params->items[1]->typ == RJ_BOOL && !strcmp(params->items[1]->str,"1")) disable_priv = 1;
    if (params->nitems >= 3 && params->items[2]->typ == RJ_BOOL && !strcmp(params->items[2]->str,"1")) blank = 1;
    if (params->nitems >= 4 && params->items[3]->typ == RJ_STR && params->items[3]->str[0])
        return wop_err(ec, em, -4,
            "wallet creation with a passphrase is not supported for named wallets on "
            "this node; at-rest encryption serves the default wallet (encryptwallet)");
    char st[640];
    if (wop_named_store_path(name, WOP_WALLET_REL, st, sizeof st) ||
        wop_named_store_path(name, WOP_WATCH_REL, st, sizeof st)){
        snprintf(perr, sizeof perr, "Wallet \"%s\" already exists.", name);
        return wop_err(ec, em, -4, perr);
    }
    char dir[640];
    if (!wop_wallet_mkdir(name, dir, sizeof dir))
        return wop_err(ec, em, -4, "could not create the wallet directory");
    if (disable_priv || blank){
        char b[720]; snprintf(b, sizeof b, "%s/%s", dir, WOP_WATCH_REL);
        FILE* f = fopen(b, "w");
        if (!f) return wop_err(ec, em, -4, "could not write the wallet");
        fputs("BMCWATCH v1\n", f); fclose(f);
    } else {
        char mn[256];
        if (!wallet_mnemonic_generate(mn))
            return wop_err(ec, em, -4, "mnemonic generation failed");
        char b[720]; snprintf(b, sizeof b, "%s/%s", dir, WOP_WALLET_REL);
        int rc = wallet_store_create(b, mn, "");
        memset(mn, 0, sizeof mn);
        if (rc != 0) return wop_err(ec, em, -4, "could not write the wallet store");
    }
    if (!wop_activate(name, ec, em)) return 0;   /* Core loads on create */
    rj_val* o = rj_obj();
    rj_obj_set(o, "name", rj_str(name));
    rj_val* w = rj_arr();
    if (disable_priv || blank)
        rj_arr_push(w, rj_str("watch-only wallet: import descriptors with "
                              "importdescriptors, then rescanblockchain"));
    rj_obj_set(o, "warnings", w);
    *res = o;
    return 1;
}

static int cmd_restorewallet(const rj_val* params, long* ec, const char** em, rj_val** res){
    static char perr[192];
    const char* name = wop_str_arg(params, 0);
    const char* backup = wop_str_arg(params, 1);
    if (!name || !backup)
        return wop_err(ec, em, -8, "restorewallet requires a wallet name and a backup path");
    if (!wop_name_ok(name) || !strcmp(name, WOP_WALLET_NAME))
        return wop_err(ec, em, -8, "Invalid wallet name");
    char st[640];
    if (wop_named_store_path(name, WOP_WALLET_REL, st, sizeof st) ||
        wop_named_store_path(name, WOP_WATCH_REL, st, sizeof st)){
        snprintf(perr, sizeof perr, "Wallet \"%s\" already exists.", name);
        return wop_err(ec, em, -36, perr);      /* Core: RPC_WALLET_ALREADY_EXISTS */
    }
    /* An exportwatchonlywallet file is also a valid backup -- Core says so
     * explicitly ("can be imported into another node using restorewallet"),
     * and it installs a WATCH-ONLY wallet rather than a seed one. Detected by
     * its header so the two kinds cannot be confused. */
    int watch_export = 0;
    { FILE* bf = fopen(backup, "r");
      if (bf){ char hdr[64]; hdr[0] = 0;
               if (fgets(hdr, sizeof hdr, bf) &&
                   !strncmp(hdr, WOP_WATCH_EXPORT_MAGIC, strlen(WOP_WATCH_EXPORT_MAGIC)))
                   watch_export = 1;
               fclose(bf); } }

    /* prove the backup loads BEFORE installing it */
    if (!watch_export)
    { char mn[768], ps[256]; ps[0] = 0;
      if (wallet_store_load(backup, mn, (int)sizeof mn, ps, (int)sizeof ps) != 0){
          memset(mn, 0, sizeof mn);
          return wop_err(ec, em, -18, "Backup file does not exist or is not a wallet store"); }
      memset(mn, 0, sizeof mn); memset(ps, 0, sizeof ps); }
    char dir[640];
    if (!wop_wallet_mkdir(name, dir, sizeof dir))
        return wop_err(ec, em, -4, "could not create the wallet directory");
    if (watch_export){
        /* the marker makes it a watch-only wallet; the descriptors are the
         * export's body, with the header line dropped */
        char mk[720]; snprintf(mk, sizeof mk, "%s/%s", dir, WOP_WATCH_REL);
        FILE* mf = fopen(mk, "w");
        if (!mf) return wop_err(ec, em, -4, "could not write the wallet");
        fputs("BMCWATCH v1\n", mf); fclose(mf);
        char dp[720]; snprintf(dp, sizeof dp, "%s/%s", dir, WOP_DESCS_REL);
        FILE* in = fopen(backup, "r"); FILE* outf = in ? fopen(dp, "w") : NULL;
        if (!in || !outf){ if (in) fclose(in); if (outf) fclose(outf);
            return wop_err(ec, em, -4, "could not copy the exported descriptors"); }
        char line[512]; int first = 1;
        while (fgets(line, sizeof line, in)){
            if (first){ first = 0; continue; }      /* drop the header */
            fputs(line, outf);
        }
        fclose(in); fclose(outf);
        wop_watch_keys_invalidate();
        if (!wop_activate(name, ec, em)) return 0;
        rj_val* o = rj_obj();
        rj_obj_set(o, "name", rj_str(name));
        rj_val* wn = rj_arr();
        rj_arr_push(wn, rj_str("watch-only wallet restored from an export: "
                               "run rescanblockchain to find its history"));
        rj_obj_set(o, "warnings", wn);
        *res = o;
        return 1;
    }

    char dst[720]; snprintf(dst, sizeof dst, "%s/%s", dir, WOP_WALLET_REL);
    FILE* in = fopen(backup, "rb"); FILE* outf = in ? fopen(dst, "wb") : NULL;
    if (!in || !outf){ if (in) fclose(in); return wop_err(ec, em, -4, "could not copy the backup"); }
    { char buf[4096]; size_t n;
      while ((n = fread(buf, 1, sizeof buf, in)) > 0)
          if (fwrite(buf, 1, n, outf) != n){ fclose(in); fclose(outf);
              return wop_err(ec, em, -4, "could not copy the backup"); } }
    fclose(in); fclose(outf);
    if (!wop_activate(name, ec, em)) return 0;
    rj_val* o = rj_obj();
    rj_obj_set(o, "name", rj_str(name));
    rj_obj_set(o, "warnings", rj_arr());
    *res = o;
    return 1;
}

#define WOP_MAX_DESCS 16
typedef struct { char desc[340]; long range; long next; int script; } wop_desc_t;
static wop_desc_t g_wd[WOP_MAX_DESCS];
static int  g_wd_n = -1;                  /* -1 = not loaded from file */
static wscan_key* g_wk;                   /* descriptor-derived key window */
static int  g_wk_n = -1;
static void wop_watch_keys_invalidate(void){ g_wd_n = -1; g_wk_n = -1; }

static int wop_descs_load(void){
    if (g_wd_n >= 0) return g_wd_n;
    g_wd_n = 0;
    char pb[512]; FILE* f = fopen(wop_path(WOP_DESCS_REL, pb, sizeof pb), "r");
    if (!f) return 0;
    char line[512];
    while (g_wd_n < WOP_MAX_DESCS && fgets(line, sizeof line, f)){
        char* t1 = strchr(line, '\t'); if (!t1) continue;
        *t1 = 0;
        long range = strtol(t1+1, NULL, 10);
        char* t2 = strchr(t1+1, '\t');
        long next = t2 ? strtol(t2+1, NULL, 10) : 0;
        wop_desc_t* d = &g_wd[g_wd_n];
        snprintf(d->desc, sizeof d->desc, "%s", line);
        d->range = range > 0 ? range : 1; d->next = next; d->script = 1;
        g_wd_n++;
    }
    fclose(f);
    return g_wd_n;
}
static int wop_descs_save(void){
    char pb[512]; FILE* f = fopen(wop_path(WOP_DESCS_REL, pb, sizeof pb), "w");
    if (!f) return 0;
    for (int i = 0; i < g_wd_n; i++)
        fprintf(f, "%s\t%ld\t%ld\n", g_wd[i].desc, g_wd[i].range, g_wd[i].next);
    fclose(f);
    return 1;
}

/* ==== output locks =======================================================
 * Core's lock set is IN MEMORY and explicitly documented as lost when the
 * node stops. A process-lifetime set is therefore exact parity, not a
 * simplification -- persisting it would be the divergence. */
#define WOP_MAX_LOCKS 256
typedef struct { unsigned char txid[32]; unsigned long vout; } wop_lock_t;
static wop_lock_t g_locks[WOP_MAX_LOCKS];
static int g_nlocks;

/* one hex nibble, or -1 */
static int wop_hex1(char c){
    if (c>='0'&&c<='9') return c-'0';
    if ((c|32)>='a'&&(c|32)<='f') return (c|32)-'a'+10;
    return -1;
}
static int wop_hex32_le(const char* h, unsigned char out[32]){
    if (!h || strlen(h) != 64) return 0;
    for (int i = 0; i < 32; i++){
        int hi = -1, lo = -1;
        char a = h[i*2], b = h[i*2+1];
        if (a>='0'&&a<='9') hi=a-'0'; else if (a>='a'&&a<='f') hi=a-'a'+10;
        else if (a>='A'&&a<='F') hi=a-'A'+10; else return 0;
        if (b>='0'&&b<='9') lo=b-'0'; else if (b>='a'&&b<='f') lo=b-'a'+10;
        else if (b>='A'&&b<='F') lo=b-'A'+10; else return 0;
        out[31-i] = (unsigned char)((hi<<4)|lo);   /* display -> internal */
    }
    return 1;
}
static void wop_txid_hex(const unsigned char txid[32], char out[65]){
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < 32; i++){
        unsigned char b = txid[31-i];              /* internal -> display */
        out[i*2] = H[b>>4]; out[i*2+1] = H[b&15];
    }
    out[64] = 0;
}

static int cmd_listlockunspent(rj_val** res){
    rj_val* arr = rj_arr();
    for (int i = 0; i < g_nlocks; i++){
        rj_val* e = rj_obj();
        char h[65]; wop_txid_hex(g_locks[i].txid, h);
        rj_obj_set(e, "txid", rj_str(h));
        rj_obj_set(e, "vout", rj_numf("%lu", g_locks[i].vout));
        rj_arr_push(arr, e);
    }
    *res = arr;
    return 1;
}

static int cmd_lockunspent(const rj_val* params, long* ec, const char** em, rj_val** res){
    if (!params || params->typ != RJ_ARR || params->nitems < 1 ||
        params->items[0]->typ != RJ_BOOL)
        return wop_err(ec, em, -8, "Invalid parameter, expected boolean unlock");
    int unlock = !strcmp(params->items[0]->str, "1");
    const rj_val* list = (params->nitems >= 2) ? params->items[1] : NULL;

    /* Core: `lockunspent true` with no list unlocks EVERYTHING. */
    if (unlock && (!list || list->typ != RJ_ARR)){ g_nlocks = 0; *res = rj_bool(1); return 1; }
    if (!list || list->typ != RJ_ARR)
        return wop_err(ec, em, -8, "Invalid parameter, expected an array of outputs");

    /* Validate the WHOLE list before mutating: Core applies all-or-nothing,
     * and a half-applied lock set would be a silent, invisible wrong state. */
    unsigned char txids[WOP_MAX_LOCKS][32]; unsigned long vouts[WOP_MAX_LOCKS];
    if ((int)list->nitems > WOP_MAX_LOCKS)
        return wop_err(ec, em, -8, "Too many outputs for this node's lock set");
    for (size_t i = 0; i < list->nitems; i++){
        const rj_val* e = list->items[i];
        if (e->typ != RJ_OBJ) return wop_err(ec, em, -8, "Invalid parameter, expected object");
        rj_val* t = rj_obj_get((rj_val*)e, "txid");
        rj_val* v = rj_obj_get((rj_val*)e, "vout");
        if (!t || t->typ != RJ_STR || !wop_hex32_le(t->str, txids[i]))
            return wop_err(ec, em, -8, "Invalid parameter, expected hex txid");
        if (!v || v->typ != RJ_NUM) return wop_err(ec, em, -8, "Invalid parameter, vout must be a number");
        long vv = atol(v->str);
        if (vv < 0) return wop_err(ec, em, -8, "Invalid parameter, vout cannot be negative");
        vouts[i] = (unsigned long)vv;
    }
    for (size_t i = 0; i < list->nitems; i++){
        int at = -1;
        for (int j = 0; j < g_nlocks; j++)
            if (!memcmp(g_locks[j].txid, txids[i], 32) && g_locks[j].vout == vouts[i]){ at = j; break; }
        if (unlock){
            if (at >= 0) g_locks[at] = g_locks[--g_nlocks];
        } else if (at < 0){
            if (g_nlocks >= WOP_MAX_LOCKS)
                return wop_err(ec, em, -8, "This node's lock set is full");
            memcpy(g_locks[g_nlocks].txid, txids[i], 32);
            g_locks[g_nlocks].vout = vouts[i];
            g_nlocks++;
        }
    }
    *res = rj_bool(1);
    return 1;
}

/* Exposed so a future funding path can honour the locks rather than
 * silently spending a locked output. */
int rpc_wops_is_locked(const unsigned char txid[32], unsigned long vout){
    for (int i = 0; i < g_nlocks; i++)
        if (!memcmp(g_locks[i].txid, txid, 32) && g_locks[i].vout == vout) return 1;
    return 0;
}
void rpc_wops_reset_locks(void){ g_nlocks = 0; }

/* ==== signmessage ========================================================
 * Core signs only for a P2PKH destination ("Address does not refer to key"
 * otherwise), so this does too. The wallet's keys are BIP32-derived; the
 * same key that forms its P2WPKH address also forms a P2PKH address, so the
 * search is over hash160(pubkey) at each derived index.
 *
 * The scan window is bounded because the derivation is unbounded. This
 * wallet only ever hands out index 0 today (cmd_getnewaddress derives 0),
 * so the window is generous rather than load-bearing -- but it is a REAL
 * bound: an address derived beyond it reports "Private key not available",
 * which is honest (this code did not find the key) rather than wrong. */
#define WOP_KEY_SCAN 1000

static int wop_key_for_p2pkh(const unsigned char seed[64], const unsigned char want_h160[20],
                             unsigned char priv_out[32]){
    for (unsigned i = 0; i < WOP_KEY_SCAN; i++){
        for (int chain = 0; chain <= 1; chain++){
            unsigned idx[5] = {0x80000000u | 84u, 0x80000000u, 0x80000000u, i, (unsigned)chain};
            unsigned char k[32], c[32], pub[33], h[20];
            if (bip32_derive_path(k, c, seed, 64, idx, 5) != 1) continue;
            scalar_to_pubkey(pub, k);
            hash160(h, pub, 33);
            if (!memcmp(h, want_h160, 20)){ memcpy(priv_out, k, 32); return 1; }
        }
    }
    return 0;
}

static int cmd_signmessage(const rj_val* params, const rpc_wallet* w,
                           long* ec, const char** em, rj_val** res){
    const char* addr = wop_str_arg(params, 0);
    const char* msg  = wop_str_arg(params, 1);
    if (!addr || !msg) return wop_err(ec, em, -8, "signmessage requires an address and a message");
    int t; unsigned char v, h160[20], p32[32];
    if (!wallet_validate_address(addr, &t, &v, h160, p32) ||
        t < WOP_ADDR_P2PKH || t > WOP_ADDR_P2TR)
        return wop_err(ec, em, -5, "Invalid address");
    /* Core: only a PKHash destination carries a signable key. */
    if (t != WOP_ADDR_P2PKH) return wop_err(ec, em, -3, "Address does not refer to key");
    if (!w || !w->seed)      return wop_err(ec, em, -4, "Private key not available");
    unsigned char priv[32];
    if (!wop_key_for_p2pkh(w->seed, h160, priv))
        return wop_err(ec, em, -4, "Private key not available");
    char sig[96];
    if (msg_sign_core(priv, msg, sig) != 0) return wop_err(ec, em, -5, "Sign failed");
    *res = rj_str(sig);
    return 1;
}

/* ==== descriptor reporting ===============================================
 * An honest listdescriptors is possible here, and it is more specific than
 * Core's usual output rather than less: this wallet's key derivation puts
 * the ACCOUNT index at depth 4 and the receive/change branch LAST
 * (m/84'/0'/0'/<i>/<0|1>), which is the reverse of BIP84's ordering. A
 * ranged descriptor cannot express that -- `*` has to be the final step --
 * so what gets emitted is the concrete, non-ranged descriptor for each key
 * the wallet actually uses. Since getnewaddress/getrawchangeaddress always
 * derive index 0, that is exactly two keys, and the output is complete.
 * Documented in docs/RPC_LIVE_NODE.md; NOT a truncation of a longer list. */

static int wop_account_xpub(const unsigned char seed[64], char out[128]){
    unsigned acct[3] = {0x80000000u | 84u, 0x80000000u, 0x80000000u};
    unsigned char k[32], c[32], pub[33], ser[78];
    if (bip32_derive_path(k, c, seed, 64, acct, 3) != 1) return 0;
    /* parent fingerprint = first 4 of hash160(pubkey(m/84'/0')) */
    unsigned par[2] = {0x80000000u | 84u, 0x80000000u};
    unsigned char pk[32], pc[32], ppub[33], ph[20], fp[4] = {0,0,0,0};
    if (bip32_derive_path(pk, pc, seed, 64, par, 2) == 1){
        scalar_to_pubkey(ppub, pk);
        hash160(ph, ppub, 33);
        memcpy(fp, ph, 4);
    }
    scalar_to_pubkey(pub, k);
    bip32_extkey_serialize(ser, 0, 3, fp, 0x80000000u, c, pub, 33);
    wop_stamp_extkey_version(ser, 0);
    base58check_encode(out, ser, 78);
    return 1;
}

/* master key fingerprint: first 4 bytes of hash160(pubkey(m)) */
static int wop_master_fp(const unsigned char seed[64], char out[9]){
    extern int bip32_master(unsigned char k[32], unsigned char c[32],
                            const unsigned char* seed, long seedlen);
    unsigned char k[32], c[32], pub[33], h[20];
    if (bip32_master(k, c, seed, 64) != 1) return 0;
    scalar_to_pubkey(pub, k);
    hash160(h, pub, 33);
    snprintf(out, 9, "%02x%02x%02x%02x", h[0], h[1], h[2], h[3]);
    return 1;
}

static rj_val* wop_desc_entry_t(const unsigned char seed[64], int t, int is_change){
    char mfp[9];
    if (!wop_master_fp(seed, mfp)) return NULL;
    unsigned idx[5]; rpc_wops_type_path(t, 0, is_change, idx);
    unsigned char k[32], c[32], pub[33];
    if (bip32_derive_path(k, c, seed, 64, idx, 5) != 1) return NULL;
    scalar_to_pubkey(pub, k);
    char pubhex[67];
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < 33; i++){ pubhex[i*2] = H[pub[i]>>4]; pubhex[i*2+1] = H[pub[i]&15]; }
    pubhex[66] = 0;
    char inner[256];
    unsigned purpose = idx[0] & 0x7fffffffu;
    if (t == WOT_LEGACY)           snprintf(inner, sizeof inner, "pkh([%s/%uh/0h/0h/0/%d]%s)", mfp, purpose, is_change, pubhex);
    else if (t == WOT_P2SH_SEGWIT) snprintf(inner, sizeof inner, "sh(wpkh([%s/%uh/0h/0h/0/%d]%s))", mfp, purpose, is_change, pubhex);
    else if (t == WOT_BECH32M)     snprintf(inner, sizeof inner, "tr([%s/%uh/0h/0h/0/%d]%s)", mfp, purpose, is_change, pubhex + 2);   /* x-only, as Core prints tr() keys */
    else                           snprintf(inner, sizeof inner, "wpkh([%s/%uh/0h/0h/0/%d]%s)", mfp, purpose, is_change, pubhex);
    char cks[9];
    char desc[288];
    if (rpc_chain_desc_checksum(inner, cks)) snprintf(desc, sizeof desc, "%s#%s", inner, cks);
    else                                     snprintf(desc, sizeof desc, "%s", inner);
    rj_val* e = rj_obj();
    rj_obj_set(e, "desc", rj_str(desc));
    /* timestamp: Core reports when the descriptor entered the wallet. This
     * wallet records no such time, so the field is OMITTED rather than
     * filled with a plausible number. */
    rj_obj_set(e, "active", rj_bool(1));
    rj_obj_set(e, "internal", rj_bool(is_change));
    return e;
}
static rj_val* wop_desc_entry(const unsigned char seed[64], int is_change){ return wop_desc_entry_t(seed, WOT_BECH32, is_change);
}

static int cmd_listdescriptors(const rj_val* params, const rpc_wallet* w,
                               long* ec, const char** em, rj_val** res){
    /* Core's `private` argument dumps xprvs. This node will not export
     * private material over RPC at all, so ask for it and you get told. */
    if (params && params->typ == RJ_ARR && params->nitems >= 1 &&
        params->items[0]->typ == RJ_BOOL && !strcmp(params->items[0]->str, "1"))
        return wop_err(ec, em, -1,
            "listdescriptors true would export private keys; this node does not "
            "serve private key material over RPC. Use the wallet CLI on the host.");
    if ((!w || !w->seed) && g_aw_watchonly){
        /* watch-only: report the imported descriptors verbatim */
        wop_descs_load();
        rj_val* arr = rj_arr();
        for (int i = 0; i < g_wd_n; i++){
            rj_val* e = rj_obj();
            rj_obj_set(e, "desc", rj_str(g_wd[i].desc));
            rj_obj_set(e, "active", rj_bool(i == 0));
            rj_val* rg = rj_arr();
            rj_arr_push(rg, rj_numf("%d", 0));
            rj_arr_push(rg, rj_numf("%ld", g_wd[i].range - 1));
            rj_obj_set(e, "range", rg);
            rj_obj_set(e, "next_index", rj_numf("%ld", g_wd[i].next));
            rj_arr_push(arr, e);
        }
        rj_val* o = rj_obj();
        rj_obj_set(o, "wallet_name", rj_str(rpc_wops_active_wallet_name()));
        rj_obj_set(o, "descriptors", arr);
        *res = o;
        return 1;
    }
    if (!w || !w->seed) return wop_err(ec, em, -4, "No wallet is loaded");
    rj_val* arr = rj_arr();
    int mask = rpc_wops_active_types();
    for (int t = 0; t < 4; t++){
        if (!(mask & (1 << t))) continue;
        for (int ch = 0; ch <= 1; ch++){
            rj_val* e = wop_desc_entry_t(w->seed, t, ch);
            if (e) rj_arr_push(arr, e);
        }
    }
    rj_val* o = rj_obj();
    rj_obj_set(o, "wallet_name", rj_str(rpc_wops_active_wallet_name()));
    rj_obj_set(o, "descriptors", arr);
    *res = o;
    return 1;
}

/* ==== exportwatchonlywallet ===============================================
 * Core: "creates a wallet file at the specified destination containing a
 * watchonly version of the current wallet", importable elsewhere with
 * restorewallet. That is expressible here, and completely, for the reason
 * listdescriptors documents above: this wallet derives
 * m/84'/0'/0'/<i>/<0|1> with the branch LAST, so a ranged descriptor cannot
 * describe it -- but it only ever uses index 0, so its ENTIRE key set is the
 * two concrete descriptors that get written. This is not a truncated export.
 *
 * The file is the same descriptors.dat format a watch-only wallet already
 * loads, behind a header line so restorewallet can tell an exported
 * watch-only wallet from a seed backup and install the right kind.
 *
 * STATED OMISSION: Core's export also carries the wallet's transactions and
 * address book. This one carries the descriptors -- the part that makes the
 * wallet watchable at all. A restored export finds its history by
 * rescanning, which is what a watch-only wallet on this node does anyway. */
/* ==== addhdkey / gethdkeys ==============================================
 * Core: "Add a BIP 32 HD key to the wallet that can be used with
 * 'createwalletdescriptor'". With no argument it generates one. */
static int cmd_addhdkey(const rj_val* params, const rpc_wallet* w,
                        long* ec, const char** em, rj_val** res){
    if (rpc_wops_watchonly() || !w || !w->seed)
        return wop_err(ec, em, -4,
            "addhdkey is not available for wallets without private keys");
    char pass[256];
    if (!wop_wallet_pass(pass, sizeof pass))
        return wop_err(ec, em, -4,
            "addhdkey stores an extended PRIVATE key, and this node will only "
            "store one encrypted. The wallet passphrase is not available "
            "(set BMC_WALLET_PASS or walletpassfile=)");
    memset(pass, 0, sizeof pass);

    int n = wop_hdkeys_load();
    if (n >= WOP_MAX_HDKEYS - 1)
        return wop_err(ec, em, -4, "this wallet already holds the maximum number of HD keys");

    char xprv[128]; xprv[0] = 0;
    const char* given = wop_str_arg(params, 0);
    if (given && given[0]){
        unsigned char k[32], c[32];
        if (!wop_hdk_parse(given, k, c))
            return wop_err(ec, em, -5, "Unable to parse HD key. Please provide a valid xprv");
        memset(k, 0, 32); memset(c, 0, 32);
        snprintf(xprv, sizeof xprv, "%s", given);
    } else {
        /* Core generates one when none is given. Ours comes from a fresh
         * BIP39 mnemonic run through the same derivation the wallet's own
         * seed uses -- no second source of randomness to review. */
        char mn[256];
        if (!wallet_mnemonic_generate(mn))
            return wop_err(ec, em, -4, "key generation failed");
        unsigned char seed[64], k[32], c[32], ser[78];
        int ok = wallet_mnemonic_seed(seed, mn, "", 0) == 1;
        memset(mn, 0, sizeof mn);
        if (ok){ extern int bip32_master(unsigned char[32], unsigned char[32],
                                         const unsigned char*, long);
                 ok = bip32_master(k, c, seed, 64) == 1; }
        memset(seed, 0, sizeof seed);
        if (!ok) return wop_err(ec, em, -4, "key generation failed");
        unsigned char kd[33]; kd[0] = 0x00; memcpy(kd + 1, k, 32);
        unsigned char zfp[4] = {0,0,0,0};
        bip32_extkey_serialize(ser, 1, 0, zfp, 0, c, kd, 33);
        wop_stamp_extkey_version(ser, 1);
        base58check_encode(xprv, ser, 78);
        memset(k, 0, 32); memset(c, 0, 32); memset(kd, 0, 33);
    }

    /* refuse a duplicate: adding the same key twice would double every
     * address it contributes to the window */
    for (int i = 1; i <= g_hdk_n; i++)
        if (!strcmp(g_hdk[i], xprv))
            return wop_err(ec, em, -4, "This HD key is already in the wallet");

    snprintf(g_hdk[++g_hdk_n], sizeof g_hdk[0], "%s", xprv);
    if (!wop_hdkeys_save()){ g_hdk_n--;
        return wop_err(ec, em, -4, "could not persist the HD key"); }
    char xpub[128]; xpub[0] = 0;
    wop_hdk_xpub(xprv, xpub);
    memset(xprv, 0, sizeof xprv);
    /* the key window and every record view change the moment a key is added */
    wop_keyset_invalidate(); wop_records_invalidate(); wop_watch_keys_invalidate();
    rj_val* o = rj_obj();
    rj_obj_set(o, "xpub", rj_str(xpub));
    *res = o;
    return 1;
}

/* ==== setwalletflag ======================================================
 * Core's one mutable flag is avoid_reuse, and its errors are specific:
 * unknown flag, immutable flag, and "already set to <value>" -- that last
 * one matters, because a caller that sets a flag twice should learn the
 * second call did nothing rather than be told it succeeded. */
static int cmd_setwalletflag(const rj_val* params, long* ec, const char** em,
                             rj_val** res){
    const char* flag = wop_str_arg(params, 0);
    if (!flag || !flag[0])
        return wop_err(ec, em, -8, "setwalletflag requires a flag name");
    static char msg[160];
    /* Core's immutable flags are real flags that this call still refuses;
     * naming them separately from "unknown" is the difference between "no
     * such thing" and "not yours to change". */
    if (!strcmp(flag, "disable_private_keys") || !strcmp(flag, "blank") ||
        !strcmp(flag, "descriptor_wallet") || !strcmp(flag, "external_signer")){
        snprintf(msg, sizeof msg, "Wallet flag is immutable: %s", flag);
        return wop_err(ec, em, -8, msg);
    }
    if (strcmp(flag, "avoid_reuse")){
        snprintf(msg, sizeof msg, "Unknown wallet flag: %s", flag);
        return wop_err(ec, em, -8, msg);
    }
    int value = 1;
    { const rj_val* v = (params && params->typ == RJ_ARR && params->nitems >= 2)
                        ? params->items[1] : NULL;
      if (v && v->typ == RJ_BOOL && v->str) value = (v->str[0] == '1');
      else if (v && v->typ != RJ_NULL && v->typ != RJ_BOOL)
          return wop_err(ec, em, -8, "value must be a boolean"); }
    if (wop_avoid_reuse_load() == value){
        snprintf(msg, sizeof msg, "Wallet flag is already set to %s: %s",
                 value ? "true" : "false", flag);
        return wop_err(ec, em, -8, msg);
    }
    if (!wop_avoid_reuse_save(value))
        return wop_err(ec, em, -4, "could not persist the wallet flag");
    rj_val* o = rj_obj();
    rj_obj_set(o, "flag_name", rj_str(flag));
    rj_obj_set(o, "flag_state", rj_bool(value));
    if (value)
        rj_obj_set(o, "warnings", rj_str(
            "You need to rescan the blockchain in order to correctly mark used "
            "destinations in the past. Until this is done, some destinations may "
            "be considered unused even if the opposite is the case."));
    *res = o;
    return 1;
}

/* ==== migratewallet ======================================================
 * Core migrates a LEGACY (pre-descriptor) wallet to a descriptor one, and
 * refuses when there is nothing to migrate: "Error: This wallet is already a
 * descriptor wallet".
 *
 * That refusal is the correct answer for every wallet this node has. The
 * store is a BIP32 seed whose keys are described by descriptors --
 * listdescriptors reports them, importdescriptors consumes them,
 * exportwatchonlywallet writes them. There is no legacy keypool form here to
 * migrate FROM, so Core's own error is not a stand-in for an unimplemented
 * feature; it is the verdict Core would reach on the same wallet. Answering
 * it is more useful than the blanket refusal that used to sit here, which
 * said this node had no multi-wallet manager -- untrue since the
 * createwallet/loadwallet lifecycle shipped. */
static int cmd_migratewallet(const rj_val* params, long* ec, const char** em){
    /* Core: if a wallet name is given both here and on the endpoint, the two
     * must be identical. We serve the active wallet, so a name that names a
     * DIFFERENT wallet is the same mistake and gets the same -8. */
    const char* name = wop_str_arg(params, 0);
    if (name && name[0] && strcmp(name, rpc_wops_active_wallet_name()) != 0)
        return wop_err(ec, em, -8,
            "RPC endpoint wallet and wallet_name parameter specify different wallets");
    return wop_err(ec, em, -4, "Error: This wallet is already a descriptor wallet");
}

/* ==== createwalletdescriptor =============================================
 * Core creates the wallet's descriptor for an address type it does not
 * already have one for, and errors "Descriptor already exists" when it does.
 *
 * This wallet has wpkh (bech32) descriptors for both the external and
 * internal branch, so `bech32` gets Core's exact already-exists error -- a
 * real verdict, reached the same way. The other three types are refused with
 * the specific reason rather than a blanket one: deriving the KEY for them
 * is trivial (same BIP32 path, different script), but a descriptor whose
 * outputs the rescan cannot recognise and getnewaddress will never hand out
 * would be a descriptor in name only, and the wallet would quietly fail to
 * see funds paid to it. Refusing is the honest answer until the scan and the
 * address path learn those script types. */
static int cmd_createwalletdescriptor(const rj_val* params, const rpc_wallet* w,
                                      long* ec, const char** em, rj_val** res){
    const char* type = wop_str_arg(params, 0);
    if (!type || !type[0])
        return wop_err(ec, em, -8, "createwalletdescriptor requires an address type");
    static char msg[224];
    int known = !strcmp(type, "legacy") || !strcmp(type, "p2sh-segwit") ||
                !strcmp(type, "bech32") || !strcmp(type, "bech32m");
    if (!known){
        snprintf(msg, sizeof msg, "Unknown address type '%s'", type);
        return wop_err(ec, em, -5, msg);        /* Core's wording and code */
    }
    if (!w || !w->seed){
        if (rpc_wops_watchonly())
            return wop_err(ec, em, -4,
                "createwalletdescriptor needs the wallet's HD key; this is a "
                "watch-only wallet. Use importdescriptors instead.");
        return wop_err(ec, em, -4, "No wallet is loaded");
    }
    /* bech32 is always present (for the seed AND every addhdkey key, which
     * join the derivation window the moment they are added); the other three
     * are activated here (2026-09-01): their descriptors join listdescriptors,
     * their keys join the rescan window, getnewaddress can hand them out and
     * the wallet signs for them (P2PKH / P2SH-P2WPKH / P2TR key path). */
    int t = rpc_wops_type_from_name(type);
    if (t < 0) { snprintf(msg, sizeof msg, "Unknown address type '%s'", type); return wop_err(ec, em, -5, msg); }
    int r = rpc_wops_activate_type(t);
    if (r == 0) return wop_err(ec, em, -4, "Descriptor already exists");
    if (r < 0)  return wop_err(ec, em, -4, "could not record the new descriptor in the wallet directory");
    /* Core: {"descs": [<external>, <internal>]} */
    rj_val* descs = rj_arr();
    for (int ch = 0; ch <= 1; ch++){
        rj_val* e = wop_desc_entry_t(w->seed, t, ch);
        if (e){ rj_val* d = rj_obj_get(e, "desc"); if (d) rj_arr_push(descs, rj_str(d->str)); rj_free(e); }
    }
    rj_val* o = rj_obj(); rj_obj_set(o, "descs", descs);
    *res = o;
    return 1;
}

static int cmd_exportwatchonlywallet(const rj_val* params, const rpc_wallet* w,
                                     long* ec, const char** em, rj_val** res){
    const char* dest = wop_str_arg(params, 0);
    if (!dest || !dest[0])
        return wop_err(ec, em, -8, "exportwatchonlywallet requires a destination path");

    /* gather this wallet's public descriptors, from whichever kind it is */
    char descs[WOP_MAX_DESCS][340];
    long ranges[WOP_MAX_DESCS], nexts[WOP_MAX_DESCS];
    int nd = 0;
    if (w && w->seed){
        int mask = rpc_wops_active_types();
        for (int t = 0; t < 4; t++) for (int ch = 0; (mask & (1 << t)) && ch <= 1 && nd < WOP_MAX_DESCS; ch++){
            rj_val* e = wop_desc_entry_t(w->seed, t, ch);
            if (!e) continue;
            rj_val* d = rj_obj_get(e, "desc");
            if (d && d->str){
                snprintf(descs[nd], sizeof descs[nd], "%s", d->str);
                ranges[nd] = 1; nexts[nd] = 0; nd++;
            }
            rj_free(e);
        }
    } else if (g_aw_watchonly){
        wop_descs_load();
        for (int i = 0; i < g_wd_n && nd < WOP_MAX_DESCS; i++){
            snprintf(descs[nd], sizeof descs[nd], "%s", g_wd[i].desc);
            ranges[nd] = g_wd[i].range; nexts[nd] = g_wd[i].next; nd++;
        }
    } else {
        return wop_err(ec, em, -4, "No wallet is loaded");
    }
    if (nd == 0)
        return wop_err(ec, em, -4, "this wallet has no descriptors to export "
                                   "(a blank watch-only wallet: importdescriptors first)");

    /* refuse to clobber: an export that silently overwrote a wallet file
     * would be the worst possible way to learn the path was wrong */
    { struct stat sb;
      if (stat(dest, &sb) == 0)
          return wop_err(ec, em, -4, "the destination already exists; "
                                     "exportwatchonlywallet will not overwrite it"); }

    FILE* f = fopen(dest, "w");
    if (!f) return wop_err(ec, em, -4, "could not write the export file");
    fputs(WOP_WATCH_EXPORT_MAGIC "\n", f);
    for (int i = 0; i < nd; i++)
        fprintf(f, "%s\t%ld\t%ld\n", descs[i], ranges[i], nexts[i]);
    if (fflush(f) != 0 || fsync(fileno(f)) != 0){ fclose(f);
        return wop_err(ec, em, -4, "could not flush the export file"); }
    fclose(f);

    /* Core answers with the FULL path it wrote */
    char abs[1024];
    if (dest[0] == '/') snprintf(abs, sizeof abs, "%s", dest);
    else { char cwd[768];
           if (getcwd(cwd, sizeof cwd)) snprintf(abs, sizeof abs, "%s/%s", cwd, dest);
           else snprintf(abs, sizeof abs, "%s", dest); }
    rj_val* o = rj_obj();
    rj_obj_set(o, "exported_file", rj_str(abs));
    *res = o;
    return 1;
}

static int cmd_gethdkeys(const rj_val* params, const rpc_wallet* w, rj_val** res){
    (void)params;
    rj_val* arr = rj_arr();
    char xpub[128];
    if (w && w->seed && wop_account_xpub(w->seed, xpub)){
        rj_val* e = rj_obj();
        rj_obj_set(e, "xpub", rj_str(xpub));
        /* the seed is present, so the private half exists -- but see
         * listdescriptors: it is never rendered over RPC. */
        rj_obj_set(e, "has_private", rj_bool(1));
        rj_arr_push(arr, e);
    }
    /* ...plus every key addhdkey added. Listing only the seed once added
     * keys exist would hide half the wallet from a caller deciding which
     * hdkey to pass to createwalletdescriptor. */
    { int nh = wop_hdkeys_load();
      for (int h = 1; h <= nh; h++){
          char xp[128];
          if (!wop_hdk_xpub(g_hdk[h], xp)) continue;
          rj_val* e = rj_obj();
          rj_obj_set(e, "xpub", rj_str(xp));
          rj_obj_set(e, "has_private", rj_bool(1));
          rj_arr_push(arr, e);
      } }
    *res = arr;
    return 1;
}

/* ==== encryption state ===================================================
 * These are not refusals. This node's wallet IS unencrypted, and the answers
 * below are byte-for-byte what Core returns for an unencrypted wallet --
 * verified against the oracle. encryptwallet is the one real gap. */
/* wallet encryption state machine (daemon/wallet_enc_state.c) */
extern int  wenc_is_encrypted(void);
extern int  wenc_encrypt(const char* mn, const char* mn_pass, const char* wpass, long wplen);
extern int  wenc_unlock(const char* pass, long plen, long seconds);
extern void wenc_lock(void);
extern int  wenc_change(const char* oldp, long ol, const char* newp, long nl);
/* the loaded mnemonic, exposed by the daemon so encryptwallet can seal it */
extern int  wenc_current_mnemonic(char* out, long cap, char* pass_out, long pcap);

static int cmd_walletlock(long* ec, const char** em){
    if (!wenc_is_encrypted())
        return wop_err(ec, em, -15,
            "Error: running with an unencrypted wallet, but walletlock was called.");
    wenc_lock();
    return 1;   /* Core returns null on success */
}
static int cmd_walletpassphrase(const rj_val* params, long* ec, const char** em){
    if (!wenc_is_encrypted())
        return wop_err(ec, em, -15,
            "Error: running with an unencrypted wallet, but walletpassphrase was called.");
    if (!params || params->typ != RJ_ARR || params->nitems < 2 ||
        params->items[0]->typ != RJ_STR || params->items[1]->typ != RJ_NUM)
        return wop_err(ec, em, -8, "walletpassphrase(passphrase, timeout)");
    const char* pass = params->items[0]->str;
    long secs = atol(params->items[1]->str);
    if (secs <= 0) return wop_err(ec, em, -8, "Timeout must be a positive integer");
    if (wenc_unlock(pass, (long)strlen(pass), secs) != 1)
        return wop_err(ec, em, -14,
            "Error: The wallet passphrase entered was incorrect.");
    return 1;
}
static int cmd_walletpassphrasechange(const rj_val* params, long* ec, const char** em){
    if (!wenc_is_encrypted())
        return wop_err(ec, em, -15,
            "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");
    if (!params || params->typ != RJ_ARR || params->nitems < 2 ||
        params->items[0]->typ != RJ_STR || params->items[1]->typ != RJ_STR)
        return wop_err(ec, em, -8, "walletpassphrasechange(old, new)");
    const char* op = params->items[0]->str;
    const char* np = params->items[1]->str;
    if (wenc_change(op, (long)strlen(op), np, (long)strlen(np)) != 1)
        return wop_err(ec, em, -14,
            "Error: The wallet passphrase entered was incorrect.");
    return 1;
}
static int wop_named_active(void){ return g_aw_state == 1; }
static int cmd_encryptwallet(const rj_val* params, const rpc_wallet* w,
                             long* ec, const char** em, rj_val** res){
    if (wop_named_active())
        return wop_err(ec, em, -4,
            "at-rest encryption serves the DEFAULT wallet on this node "
            "(daemon/wallet_enc_state.c is single-instance); load the default "
            "wallet to encrypt it");
    if (wenc_is_encrypted())
        return wop_err(ec, em, -15,
            "Error: running with an encrypted wallet, but encryptwallet was called.");
    if (!w || !w->seed)
        return wop_err(ec, em, -4, "Error: the wallet is not loaded, cannot encrypt");
    if (!params || params->typ != RJ_ARR || params->nitems < 1 || params->items[0]->typ != RJ_STR)
        return wop_err(ec, em, -8, "encryptwallet(passphrase)");
    const char* pass = params->items[0]->str;
    if (strlen(pass) < 1) return wop_err(ec, em, -8, "passphrase can not be empty");
    static char mn[768], mp[256];
    if (wenc_current_mnemonic(mn, sizeof mn, mp, sizeof mp) != 1)
        return wop_err(ec, em, -4, "Error: could not read the wallet mnemonic to encrypt");
    int r = wenc_encrypt(mn, mp[0]?mp:0, pass, (long)strlen(pass));
    memset(mn, 0, sizeof mn); memset(mp, 0, sizeof mp);
    if (r != 1) return wop_err(ec, em, -4, "Error: failed to write the encrypted wallet");
    *res = rj_str("wallet encrypted; The wallet is now locked. Use walletpassphrase to unlock it.");
    return 1;
}

/* ==== rescan state =======================================================
 * abortrescan reports whether it aborted a rescan in progress. This node
 * never starts one, so `false` is not a stub -- it is the correct answer,
 * and the only answer this method could ever give here. */
static int cmd_abortrescan(rj_val** res){ *res = rj_bool(0); return 1; }

/* ==== keypoolrefill ======================================================
 * Core pre-generates keys so a locked wallet can still hand out addresses.
 * This wallet derives on demand from a BIP32 seed: the pool is unbounded and
 * the postcondition "at least N keys are available" already holds for any N.
 * Returning null is therefore the honest answer -- the request is satisfied,
 * with nothing to do -- not a silent no-op standing in for missing work. */
static int cmd_keypoolrefill(rj_val** res){ *res = rj_null(); return 1; }

/* ==== backupwallet =======================================================
 * Really copies the file, and really fails if it cannot. */
static int cmd_backupwallet(const rj_val* params, long* ec, const char** em, rj_val** res){
    const char* dest = wop_str_arg(params, 0);
    if (!dest || !dest[0]) return wop_err(ec, em, -8, "backupwallet requires a destination");
    char pb[512];
    if (!wop_exists(WOP_WALLET_REL)) return wop_err(ec, em, -4, "No wallet file to back up");
    const char* src = wop_path(WOP_WALLET_REL, pb, sizeof pb);
    /* Core accepts a directory and writes <dir>/<walletname> into it. */
    char out[1024]; struct stat sb;
    if (stat(dest, &sb) == 0 && S_ISDIR(sb.st_mode))
        snprintf(out, sizeof out, "%s/%s", dest, WOP_WALLET_NAME);
    else
        snprintf(out, sizeof out, "%s", dest);
    FILE* in = fopen(src, "rb");
    if (!in) return wop_err(ec, em, -4, "Cannot open the wallet file for reading");
    FILE* o = fopen(out, "wb");
    if (!o){ fclose(in); return wop_err(ec, em, -4, "Cannot open the backup destination for writing"); }
    char buf[16384]; size_t n; int bad = 0;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0)
        if (fwrite(buf, 1, n, o) != n){ bad = 1; break; }
    if (ferror(in)) bad = 1;
    if (fflush(o) != 0) bad = 1;
    if (fclose(o) != 0) bad = 1;
    fclose(in);
    if (bad){ remove(out); return wop_err(ec, em, -4, "Backup failed while copying; destination removed"); }
    *res = rj_null();
    return 1;
}

/* ==== the wallet rescan ==================================================
 * asm/wallet_scan.c walks the archive and records every output paying this
 * wallet and every input spending one. Everything below reads that record
 * file; nothing here re-derives money from anywhere else, so a figure this
 * module reports is a figure the scan actually saw.
 *
 * The archive reader and the tip are INJECTED rather than linked, for the
 * same reason the mempool hooks and the address book are: rpc_wallet_ops.c
 * has no business pulling the block store into every target that links it.
 */
static long (*g_wops_read_block)(long h, unsigned char* buf, long cap);
static unsigned char* g_wops_blockbuf;
static long g_wops_bufcap;
static long (*g_wops_tip)(void);

void rpc_wops_set_scanner(long (*read_block)(long, unsigned char*, long),
                          unsigned char* blockbuf, long bufcap,
                          long (*tip)(void)){
    g_wops_read_block = read_block; g_wops_blockbuf = blockbuf;
    g_wops_bufcap = bufcap; g_wops_tip = tip;
}

#define WOP_SCAN_REL   "walletscan.dat"
/* The derivation window the scan covers. getnewaddress hands out index 0
 * today, and the CLI can be asked for an explicit index; 1000 across both
 * branches is generous. It is a REAL bound, not a formality: an output paid
 * to a key beyond it is not found, which is why the number is stated here
 * and in the docs rather than buried. */
#define WOP_SCAN_KEYS  1000
/* An ADDED hd key is new, so its address history is short; a smaller window
 * per added key keeps the matcher (searched once per output of every
 * transaction in the chain) from growing by an order of magnitude. */
#define WOP_HDK_WINDOW 100
#define WOP_KEYSET_CAP (WOP_SCAN_KEYS*2*4 + WOP_MAX_HDKEYS*WOP_HDK_WINDOW*2)   /* x4: one window per output type */

extern int  bip32_derive_path(unsigned char k[32], unsigned char c[32],
                              const unsigned char* seed, long seedlen,
                              const unsigned* indexes, long n);

/* Build the sorted key window. Returns the count, or 0 with no wallet.
 *
 * CACHED, because it is 2000 BIP32 derivations and 2000 point multiplies:
 * without the cache every getreceivedbyaddress would repeat all of it, and
 * listreceivedbyaddress would do so once per candidate. The cache is keyed
 * on the seed bytes, so a different wallet rebuilds rather than silently
 * answering from the previous one's keys. */
static unsigned char g_ks_seed[64];
static int g_ks_valid;
/* the derived key window is a cache of the seed AND every added hd key, so
 * adding a key must drop it -- otherwise the new key's addresses stay
 * invisible until the process restarts */
static void wop_keyset_invalidate(void){ g_ks_valid = 0; }
static wscan_key* g_ks;
static int g_ks_n;

/* ---- watch-only descriptor keyset ---------------------------------------
 * A watch-only wallet has no seed; its scan window comes from the imported
 * descriptors instead: for slot s and index i the entry is
 *   { h160 = the 20 bytes rpc_desc_expand computes, keyidx = i, branch = s }
 * so every journal record maps back to (descriptor, index) for address
 * rendering, exactly as an HD record maps to (branch, index). Slot count is
 * bounded by the branch byte (255) and total entries by the same window the
 * HD wallet uses. */
long rpc_desc_expand(const char* in, long start, long count,
                     unsigned char (*h160s)[20], long cap, int* script_type,
                     char* err, unsigned long errcap);
int  rpc_desc_normalize(const char* in, char* out, long cap, int* is_range,
                        char* err, unsigned long errcap);
int  rpc_desc_address_at(const char* in, long idx, char* out, long cap,
                         char* err, unsigned long errcap);

static int wop_watch_keyset(const wscan_key** out){
    if (g_wk_n >= 0){ *out = g_wk; return g_wk_n; }
    int nd = wop_descs_load();
    if (!g_wk) g_wk = malloc((size_t)(WOP_SCAN_KEYS*2) * sizeof *g_wk);
    if (!g_wk){ *out = NULL; return 0; }
    g_wk_n = 0;
    static unsigned char h[WOP_SCAN_KEYS*2][20];
    for (int sdx = 0; sdx < nd && sdx < 255; sdx++){
        long cap = WOP_SCAN_KEYS*2 - g_wk_n;
        long want = g_wd[sdx].range < cap ? g_wd[sdx].range : cap;
        char err[128]; int sc;
        long n = rpc_desc_expand(g_wd[sdx].desc, 0, want, h, want, &sc, err, sizeof err);
        if (n < 0) continue;
        g_wd[sdx].script = sc;
        for (long i = 0; i < n; i++){
            memcpy(g_wk[g_wk_n].h160, h[i], 20);
            g_wk[g_wk_n].keyidx = (unsigned)i;
            g_wk[g_wk_n].branch = (unsigned char)sdx;
            g_wk_n++;
        }
    }
    qsort(g_wk, (size_t)g_wk_n, sizeof g_wk[0], wscan_key_cmp);
    *out = g_wk;
    return g_wk_n;
}

static int wop_keyset_cached(const rpc_wallet* w, const wscan_key** out){
    if ((!w || !w->seed) && g_aw_watchonly) return wop_watch_keyset(out);
    if (!w || !w->seed){ *out = NULL; return 0; }
    if (g_ks_valid && !memcmp(g_ks_seed, w->seed, 64)){ *out = g_ks; return g_ks_n; }
    if (!g_ks) g_ks = malloc((size_t)WOP_KEYSET_CAP * sizeof *g_ks);
    if (!g_ks){ *out = NULL; return 0; }
    extern int wop_keyset(const rpc_wallet*, wscan_key*, int);
    g_ks_n = wop_keyset(w, g_ks, WOP_KEYSET_CAP);
    memcpy(g_ks_seed, w->seed, 64);
    g_ks_valid = 1;
    *out = g_ks;
    return g_ks_n;
}

int wop_keyset(const rpc_wallet* w, wscan_key* keys, int cap){
    if (!w || !w->seed) return 0;
    int n = 0;
    /* every ACTIVE output type gets its own window over its own purpose path;
     * the 20 bytes stored are what the chain scan matches: the key hash for
     * pkh/wpkh, the script hash for sh(wpkh), the first 20 of Q for tr */
    int mask = rpc_wops_active_types();
    for (int t = 0; t < 4; t++){
        if (!(mask & (1 << t))) continue;
        for (unsigned i = 0; i < WOP_SCAN_KEYS && n + 2 <= cap; i++){
            for (int b = 0; b <= 1; b++){
                unsigned path[5]; rpc_wops_type_path(t, i, b, path);
                unsigned char k[32], c[32], pub[33], spk[34]; unsigned long sl;
                if (bip32_derive_path(k, c, w->seed, 64, path, 5) != 1) continue;
                scalar_to_pubkey(pub, k);
                if (!rpc_wops_type_spk(t, pub, spk, &sl, keys[n].h160)) continue;
                keys[n].keyidx = i; keys[n].branch = WOT_BRANCH(t, b);
                keys[n].hdkey = 0;                     /* 0 = the wallet's own seed */
                n++;
            }
        }
    }
    /* ...then every key ADDED by addhdkey. They join the same window, so the
     * rescan finds their outputs and getbalance counts them; without this the
     * added key would be stored and otherwise inert. */
    { int nh = wop_hdkeys_load();
      for (int h = 1; h <= nh; h++)
          for (unsigned i = 0; i < WOP_HDK_WINDOW && n + 2 <= cap; i++)
              for (int b = 0; b <= 1; b++){
                  unsigned char k[32], pub[33];
                  if (!wop_hdk_derive(h, i, b, k)) continue;
                  scalar_to_pubkey(pub, k);
                  hash160(keys[n].h160, pub, 33);
                  keys[n].keyidx = i; keys[n].branch = (unsigned char)b;
                  keys[n].hdkey = (unsigned char)h;
                  n++;
              } }
    qsort(keys, (size_t)n, sizeof keys[0], wscan_key_cmp);
    return n;
}

/* ==== importdescriptors (watch-only wallets), 2026-08-27 =================
 * Core imports descriptors into any descriptor wallet. This node's HD wallet
 * is seed-defined, so descriptor import is supported for WATCH-ONLY wallets
 * (createwallet name true) -- stated in the error for the seed case rather
 * than half-imported. Result shape matches Core: one {success[,error]} per
 * request, and a warnings entry telling the caller to rescan (Core rescans
 * from `timestamp` automatically; here the rescan is the explicit
 * rescanblockchain the rest of this file already documents). */
static int cmd_importdescriptors(const rj_val* params, const rpc_wallet* w,
                                 long* ec, const char** em, rj_val** res){
    if (!params || params->typ != RJ_ARR || params->nitems < 1 ||
        params->items[0]->typ != RJ_ARR)
        return wop_err(ec, em, -8, "importdescriptors requires an array of requests");
    if (!g_aw_watchonly)
        return wop_err(ec, em, -4,
            (w && w->seed)
              ? "importdescriptors on this node serves watch-only wallets "
                "(createwallet <name> true); the loaded wallet's keys come from "
                "its own seed and cannot adopt foreign descriptors"
              : "no wallet is loaded");
    const rj_val* reqs = params->items[0];
    wop_descs_load();
    rj_val* arr = rj_arr();
    int added = 0;
    for (unsigned long i = 0; i < reqs->nitems; i++){
        rj_val* r = rj_obj();
        const rj_val* q = reqs->items[i];
        const rj_val* dv = q->typ == RJ_OBJ ? rj_obj_get((rj_val*)q, "desc") : NULL;
        char norm[340]; char err[192]; int is_range = 0;
        if (!dv || dv->typ != RJ_STR){
            rj_obj_set(r, "success", rj_bool(0));
            rj_val* e = rj_obj();
            rj_obj_set(e, "code", rj_numf("%d", -8));
            rj_obj_set(e, "message", rj_str("Descriptor not found."));
            rj_obj_set(r, "error", e);
            rj_arr_push(arr, r); continue;
        }
        if (!rpc_desc_normalize(dv->str, norm, sizeof norm, &is_range, err, sizeof err)){
            rj_obj_set(r, "success", rj_bool(0));
            rj_val* e = rj_obj();
            rj_obj_set(e, "code", rj_numf("%d", -5));
            rj_obj_set(e, "message", rj_str(err));
            rj_obj_set(r, "error", e);
            rj_arr_push(arr, r); continue;
        }
        long range = 1;
        if (is_range){
            const rj_val* rg = rj_obj_get((rj_val*)q, "range");
            range = 1000;                            /* the scan window default */
            if (rg && rg->typ == RJ_NUM) range = strtol(rg->str, NULL, 10) + 1;
            else if (rg && rg->typ == RJ_ARR && rg->nitems == 2 &&
                     rg->items[1]->typ == RJ_NUM)
                range = strtol(rg->items[1]->str, NULL, 10) + 1;
            if (range < 1) range = 1;
            if (range > WOP_SCAN_KEYS) range = WOP_SCAN_KEYS;
        }
        int dup = 0;
        for (int k = 0; k < g_wd_n; k++) if (!strcmp(g_wd[k].desc, norm)){ dup = 1; break; }
        if (!dup && g_wd_n >= WOP_MAX_DESCS){
            rj_obj_set(r, "success", rj_bool(0));
            rj_val* e = rj_obj();
            rj_obj_set(e, "code", rj_numf("%d", -4));
            rj_obj_set(e, "message", rj_str("descriptor limit reached"));
            rj_obj_set(r, "error", e);
            rj_arr_push(arr, r); continue;
        }
        if (!dup){
            wop_desc_t* d = &g_wd[g_wd_n++];
            snprintf(d->desc, sizeof d->desc, "%s", norm);
            d->range = range; d->next = 0; d->script = 1;
            added++;
        }
        rj_obj_set(r, "success", rj_bool(1));
        rj_val* wa = rj_arr();
        rj_arr_push(wa, rj_str("run rescanblockchain to discover this descriptor's "
                               "history (this node does not rescan on import)"));
        rj_obj_set(r, "warnings", wa);
        rj_arr_push(arr, r);
    }
    if (added){ wop_descs_save(); g_wk_n = -1; wop_records_invalidate(); }
    *res = arr;
    return 1;
}

/* The next unused receive address of a watch-only wallet: descriptor slot 0's
 * next index (bumped and persisted). Exported for rpc_commands.c's
 * getnewaddress, whose HD path needs a seed this wallet does not have. */
int rpc_wops_watch_newaddress(char* out, long cap, long* ec, const char** em){
    static char perr[192];
    if (!g_aw_watchonly) return 0;
    if (wop_descs_load() < 1)
        return wop_err(ec, em, -4, "watch-only wallet has no descriptors: importdescriptors first");
    wop_desc_t* d = &g_wd[0];
    if (d->next >= d->range)
        return wop_err(ec, em, -4, "descriptor range exhausted");
    char err[128];
    if (!rpc_desc_address_at(d->desc, d->next, out, cap, err, sizeof err)){
        snprintf(perr, sizeof perr, "%s", err);
        return wop_err(ec, em, -4, perr);
    }
    d->next++;
    wop_descs_save();
    return 1;
}

/* hash160 of the key a record belongs to. */
static int wop_rec_h160(const wscan_key* keys, int nk, const wscan_rec* r, unsigned char h[20]){
    /* hdkey FIRST: two HD keys both have an index-0 receive key, so matching
     * on (keyidx, branch) alone hands back the wrong address as soon as a
     * second key exists -- and the wallet would then build a spend against a
     * scriptPubKey the coin is not locked to. */
    for (int i = 0; i < nk; i++)
        if (keys[i].hdkey == r->hdkey &&
            keys[i].keyidx == r->keyidx && keys[i].branch == r->branch){
            memcpy(h, keys[i].h160, 20); return 1; }
    return 0;
}

/* The wallet's own P2WPKH address for a key, as getnewaddress renders it. */
extern long wallet_p2wpkh_address(char* out, long cap, const unsigned char h160[20]);
extern int  wallet_script_to_address(char* out, long cap, const unsigned char* script, long slen);
/* the address of a key-window entry, by its output type: the stored 20 bytes
 * are the key hash (wpkh/pkh) or script hash (sh) directly; a tr entry holds
 * only the first 20 bytes of Q, so it is re-derived from the cached seed */
static int wop_key_address(const wscan_key* k, char* out, long cap){
    int t = WOT_TYPE(k->branch); unsigned char spk[34]; unsigned long sl = 0;
    if (t == WOT_BECH32){ spk[0]=0x00; spk[1]=0x14; memcpy(spk+2, k->h160, 20); sl = 22; }
    else if (t == WOT_LEGACY){ spk[0]=0x76; spk[1]=0xa9; spk[2]=0x14; memcpy(spk+3, k->h160, 20); spk[23]=0x88; spk[24]=0xac; sl = 25; }
    else if (t == WOT_P2SH_SEGWIT){ spk[0]=0xa9; spk[1]=0x14; memcpy(spk+2, k->h160, 20); spk[22]=0x87; sl = 23; }
    else {
        if (k->hdkey != 0) return -1;
        unsigned path[5]; rpc_wops_type_path(t, k->keyidx, WOT_CHAIN(k->branch), path);
        unsigned char kk[32], cc[32], pub[33], h20[20];
        if (bip32_derive_path(kk, cc, g_ks_seed, 64, path, 5) != 1) return -1;
        scalar_to_pubkey(pub, kk);
        if (!rpc_wops_type_spk(t, pub, spk, &sl, h20)) return -1;
    }
    out[0] = 0;
    return wallet_script_to_address(out, cap, spk, (long)sl) > 0 ? (int)strlen(out) : -1;
}
static const wscan_key* wop_rec_key(const wscan_key* keys, int nk, const wscan_rec* r){
    for (int i = 0; i < nk; i++)
        if (keys[i].hdkey == r->hdkey && keys[i].keyidx == r->keyidx && keys[i].branch == r->branch) return &keys[i];
    return NULL;
}

#define WOP_MAXREC 200000
static wscan_rec* g_wop_recs;
static long g_wop_nrec = -1;
static long g_wop_tipscanned = -1;

/* Load the record file once per process; re-loaded after a rescan. */
static long wop_records(wscan_rec** out){
    if (g_wop_nrec < 0){
        if (!g_wop_recs) g_wop_recs = malloc((size_t)WOP_MAXREC * sizeof *g_wop_recs);
        if (!g_wop_recs){ *out = NULL; return 0; }
        char pb[512];
        g_wop_nrec = wscan_read(wop_path(WOP_SCAN_REL, pb, sizeof pb),
                                g_wop_recs, WOP_MAXREC, &g_wop_tipscanned);
    }
    *out = g_wop_recs;
    return g_wop_nrec;
}
static void wop_records_invalidate(void){ g_wop_nrec = -1; g_wop_tipscanned = -1; }

/* No scan yet is a distinct state from "scanned and found nothing", and the
 * two must not be conflated: reporting 0.00000000 for an address when no
 * scan has run tells the caller something false. */
static int wop_need_scan(long* ec, const char** em){
    wscan_rec* r; wop_records(&r);
    if (g_wop_tipscanned >= 0) return 0;
    *ec = -4;
    *em = "no wallet rescan has completed, so this node does not know what "
          "this wallet has received. Run rescanblockchain first; answering "
          "0.00000000 here would be indistinguishable from an address that "
          "genuinely received nothing";
    return 1;
}

static int wop_confs(unsigned int height){
    long tip = g_wops_tip ? g_wops_tip() : -1;
    if (tip < 0 || (long)height > tip) return 0;
    return (int)(tip - (long)height + 1);
}

/* Look one of the wallet's own outputs up by outpoint, for the signer:
 * signrawtransactionwithwallet must know each input's value and
 * scriptPubKey (BIP143 commits to both), and for the wallet's own coins the
 * scan records carry exactly that. Spent-ness is deliberately not checked
 * here -- signing a transaction is not spending it, and the mempool is the
 * authority on double-spends at broadcast time. Returns 1 and fills value +
 * the P2WPKH h160, or 0 when the outpoint is not one the scan recorded. */
int rpc_wops_own_coin(const void* wseed, const unsigned char txid_wire[32], unsigned int vout,
                      unsigned long long* value_out, unsigned char h160_out[20]){
    rpc_wallet w; memset(&w, 0, sizeof w); w.seed = (const unsigned char*)wseed;
    const wscan_key* keys; int nk = wop_keyset_cached(&w, &keys);
    if (!keys) return 0;
    wscan_rec* recs; long n = wop_records(&recs);
    for (long i = 0; i < n; i++){
        if (recs[i].kind != 0) continue;
        if (recs[i].vout != vout || memcmp(recs[i].txid, txid_wire, 32)) continue;
        if (!wop_rec_h160(keys, nk, &recs[i], h160_out)) return 0;
        *value_out = recs[i].value;
        return 1;
    }
    return 0;
}

/* See rpc_wallet_ops.h. A receive is unspent when no SPEND record names its
 * outpoint -- a spend stores the outpoint it consumed as (prev_txid, vout).
 * Deliberately self-contained: the embedded RPC server has no UTXO handle
 * (only the standalone rpcd installs one) and the download worker writes
 * that store from another process, so the scan is the only source here that
 * is both available and safe.
 *
 * Returns -1 when no rescan has completed. A caller must NOT turn that into
 * 0.00000000: "I have not looked" and "you have nothing" are different
 * answers, and only one of them is true. */
int rpc_wops_wallet_coins(const void* wseed, rpc_wops_coin* out, int cap){
    if (!out || cap <= 0) return 0;
    rpc_wallet w; memset(&w, 0, sizeof w); w.seed = (const unsigned char*)wseed;
    const wscan_key* keys; int nk = wop_keyset_cached(&w, &keys);
    wscan_rec* recs; long n = wop_records(&recs);
    if (g_wop_tipscanned < 0) return -1;          /* no scan has completed */
    int m = 0;
    for (long i = 0; i < n && m < cap; i++){
        if (recs[i].kind != 0) continue;          /* receives only */
        int spent = 0;
        for (long j = 0; j < n; j++){
            if (recs[j].kind != 1) continue;
            if (recs[j].vout == recs[i].vout &&
                !memcmp(recs[j].prev_txid, recs[i].txid, 32)){ spent = 1; break; }
        }
        if (spent) continue;
        rpc_wops_coin* c = &out[m];
        memcpy(c->txid, recs[i].txid, 32);
        c->vout   = recs[i].vout;
        c->value  = recs[i].value;
        c->height = recs[i].height;
        c->is_coinbase = recs[i].is_coinbase ? 1 : 0;
        c->branch = recs[i].branch;
        memset(c->h160, 0, 20); c->spklen = 0; c->redeemlen = 0;
        if (keys && wop_rec_h160(keys, nk, &recs[i], c->h160)){
            int t = WOT_TYPE(c->branch);
            if (t == WOT_BECH32M){                       /* the window holds 20 of Q's 32 bytes: re-derive */
                unsigned path[5]; rpc_wops_type_path(t, recs[i].keyidx, WOT_CHAIN(c->branch), path);
                unsigned char kk[32], cc[32], pub[33], h20[20];
                if (recs[i].hdkey == 0 && bip32_derive_path(kk, cc, w.seed, 64, path, 5) == 1){ scalar_to_pubkey(pub, kk); rpc_wops_type_spk(t, pub, c->spk, &c->spklen, h20); }
            } else if (t == WOT_LEGACY){ c->spk[0]=0x76;c->spk[1]=0xa9;c->spk[2]=0x14;memcpy(c->spk+3,c->h160,20);c->spk[23]=0x88;c->spk[24]=0xac; c->spklen=25; }
            else if (t == WOT_P2SH_SEGWIT){ c->spk[0]=0xa9;c->spk[1]=0x14;memcpy(c->spk+2,c->h160,20);c->spk[22]=0x87; c->spklen=23;
                /* redeemScript = 0 <hash160(pub)> from the key at this index */
                unsigned path[5]; rpc_wops_type_path(t, recs[i].keyidx, WOT_CHAIN(c->branch), path);
                unsigned char kk[32], cc[32], pub[33], kh[20];
                if (recs[i].hdkey == 0 && bip32_derive_path(kk, cc, w.seed, 64, path, 5) == 1){ scalar_to_pubkey(pub, kk); hash160(kh, pub, 33); c->redeem[0]=0x00; c->redeem[1]=0x14; memcpy(c->redeem+2, kh, 20); c->redeemlen = 22; } }
            else { c->spk[0]=0x00; c->spk[1]=0x14; memcpy(c->spk+2, c->h160, 20); c->spklen = 22; }
        }
        m++;
    }
    return m;
}

/* rescanblockchain ( start_height stop_height ) */
static int cmd_rescanblockchain(const rj_val* params, const rpc_wallet* w,
                                long* ec, const char** em, rj_val** res){
    if ((!w || !w->seed) && !g_aw_watchonly)   /* watch-only rescans by descriptor keyset */
        return wop_err(ec, em, -4, "No wallet is loaded");
    if (!g_wops_read_block || !g_wops_tip)
        return wop_err(ec, em, -4,
            "no block archive is attached to the RPC layer, so there is "
            "nothing to rescan");
    long tip = g_wops_tip();
    if (tip < 0) return wop_err(ec, em, -28, "Loading block index...");
    long from = 0, to = tip;
    if (params && params->typ == RJ_ARR){
        if (params->nitems >= 1 && params->items[0]->typ == RJ_NUM) from = atol(params->items[0]->str);
        if (params->nitems >= 2 && params->items[1]->typ == RJ_NUM) to   = atol(params->items[1]->str);
    }
    if (from < 0) return wop_err(ec, em, -8, "Invalid start_height");
    if (to > tip) to = tip;
    if (to < from) return wop_err(ec, em, -8, "Invalid stop_height: must be >= start_height");

    const wscan_key* keys; int nk = wop_keyset_cached(w, &keys);
    if (!keys) return wop_err(ec, em, -7, "out of memory");
    char pb[512]; const char* path = wop_path(WOP_SCAN_REL, pb, sizeof pb);
    static char err[256];
    long n = wscan_run(from, to, keys, nk, g_wops_read_block,
                       g_wops_blockbuf, g_wops_bufcap, path,
                       1u << 20, NULL, NULL, err, sizeof err);
    if (n < 0){ *ec = -1; *em = err[0] ? err : "rescan failed"; return 0; }
    wop_records_invalidate();
    rj_val* o = rj_obj();
    rj_obj_set(o, "start_height", rj_numf("%ld", from));
    rj_obj_set(o, "stop_height",  rj_numf("%ld", to));
    *res = o;
    return 1;
}

/* Sum of receives to one hash160, at or above minconf. */
static unsigned long long wop_received_h160(const unsigned char h160[20], int minconf,
                                            const wscan_key* keys, int nk,
                                            rj_val* txids_out){
    wscan_rec* recs; long n = wop_records(&recs);
    unsigned long long total = 0;
    for (long i = 0; i < n; i++){
        if (recs[i].kind != 0) continue;
        unsigned char h[20];
        if (!wop_rec_h160(keys, nk, &recs[i], h)) continue;
        if (memcmp(h, h160, 20)) continue;
        if (wop_confs(recs[i].height) < minconf) continue;
        total += recs[i].value;
        if (txids_out){
            char hx[65];
            static const char* H = "0123456789abcdef";
            for (int k = 0; k < 32; k++){
                unsigned char b = recs[i].txid[31-k];
                hx[k*2] = H[b>>4]; hx[k*2+1] = H[b&15];
            }
            hx[64] = 0;
            int dup = 0;
            for (size_t j = 0; j < txids_out->nitems; j++)
                if (!strcmp(txids_out->items[j]->str, hx)){ dup = 1; break; }
            if (!dup) rj_arr_push(txids_out, rj_str(hx));
        }
    }
    return total;
}

static int wop_minconf_arg(const rj_val* params, size_t i, int dflt){
    if (params && params->typ == RJ_ARR && params->nitems > i &&
        params->items[i]->typ == RJ_NUM) return (int)atol(params->items[i]->str);
    return dflt;
}

/* Decode an address argument into the hash160 this wallet would match. */
static int wop_addr_h160(const char* addr, unsigned char h160[20], long* ec, const char** em){
    int t; unsigned char v, h[20], p32[32];
    if (!wallet_validate_address(addr, &t, &v, h, p32) ||
        (t != WOP_ADDR_P2PKH && t != WOP_ADDR_P2WPKH))
        return wop_err(ec, em, -5, "Invalid Bitcoin address");
    memcpy(h160, h, 20);
    return 1;
}

static int cmd_getreceivedbyaddress(const rj_val* params, const rpc_wallet* w,
                                    long* ec, const char** em, rj_val** res){
    const char* addr = wop_str_arg(params, 0);
    if (!addr) return wop_err(ec, em, -8, "getreceivedbyaddress requires an address");
    if (wop_need_scan(ec, em)) return 0;
    unsigned char want[20];
    if (!wop_addr_h160(addr, want, ec, em)) return 0;
    const wscan_key* keys; int nk = wop_keyset_cached(w, &keys);
    if (!keys) return wop_err(ec, em, -7, "out of memory");
    /* Core: an address the wallet does not own is an error, not a zero --
     * a zero would look like an owned address that received nothing. */
    int mine = 0;
    for (int i = 0; i < nk; i++) if (!memcmp(keys[i].h160, want, 20)){ mine = 1; break; }
    if (!mine) return wop_err(ec, em, -4, "Address not found in wallet");
    unsigned long long total = wop_received_h160(want, wop_minconf_arg(params, 1, 1), keys, nk, NULL);
    char am[32]; rpc_amounts((long long)total, am, sizeof am);
    *res = rj_numf("%s", am);
    return 1;
}

static int cmd_getreceivedbylabel(const rj_val* params, const rpc_wallet* w,
                                  long* ec, const char** em, rj_val** res){
    const char* label = wop_str_arg(params, 0);
    if (!label) return wop_err(ec, em, -8, "getreceivedbylabel requires a label");
    if (wop_need_scan(ec, em)) return 0;
    const wscan_key* keys; int nk = wop_keyset_cached(w, &keys);
    if (!keys) return wop_err(ec, em, -7, "out of memory");
    int minconf = wop_minconf_arg(params, 1, 1);
    char pb[512]; const char* lp = wop_path(WOP_LABELS_REL, pb, sizeof pb);
    int ln = lbl_count(lp), hits = 0;
    unsigned long long total = 0;
    for (int i = 0; i < ln; i++){
        char a[128], l[256];
        if (!lbl_get_i(lp, i, a, sizeof a, l, sizeof l)) continue;
        if (strcmp(l, label)) continue;
        unsigned char h[20];
        long e2; const char* m2;
        if (!wop_addr_h160(a, h, &e2, &m2)) continue;
        hits++;
        total += wop_received_h160(h, minconf, keys, nk, NULL);
    }
    if (!hits){
        static char msg[320];
        snprintf(msg, sizeof msg, "No addresses with label %s", label);
        return wop_err(ec, em, -11, msg);
    }
    char am[32]; rpc_amounts((long long)total, am, sizeof am);
    *res = rj_numf("%s", am);
    return 1;
}

/* The label of an address, "" when unlabelled. */
static void wop_label_of(const char* addr, char* out, int cap){
    char pb[512];
    lbl_get(wop_path(WOP_LABELS_REL, pb, sizeof pb), addr, out, cap);
}

static int cmd_listreceivedbyaddress(const rj_val* params, const rpc_wallet* w,
                                     long* ec, const char** em, rj_val** res){
    if (wop_need_scan(ec, em)) return 0;
    int minconf = wop_minconf_arg(params, 0, 1);
    int include_empty = 0;
    if (params && params->typ == RJ_ARR && params->nitems >= 2 &&
        params->items[1]->typ == RJ_BOOL) include_empty = params->items[1]->str[0] == '1';
    const wscan_key* keys; int nk = wop_keyset_cached(w, &keys);
    if (!keys) return wop_err(ec, em, -7, "out of memory");
    /* Only keys that actually appear in the scan are candidates, unless the
     * caller asked for empties -- otherwise this would list 2000 addresses. */
    wscan_rec* recs; long n = wop_records(&recs);
    rj_val* arr = rj_arr();
    for (int i = 0; i < nk; i++){
        int seen = 0;
        for (long r = 0; r < n && !seen; r++)
            if (recs[r].kind == 0 && recs[r].keyidx == keys[i].keyidx &&
                recs[r].branch == keys[i].branch) seen = 1;
        if (!seen && !include_empty) continue;
        char addr[96];
        if (wop_key_address(&keys[i], addr, sizeof addr) < 0) continue;
        rj_val* txids = rj_arr();
        unsigned long long total = wop_received_h160(keys[i].h160, minconf, keys, nk, txids);
        if (!total && !include_empty){ rj_free(txids); continue; }
        /* confirmations: Core reports the deepest (oldest) contributing tx */
        int confs = 0;
        for (long r = 0; r < n; r++)
            if (recs[r].kind == 0 && recs[r].keyidx == keys[i].keyidx &&
                recs[r].branch == keys[i].branch){
                int c = wop_confs(recs[r].height);
                if (c > confs) confs = c;
            }
        rj_val* e = rj_obj();
        rj_obj_set(e, "address", rj_str(addr));
        { char am[32]; rpc_amounts((long long)total, am, sizeof am);
          rj_obj_set(e, "amount", rj_numf("%s", am)); }
        rj_obj_set(e, "confirmations", rj_numf("%d", confs));
        { char lab[256]; wop_label_of(addr, lab, sizeof lab);
          rj_obj_set(e, "label", rj_str(lab)); }
        rj_obj_set(e, "txids", txids);
        rj_arr_push(arr, e);
    }
    *res = arr;
    return 1;
}

static int cmd_listreceivedbylabel(const rj_val* params, const rpc_wallet* w,
                                   long* ec, const char** em, rj_val** res){
    if (wop_need_scan(ec, em)) return 0;
    int minconf = wop_minconf_arg(params, 0, 1);
    const wscan_key* keys; int nk = wop_keyset_cached(w, &keys);
    if (!keys) return wop_err(ec, em, -7, "out of memory");
    char pb[512]; const char* lp = wop_path(WOP_LABELS_REL, pb, sizeof pb);
    int ln = lbl_count(lp);
    rj_val* arr = rj_arr();
    /* one entry per DISTINCT label that received something */
    char seen[64][256]; int ns = 0;
    for (int i = 0; i < ln && ns < 64; i++){
        char a[128], l[256];
        if (!lbl_get_i(lp, i, a, sizeof a, l, sizeof l)) continue;
        int dup = 0;
        for (int j = 0; j < ns; j++) if (!strcmp(seen[j], l)){ dup = 1; break; }
        if (dup) continue;
        snprintf(seen[ns++], 256, "%s", l);
        unsigned long long total = 0; int confs = 0;
        for (int k = 0; k < ln; k++){
            char a2[128], l2[256];
            if (!lbl_get_i(lp, k, a2, sizeof a2, l2, sizeof l2)) continue;
            if (strcmp(l2, l)) continue;
            unsigned char h[20]; long e2; const char* m2;
            if (!wop_addr_h160(a2, h, &e2, &m2)) continue;
            total += wop_received_h160(h, minconf, keys, nk, NULL);
            wscan_rec* recs; long n = wop_records(&recs);
            for (long r = 0; r < n; r++){
                if (recs[r].kind != 0) continue;
                unsigned char rh[20];
                if (!wop_rec_h160(keys, nk, &recs[r], rh) || memcmp(rh, h, 20)) continue;
                int c = wop_confs(recs[r].height);
                if (c > confs) confs = c;
            }
        }
        if (!total) continue;
        rj_val* e = rj_obj();
        { char am[32]; rpc_amounts((long long)total, am, sizeof am);
          rj_obj_set(e, "amount", rj_numf("%s", am)); }
        rj_obj_set(e, "confirmations", rj_numf("%d", confs));
        rj_obj_set(e, "label", rj_str(l));
        rj_arr_push(arr, e);
    }
    *res = arr;
    return 1;
}

/* listaddressgroupings -- Core groups addresses proven to share ownership by
 * having been spent together. This wallet is a single seed, so every address
 * it owns is provably one owner: one group. That is the honest grouping, and
 * it is also the maximally-correct one -- there is no partition of a
 * single-seed wallet into distinct owners. */
static int cmd_listaddressgroupings(const rpc_wallet* w, long* ec, const char** em, rj_val** res){
    if (wop_need_scan(ec, em)) return 0;
    const wscan_key* keys; int nk = wop_keyset_cached(w, &keys);
    if (!keys) return wop_err(ec, em, -7, "out of memory");
    wscan_rec* recs; long n = wop_records(&recs);
    rj_val* group = rj_arr();
    for (int i = 0; i < nk; i++){
        unsigned long long bal = 0; int seen = 0;
        for (long r = 0; r < n; r++){
            if (recs[r].keyidx != keys[i].keyidx || recs[r].branch != keys[i].branch) continue;
            seen = 1;
            if (recs[r].kind == 0) bal += recs[r].value; else bal -= recs[r].value;
        }
        if (!seen) continue;
        char addr[96];
        if (wop_key_address(&keys[i], addr, sizeof addr) < 0) continue;
        rj_val* e = rj_arr();
        rj_arr_push(e, rj_str(addr));
        { char am[32]; rpc_amounts((long long)bal, am, sizeof am);
          rj_arr_push(e, rj_numf("%s", am)); }
        { char lab[256]; wop_label_of(addr, lab, sizeof lab);
          if (lab[0]) rj_arr_push(e, rj_str(lab)); }
        rj_arr_push(group, e);
    }
    rj_val* arr = rj_arr();
    if (group->nitems) rj_arr_push(arr, group); else rj_free(group);
    *res = arr;
    return 1;
}

/* listsinceblock ( "blockhash" target_confirmations ... ) */
static int cmd_listsinceblock(const rj_val* params, const rpc_wallet* w,
                              long* ec, const char** em, rj_val** res){
    if (wop_need_scan(ec, em)) return 0;
    long since = -1;
    if (params && params->typ == RJ_ARR && params->nitems >= 1 &&
        params->items[0]->typ == RJ_STR && params->items[0]->str[0]){
        /* resolve the block hash to a height through the chain module */
        rj_val* hv = NULL; long e2; const char* m2;
        rj_val* p1 = rj_arr(); rj_arr_push(p1, rj_str(params->items[0]->str));
        int rc = rpc_chain_dispatch("getblockheader", p1, &hv, &e2, &m2);
        rj_free(p1);
        if (rc != 1 || !hv){ if (hv) rj_free(hv);
            return wop_err(ec, em, -5, "Block not found"); }
        rj_val* hh = rj_obj_get(hv, "height");
        since = hh ? atol(hh->str) : -1;
        rj_free(hv);
        if (since < 0) return wop_err(ec, em, -5, "Block not found");
    }
    const wscan_key* keys; int nk = wop_keyset_cached(w, &keys);
    if (!keys) return wop_err(ec, em, -7, "out of memory");
    wscan_rec* recs; long n = wop_records(&recs);
    rj_val* txs = rj_arr();
    static const char* HEX = "0123456789abcdef";
    for (long r = 0; r < n; r++){
        if ((long)recs[r].height <= since) continue;
        const wscan_key* rk = wop_rec_key(keys, nk, &recs[r]);
        if (!rk) continue;
        char addr[96];
        if (wop_key_address(rk, addr, sizeof addr) < 0) continue;
        rj_val* e = rj_obj();
        rj_obj_set(e, "address", rj_str(addr));
        rj_obj_set(e, "category", rj_str(recs[r].kind == 0 ? "receive" : "send"));
        { char am[32];
          rpc_amounts(recs[r].kind == 0 ? (long long)recs[r].value
                                        : -(long long)recs[r].value, am, sizeof am);
          rj_obj_set(e, "amount", rj_numf("%s", am)); }
        rj_obj_set(e, "vout", rj_numf("%u", recs[r].vout));
        rj_obj_set(e, "confirmations", rj_numf("%d", wop_confs(recs[r].height)));
        rj_obj_set(e, "blockheight", rj_numf("%u", recs[r].height));
        { char hx[65];
          for (int k = 0; k < 32; k++){
              unsigned char b = recs[r].txid[31-k];
              hx[k*2] = HEX[b>>4]; hx[k*2+1] = HEX[b&15];
          }
          hx[64] = 0;
          rj_obj_set(e, "txid", rj_str(hx)); }
        { char lab[256]; wop_label_of(addr, lab, sizeof lab);
          if (lab[0]) rj_obj_set(e, "label", rj_str(lab)); }
        rj_obj_set(e, "abandoned", rj_bool(0));
        /* blockhash/blocktime/blockindex/time are NOT emitted: the scan
         * records the height, and the rest would have to be invented. */
        rj_arr_push(txs, e);
    }
    rj_val* o = rj_obj();
    rj_obj_set(o, "transactions", txs);
    rj_obj_set(o, "removed", rj_arr());
    { long tip = g_wops_tip ? g_wops_tip() : -1;
      if (tip >= 0){
          rj_val* hv = NULL; long e2; const char* m2;
          rj_val* p1 = rj_arr(); rj_arr_push(p1, rj_numf("%ld", tip));
          if (rpc_chain_dispatch("getblockhash", p1, &hv, &e2, &m2) == 1 && hv)
              rj_obj_set(o, "lastblock", rj_str(hv->str));
          if (hv) rj_free(hv);
          rj_free(p1);
      } }
    *res = o;
    return 1;
}

/* abandontransaction "txid"
 * Core abandons an UNCONFIRMED wallet transaction so its inputs can be
 * respent. A transaction the scan has seen is confirmed, and Core refuses
 * that with -5. A transaction this node journalled but never saw confirmed
 * is the abandonable case, and the marker is recorded in labels-style
 * sidecar so gettransaction can report abandoned:true. */
#define WOP_ABANDON_REL "abandoned.dat"

static int wop_txid_from_arg(const rj_val* params, unsigned char out_wire[32],
                             char disp[65], long* ec, const char** em){
    const char* t = wop_str_arg(params, 0);
    if (!t || strlen(t) != 64) return wop_err(ec, em, -8, "Invalid or missing txid");
    for (int i = 0; i < 32; i++){
        int hi, lo; char a = t[i*2], b = t[i*2+1];
        if (a>='0'&&a<='9') hi=a-'0'; else if ((a|32)>='a'&&(a|32)<='f') hi=(a|32)-'a'+10;
        else return wop_err(ec, em, -8, "Invalid txid");
        if (b>='0'&&b<='9') lo=b-'0'; else if ((b|32)>='a'&&(b|32)<='f') lo=(b|32)-'a'+10;
        else return wop_err(ec, em, -8, "Invalid txid");
        out_wire[31-i] = (unsigned char)((hi<<4)|lo);
    }
    snprintf(disp, 65, "%s", t);
    return 1;
}

int rpc_wops_is_abandoned(const char* txid_display){
    char pb[512]; const char* p = wop_path(WOP_ABANDON_REL, pb, sizeof pb);
    FILE* f = fopen(p, "r");
    if (!f) return 0;
    char line[128]; int hit = 0;
    while (fgets(line, sizeof line, f)){
        size_t l = strlen(line);
        while (l && (line[l-1]=='\n' || line[l-1]=='\r')) line[--l] = 0;
        if (!strcmp(line, txid_display)){ hit = 1; break; }
    }
    fclose(f);
    return hit;
}

static int cmd_abandontransaction(const rj_val* params, long* ec, const char** em, rj_val** res){
    unsigned char wire[32]; char disp[65];
    if (!wop_txid_from_arg(params, wire, disp, ec, em)) return 0;
    if (wop_need_scan(ec, em)) return 0;
    wscan_rec* recs; long n = wop_records(&recs);
    for (long i = 0; i < n; i++)
        if (!memcmp(recs[i].txid, wire, 32))
            /* Core's exact refusal for a confirmed transaction */
            return wop_err(ec, em, -5, "Transaction not eligible for abandonment");
    if (rpc_wops_is_abandoned(disp)){ *res = rj_null(); return 1; }   /* idempotent */
    char pb[512]; const char* p = wop_path(WOP_ABANDON_REL, pb, sizeof pb);
    FILE* f = fopen(p, "a");
    if (!f) return wop_err(ec, em, -4, "Could not write the abandoned-transaction store");
    int bad = fprintf(f, "%s\n", disp) < 0;
    if (fflush(f) != 0 || fsync(fileno(f)) != 0) bad = 1;
    if (fclose(f) != 0) bad = 1;
    if (bad) return wop_err(ec, em, -4, "Could not write the abandoned-transaction store");
    *res = rj_null();
    return 1;
}

/* ==== coin selection, change, fee estimation, and the spend family =======
 * The four pieces Core has and this node did not: which of our outputs are
 * still unspent, which to select, what change to make, and what fee to pay.
 *
 * SIGNING IS DELEGATED. rpc_commands.c's signrawtransactionwithkey already
 * implements legacy, P2SH, BIP143 v0 and P2SH-wrapped v0 signing, and its
 * P2WPKH output is Core-validated in tests/test_rpc_signraw.c. The spend
 * path builds the transaction, then calls signrawtransactionwithwallet
 * through rpc_dispatch. A second signer here would be a second thing to keep
 * correct, and this is the one place in the node where getting signing
 * subtly wrong loses money rather than returning a wrong number.
 *
 * That also closes the gap recorded in the previous slice: wallet_core.c's
 * wallet_send_tx is legacy-P2PKH end to end and cannot spend this wallet's
 * P2WPKH outputs. Nothing below calls it. */

extern int rpc_dispatch(const char* method, const rj_val* params, const rpc_wallet* w,
                        rj_val** result, long* err_code, const char** err_msg);

/* ---- size model ---------------------------------------------------------
 * Weight units, so the vsize is Core's ceil(weight/4) rather than a
 * hand-rounded byte count. Every output this wallet spends is P2WPKH, which
 * is the only input form the selector will pick. */
#define WF_IN_BASE_WU   (41 * 4)     /* outpoint 36 + empty scriptSig 1 + seq 4 */
#define WF_IN_WIT_WU    108          /* count 1 + (1+72) sig + (1+33) pubkey */
#define WF_OVERHEAD_WU  (10 * 4 + 2) /* version+locktime+2 varints, + marker/flag */

static long wf_out_wu(unsigned long spklen){
    /* 8 value + varint(spklen) + spklen, all base bytes */
    unsigned long v = spklen < 0xfd ? 1 : 3;
    return (long)((8 + v + spklen) * 4);
}
static long wf_vsize(long weight){ return (weight + 3) / 4; }

/* ---- the wallet's spendable outputs -------------------------------------
 * Straight from the rescan: a receive with no later spend of the same
 * outpoint. Locked outputs (lockunspent) are excluded, which is the whole
 * point of having a lock set -- a funder that ignored it would spend coins
 * the operator explicitly reserved. */
typedef struct {
    unsigned char txid[32];      /* wire order */
    unsigned int  vout;
    unsigned long long value;
    unsigned int  keyidx;
    unsigned char branch;
    unsigned char h160[20];
} wf_coin;

static int wf_coins(const rpc_wallet* w, wf_coin* out, int cap, int minconf){
    const wscan_key* keys; int nk = wop_keyset_cached(w, &keys);
    if (!keys) return 0;
    wscan_rec* recs; long n = wop_records(&recs);
    int m = 0;
    for (long i = 0; i < n && m < cap; i++){
        if (recs[i].kind != 0) continue;
        if (wop_confs(recs[i].height) < minconf) continue;
        /* Spent later? Matched on the OUTPOINT the spend record carries --
         * (prev_txid, vout) -- not on a heuristic over value and key. Two
         * equal-valued receives at the same index to the same key would
         * collide under such a heuristic, and a collision here makes coin
         * selection spend an already-spent output: an invalid transaction,
         * not merely a wrong number. */
        int spent = 0;
        for (long j = 0; j < n; j++)
            if (recs[j].kind == 1 && recs[j].vout == recs[i].vout &&
                !memcmp(recs[j].prev_txid, recs[i].txid, 32)){ spent = 1; break; }
        if (spent) continue;
        if (rpc_wops_is_locked(recs[i].txid, recs[i].vout)) continue;
        /* avoid_reuse: skip a coin paying a destination this wallet has
         * already spent from. Storing the flag and then selecting the coin
         * anyway would tell the caller the wallet avoids reuse when it does
         * not, which is worse than not having the flag. */
        if (wop_avoid_reuse_load() &&
            wop_key_is_reused(recs, n, recs[i].keyidx, recs[i].branch)) continue;
        memcpy(out[m].txid, recs[i].txid, 32);
        out[m].vout = recs[i].vout;
        out[m].value = recs[i].value;
        out[m].keyidx = recs[i].keyidx;
        out[m].branch = recs[i].branch;
        if (!wop_rec_h160(keys, nk, &recs[i], out[m].h160)) continue;
        m++;
    }
    return m;
}

/* ---- fee rate -----------------------------------------------------------
 * Ask the node's own estimator (rpc_node's estimatesmartfee, an EMA over
 * accepted transactions). When it has no estimate -- a fresh node, an empty
 * mempool -- fall back to the minimum relay rate rather than inventing a
 * confident number. Returned in satoshis per 1000 vbytes, Core's unit. */
#define WF_MIN_RELAY_SAT_KVB 1000

static unsigned long long wf_feerate_sat_kvb(int conf_target){
    rj_val* p = rj_arr();
    rj_arr_push(p, rj_numf("%d", conf_target > 0 ? conf_target : 6));
    rj_val* r = NULL; long ec; const char* em;
    rpc_wallet dummy; memset(&dummy, 0, sizeof dummy);
    unsigned long long rate = 0;
    if (rpc_dispatch("estimatesmartfee", p, &dummy, &r, &ec, &em) == 1 && r){
        rj_val* fr = rj_obj_get(r, "feerate");
        if (fr && fr->str){
            /* BTC/kvB -> sat/kvB, parsed off the fixed-8 rendering */
            const char* dot = strchr(fr->str, '.');
            unsigned long long whole = strtoull(fr->str, NULL, 10), frac = 0;
            if (dot){
                char f[9]; int k = 0;
                for (const char* q = dot + 1; *q && k < 8; q++) f[k++] = *q;
                while (k < 8) f[k++] = '0';
                f[8] = 0;
                frac = strtoull(f, NULL, 10);
            }
            rate = whole * 100000000ULL + frac;
        }
    }
    if (r) rj_free(r);
    rj_free(p);
    if (rate < WF_MIN_RELAY_SAT_KVB) rate = WF_MIN_RELAY_SAT_KVB;
    return rate;
}

/* ---- selection ----------------------------------------------------------
 * Largest-first, iterating because the fee depends on how many inputs were
 * chosen and choosing another input raises the fee again. Core's algorithm
 * is branch-and-bound with a changeless preference; this is simpler and
 * says so -- it always pays a correct fee for the transaction it builds,
 * it just does not search for the cheapest input set.
 *
 * Returns the number selected, or -1 when the wallet cannot cover
 * target + fee at all. */
#define WF_MAX_IN 64
/* Below this, change is dropped into the fee rather than created: an output
 * that costs more to spend than it is worth is not worth making. Core calls
 * this the dust threshold; for P2WPKH at the min relay rate it is 294 sat. */
#define WF_DUST_SAT 294

static int wf_select(wf_coin* coins, int ncoins, unsigned long long target,
                     long out_wu, unsigned long long feerate_kvb,
                     int* pick, unsigned long long* fee_out,
                     unsigned long long* change_out){
    /* sort largest first */
    for (int i = 1; i < ncoins; i++){
        wf_coin k = coins[i]; int j = i - 1;
        while (j >= 0 && coins[j].value < k.value){ coins[j+1] = coins[j]; j--; }
        coins[j+1] = k;
    }
    unsigned long long sum = 0;
    int n = 0;
    for (int i = 0; i < ncoins && n < WF_MAX_IN; i++){
        pick[n++] = i;
        sum += coins[i].value;
        /* fee for this input count, WITH a change output -- assume change
         * until we find we do not need it, so we never under-pay */
        long wu = WF_OVERHEAD_WU + (long)n * (WF_IN_BASE_WU + WF_IN_WIT_WU)
                  + out_wu + wf_out_wu(22);
        unsigned long long fee = ((unsigned long long)wf_vsize(wu) * feerate_kvb + 999) / 1000;
        if (sum < target + fee) continue;
        unsigned long long change = sum - target - fee;
        if (change < WF_DUST_SAT){
            /* drop the change output: recompute the fee without it and give
             * the remainder to the miner rather than creating dust */
            long wu2 = WF_OVERHEAD_WU + (long)n * (WF_IN_BASE_WU + WF_IN_WIT_WU) + out_wu;
            unsigned long long fee2 = ((unsigned long long)wf_vsize(wu2) * feerate_kvb + 999) / 1000;
            if (sum < target + fee2) continue;
            *fee_out = sum - target;      /* everything left over is the fee */
            *change_out = 0;
            return n;
        }
        *fee_out = fee;
        *change_out = change;
        return n;
    }
    return -1;
}

/* ---- raw tx assembly ---------------------------------------------------- */
static long wf_vi(unsigned char* o, unsigned long long v){
    if (v < 0xfd){ o[0] = (unsigned char)v; return 1; }
    if (v <= 0xffff){ o[0]=0xfd; o[1]=(unsigned char)v; o[2]=(unsigned char)(v>>8); return 3; }
    o[0]=0xfe; for (int i=0;i<4;i++) o[1+i]=(unsigned char)(v>>(8*i)); return 5;
}
typedef struct { unsigned long long value; unsigned char spk[64]; unsigned long spklen; } wf_out;

static long wf_build_unsigned(unsigned char* o, const wf_coin* coins, const int* pick, int nin,
                              const wf_out* outs, int nout){
    long p = 0;
    for (int i=0;i<4;i++) o[p++] = (unsigned char)(2 >> (8*i));      /* version 2 */
    p += wf_vi(o + p, (unsigned long long)nin);
    for (int i = 0; i < nin; i++){
        memcpy(o + p, coins[pick[i]].txid, 32); p += 32;
        unsigned int vo = coins[pick[i]].vout;
        for (int k=0;k<4;k++) o[p++] = (unsigned char)(vo >> (8*k));
        o[p++] = 0x00;                                              /* empty scriptSig */
        for (int k=0;k<4;k++) o[p++] = (unsigned char)(0xfffffffdu >> (8*k)); /* RBF */
    }
    p += wf_vi(o + p, (unsigned long long)nout);
    for (int i = 0; i < nout; i++){
        for (int k=0;k<8;k++) o[p++] = (unsigned char)(outs[i].value >> (8*k));
        p += wf_vi(o + p, outs[i].spklen);
        memcpy(o + p, outs[i].spk, outs[i].spklen); p += (long)outs[i].spklen;
    }
    for (int k=0;k<4;k++) o[p++] = 0x00;                            /* locktime 0 */
    return p;
}

/* scriptPubKey for an address; 0 if it is not a destination we can pay. */
static int wf_addr_spk(const char* addr, unsigned char* spk, unsigned long* slen){
    int t; unsigned char v, h[20], p32[32];
    if (!wallet_validate_address(addr, &t, &v, h, p32)) return 0;
    switch (t){
        case WOP_ADDR_P2PKH:
            spk[0]=0x76;spk[1]=0xa9;spk[2]=0x14;memcpy(spk+3,h,20);spk[23]=0x88;spk[24]=0xac;
            *slen=25; return 1;
        case WOP_ADDR_P2SH:
            spk[0]=0xa9;spk[1]=0x14;memcpy(spk+2,h,20);spk[22]=0x87; *slen=23; return 1;
        case WOP_ADDR_P2WPKH:
            spk[0]=0x00;spk[1]=0x14;memcpy(spk+2,h,20); *slen=22; return 1;
        case WOP_ADDR_P2WSH:
            spk[0]=0x00;spk[1]=0x20;memcpy(spk+2,p32,32); *slen=34; return 1;
        case WOP_ADDR_P2TR:
            spk[0]=0x51;spk[1]=0x20;memcpy(spk+2,p32,32); *slen=34; return 1;
        default: return 0;
    }
}

static void wf_hex(char* out, const unsigned char* b, long n){
    static const char* H = "0123456789abcdef";
    for (long i = 0; i < n; i++){ out[i*2]=H[b[i]>>4]; out[i*2+1]=H[b[i]&15]; }
    out[n*2] = 0;
}

/* Fund a set of outputs: select coins, add change, return the unsigned hex
 * plus the prevtxs array signrawtransactionwithwallet needs for BIP143.
 * Returns 1, or 0 with *ec/*em set. */
static int wf_fund(const rpc_wallet* w, const wf_out* outs, int nout,
                   int conf_target, char** hex_out, rj_val** prevtxs_out,
                   unsigned long long* fee_out, int* changepos_out,
                   long* ec, const char** em){
    *hex_out = NULL; *prevtxs_out = NULL; *changepos_out = -1;
    if (wop_need_scan(ec, em)) return 0;
    static wf_coin coins[4096];
    int nc = wf_coins(w, coins, 4096, 1);
    if (nc == 0)
        return wop_err(ec, em, -6,
            "Insufficient funds: this wallet has no confirmed unspent outputs "
            "that the last rescan knows about. If it should have coins, the "
            "rescan may not have covered their height");
    unsigned long long target = 0;
    long out_wu = 0;
    for (int i = 0; i < nout; i++){ target += outs[i].value; out_wu += wf_out_wu(outs[i].spklen); }
    unsigned long long rate = wf_feerate_sat_kvb(conf_target);
    int pick[WF_MAX_IN];
    unsigned long long fee = 0, change = 0;
    /* ---- Branch-and-Bound first (Core SelectCoinsBnB; wallet_bnb.c) ----
     * A changeless solution beats every change-making one: no change output
     * to pay for now, no future fee to spend it. Effective values subtract
     * each input's own fee; the BnB target is the recipients plus the
     * NON-input fees (overhead + recipient outputs, no change); the window
     * is what change would cost -- creating it now at the target rate plus
     * spending it later at Core's DEFAULT_DISCARD_FEE (10000 sat/kvB over a
     * ~68 vbyte P2WPKH input). Falls back to the iterative largest-first
     * selector below whenever BnB finds nothing. */
    int nin = -1;
    {
        extern long wallet_bnb_select(const unsigned long long*, const long long*, int,
                                      unsigned long long, unsigned long long, int*, int);
        static int order[4096]; static unsigned long long eff[4096];
        unsigned long long in_fee =
            ((unsigned long long)wf_vsize(WF_IN_BASE_WU + WF_IN_WIT_WU) * rate + 999) / 1000;
        int ne = 0;
        for (int i = 0; i < nc && ne < 4096; i++)
            if (coins[i].value > in_fee){ order[ne] = i; eff[ne] = coins[i].value - in_fee; ne++; }
        for (int i = 1; i < ne; i++){                     /* sort DESCENDING by eff */
            int oi = order[i]; unsigned long long ei = eff[i]; int j = i - 1;
            while (j >= 0 && eff[j] < ei){ order[j+1] = order[j]; eff[j+1] = eff[j]; j--; }
            order[j+1] = oi; eff[j+1] = ei;
        }
        long base_wu = WF_OVERHEAD_WU + out_wu;
        unsigned long long base_fee = ((unsigned long long)wf_vsize(base_wu) * rate + 999) / 1000;
        unsigned long long change_out_cost =
            ((unsigned long long)wf_vsize(wf_out_wu(22)) * rate + 999) / 1000;
        unsigned long long change_spend_cost = (68ULL * 10000ULL + 999) / 1000;
        int bpick[WF_MAX_IN];
        long bn = wallet_bnb_select(eff, NULL, ne, target + base_fee,
                                    change_out_cost + change_spend_cost,
                                    bpick, WF_MAX_IN);
        if (bn > 0){
            unsigned long long sum = 0;
            for (long k = 0; k < bn; k++){ pick[k] = order[bpick[k]]; sum += coins[order[bpick[k]]].value; }
            nin = (int)bn;
            fee = sum - target;               /* changeless: the excess is fee */
            change = 0;
        }
    }
    if (nin < 0)
        nin = wf_select(coins, nc, target, out_wu, rate, pick, &fee, &change);
    if (nin < 0){
        unsigned long long have = 0;
        for (int i = 0; i < nc; i++) have += coins[i].value;
        static char msg[256];
        snprintf(msg, sizeof msg,
                 "Insufficient funds: %llu.%08llu available, and the target plus "
                 "fee at %llu sat/kvB exceeds it",
                 have/100000000ULL, have%100000000ULL, rate);
        return wop_err(ec, em, -6, msg);
    }
    /* outputs + change */
    wf_out all[64];
    int n_all = 0;
    for (int i = 0; i < nout && n_all < 63; i++) all[n_all++] = outs[i];
    if (change > 0){
        const wscan_key* keys; int nk = wop_keyset_cached(w, &keys);
        /* change goes to the internal branch at index 0, which is exactly
         * what getrawchangeaddress hands out */
        const unsigned char* ch = NULL;
        for (int i = 0; i < nk; i++)
            if (keys[i].keyidx == 0 && keys[i].branch == 1){ ch = keys[i].h160; break; }
        if (!ch) return wop_err(ec, em, -4, "cannot derive a change address");
        all[n_all].value = change;
        all[n_all].spk[0] = 0x00; all[n_all].spk[1] = 0x14;
        memcpy(all[n_all].spk + 2, ch, 20);
        all[n_all].spklen = 22;
        *changepos_out = n_all;
        n_all++;
    }
    static unsigned char raw[200000];
    long rlen = wf_build_unsigned(raw, coins, pick, nin, all, n_all);
    char* hx = malloc((size_t)rlen * 2 + 1);
    if (!hx) return wop_err(ec, em, -7, "out of memory");
    wf_hex(hx, raw, rlen);
    /* prevtxs: BIP143 commits to the value and the scriptPubKey of each
     * input, so the signer must be given both. */
    rj_val* pv = rj_arr();
    for (int i = 0; i < nin; i++){
        const wf_coin* c = &coins[pick[i]];
        rj_val* e = rj_obj();
        char tx[65];
        for (int k = 0; k < 32; k++){
            static const char* H = "0123456789abcdef";
            unsigned char b = c->txid[31-k];
            tx[k*2] = H[b>>4]; tx[k*2+1] = H[b&15];
        }
        tx[64] = 0;
        rj_obj_set(e, "txid", rj_str(tx));
        rj_obj_set(e, "vout", rj_numf("%u", c->vout));
        { char spkh[64]; unsigned char spk[22];
          spk[0]=0x00; spk[1]=0x14; memcpy(spk+2, c->h160, 20);
          wf_hex(spkh, spk, 22);
          rj_obj_set(e, "scriptPubKey", rj_str(spkh)); }
        { char am[32]; rpc_amounts((long long)c->value, am, sizeof am);
          rj_obj_set(e, "amount", rj_numf("%s", am)); }
        rj_arr_push(pv, e);
    }
    *hex_out = hx; *prevtxs_out = pv; *fee_out = fee;
    return 1;
}

/* Sign a funded transaction with the wallet, through the existing signer. */
static int wf_sign(const rpc_wallet* w, const char* hex, rj_val* prevtxs,
                   char** signed_out, long* ec, const char** em){
    *signed_out = NULL;
    rj_val* p = rj_arr();
    rj_arr_push(p, rj_str(hex));
    rj_arr_push(p, prevtxs);                 /* ownership moves into p */
    rj_val* r = NULL;
    int rc = rpc_dispatch("signrawtransactionwithwallet", p, w, &r, ec, em);
    rj_free(p);
    if (rc != 1){ if (r) rj_free(r); return 0; }
    rj_val* comp = rj_obj_get(r, "complete");
    rj_val* hx   = rj_obj_get(r, "hex");
    if (!comp || !comp->str || comp->str[0] != '1' || !hx){
        rj_free(r);
        return wop_err(ec, em, -4,
            "the wallet could not sign every input it selected. This should not "
            "happen for a wallet spending its own outputs -- it means an input "
            "was selected whose key is outside the derivation window the rescan "
            "and the signer share");
    }
    *signed_out = strdup(hx->str);
    rj_free(r);
    return *signed_out ? 1 : wop_err(ec, em, -7, "out of memory");
}

/* Broadcast through the same channel sendrawtransaction uses. */
static int wf_send(const rpc_wallet* w, const char* signed_hex, char** txid_out,
                   long* ec, const char** em){
    *txid_out = NULL;
    rj_val* p = rj_arr();
    rj_arr_push(p, rj_str(signed_hex));
    rj_val* r = NULL;
    int rc = rpc_dispatch("sendrawtransaction", p, w, &r, ec, em);
    rj_free(p);
    if (rc != 1){ if (r) rj_free(r); return 0; }
    *txid_out = r->str ? strdup(r->str) : NULL;
    rj_free(r);
    return *txid_out ? 1 : wop_err(ec, em, -7, "out of memory");
}

/* Collect (address -> amount) pairs from a Core-shaped amounts object. */
static int wf_outs_from_obj(const rj_val* o, wf_out* outs, int cap, int* n_out,
                            long* ec, const char** em){
    *n_out = 0;
    if (!o || o->typ != RJ_OBJ || o->nmembers == 0)
        return wop_err(ec, em, -8, "Invalid amounts object");
    for (size_t i = 0; i < o->nmembers && *n_out < cap; i++){
        const char* addr = o->members[i].key;
        rj_val* v = o->members[i].val;
        if (!v || v->typ != RJ_NUM) return wop_err(ec, em, -3, "Amount is not a number");
        long long sat = rpc_amount_to_sat(v->str);
        if (sat <= 0) return wop_err(ec, em, -3, "Invalid amount");
        wf_out* w = &outs[(*n_out)];
        if (!wf_addr_spk(addr, w->spk, &w->spklen)){
            static char msg[160];
            snprintf(msg, sizeof msg, "Invalid Bitcoin address: %s", addr);
            return wop_err(ec, em, -5, msg);
        }
        w->value = (unsigned long long)sat;
        (*n_out)++;
    }
    return 1;
}

static int cmd_sendtoaddress(const rj_val* params, const rpc_wallet* w,
                             long* ec, const char** em, rj_val** res){
    const char* addr = wop_str_arg(params, 0);
    if (!addr) return wop_err(ec, em, -8, "sendtoaddress requires an address");
    if (!params || params->nitems < 2 || params->items[1]->typ != RJ_NUM)
        return wop_err(ec, em, -3, "Amount is not a number");
    long long sat = rpc_amount_to_sat(params->items[1]->str);
    if (sat <= 0) return wop_err(ec, em, -3, "Invalid amount");
    wf_out o;
    if (!wf_addr_spk(addr, o.spk, &o.spklen))
        return wop_err(ec, em, -5, "Invalid Bitcoin address");
    o.value = (unsigned long long)sat;
    char* hex; rj_val* pv; unsigned long long fee; int cp;
    if (!wf_fund(w, &o, 1, 6, &hex, &pv, &fee, &cp, ec, em)) return 0;
    char* sgn;
    if (!wf_sign(w, hex, pv, &sgn, ec, em)){ free(hex); return 0; }
    free(hex);
    char* txid;
    if (!wf_send(w, sgn, &txid, ec, em)){ free(sgn); return 0; }
    free(sgn);
    *res = rj_str(txid);
    free(txid);
    return 1;
}

static int cmd_sendmany(const rj_val* params, const rpc_wallet* w,
                        long* ec, const char** em, rj_val** res){
    /* Core's signature is sendmany "" {addr:amt,...}; the first argument is
     * a legacy dummy that must be empty. */
    const rj_val* amounts = NULL;
    if (params && params->typ == RJ_ARR){
        if (params->nitems >= 2 && params->items[1]->typ == RJ_OBJ) amounts = params->items[1];
        else if (params->nitems >= 1 && params->items[0]->typ == RJ_OBJ) amounts = params->items[0];
    }
    wf_out outs[32]; int nout;
    if (!wf_outs_from_obj(amounts, outs, 32, &nout, ec, em)) return 0;
    char* hex; rj_val* pv; unsigned long long fee; int cp;
    if (!wf_fund(w, outs, nout, 6, &hex, &pv, &fee, &cp, ec, em)) return 0;
    char* sgn;
    if (!wf_sign(w, hex, pv, &sgn, ec, em)){ free(hex); return 0; }
    free(hex);
    char* txid;
    if (!wf_send(w, sgn, &txid, ec, em)){ free(sgn); return 0; }
    free(sgn);
    *res = rj_str(txid);
    free(txid);
    return 1;
}

/* send [{address:amount},...] ( conf_target ... ) -- Core's newer form,
 * returning {complete, txid}. */
static int cmd_send(const rj_val* params, const rpc_wallet* w,
                    long* ec, const char** em, rj_val** res){
    wf_out outs[32]; int nout = 0;
    if (!params || params->typ != RJ_ARR || params->nitems < 1)
        return wop_err(ec, em, -8, "send requires an outputs array");
    const rj_val* a = params->items[0];
    if (a->typ == RJ_OBJ){
        if (!wf_outs_from_obj(a, outs, 32, &nout, ec, em)) return 0;
    } else if (a->typ == RJ_ARR){
        for (size_t i = 0; i < a->nitems && nout < 32; i++){
            int k;
            if (!wf_outs_from_obj(a->items[i], outs + nout, 32 - nout, &k, ec, em)) return 0;
            nout += k;
        }
    } else return wop_err(ec, em, -8, "send requires an outputs array or object");
    int conf = 6;
    if (params->nitems >= 2 && params->items[1]->typ == RJ_NUM)
        conf = (int)atol(params->items[1]->str);
    char* hex; rj_val* pv; unsigned long long fee; int cp;
    if (!wf_fund(w, outs, nout, conf, &hex, &pv, &fee, &cp, ec, em)) return 0;
    char* sgn;
    if (!wf_sign(w, hex, pv, &sgn, ec, em)){ free(hex); return 0; }
    free(hex);
    char* txid;
    if (!wf_send(w, sgn, &txid, ec, em)){ free(sgn); return 0; }
    free(sgn);
    rj_val* o = rj_obj();
    rj_obj_set(o, "complete", rj_bool(1));
    rj_obj_set(o, "txid", rj_str(txid));
    free(txid);
    *res = o;
    return 1;
}

/* sendall ["addr",...] -- sweep every spendable output to the recipients.
 * With one recipient the whole balance minus the fee goes there and there is
 * no change output at all. */
static int cmd_sendall(const rj_val* params, const rpc_wallet* w,
                       long* ec, const char** em, rj_val** res){
    if (!params || params->typ != RJ_ARR || params->nitems < 1 ||
        params->items[0]->typ != RJ_ARR || params->items[0]->nitems != 1 ||
        params->items[0]->items[0]->typ != RJ_STR)
        return wop_err(ec, em, -8,
            "this node's sendall takes exactly one recipient address; splitting "
            "a sweep across several recipients needs Core's per-recipient "
            "proportioning, which is not implemented");
    if (wop_need_scan(ec, em)) return 0;
    const char* addr = params->items[0]->items[0]->str;
    unsigned char spk[64]; unsigned long slen;
    if (!wf_addr_spk(addr, spk, &slen)) return wop_err(ec, em, -5, "Invalid Bitcoin address");
    static wf_coin coins[4096];
    int nc = wf_coins(w, coins, 4096, 1);
    if (nc == 0) return wop_err(ec, em, -6, "Insufficient funds: nothing spendable to sweep");
    if (nc > WF_MAX_IN) nc = WF_MAX_IN;
    unsigned long long sum = 0;
    int pick[WF_MAX_IN];
    for (int i = 0; i < nc; i++){ pick[i] = i; sum += coins[i].value; }
    unsigned long long rate = wf_feerate_sat_kvb(6);
    long wu = WF_OVERHEAD_WU + (long)nc * (WF_IN_BASE_WU + WF_IN_WIT_WU) + wf_out_wu(slen);
    unsigned long long fee = ((unsigned long long)wf_vsize(wu) * rate + 999) / 1000;
    if (sum <= fee)
        return wop_err(ec, em, -6, "Insufficient funds: the sweep would not cover its own fee");
    wf_out o; o.value = sum - fee; memcpy(o.spk, spk, slen); o.spklen = slen;
    static unsigned char raw[200000];
    long rlen = wf_build_unsigned(raw, coins, pick, nc, &o, 1);
    char* hx = malloc((size_t)rlen*2+1);
    if (!hx) return wop_err(ec, em, -7, "out of memory");
    wf_hex(hx, raw, rlen);
    rj_val* pv = rj_arr();
    for (int i = 0; i < nc; i++){
        rj_val* e = rj_obj();
        char tx[65];
        static const char* H = "0123456789abcdef";
        for (int k = 0; k < 32; k++){ unsigned char b = coins[i].txid[31-k];
            tx[k*2]=H[b>>4]; tx[k*2+1]=H[b&15]; }
        tx[64]=0;
        rj_obj_set(e, "txid", rj_str(tx));
        rj_obj_set(e, "vout", rj_numf("%u", coins[i].vout));
        { char sh[64]; unsigned char s2[22];
          s2[0]=0x00;s2[1]=0x14; memcpy(s2+2, coins[i].h160, 20);
          wf_hex(sh, s2, 22); rj_obj_set(e, "scriptPubKey", rj_str(sh)); }
        { char am[32]; rpc_amounts((long long)coins[i].value, am, sizeof am);
          rj_obj_set(e, "amount", rj_numf("%s", am)); }
        rj_arr_push(pv, e);
    }
    char* sgn;
    if (!wf_sign(w, hx, pv, &sgn, ec, em)){ free(hx); return 0; }
    free(hx);
    char* txid;
    if (!wf_send(w, sgn, &txid, ec, em)){ free(sgn); return 0; }
    free(sgn);
    rj_val* out = rj_obj();
    rj_obj_set(out, "complete", rj_bool(1));
    rj_obj_set(out, "txid", rj_str(txid));
    free(txid);
    *res = out;
    return 1;
}

/* fundrawtransaction "hexstring" -- add inputs and change to a transaction
 * that already carries its outputs. Core also permits existing inputs; this
 * node funds only an INPUTLESS transaction and says so rather than
 * pretending to preserve inputs it did not select and cannot value. */
static int cmd_fundrawtransaction(const rj_val* params, const rpc_wallet* w,
                                  long* ec, const char** em, rj_val** res){
    const char* hex = wop_str_arg(params, 0);
    if (!hex) return wop_err(ec, em, -8, "fundrawtransaction requires a raw transaction");
    size_t hl = strlen(hex);
    if ((hl & 1) || hl/2 < 10) return wop_err(ec, em, -22, "TX decode failed");
    static unsigned char tx[200000];
    for (size_t i = 0; i < hl/2; i++){
        int a = hex[i*2], b = hex[i*2+1];
        a = (a<='9')?a-'0':((a|32)-'a'+10);
        b = (b<='9')?b-'0':((b|32)-'a'+10);
        if (a < 0 || a > 15 || b < 0 || b > 15) return wop_err(ec, em, -22, "TX decode failed");
        tx[i] = (unsigned char)((a<<4)|b);
    }
    unsigned long len = (unsigned long)(hl/2), p = 4;
    /* An inputless transaction's serialization -- version | 00 | n_out --
     * is byte-identical to a segwit marker+flag (00 01) followed by a real
     * input count, which is exactly why Core's fundrawtransaction carries an
     * `iswitness` heuristic parameter. This method accepts ONLY the
     * inputless form, so the inputless reading wins: tx[4] must be 0x00
     * (zero inputs) and what follows is the output count. A transaction
     * that genuinely carries inputs (segwit or not) is refused below either
     * way, so the ambiguity cannot make an inputful tx fund. */
    if (tx[p] != 0x00)
        return wop_err(ec, em, -8,
            "this node funds only an inputless transaction: it has no way to "
            "value inputs it did not select (no txindex), so it cannot compute "
            "the fee for a transaction that already carries some. Pass the "
            "outputs alone (createrawtransaction with an empty inputs array)");
    p += 1;
    unsigned long n_out = tx[p]; p += 1;
    if (n_out == 0 || n_out > 32) return wop_err(ec, em, -8, "expected 1..32 outputs");
    wf_out outs[32];
    for (unsigned long i = 0; i < n_out; i++){
        if (p + 8 > len) return wop_err(ec, em, -22, "TX decode failed");
        outs[i].value = 0;
        for (int k=0;k<8;k++) outs[i].value |= (unsigned long long)tx[p+k] << (8*k);
        p += 8;
        unsigned long sl = tx[p]; p += 1;
        if (sl > 64 || p + sl > len) return wop_err(ec, em, -22, "TX decode failed");
        memcpy(outs[i].spk, tx + p, sl); outs[i].spklen = sl; p += sl;
    }
    char* fhex; rj_val* pv; unsigned long long fee; int cp;
    if (!wf_fund(w, outs, (int)n_out, 6, &fhex, &pv, &fee, &cp, ec, em)) return 0;
    rj_free(pv);                       /* funding only; the caller signs */
    rj_val* o = rj_obj();
    rj_obj_set(o, "hex", rj_str(fhex));
    { char am[32]; rpc_amounts((long long)fee, am, sizeof am);
      rj_obj_set(o, "fee", rj_numf("%s", am)); }
    rj_obj_set(o, "changepos", rj_numf("%d", cp));
    free(fhex);
    *res = o;
    return 1;
}

/* walletcreatefundedpsbt -- the same funding, emitted as a PSBT. The PSBT is
 * produced by converttopsbt on the funded transaction, so there is one
 * serializer rather than two. */
static int cmd_walletcreatefundedpsbt(const rj_val* params, const rpc_wallet* w,
                                      long* ec, const char** em, rj_val** res){
    /* Core: walletcreatefundedpsbt ( [inputs] ) [outputs] ... -- the outputs
     * are the first ARRAY or OBJECT argument that is not an inputs list. */
    const rj_val* outs_arg = NULL;
    if (params && params->typ == RJ_ARR)
        for (size_t i = 0; i < params->nitems; i++){
            const rj_val* a = params->items[i];
            if (a->typ == RJ_OBJ){ outs_arg = a; break; }
            if (a->typ == RJ_ARR && a->nitems && a->items[0]->typ == RJ_OBJ &&
                rj_obj_get(a->items[0], "txid") == NULL){ outs_arg = a; break; }
        }
    wf_out outs[32]; int nout = 0;
    if (!outs_arg) return wop_err(ec, em, -8, "walletcreatefundedpsbt requires outputs");
    if (outs_arg->typ == RJ_OBJ){
        if (!wf_outs_from_obj(outs_arg, outs, 32, &nout, ec, em)) return 0;
    } else {
        for (size_t i = 0; i < outs_arg->nitems && nout < 32; i++){
            int k;
            if (!wf_outs_from_obj(outs_arg->items[i], outs + nout, 32 - nout, &k, ec, em)) return 0;
            nout += k;
        }
    }
    char* hex; rj_val* pv; unsigned long long fee; int cp;
    if (!wf_fund(w, outs, nout, 6, &hex, &pv, &fee, &cp, ec, em)) return 0;
    rj_free(pv);
    rj_val* p = rj_arr(); rj_arr_push(p, rj_str(hex));
    rj_val* r = NULL;
    int rc = rpc_dispatch("converttopsbt", p, w, &r, ec, em);
    rj_free(p);
    free(hex);
    if (rc != 1){ if (r) rj_free(r); return 0; }
    rj_val* o = rj_obj();
    rj_obj_set(o, "psbt", rj_str(r->str ? r->str : ""));
    { char am[32]; rpc_amounts((long long)fee, am, sizeof am);
      rj_obj_set(o, "fee", rj_numf("%s", am)); }
    rj_obj_set(o, "changepos", rj_numf("%d", cp));
    rj_free(r);
    *res = o;
    return 1;
}

/* ==== the refusals =======================================================
 * Each names the specific missing capability. None of them pretends. */
/* Three refusal texts lived here and every one of them had become FALSE as
 * the features they described being absent shipped: WOP_ONE_WALLET said
 * there was no multi-wallet manager (createwallet/loadwallet/unloadwallet/
 * restorewallet are real), WOP_NO_ENCRYPTION said there was no encryption
 * path (encryptwallet is real), WOP_NO_RESCAN said no rescan existed
 * (rescanblockchain is real, and getbalance/listunspent answer from it).
 * A stale refusal is worse than no refusal: it is a confident, specific,
 * wrong explanation, and a reader has no way to tell it from a live one.
 * Deleted 2026-08-27 with the calls that used them.
 *
 * WOP_NO_IMPORT survives because it is still true: adopting FOREIGN key
 * material needs a key store this single-seed wallet does not have. */
#define WOP_NO_IMPORT \
    "this wallet is a single BIP32 seed with no import path: it cannot adopt " \
    "foreign descriptors, keys or watch-only scripts, so there is nothing " \
    "this call could add"

/* The spend family. This is the one gap worth stating precisely, because the
 * pieces LOOK present and are not.
 *
 * wallet_core.c does have a send path -- wallet_sendtoaddress /
 * wallet_send_tx -- but it is legacy P2PKH end to end: every prevout is
 * assumed to be the spending key's P2PKH script, the destination is a P2PKH
 * hash160, change returns to a P2PKH, and signing produces legacy
 * SIGHASH_ALL scriptSigs with no witness. Meanwhile getnewaddress and
 * getrawchangeaddress hand out P2WPKH (bech32) addresses, so the wallet's
 * actual outputs are witness outputs that this path cannot spend.
 *
 * Wiring sendtoaddress onto it would build a transaction with an empty
 * witness and a legacy scriptSig against a v0 witness prevout: the RPC would
 * return a txid and the network would reject the transaction. A refusal is
 * strictly better than a plausible txid for a transaction that can never
 * confirm. Closing this properly means segwit wallet signing plus coin
 * selection, change policy and fee estimation -- a subsystem, not an RPC
 * shim -- and it is tracked as such. */
/* ==== bumpfee / psbtbumpfee (Core wallet/feebumper.cpp semantics) ==========
 *
 * The original of a bump is an UNCONFIRMED wallet transaction. This wallet
 * journals metadata, not raw bytes, so the MEMPOOL is the only place the
 * original still exists -- rpc_node_mempool_rawtx() copies it out under the
 * pool lock. Consequences, each stated where it bites below:
 *   - a wallet tx that has dropped out of the mempool cannot be re-bumped
 *     (Core can: mapWallet stores the tx). Refused with its own message.
 *   - "is this a wallet transaction" is decided by input ownership against
 *     the scan records (Core consults mapWallet).
 * Fee arithmetic mirrors Core's EstimateFeeRate/CheckFeeRate: the default
 * bump rate is the original's feerate + 1 sat/kvB + max(incrementalrelayfee,
 * WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB), floored by the estimator's
 * rate for the conf target; an explicit fee_rate (sat/vB) bypasses the
 * estimate but not the checks. The increase is taken from the CHANGE output
 * (shrunk; dropped to fees when it falls under the P2WPKH dust threshold).
 * DIVERGENCE (documented): Core's CreateTransaction may add further wallet
 * inputs when change cannot cover the increase; this implementation keeps
 * the input set fixed and refuses instead. Core's `outputs` /
 * `original_change_index` options are refused, not half-implemented. */

#define BF_WALLET_INCREMENTAL_KVB 5000ULL   /* Core WALLET_INCREMENTAL_RELAY_FEE */
#define BF_MAXTXFEE_SAT 10000000ULL         /* Core -maxtxfee default, 0.1 BTC */

/* Core's FormatMoney: BTC with trailing zeros stripped ("0.00001"). */
static void bf_fmt_money(long long sat, char* out, size_t cap){
    snprintf(out, cap, "%lld.%08lld", sat/100000000LL, sat%100000000LL);
    size_t l = strlen(out);
    while (l && out[l-1] == '0') out[--l] = 0;
    if (l && out[l-1] == '.') out[--l] = 0;
}

/* one dispatched call, result freed by caller; 0 on dispatch error (ec/em set) */
static int bf_call(const char* method, rj_val* params, const rpc_wallet* w,
                   rj_val** r, long* ec, const char** em){
    *r = NULL;
    int rc = rpc_dispatch(method, params, w, r, ec, em);
    rj_free(params);
    if (rc != 1){ if (*r){ rj_free(*r); *r = NULL; } return 0; }
    return 1;
}

/* ==== importprunedfunds / removeprunedfunds ==============================
 * Core's pair for a PRUNED node, which cannot rescan: you hand it a raw
 * transaction plus a BIP37 merkle proof, and it adds the transaction to the
 * wallet without touching the chain. Both were refused here as "no import
 * path", which conflated two different things -- this call imports no KEY
 * material, only the knowledge that an output we already own exists. Every
 * piece it needs was already built and tested:
 *
 *   - the proof is verified by verifytxoutproof, called as an RPC rather
 *     than reimplemented, so the BIP37 partial-merkle-tree walk and the
 *     "is this block in our chain" check are the same code the standalone
 *     call uses;
 *   - "is this output ours" is answered by wscan_spk_h160 against the same
 *     key window the rescan uses, exported for exactly this reason;
 *   - the record set is rewritten through wscan_write, which owns the
 *     on-disk layout, header-last, so a crash cannot leave a half file.
 *
 * What the wallet learns is a RECEIVE record per matching output, which is
 * precisely what a rescan of that block would have produced. */

static int cmd_importprunedfunds(const rj_val* params, const rpc_wallet* w,
                                 long* ec, const char** em, rj_val** res){
    const char* rawhex   = wop_str_arg(params, 0);
    const char* proofhex = wop_str_arg(params, 1);
    if (!rawhex || !proofhex)
        return wop_err(ec, em, -8, "importprunedfunds requires a raw transaction and a proof");
    /* Decoded by the RPC that already knows how to decode one, the same way
     * bumpfee reads its original -- parsing the bytes again here would be a
     * second transaction parser in a file that does not need one. */
    rj_val* dec = NULL;
    { rj_val* dp = rj_arr(); rj_arr_push(dp, rj_str(rawhex));
      if (!bf_call("decoderawtransaction", dp, w, &dec, ec, em)) return 0; }
    char txid_disp[65]; txid_disp[0] = 0;
    { rj_val* t = rj_obj_get(dec, "txid");
      if (t && t->str) snprintf(txid_disp, sizeof txid_disp, "%s", t->str); }
    unsigned char txid[32];
    if (!txid_disp[0] || !wop_hex32_le(txid_disp, txid)){
        rj_free(dec);
        return wop_err(ec, em, -22,
            "TX decode failed. Make sure the tx has at least one input."); }

    /* ---- the proof, through the RPC that already knows how to read one --- */
    rj_val* pv = rj_arr(); rj_arr_push(pv, rj_str(proofhex));
    rj_val* pr = NULL;
    if (!bf_call("verifytxoutproof", pv, w, &pr, ec, em)){ rj_free(dec); return 0; }
    int in_proof = 0;
    if (pr && pr->typ == RJ_ARR)
        for (size_t i = 0; i < pr->nitems; i++)
            if (pr->items[i]->str && !strcmp(pr->items[i]->str, txid_disp)) in_proof = 1;
    int proof_empty = !pr || pr->typ != RJ_ARR || pr->nitems == 0;
    rj_free(pr);
    if (proof_empty){
        rj_free(dec);
        /* our verifytxoutproof answers an empty array for BOTH a malformed
         * proof and a block outside our chain, so the message names both
         * rather than asserting which */
        return wop_err(ec, em, -5,
            "Something wrong with merkleblock: the proof did not verify, or its "
            "block is not in this node's chain"); }
    if (!in_proof){ rj_free(dec);
        return wop_err(ec, em, -5, "Transaction given doesn't exist in proof"); }

    /* ---- the block's height, from the header the proof carries ---------- */
    if (strlen(proofhex) < 160){ rj_free(dec);
        return wop_err(ec, em, -5, "Something wrong with merkleblock"); }
    unsigned char hdr80[80];
    for (int i = 0; i < 80; i++){
        int a = wop_hex1(proofhex[i*2]), b = wop_hex1(proofhex[i*2+1]);
        if (a < 0 || b < 0){ rj_free(dec);
            return wop_err(ec, em, -5, "Something wrong with merkleblock"); }
        hdr80[i] = (unsigned char)((a<<4)|b);
    }
    unsigned char bh[32];
    { extern void sha256d(unsigned char*, const void*, unsigned long);
      sha256d(bh, hdr80, 80); }
    char bh_disp[65]; wop_txid_hex(bh, bh_disp);
    long height = -1;
    { rj_val* bp = rj_arr(); rj_arr_push(bp, rj_str(bh_disp));
      rj_val* br = NULL;
      if (!bf_call("getblockheader", bp, w, &br, ec, em)){ rj_free(dec); return 0; }
      rj_val* hv = br ? rj_obj_get(br, "height") : NULL;
      if (hv && hv->str) height = atol(hv->str);
      rj_free(br); }
    if (height < 0){ rj_free(dec);
        return wop_err(ec, em, -5, "Block not found in chain"); }

    /* ---- which outputs are ours -- the SAME question the rescan asks ---- */
    const wscan_key* keys; int nk = wop_keyset_cached(w, &keys);
    if (nk <= 0){ rj_free(dec); return wop_err(ec, em, -4, "No wallet is loaded"); }
    /* a coinbase is stated by the decoded transaction itself: its single
     * input carries `coinbase` instead of a txid/vout, which is what
     * tx_to_json emits for the null outpoint */
    int is_cb = 0;
    { rj_val* vin = rj_obj_get(dec, "vin");
      if (vin && vin->typ == RJ_ARR && vin->nitems == 1 &&
          rj_obj_get(vin->items[0], "coinbase")) is_cb = 1; }

    wscan_rec* recs; long nrec = wop_records(&recs);
    if (nrec < 0) nrec = 0;
    static wscan_rec out[WOP_MAXREC];
    long n_out = 0;
    for (long i = 0; i < nrec && n_out < WOP_MAXREC; i++) out[n_out++] = recs[i];
    long tip = g_wop_tipscanned;

    int added = 0;
    { rj_val* vout = rj_obj_get(dec, "vout");
      for (size_t v = 0; vout && vout->typ == RJ_ARR && v < vout->nitems; v++){
          rj_val* o = vout->items[v];
          rj_val* amt = rj_obj_get(o, "value");
          rj_val* spk = rj_obj_get(o, "scriptPubKey");
          rj_val* shx = spk ? rj_obj_get(spk, "hex") : NULL;
          rj_val* nv  = rj_obj_get(o, "n");
          if (!amt || !amt->str || !shx || !shx->str) continue;
          unsigned vidx = nv && nv->str ? (unsigned)atol(nv->str) : (unsigned)v;
          long long sat = rpc_amount_to_sat(amt->str);
          if (sat < 0) continue;
          size_t sl2 = strlen(shx->str);
          if ((sl2 & 1) || sl2/2 > 128) continue;
          unsigned char spkb[128];
          int bad = 0;
          for (size_t k = 0; k < sl2/2; k++){
              int a = wop_hex1(shx->str[k*2]), b = wop_hex1(shx->str[k*2+1]);
              if (a < 0 || b < 0){ bad = 1; break; }
              spkb[k] = (unsigned char)((a<<4)|b);
          }
          if (bad) continue;
          const unsigned char* h160 = NULL;
          if (!wscan_spk_h160(spkb, (unsigned long)(sl2/2), &h160)) continue;
          for (int k = 0; k < nk; k++){
              if (memcmp(keys[k].h160, h160, 20)) continue;
              /* idempotent: an outpoint already recorded is left alone, so a
               * repeated import is a no-op rather than a double credit */
              int dup = 0;
              for (long q = 0; q < n_out; q++)
                  if (out[q].kind == 0 && out[q].vout == vidx &&
                      !memcmp(out[q].txid, txid, 32)){ dup = 1; break; }
              if (dup) break;
              if (n_out >= WOP_MAXREC) break;
              wscan_rec* r = &out[n_out++];
              memset(r, 0, sizeof *r);
              r->height = (unsigned)height;
              memcpy(r->txid, txid, 32);
              r->vout = vidx;
              r->value = (unsigned long long)sat;
              r->kind = 0;                       /* receive */
              r->keyidx = keys[k].keyidx;
              r->branch = keys[k].branch;
              r->is_coinbase = (unsigned char)is_cb;
              added++;
              break;
          }
      } }
    rj_free(dec);

    if (!added)
        return wop_err(ec, em, -5, "No addresses in wallet correspond to included transaction");

    /* the imported block may sit past what the last rescan covered; the file
     * must not claim to have scanned further than it has, so the tip only
     * ever moves FORWARD to at most this block */
    if (tip < height) tip = height;
    { char pb[512]; char werr[192]; werr[0] = 0;
      if (wscan_write(wop_path(WOP_SCAN_REL, pb, sizeof pb), out, n_out, tip,
                      werr, sizeof werr) != 0){
          static char msg[256];
          snprintf(msg, sizeof msg, "could not write the wallet record file: %s", werr);
          return wop_err(ec, em, -4, msg); } }
    wop_records_invalidate();
    *res = rj_null();
    return 1;
}

static int cmd_removeprunedfunds(const rj_val* params, const rpc_wallet* w,
                                 long* ec, const char** em, rj_val** res){
    (void)w;
    unsigned char txw[32]; char txd[65];
    if (!wop_txid_from_arg(params, txw, txd, ec, em)) return 0;
    wscan_rec* recs; long nrec = wop_records(&recs);
    if (nrec < 0) nrec = 0;
    static wscan_rec out[WOP_MAXREC];
    long n_out = 0; int removed = 0;
    for (long i = 0; i < nrec; i++){
        if (!memcmp(recs[i].txid, txw, 32)){ removed++; continue; }
        if (n_out < WOP_MAXREC) out[n_out++] = recs[i];
    }
    if (!removed){
        static char msg[128];
        snprintf(msg, sizeof msg, "Transaction %s does not belong to this wallet", txd);
        return wop_err(ec, em, -4, msg);          /* Core's wording and code */
    }
    { char pb[512]; char werr[192]; werr[0] = 0;
      if (wscan_write(wop_path(WOP_SCAN_REL, pb, sizeof pb), out, n_out,
                      g_wop_tipscanned, werr, sizeof werr) != 0){
          static char msg[256];
          snprintf(msg, sizeof msg, "could not write the wallet record file: %s", werr);
          return wop_err(ec, em, -4, msg); } }
    wop_records_invalidate();
    *res = rj_null();
    return 1;
}

static int cmd_bumpfee_common(const rj_val* params, const rpc_wallet* w,
                              long* ec, const char** em, rj_val** res, int want_psbt){
    if (rpc_wops_watchonly() && !want_psbt)
        return wop_err(ec, em, -4, "bumpfee is not available with wallets that "
                       "have private keys disabled. Use psbtbumpfee instead.");
    if (wop_need_scan(ec, em)) return 0;

    unsigned char txw[32]; char txd[65];
    if (!wop_txid_from_arg(params, txw, txd, ec, em)) return 0;

    /* ---- options ---- */
    long long opt_fee_rate_kvb = -1;   /* sat/kvB, -1 = not given */
    int conf_target = 0, replaceable = 1;
    if (params && params->nitems >= 2 && params->items[1]->typ == RJ_OBJ){
        const rj_val* o = params->items[1];
        const rj_val *v_ct = rj_obj_get((rj_val*)o, "conf_target");
        const rj_val *v_cT = rj_obj_get((rj_val*)o, "confTarget");
        const rj_val *v_fr = rj_obj_get((rj_val*)o, "fee_rate");
        if (v_ct && v_cT)
            return wop_err(ec, em, -8, "confTarget and conf_target options should "
                "not both be set. Use conf_target (confTarget is deprecated).");
        if (!v_ct) v_ct = v_cT;
        if (v_ct && v_fr)
            return wop_err(ec, em, -8, "Cannot specify both conf_target and fee_rate. "
                "Please provide either a confirmation target in blocks for automatic "
                "fee estimation, or an explicit fee rate.");
        if (v_ct){ if (v_ct->typ != RJ_NUM) return wop_err(ec, em, -8, "conf_target must be a number");
                   conf_target = (int)atol(v_ct->str); }
        if (v_fr){ if (v_fr->typ != RJ_NUM) return wop_err(ec, em, -3, "Invalid amount");
                   double fr = atof(v_fr->str);
                   if (fr <= 0) return wop_err(ec, em, -3, "Invalid amount");
                   opt_fee_rate_kvb = (long long)(fr * 1000.0 + 0.5); }
        { const rj_val* v = rj_obj_get((rj_val*)o, "replaceable");
          if (v && v->typ == RJ_BOOL && v->str) replaceable = (v->str[0] == '1'); }
        if (rj_obj_get((rj_val*)o, "outputs") || rj_obj_get((rj_val*)o, "original_change_index"))
            /* DIVERGENCE: Core rebuilds with caller-supplied outputs; this
             * wallet keeps the original outputs (change adjusted) only. */
            return wop_err(ec, em, -8, "the 'outputs' and 'original_change_index' "
                "options are not supported by this node; the bump keeps the "
                "original outputs with the fee drawn from change");
    }

    /* ---- the original: must be in the mempool (see header comment) ---- */
    static unsigned char raw[400000];
    long rlen = rpc_node_mempool_rawtx(txw, raw, sizeof raw);
    const wscan_key* keys; int nk = wop_keyset_cached(w, &keys);
    wscan_rec* recs; long nrec = wop_records(&recs);
    if (rlen < 0){
        /* mined? the scan saw this txid fund the wallet (its change output) */
        for (long i = 0; i < nrec; i++)
            if (recs[i].kind == 0 && !memcmp(recs[i].txid, txw, 32))
                return wop_err(ec, em, -4, "Transaction has been mined, or is "
                               "conflicted with a mined transaction");
        return wop_err(ec, em, -5, "Invalid or non-wallet transaction id");
    }

    /* ---- entry facts: old fee, vsize, descendants ---- */
    long long old_fee = -1, vsize = -1; int desc_count = 1;
    { rj_val* p = rj_arr(); rj_arr_push(p, rj_str(txd)); rj_val* r;
      if (!bf_call("getmempoolentry", p, w, &r, ec, em)) return 0;
      rj_val* vs = rj_obj_get(r, "vsize");
      rj_val* dc = rj_obj_get(r, "descendantcount");
      rj_val* fees = rj_obj_get(r, "fees");
      rj_val* base = fees ? rj_obj_get(fees, "base") : NULL;
      if (vs) vsize = atoll(vs->str);
      if (dc) desc_count = (int)atol(dc->str);
      if (base) old_fee = rpc_amount_to_sat(base->str);
      rj_free(r); }
    if (vsize <= 0 || old_fee < 0)
        return wop_err(ec, em, -4, "cannot read the original transaction's fee "
                       "from the mempool entry");
    if (desc_count > 1)
        return wop_err(ec, em, -8, "Transaction has descendants in the mempool");

    /* ---- decode the original ---- */
    static char rawhex[800001];
    wf_hex(rawhex, raw, rlen);
    rj_val* dec = NULL;
    { rj_val* p = rj_arr(); rj_arr_push(p, rj_str(rawhex));
      if (!bf_call("decoderawtransaction", p, w, &dec, ec, em)) return 0; }
    rj_val* vin = rj_obj_get(dec, "vin");
    rj_val* vout = rj_obj_get(dec, "vout");
    if (!vin || vin->typ != RJ_ARR || !vout || vout->typ != RJ_ARR || vin->nitems == 0){
        rj_free(dec); return wop_err(ec, em, -4, "cannot decode the original transaction"); }

    /* ---- inputs: every one must be a wallet-owned outpoint (require_mine;
     * for the scan-record ownership rule see the header comment) ---- */
    enum { BF_MAX_IN = 64, BF_MAX_OUT = 64 };
    if (vin->nitems > BF_MAX_IN || vout->nitems > BF_MAX_OUT){
        rj_free(dec); return wop_err(ec, em, -4, "transaction too large to bump"); }
    unsigned char in_txid[BF_MAX_IN][32]; unsigned int in_vout[BF_MAX_IN];
    unsigned long long in_val[BF_MAX_IN]; unsigned char in_h160[BF_MAX_IN][20];
    int nin = (int)vin->nitems, owned = 0;
    for (int i = 0; i < nin; i++){
        rj_val* e = vin->items[i];
        rj_val* t = rj_obj_get(e, "txid"); rj_val* n = rj_obj_get(e, "vout");
        if (!t || !n){ rj_free(dec); return wop_err(ec, em, -4, "cannot decode the original transaction"); }
        for (int k = 0; k < 32; k++){
            unsigned b; sscanf(t->str + 2*k, "%2x", &b);
            in_txid[i][31-k] = (unsigned char)b;         /* display -> wire */
        }
        in_vout[i] = (unsigned int)atol(n->str);
        int found = 0;
        for (long j = 0; j < nrec; j++)
            if (recs[j].kind == 0 && recs[j].vout == in_vout[i] &&
                !memcmp(recs[j].txid, in_txid[i], 32)){
                in_val[i] = recs[j].value;
                if (!wop_rec_h160(keys, nk, &recs[j], in_h160[i])) break;
                found = 1; break;
            }
        if (found) owned++;
    }
    if (owned != nin){
        rj_free(dec);
        /* zero wallet inputs: not our transaction at all (Core: mapWallet
         * miss, -5); some-but-not-all: Core's require_mine refusal (-4) */
        return wop_err(ec, em, owned ? -4 : -5, owned
            ? "Transaction contains inputs that don't belong to this wallet"
            : "Invalid or non-wallet transaction id");
    }

    /* ---- outputs + change detection (branch-1 P2WPKH = our change) ---- */
    wf_out outs[BF_MAX_OUT]; int nout = (int)vout->nitems, change_idx = -1;
    for (int i = 0; i < nout; i++){
        rj_val* e = vout->items[i];
        rj_val* v = rj_obj_get(e, "value");
        rj_val* spk = rj_obj_get(e, "scriptPubKey");
        rj_val* hx = spk ? rj_obj_get(spk, "hex") : NULL;
        if (!v || !hx){ rj_free(dec); return wop_err(ec, em, -4, "cannot decode the original transaction"); }
        long long sat = rpc_amount_to_sat(v->str);
        size_t hl = strlen(hx->str);
        if (sat < 0 || hl/2 > sizeof outs[i].spk){ rj_free(dec); return wop_err(ec, em, -4, "cannot decode the original transaction"); }
        outs[i].value = (unsigned long long)sat;
        outs[i].spklen = hl/2;
        for (size_t k = 0; k < hl/2; k++){ unsigned b; sscanf(hx->str + 2*k, "%2x", &b); outs[i].spk[k] = (unsigned char)b; }
        if (outs[i].spklen == 22 && outs[i].spk[0] == 0x00 && outs[i].spk[1] == 0x14)
            for (int j = 0; j < nk; j++)
                if (keys[j].branch == 1 && !memcmp(keys[j].h160, outs[i].spk + 2, 20)){
                    change_idx = i; break; }
    }
    rj_free(dec);

    /* ---- fee targets (Core EstimateFeeRate / CheckFeeRate) ---- */
    long long mempool_min_kvb = 1000, incr_kvb = 1000;
    { rj_val* p = rj_arr(); rj_val* r;
      if (bf_call("getmempoolinfo", p, w, &r, ec, em)){
          rj_val* mm = rj_obj_get(r, "mempoolminfee");
          rj_val* ir = rj_obj_get(r, "incrementalrelayfee");
          if (mm) mempool_min_kvb = rpc_amount_to_sat(mm->str);
          if (ir) incr_kvb = rpc_amount_to_sat(ir->str);
          rj_free(r);
      } else { *ec = 0; *em = NULL; } }
    long long rate_kvb;
    if (opt_fee_rate_kvb > 0) rate_kvb = opt_fee_rate_kvb;
    else {
        /* TRUNCATING, like Core's CFeeRate(old_fee, txSize) whose GetFeePerK
         * evaluates the rational DOWN. Core's comment says why the +1 below
         * exists: "calculated from the tx fee/vsize, so it may have been
         * rounded down. Add 1 satoshi to the result." Rounding up here AND
         * adding 1 would double-compensate and overpay by 1 sat/kvB on every
         * bump whose fee*1000 is not a multiple of its vsize. */
        long long orig_kvb = old_fee * 1000 / vsize;
        long long wallet_incr = incr_kvb > (long long)BF_WALLET_INCREMENTAL_KVB
                              ? incr_kvb : (long long)BF_WALLET_INCREMENTAL_KVB;
        rate_kvb = orig_kvb + 1 + wallet_incr;
        long long est = (long long)wf_feerate_sat_kvb(conf_target > 0 ? conf_target : 6);
        if (est > rate_kvb) rate_kvb = est;
    }
    if (rate_kvb < mempool_min_kvb){
        static char m[192]; char a[24], b[24];
        bf_fmt_money(rate_kvb, a, sizeof a); bf_fmt_money(mempool_min_kvb, b, sizeof b);
        snprintf(m, sizeof m, "New fee rate (%s) is lower than the minimum fee rate "
                 "(%s) to get into the mempool -- ", a, b);
        return wop_err(ec, em, -4, m);
    }
    long long new_fee = (rate_kvb * vsize + 999) / 1000;
    long long incr_fee = (incr_kvb * vsize + 999) / 1000;
    if (new_fee < old_fee + incr_fee){
        static char m[224]; char a[24], b[24], c[24], d[24];
        bf_fmt_money(new_fee, a, sizeof a); bf_fmt_money(old_fee + incr_fee, b, sizeof b);
        bf_fmt_money(old_fee, c, sizeof c); bf_fmt_money(incr_fee, d, sizeof d);
        snprintf(m, sizeof m, "Insufficient total fee %s, must be at least %s "
                 "(oldFee %s + incrementalFee %s)", a, b, c, d);
        return wop_err(ec, em, -8, m);
    }
    { long long required = (WF_MIN_RELAY_SAT_KVB * (long long)vsize + 999) / 1000;
      if (new_fee < required){
          static char m[160]; char a[24];
          bf_fmt_money(required, a, sizeof a);
          snprintf(m, sizeof m, "Insufficient total fee (cannot be less than "
                   "required fee %s)", a);
          return wop_err(ec, em, -8, m);
      } }
    if (new_fee > (long long)BF_MAXTXFEE_SAT){
        static char m[192]; char a[24], b[24];
        bf_fmt_money(new_fee, a, sizeof a); bf_fmt_money((long long)BF_MAXTXFEE_SAT, b, sizeof b);
        snprintf(m, sizeof m, "Specified or calculated fee %s is too high (cannot "
                 "be higher than -maxtxfee %s)", a, b);
        return wop_err(ec, em, -4, m);
    }

    /* ---- take the increase from change (see header for the divergence) ---- */
    if (change_idx < 0)
        return wop_err(ec, em, -4, "the original transaction has no change output "
            "this wallet can draw the fee increase from (Core would add inputs; "
            "this node keeps the input set fixed)");
    long long delta = new_fee - old_fee;
    /* P2WPKH dust at Core's default -dustrelayfee (3000 sat/kvB): 31 vB of
     * output + ~67.75 vB to later spend it -> 294 sat. The config knob lives
     * in the daemon (node_config); this file also links into the standalone
     * rpcd, so the DEFAULT is used here -- stated, not silently assumed. */
    long long dust = 294;
    long long ch = (long long)outs[change_idx].value - delta;
    int drop_change = 0;
    if (ch < dust){
        /* the whole change joins the fee, exactly Core's dust-change rule */
        drop_change = 1;
        new_fee = old_fee + (long long)outs[change_idx].value;
    } else outs[change_idx].value = (unsigned long long)ch;

    /* ---- rebuild (same inputs; sequence signals per `replaceable`) ---- */
    static unsigned char nraw[400000];
    long p2 = 0;
    unsigned int seq = replaceable ? 0xfffffffdu : 0xfffffffeu;
    for (int i = 0; i < 4; i++) nraw[p2++] = (unsigned char)(2 >> (8*i));
    p2 += wf_vi(nraw + p2, (unsigned long long)nin);
    for (int i = 0; i < nin; i++){
        memcpy(nraw + p2, in_txid[i], 32); p2 += 32;
        for (int k = 0; k < 4; k++) nraw[p2++] = (unsigned char)(in_vout[i] >> (8*k));
        nraw[p2++] = 0x00;
        for (int k = 0; k < 4; k++) nraw[p2++] = (unsigned char)(seq >> (8*k));
    }
    p2 += wf_vi(nraw + p2, (unsigned long long)(nout - drop_change));
    for (int i = 0; i < nout; i++){
        if (drop_change && i == change_idx) continue;
        for (int k = 0; k < 8; k++) nraw[p2++] = (unsigned char)(outs[i].value >> (8*k));
        p2 += wf_vi(nraw + p2, outs[i].spklen);
        memcpy(nraw + p2, outs[i].spk, outs[i].spklen); p2 += (long)outs[i].spklen;
    }
    for (int k = 0; k < 4; k++) nraw[p2++] = 0x00;
    static char nhex[800001];
    wf_hex(nhex, nraw, p2);

    char oldfee_s[24], newfee_s[24];
    rpc_amounts(old_fee, oldfee_s, sizeof oldfee_s);
    rpc_amounts(new_fee, newfee_s, sizeof newfee_s);

    if (want_psbt){
        rj_val* p = rj_arr(); rj_arr_push(p, rj_str(nhex)); rj_val* r;
        if (!bf_call("converttopsbt", p, w, &r, ec, em)) return 0;
        rj_val* o = rj_obj();
        rj_obj_set(o, "psbt", rj_str(r->str ? r->str : ""));
        rj_free(r);
        rj_obj_set(o, "origfee", rj_numf("%s", oldfee_s));
        rj_obj_set(o, "fee", rj_numf("%s", newfee_s));
        rj_obj_set(o, "errors", rj_arr());
        *res = o;
        return 1;
    }

    /* ---- sign + broadcast (RBF admission enforces the replacement rules) ---- */
    rj_val* pv = rj_arr();
    for (int i = 0; i < nin; i++){
        rj_val* e = rj_obj();
        char tx[65];
        for (int k = 0; k < 32; k++){
            static const char* H = "0123456789abcdef";
            unsigned char b = in_txid[i][31-k];
            tx[k*2] = H[b>>4]; tx[k*2+1] = H[b&15];
        }
        tx[64] = 0;
        rj_obj_set(e, "txid", rj_str(tx));
        rj_obj_set(e, "vout", rj_numf("%u", in_vout[i]));
        { char spkh[48]; unsigned char spk[22];
          spk[0]=0x00; spk[1]=0x14; memcpy(spk+2, in_h160[i], 20);
          wf_hex(spkh, spk, 22);
          rj_obj_set(e, "scriptPubKey", rj_str(spkh)); }
        { char am[32]; rpc_amounts((long long)in_val[i], am, sizeof am);
          rj_obj_set(e, "amount", rj_numf("%s", am)); }
        rj_arr_push(pv, e);
    }
    char* sgn;
    if (!wf_sign(w, nhex, pv, &sgn, ec, em)) return 0;
    char* newtxid;
    if (!wf_send(w, sgn, &newtxid, ec, em)){ free(sgn); return 0; }
    free(sgn);

    /* replaced-by linkage sidecar (gettransaction reports both directions) */
    { char pb[512]; FILE* f = fopen(wop_path("bumped.dat", pb, sizeof pb), "a");
      if (f){ fprintf(f, "%s %s\n", txd, newtxid); fclose(f); } }

    /* ...and BOTH transactions into the wallet's send journal, which is what
     * makes that sidecar reachable at all. gettransaction answers from the
     * journal, and until now nothing in the DAEMON ever wrote it -- only the
     * wallet_cli tool did -- so a bump performed over RPC produced a linkage
     * that no RPC could then read back. Writing only the replacement would
     * leave replaced_by_txid, the direction a caller actually asks for,
     * still unreachable on the original.
     *
     * The amount is the non-change total and the destination the first
     * non-change output, matching what the CLI records for a send. A bump
     * keeps the original outputs and takes the fee from change, so these are
     * the same on both rows -- only the fee differs, which is the point. */
    { long long sent = 0; unsigned char dest[20]; int have_dest = 0;
      for (int i = 0; i < nout; i++){
          if (i == change_idx) continue;
          sent += (long long)outs[i].value;
          if (!have_dest && outs[i].spklen >= 22 &&
              outs[i].spk[0] == 0x00 && outs[i].spk[1] == 0x14){
              memcpy(dest, outs[i].spk + 2, 20); have_dest = 1;      /* P2WPKH */
          } else if (!have_dest && outs[i].spklen == 25 && outs[i].spk[0] == 0x76){
              memcpy(dest, outs[i].spk + 3, 20); have_dest = 1;      /* P2PKH  */
          }
      }
      if (!have_dest) memset(dest, 0, 20);
      unsigned char nid[32];
      if (wop_hex32_le(newtxid, nid)){   /* display -> internal, the order the journal stores */
          extern int txlog_append_sent(const char*, const unsigned char[32],
                                       long long, long long, const unsigned char[20],
                                       unsigned long, long);
          /* The journal sits beside the WALLET, so it has to be resolved the
           * way every other wallet file is. Passing NULL takes the library's
           * "data/bmcwallet.dat" default, which is the CLI's layout, not the
           * daemon's -- on a per-chain datadir there is no data/ directory
           * and the write silently goes nowhere. */
          char wb[512]; const char* wpath = wop_path("bmcwallet.dat", wb, sizeof wb);
          txlog_append_sent(wpath, txw, sent, old_fee, dest, (unsigned long)nin, rlen);
          txlog_append_sent(wpath, nid, sent, new_fee, dest, (unsigned long)nin, p2);
      } }

    rj_val* o = rj_obj();
    rj_obj_set(o, "txid", rj_str(newtxid));
    free(newtxid);
    rj_obj_set(o, "origfee", rj_numf("%s", oldfee_s));
    rj_obj_set(o, "fee", rj_numf("%s", newfee_s));
    rj_obj_set(o, "errors", rj_arr());
    *res = o;
    return 1;
}

/* replaced_by/replaces lookup for gettransaction (rpc_commands.c). Fills
 * either direction from the bumped.dat sidecar; empty string = no link. */
int rpc_wops_bump_link(const char* txid_disp, char* replaced_by, size_t rb_cap,
                       char* replaces, size_t rp_cap){
    replaced_by[0] = 0; replaces[0] = 0;
    char pb[512]; FILE* f = fopen(wop_path("bumped.dat", pb, sizeof pb), "r");
    if (!f) return 0;
    char oldid[80], newid[80]; int hit = 0;
    while (fscanf(f, "%79s %79s", oldid, newid) == 2){
        if (!strcmp(oldid, txid_disp)){ snprintf(replaced_by, rb_cap, "%s", newid); hit = 1; }
        if (!strcmp(newid, txid_disp)){ snprintf(replaces, rp_cap, "%s", oldid); hit = 1; }
    }
    fclose(f);
    return hit;
}

#define WOP_NO_FUNDING \
    "this node cannot construct a spend: its wallet hands out P2WPKH " \
    "addresses but wallet_core's send path is legacy-P2PKH end to end " \
    "(legacy scriptSigs, no witness), so it cannot spend the wallet's own " \
    "outputs. There is also no coin selection, change policy or fee " \
    "estimation. Signing an EXISTING transaction does work: use " \
    "createrawtransaction then signrawtransactionwithwallet, which signs " \
    "the inputs the wallet holds keys for and reports the rest in errors[]"

static int wop_unsupported(const char* msg, long* ec, const char** em){
    *ec = -1; *em = msg; return 0;
}

/* ==== dispatch =========================================================== */

static const char* const WOP_METHODS[] = {
    "setlabel", "listlabels", "getaddressesbylabel",
    "listwallets", "listwalletdir",
    "listlockunspent", "lockunspent",
    "signmessage", "backupwallet", "keypoolrefill", "abortrescan",
    "listdescriptors", "gethdkeys",
    "walletlock", "walletpassphrase", "walletpassphrasechange",
    "encryptwallet", "createwallet", "loadwallet", "unloadwallet",
    "restorewallet", "migratewallet", "setwalletflag",
    "importdescriptors", "createwalletdescriptor", "addhdkey",
    "importprunedfunds", "removeprunedfunds", "exportwatchonlywallet",
    "walletdisplayaddress", "rescanblockchain",
    "getreceivedbyaddress", "getreceivedbylabel",
    "listreceivedbyaddress", "listreceivedbylabel",
    "listaddressgroupings", "listsinceblock", "abandontransaction",
    "sendtoaddress", "sendmany", "send", "sendall", "fundrawtransaction",
    "walletcreatefundedpsbt", "walletprocesspsbt", "bumpfee", "psbtbumpfee",
    NULL
};


const char* rpc_wops_method_at(int i){
    int n = 0;
    while (WOP_METHODS[n]) n++;
    return (i >= 0 && i < n) ? WOP_METHODS[i] : NULL;
}
int rpc_wops_known_method(const char* m){
    for (int i = 0; WOP_METHODS[i]; i++) if (!strcmp(m, WOP_METHODS[i])) return 1;
    return 0;
}

int rpc_wops_dispatch(const char* m, const rj_val* params, const rpc_wallet* w,
                      rj_val** res, long* ec, const char** em){
    if (!rpc_wops_known_method(m)) return -1;

    if (!strcmp(m, "setlabel"))            return cmd_setlabel(params, ec, em, res);
    if (!strcmp(m, "listlabels"))          return cmd_listlabels(params, res);
    if (!strcmp(m, "getaddressesbylabel")) return cmd_getaddressesbylabel(params, ec, em, res);
    if (!strcmp(m, "listwallets"))         return cmd_listwallets(res);
    if (!strcmp(m, "listwalletdir"))       return cmd_listwalletdir(res);
    if (!strcmp(m, "listlockunspent"))     return cmd_listlockunspent(res);
    if (!strcmp(m, "lockunspent"))         return cmd_lockunspent(params, ec, em, res);
    if (!strcmp(m, "signmessage"))         return cmd_signmessage(params, w, ec, em, res);
    if (!strcmp(m, "backupwallet"))        return cmd_backupwallet(params, ec, em, res);
    if (!strcmp(m, "keypoolrefill"))       return cmd_keypoolrefill(res);
    if (!strcmp(m, "abortrescan"))         return cmd_abortrescan(res);
    if (!strcmp(m, "listdescriptors"))     return cmd_listdescriptors(params, w, ec, em, res);
    if (!strcmp(m, "gethdkeys"))           return cmd_gethdkeys(params, w, res);

    if (!strcmp(m, "walletlock"))              return cmd_walletlock(ec, em);
    if (!strcmp(m, "walletpassphrase"))        return cmd_walletpassphrase(params, ec, em);
    if (!strcmp(m, "walletpassphrasechange"))  return cmd_walletpassphrasechange(params, ec, em);
    if (!strcmp(m, "encryptwallet"))           return cmd_encryptwallet(params, w, ec, em, res);
    if (!strcmp(m, "createwallet"))    return cmd_createwallet(params, ec, em, res);
    if (!strcmp(m, "loadwallet"))      return cmd_loadwallet(params, ec, em, res);
    if (!strcmp(m, "unloadwallet"))    return cmd_unloadwallet(params, ec, em, res);
    if (!strcmp(m, "restorewallet"))   return cmd_restorewallet(params, ec, em, res);
    if (!strcmp(m, "migratewallet"))    return cmd_migratewallet(params, ec, em);
    if (!strcmp(m, "setwalletflag"))   return cmd_setwalletflag(params, ec, em, res);
    if (!strcmp(m, "importdescriptors")) return cmd_importdescriptors(params, w, ec, em, res);
    if (!strcmp(m, "exportwatchonlywallet"))
        return cmd_exportwatchonlywallet(params, w, ec, em, res);
    if (!strcmp(m, "createwalletdescriptor"))
        return cmd_createwalletdescriptor(params, w, ec, em, res);
    if (!strcmp(m, "importprunedfunds"))
        return cmd_importprunedfunds(params, w, ec, em, res);
    if (!strcmp(m, "removeprunedfunds"))
        return cmd_removeprunedfunds(params, w, ec, em, res);
    if (!strcmp(m, "addhdkey")) return cmd_addhdkey(params, w, ec, em, res);
    if (!strcmp(m, "walletdisplayaddress")){
        /* Core: walletdisplayaddress "address". The signer wants a
         * DESCRIPTOR; an address becomes addr(<address>), which HWI
         * accepts for display. */
        extern int rpc_signer_display(const char*, const char*, rj_val**, long*, const char**);
        extern int rpc_signer_configured(void);
        const char* addr = wop_str_arg(params, 0);
        if (!addr) return wop_err(ec, em, -8, "walletdisplayaddress requires an address");
        if (!rpc_signer_configured())
            return wop_err(ec, em, -1, "Error: restart bitcoind with -signer=<cmd>");
        { int t; unsigned char v, h[20], p32[32];
          if (!wallet_validate_address(addr, &t, &v, h, p32) ||
              t < WOP_ADDR_P2PKH || t > WOP_ADDR_P2TR)
              return wop_err(ec, em, -5, "Invalid address"); }
        char desc[256];
        snprintf(desc, sizeof desc, "addr(%s)", addr);
        return rpc_signer_display(NULL, desc, res, ec, em);
    }

    /* Everything that needs a receive-side view of the chain. The wallet
     * journals only its own SENDS, so "how much did this address receive"
     * has no data behind it. Answering 0.00000000 would be a wrong answer
     * dressed as a real one -- the caller cannot tell it apart from an
     * address that genuinely received nothing. */
    if (!strcmp(m, "rescanblockchain"))     return cmd_rescanblockchain(params, w, ec, em, res);
    if (!strcmp(m, "getreceivedbyaddress")) return cmd_getreceivedbyaddress(params, w, ec, em, res);
    if (!strcmp(m, "getreceivedbylabel"))   return cmd_getreceivedbylabel(params, w, ec, em, res);
    if (!strcmp(m, "listreceivedbyaddress"))return cmd_listreceivedbyaddress(params, w, ec, em, res);
    if (!strcmp(m, "listreceivedbylabel"))  return cmd_listreceivedbylabel(params, w, ec, em, res);
    if (!strcmp(m, "listaddressgroupings")) return cmd_listaddressgroupings(w, ec, em, res);
    if (!strcmp(m, "listsinceblock"))       return cmd_listsinceblock(params, w, ec, em, res);
    if (!strcmp(m, "abandontransaction"))   return cmd_abandontransaction(params, ec, em, res);

    /* the spend family -- see WOP_NO_FUNDING for why refusing is the only
     * answer that does not hand the caller a transaction the network will
     * reject */
    if (g_aw_watchonly &&
        (!strcmp(m, "sendtoaddress") || !strcmp(m, "sendmany") || !strcmp(m, "send") ||
         !strcmp(m, "sendall") || !strcmp(m, "signmessage") ||
         !strcmp(m, "walletprocesspsbt") || !strcmp(m, "fundrawtransaction") ||
         !strcmp(m, "walletcreatefundedpsbt")))
        return wop_err(ec, em, -4, "Error: Private keys are disabled for this wallet");
    if (!strcmp(m, "sendtoaddress"))          return cmd_sendtoaddress(params, w, ec, em, res);
    if (!strcmp(m, "sendmany"))               return cmd_sendmany(params, w, ec, em, res);
    if (!strcmp(m, "send"))                   return cmd_send(params, w, ec, em, res);
    if (!strcmp(m, "sendall"))                return cmd_sendall(params, w, ec, em, res);
    if (!strcmp(m, "fundrawtransaction"))     return cmd_fundrawtransaction(params, w, ec, em, res);
    if (!strcmp(m, "walletcreatefundedpsbt")) return cmd_walletcreatefundedpsbt(params, w, ec, em, res);
    if (!strcmp(m, "walletprocesspsbt")){
        /* real since 2026-08-26: the Signer role by delegation to the
         * Core-validated signrawtransactionwithwallet path (rpc_commands.c) */
        extern int rpc_cmd_walletprocesspsbt(const rj_val*, const rpc_wallet*,
                                             long*, const char**, rj_val**);
        return rpc_cmd_walletprocesspsbt(params, w, ec, em, res);
    }
    if (!strcmp(m, "bumpfee"))     return cmd_bumpfee_common(params, w, ec, em, res, 0);
    if (!strcmp(m, "psbtbumpfee")) return cmd_bumpfee_common(params, w, ec, em, res, 1);

    return -1;   /* unreachable while WOP_METHODS and this ladder agree */
}


/* ==== output types (2026-09-01) ============================================
 * See rpc_wallet_ops.h. The active set is a line-per-type file in the wallet
 * directory (wallet.types); bech32 needs no line. */
#define WOP_TYPES_REL "wallet.types"
static int g_wot_mask = -1;
const char* rpc_wops_type_name(int t){ return t==WOT_LEGACY?"legacy" : t==WOT_P2SH_SEGWIT?"p2sh-segwit" : t==WOT_BECH32M?"bech32m" : "bech32"; }
int rpc_wops_type_from_name(const char* s){
    if (!s) return -1;
    if (!strcmp(s, "bech32")) return WOT_BECH32;
    if (!strcmp(s, "legacy")) return WOT_LEGACY;
    if (!strcmp(s, "p2sh-segwit")) return WOT_P2SH_SEGWIT;
    if (!strcmp(s, "bech32m")) return WOT_BECH32M;
    return -1;
}
int rpc_wops_active_types(void){
    if (g_wot_mask >= 0) return g_wot_mask;
    g_wot_mask = 1 << WOT_BECH32;
    char pb[512]; FILE* f = fopen(wop_path(WOP_TYPES_REL, pb, sizeof pb), "r");
    if (f){
        char line[64];
        while (fgets(line, sizeof line, f)){ line[strcspn(line, "\r\n")] = 0; int t = rpc_wops_type_from_name(line); if (t >= 0) g_wot_mask |= 1 << t; }
        fclose(f);
    }
    return g_wot_mask;
}
int rpc_wops_activate_type(int t){
    if (t < 0 || t > 3) return -1;
    if (rpc_wops_active_types() & (1 << t)) return 0;
    char pb[512]; FILE* f = fopen(wop_path(WOP_TYPES_REL, pb, sizeof pb), "a");
    if (!f) return -1;
    fprintf(f, "%s\n", rpc_wops_type_name(t)); fclose(f);
    g_wot_mask |= 1 << t;
    wop_keyset_invalidate();
    return 1;
}
void rpc_wops_set_active_types_for_test(int mask){ g_wot_mask = mask | 1; wop_keyset_invalidate(); }
void rpc_wops_type_path(int t, unsigned i, int chain, unsigned idx[5]){
    unsigned purpose = t==WOT_LEGACY?44u : t==WOT_P2SH_SEGWIT?49u : t==WOT_BECH32M?86u : 84u;
    idx[0] = 0x80000000u | purpose; idx[1] = 0x80000000u; idx[2] = 0x80000000u; idx[3] = i; idx[4] = (unsigned)chain;
}
int rpc_wops_type_spk(int t, const unsigned char pub[33], unsigned char spk[34], unsigned long* spklen, unsigned char h20[20]){
    unsigned char h[20]; hash160(h, pub, 33);
    switch (t){
    case WOT_LEGACY:
        spk[0]=0x76; spk[1]=0xa9; spk[2]=0x14; memcpy(spk+3, h, 20); spk[23]=0x88; spk[24]=0xac; *spklen = 25; memcpy(h20, h, 20); return 1;
    case WOT_P2SH_SEGWIT: {
        unsigned char rd[22] = {0x00, 0x14}; memcpy(rd+2, h, 20); unsigned char sh[20]; hash160(sh, rd, 22);
        spk[0]=0xa9; spk[1]=0x14; memcpy(spk+2, sh, 20); spk[22]=0x87; *spklen = 23; memcpy(h20, sh, 20); return 1; }
    case WOT_BECH32M: {
        extern void sha256_full(unsigned char out[32], const void* msg, unsigned long len);
        extern int  bip32_xonly_tweak_add(const unsigned char x[32], const unsigned char t[32], unsigned char out_x[32]);
        unsigned char th[32]; sha256_full(th, "TapTweak", 8);
        unsigned char tb[96]; memcpy(tb, th, 32); memcpy(tb+32, th, 32); memcpy(tb+64, pub+1, 32);
        unsigned char tw[32]; sha256_full(tw, tb, 96);
        unsigned char q[32]; if (!bip32_xonly_tweak_add(pub+1, tw, q)) return 0;
        spk[0]=0x51; spk[1]=0x20; memcpy(spk+2, q, 32); *spklen = 34; memcpy(h20, q, 20); return 1; }
    default:
        spk[0]=0x00; spk[1]=0x14; memcpy(spk+2, h, 20); *spklen = 22; memcpy(h20, h, 20); return 1;
    }
}
int rpc_wops_own_coin_spk(const void* wseed, const unsigned char txid_wire[32], unsigned int vout,
                          unsigned long long* value_out, unsigned char spk[34], unsigned long* spklen,
                          unsigned char redeem[22], unsigned long* redeemlen){
    rpc_wallet w; memset(&w, 0, sizeof w); w.seed = (const unsigned char*)wseed;
    const wscan_key* keys; int nk = wop_keyset_cached(&w, &keys);
    if (!keys) return 0;
    wscan_rec* recs; long n = wop_records(&recs);
    for (long i = 0; i < n; i++){
        if (recs[i].kind != 0) continue;
        if (recs[i].vout != vout || memcmp(recs[i].txid, txid_wire, 32)) continue;
        const wscan_key* k = wop_rec_key(keys, nk, &recs[i]);
        if (!k) return 0;
        *value_out = recs[i].value; *redeemlen = 0;
        int t = WOT_TYPE(k->branch);
        if (t == WOT_BECH32M || t == WOT_P2SH_SEGWIT){
            if (k->hdkey != 0) return 0;
            unsigned path[5]; rpc_wops_type_path(t, k->keyidx, WOT_CHAIN(k->branch), path);
            unsigned char kk[32], cc[32], pub[33], h20[20];
            if (bip32_derive_path(kk, cc, w.seed, 64, path, 5) != 1) return 0;
            scalar_to_pubkey(pub, kk);
            if (!rpc_wops_type_spk(t, pub, spk, spklen, h20)) return 0;
            if (t == WOT_P2SH_SEGWIT){ unsigned char kh[20]; hash160(kh, pub, 33); redeem[0]=0x00; redeem[1]=0x14; memcpy(redeem+2, kh, 20); *redeemlen = 22; }
        } else if (t == WOT_LEGACY){ spk[0]=0x76; spk[1]=0xa9; spk[2]=0x14; memcpy(spk+3, k->h160, 20); spk[23]=0x88; spk[24]=0xac; *spklen = 25; }
        else { spk[0]=0x00; spk[1]=0x14; memcpy(spk+2, k->h160, 20); *spklen = 22; }
        return 1;
    }
    return 0;
}
