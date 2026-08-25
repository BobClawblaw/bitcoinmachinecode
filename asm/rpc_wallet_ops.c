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

#include "rpc_wallet_ops.h"
#include "rpc_chain.h"
#include "wallet_scan.h"
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

static const char* wop_path(const char* rel, char* buf, size_t cap){
    snprintf(buf, cap, "data/%s", rel);
    struct stat sb;
    if (stat(buf, &sb) == 0) return buf;
    snprintf(buf, cap, "%s", rel);
    if (stat(buf, &sb) == 0) return buf;
    /* Neither exists yet. Writers need a path anyway: prefer data/ when that
     * directory is present, else the cwd -- the same choice the CLI makes. */
    if (stat("data", &sb) == 0 && S_ISDIR(sb.st_mode)) snprintf(buf, cap, "data/%s", rel);
    else snprintf(buf, cap, "%s", rel);
    return buf;
}
static int wop_exists(const char* rel){
    char b[512]; struct stat sb;
    snprintf(b, sizeof b, "data/%s", rel); if (stat(b, &sb) == 0) return 1;
    snprintf(b, sizeof b, "%s", rel);      return stat(b, &sb) == 0;
}

/* The single wallet's name. This node loads one wallet from a fixed path, so
 * the name is fixed too; Core would report the wallet's directory name. */
#define WOP_WALLET_NAME "bmcwallet"

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
    /* Core lists LOADED wallets. This node loads its one wallet at startup
     * when the store exists, so presence of the store is the load state. */
    if (wop_exists(WOP_WALLET_REL)) rj_arr_push(arr, rj_str(WOP_WALLET_NAME));
    *res = arr;
    return 1;
}

static int cmd_listwalletdir(rj_val** res){
    rj_val* arr = rj_arr();
    if (wop_exists(WOP_WALLET_REL)){
        rj_val* e = rj_obj();
        rj_obj_set(e, "name", rj_str(WOP_WALLET_NAME));
        rj_obj_set(e, "warnings", rj_arr());
        rj_arr_push(arr, e);
    }
    rj_val* o = rj_obj();
    rj_obj_set(o, "wallets", arr);
    *res = o;
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

static rj_val* wop_desc_entry(const unsigned char seed[64], int is_change){
    char mfp[9];
    if (!wop_master_fp(seed, mfp)) return NULL;
    unsigned idx[5] = {0x80000000u | 84u, 0x80000000u, 0x80000000u, 0, (unsigned)is_change};
    unsigned char k[32], c[32], pub[33];
    if (bip32_derive_path(k, c, seed, 64, idx, 5) != 1) return NULL;
    scalar_to_pubkey(pub, k);
    char pubhex[67];
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < 33; i++){ pubhex[i*2] = H[pub[i]>>4]; pubhex[i*2+1] = H[pub[i]&15]; }
    pubhex[66] = 0;
    char inner[256];
    snprintf(inner, sizeof inner, "wpkh([%s/84h/0h/0h/0/%d]%s)", mfp, is_change, pubhex);
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

static int cmd_listdescriptors(const rj_val* params, const rpc_wallet* w,
                               long* ec, const char** em, rj_val** res){
    /* Core's `private` argument dumps xprvs. This node will not export
     * private material over RPC at all, so ask for it and you get told. */
    if (params && params->typ == RJ_ARR && params->nitems >= 1 &&
        params->items[0]->typ == RJ_BOOL && !strcmp(params->items[0]->str, "1"))
        return wop_err(ec, em, -1,
            "listdescriptors true would export private keys; this node does not "
            "serve private key material over RPC. Use the wallet CLI on the host.");
    if (!w || !w->seed) return wop_err(ec, em, -4, "No wallet is loaded");
    rj_val* arr = rj_arr();
    for (int ch = 0; ch <= 1; ch++){
        rj_val* e = wop_desc_entry(w->seed, ch);
        if (e) rj_arr_push(arr, e);
    }
    rj_val* o = rj_obj();
    rj_obj_set(o, "wallet_name", rj_str(WOP_WALLET_NAME));
    rj_obj_set(o, "descriptors", arr);
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
    *res = arr;
    return 1;
}

/* ==== encryption state ===================================================
 * These are not refusals. This node's wallet IS unencrypted, and the answers
 * below are byte-for-byte what Core returns for an unencrypted wallet --
 * verified against the oracle. encryptwallet is the one real gap. */
static int cmd_walletlock(long* ec, const char** em){
    return wop_err(ec, em, -15,
        "Error: running with an unencrypted wallet, but walletlock was called.");
}
static int cmd_walletpassphrase(long* ec, const char** em){
    return wop_err(ec, em, -15,
        "Error: running with an unencrypted wallet, but walletpassphrase was called.");
}
static int cmd_walletpassphrasechange(long* ec, const char** em){
    return wop_err(ec, em, -15,
        "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");
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
static wscan_key* g_ks;
static int g_ks_n;

static int wop_keyset_cached(const rpc_wallet* w, const wscan_key** out){
    if (!w || !w->seed){ *out = NULL; return 0; }
    if (g_ks_valid && !memcmp(g_ks_seed, w->seed, 64)){ *out = g_ks; return g_ks_n; }
    if (!g_ks) g_ks = malloc((size_t)(WOP_SCAN_KEYS*2) * sizeof *g_ks);
    if (!g_ks){ *out = NULL; return 0; }
    extern int wop_keyset(const rpc_wallet*, wscan_key*, int);
    g_ks_n = wop_keyset(w, g_ks, WOP_SCAN_KEYS*2);
    memcpy(g_ks_seed, w->seed, 64);
    g_ks_valid = 1;
    *out = g_ks;
    return g_ks_n;
}

int wop_keyset(const rpc_wallet* w, wscan_key* keys, int cap){
    if (!w || !w->seed) return 0;
    int n = 0;
    for (unsigned i = 0; i < WOP_SCAN_KEYS && n + 2 <= cap; i++){
        for (int b = 0; b <= 1; b++){
            unsigned path[5] = {0x80000000u|84u, 0x80000000u, 0x80000000u, i, (unsigned)b};
            unsigned char k[32], c[32], pub[33];
            if (bip32_derive_path(k, c, w->seed, 64, path, 5) != 1) continue;
            scalar_to_pubkey(pub, k);
            hash160(keys[n].h160, pub, 33);
            keys[n].keyidx = i; keys[n].branch = (unsigned char)b;
            n++;
        }
    }
    qsort(keys, (size_t)n, sizeof keys[0], wscan_key_cmp);
    return n;
}

/* hash160 of the key a record belongs to. */
static int wop_rec_h160(const wscan_key* keys, int nk, const wscan_rec* r, unsigned char h[20]){
    for (int i = 0; i < nk; i++)
        if (keys[i].keyidx == r->keyidx && keys[i].branch == r->branch){
            memcpy(h, keys[i].h160, 20); return 1; }
    return 0;
}

/* The wallet's own P2WPKH address for a key, as getnewaddress renders it. */
extern long wallet_p2wpkh_address(char* out, long cap, const unsigned char h160[20]);

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

/* rescanblockchain ( start_height stop_height ) */
static int cmd_rescanblockchain(const rj_val* params, const rpc_wallet* w,
                                long* ec, const char** em, rj_val** res){
    if (!w || !w->seed) return wop_err(ec, em, -4, "No wallet is loaded");
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
        if (wallet_p2wpkh_address(addr, sizeof addr, keys[i].h160) < 0) continue;
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
        if (wallet_p2wpkh_address(addr, sizeof addr, keys[i].h160) < 0) continue;
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
        unsigned char h[20];
        if (!wop_rec_h160(keys, nk, &recs[r], h)) continue;
        char addr[96];
        if (wallet_p2wpkh_address(addr, sizeof addr, h) < 0) continue;
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

/* ==== the refusals =======================================================
 * Each names the specific missing capability. None of them pretends. */
#define WOP_ONE_WALLET \
    "this node serves exactly one wallet, loaded at startup from " \
    "data/bmcwallet.dat; it has no multi-wallet manager, so there is nothing " \
    "for this call to create, load, unload or switch between"
#define WOP_NO_ENCRYPTION \
    "this node's wallet store is not encrypted and has no encryption path " \
    "(wallet_store.c persists a BIP39 mnemonic; adding Core's AES keystore " \
    "is unimplemented). walletlock/walletpassphrase already report the " \
    "unencrypted state exactly as Core does"
#define WOP_NO_IMPORT \
    "this wallet is a single BIP32 seed with no import path: it cannot adopt " \
    "foreign descriptors, keys or watch-only scripts, so there is nothing " \
    "this call could add"
#define WOP_NO_RESCAN \
    "no wallet rescan exists: the wallet learns of its outputs only from the " \
    "sends it journals, so there is no chain-scan to start, abort or bound. " \
    "This is why getreceivedbyaddress and the listreceivedby* family are " \
    "also absent rather than answering zero"
#define WOP_NO_SIGNER \
    "no external signer is configured and this node has no signer interface"

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
    "sendtoaddress", "sendmany", "send", "sendall",
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
    if (!strcmp(m, "walletpassphrase"))        return cmd_walletpassphrase(ec, em);
    if (!strcmp(m, "walletpassphrasechange"))  return cmd_walletpassphrasechange(ec, em);

    if (!strcmp(m, "encryptwallet"))       return wop_unsupported(WOP_NO_ENCRYPTION, ec, em);
    if (!strcmp(m, "createwallet") || !strcmp(m, "loadwallet") ||
        !strcmp(m, "unloadwallet") || !strcmp(m, "restorewallet") ||
        !strcmp(m, "migratewallet") || !strcmp(m, "setwalletflag"))
        return wop_unsupported(WOP_ONE_WALLET, ec, em);
    if (!strcmp(m, "importdescriptors") || !strcmp(m, "createwalletdescriptor") ||
        !strcmp(m, "addhdkey") || !strcmp(m, "importprunedfunds") ||
        !strcmp(m, "removeprunedfunds") || !strcmp(m, "exportwatchonlywallet"))
        return wop_unsupported(WOP_NO_IMPORT, ec, em);
    if (!strcmp(m, "walletdisplayaddress")) return wop_unsupported(WOP_NO_SIGNER, ec, em);

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
    if (!strcmp(m, "sendtoaddress") || !strcmp(m, "sendmany") ||
        !strcmp(m, "send") || !strcmp(m, "sendall") ||
        !strcmp(m, "walletcreatefundedpsbt") || !strcmp(m, "walletprocesspsbt") ||
        !strcmp(m, "bumpfee") || !strcmp(m, "psbtbumpfee"))
        return wop_unsupported(WOP_NO_FUNDING, ec, em);

    return -1;   /* unreachable while WOP_METHODS and this ladder agree */
}
