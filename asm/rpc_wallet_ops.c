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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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
    if (!strcmp(m, "rescanblockchain") || !strcmp(m, "getreceivedbyaddress") ||
        !strcmp(m, "getreceivedbylabel") || !strcmp(m, "listreceivedbyaddress") ||
        !strcmp(m, "listreceivedbylabel") || !strcmp(m, "listaddressgroupings") ||
        !strcmp(m, "listsinceblock") || !strcmp(m, "abandontransaction"))
        return wop_unsupported(WOP_NO_RESCAN, ec, em);

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
