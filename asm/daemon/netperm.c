/* daemon/netperm.c -- see netperm.h. */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "netperm.h"

#define NP_MAX_ENTRIES 64

typedef struct {
    int           family;          /* AF_INET / AF_INET6           */
    unsigned char addr[16];        /* network order, masked        */
    int           bits;            /* prefix length                */
    unsigned      flags;
    int           implicit;        /* spec carried no permissions  */
} np_entry_t;

static np_entry_t g_np[NP_MAX_ENTRIES];
static int        g_np_n;

int netperm_count(void){ return g_np_n; }

int netperm_has_implicit(void){
    for (int i = 0; i < g_np_n; i++) if (g_np[i].implicit) return 1;
    return 0;
}
void netperm_reset(void){ g_np_n = 0; }

/* Core's token names. Only noban is enforced; the others are listed so the
 * error can say "recognised but not enforced" rather than "unknown", which
 * are different problems for whoever wrote the config. */
static const char* const k_known[] = {
    "bloomfilter", "relay", "forcerelay", "download", "mempool", "addr",
    "in", "out", 0
};

static int parse_perms(const char* s, unsigned* flags, const char** err){
    char buf[256];
    if (strlen(s) >= sizeof buf){ *err = "permission list too long"; return 0; }
    snprintf(buf, sizeof buf, "%s", s);
    *flags = 0;
    char* save = 0;
    for (char* t = strtok_r(buf, ",", &save); t; t = strtok_r(0, ",", &save)){
        if (!strcmp(t, "noban")){ *flags |= NP_NOBAN; continue; }
        for (int i = 0; k_known[i]; i++)
            if (!strcmp(t, k_known[i])){
                /* Recognised by Core, not enforced here. Saying so is the
                 * whole point: the alternative is accepting it silently. */
                *err = "recognised by Core but NOT enforced by this node "
                       "(only `noban` is); remove it rather than rely on it";
                return 0;
            }
        *err = "unknown permission";
        return 0;
    }
    return 1;
}

/* Zero every bit past `bits`, so a sloppy 10.0.0.1/8 matches what it means. */
static void mask_addr(unsigned char* a, int len, int bits){
    for (int i = 0; i < len; i++){
        int keep = bits - i * 8;
        if (keep >= 8) continue;
        a[i] = (unsigned char)(keep <= 0 ? 0 : (a[i] & (0xff << (8 - keep))));
    }
}

/* "[::1]" and "::1" are the same peer; the node prints both forms. */
static void strip_brackets(char* s){
    size_t n = strlen(s);
    if (n >= 2 && s[0] == '[' && s[n-1] == ']'){
        memmove(s, s + 1, n - 2);
        s[n-2] = 0;
    }
}

int netperm_add(const char* spec, const char** err){
    static const char* dummy;
    if (!err) err = &dummy;
    *err = 0;
    if (!spec || !*spec){ *err = "empty"; return 0; }
    if (g_np_n >= NP_MAX_ENTRIES){ *err = "too many whitelist entries"; return 0; }

    char buf[256];
    if (strlen(spec) >= sizeof buf){ *err = "too long"; return 0; }
    snprintf(buf, sizeof buf, "%s", spec);

    unsigned flags = NP_NOBAN;
    int implicit = 1;
    char* at = strrchr(buf, '@');       /* rightmost: IPv6 has no '@' */
    char* addrpart = buf;
    if (at){
        *at = 0;
        addrpart = at + 1;
        implicit = 0;
        if (!parse_perms(buf, &flags, err)) return 0;
        if (!flags){ *err = "no permissions granted"; return 0; }
    }

    int bits = -1;
    char* slash = strchr(addrpart, '/');
    if (slash){
        *slash = 0;
        char* end = 0;
        long v = strtol(slash + 1, &end, 10);
        if (!end || *end || v < 0 || v > 128){ *err = "bad prefix length"; return 0; }
        bits = (int)v;
    }
    strip_brackets(addrpart);

    np_entry_t e;
    memset(&e, 0, sizeof e);
    if (inet_pton(AF_INET, addrpart, e.addr) == 1){
        e.family = AF_INET;
        if (bits < 0) bits = 32;
        if (bits > 32){ *err = "prefix length > 32 for an IPv4 address"; return 0; }
        mask_addr(e.addr, 4, bits);
    } else if (inet_pton(AF_INET6, addrpart, e.addr) == 1){
        e.family = AF_INET6;
        if (bits < 0) bits = 128;
        mask_addr(e.addr, 16, bits);
    } else {
        *err = "not an IPv4 or IPv6 address";
        return 0;
    }
    e.bits = bits;
    e.flags = flags;
    e.implicit = implicit;
    g_np[g_np_n++] = e;
    return 1;
}

unsigned netperm_for(const char* ip){
    if (!ip || !*ip || g_np_n == 0) return 0;
    char buf[128];
    if (strlen(ip) >= sizeof buf) return 0;
    snprintf(buf, sizeof buf, "%s", ip);
    strip_brackets(buf);
    /* a peer string may carry a port ("1.2.3.4:8333"); IPv6 without brackets
     * cannot, so only trim for the v4 form. */
    char* colon = strchr(buf, ':');
    if (colon && !strchr(colon + 1, ':')) *colon = 0;

    unsigned char a[16];
    int fam;
    if (inet_pton(AF_INET, buf, a) == 1) fam = AF_INET;
    else if (inet_pton(AF_INET6, buf, a) == 1) fam = AF_INET6;
    else return 0;

    unsigned out = 0;
    int len = (fam == AF_INET) ? 4 : 16;
    for (int i = 0; i < g_np_n; i++){
        if (g_np[i].family != fam) continue;
        unsigned char m[16];
        memcpy(m, a, (size_t)len);
        mask_addr(m, len, g_np[i].bits);
        if (memcmp(m, g_np[i].addr, (size_t)len) == 0) out |= g_np[i].flags;
    }
    return out;
}
