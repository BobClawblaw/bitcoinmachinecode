/* daemon/netperm.c -- see netperm.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "netperm.h"
#include "subnet.h"

#define NP_MAX_ENTRIES 64

typedef struct {
    subnet_t net;
    unsigned flags;
    int      implicit;             /* spec carried no permissions  */
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

    np_entry_t e;
    memset(&e, 0, sizeof e);
    if (!subnet_parse(addrpart, &e.net)){
        *err = "not an IPv4 or IPv6 address (or a bad prefix length)";
        return 0;
    }
    e.flags = flags;
    e.implicit = implicit;
    g_np[g_np_n++] = e;
    return 1;
}

unsigned netperm_for(const char* ip){
    if (!ip || !*ip || g_np_n == 0) return 0;
    unsigned out = 0;
    for (int i = 0; i < g_np_n; i++)
        if (subnet_covers(&g_np[i].net, ip)) out |= g_np[i].flags;
    return out;
}
