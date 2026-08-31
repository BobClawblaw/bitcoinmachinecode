/* daemon/netperm.c -- see netperm.h. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "netperm.h"
#include <arpa/inet.h>
#include "subnet.h"

#define NP_MAX_ENTRIES 64

typedef struct {
    subnet_t net;
    unsigned flags;
    int      implicit;             /* spec carried no permissions  */
} np_entry_t;

/* Defined near the bottom, used by both netperm_add and the whitebind parser.
 * DECLARED rather than moved: shuffling function bodies to satisfy an ordering
 * constraint is what broke this file a moment ago. */
static int parse_perms(const char* s, unsigned* flags, const char** err);

static np_entry_t g_np[NP_MAX_ENTRIES];
static int        g_np_n;

int netperm_count(void){ return g_np_n; }

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

/* ---- whitebind ---------------------------------------------------------- */
typedef struct {
    char     addr[64];
    int      port;
    unsigned flags;
    int      fd;              /* the listening socket, once bound */
} np_bind_t;

static np_bind_t g_nb[NETPERM_MAX_BIND];
static int       g_nb_n;

int netperm_whitebind_count(void){ return g_nb_n; }
const char* netperm_whitebind_addr(int i){ return (i>=0 && i<g_nb_n) ? g_nb[i].addr : ""; }
int netperm_whitebind_port(int i){ return (i>=0 && i<g_nb_n) ? g_nb[i].port : 0; }
unsigned netperm_whitebind_flags(int i){ return (i>=0 && i<g_nb_n) ? g_nb[i].flags : 0; }

void netperm_bind_fd(int fd, unsigned flags){
    for (int i = 0; i < g_nb_n; i++)
        if (g_nb[i].flags == flags && g_nb[i].fd < 0){ g_nb[i].fd = fd; return; }
}

unsigned netperm_for_fd(int fd){
    if (fd < 0) return 0;
    for (int i = 0; i < g_nb_n; i++)
        if (g_nb[i].fd == fd) return g_nb[i].flags;
    return 0;
}

int netperm_whitebind_add(const char* spec, const char** err){
    static const char* dummy;
    if (!err) err = &dummy;
    *err = 0;
    if (!spec || !*spec){ *err = "empty"; return 0; }
    if (g_nb_n >= NETPERM_MAX_BIND){ *err = "too many whitebind entries"; return 0; }

    char buf[160];
    if (strlen(spec) >= sizeof buf){ *err = "too long"; return 0; }
    snprintf(buf, sizeof buf, "%s", spec);

    unsigned flags = NP_NOBAN;
    char* at = strrchr(buf, '@');
    char* hostpart = buf;
    if (at){
        *at = 0; hostpart = at + 1;
        if (!parse_perms(buf, &flags, err)) return 0;
        if (!flags){ *err = "no permissions granted"; return 0; }
    }

    /* addr:port. Core requires a port here -- an address alone would be
     * ambiguous with the main listener, and silently sharing it would grant
     * every inbound peer these permissions. */
    char* colon = strrchr(hostpart, ':');
    if (!colon){ *err = "needs <addr>:<port>"; return 0; }
    *colon = 0;
    char* end = 0;
    long port = strtol(colon + 1, &end, 10);
    if (!end || *end || port < 1 || port > 65535){ *err = "bad port"; return 0; }
    if (!*hostpart){ *err = "needs an address"; return 0; }

    subnet_t probe;                       /* reuse the parser to validate */
    if (!subnet_parse(hostpart, &probe)){ *err = "not an IPv4 or IPv6 address"; return 0; }
    if (probe.family != AF_INET){
        *err = "only IPv4 addresses are supported here yet";
        return 0;
    }

    snprintf(g_nb[g_nb_n].addr, sizeof g_nb[g_nb_n].addr, "%s", hostpart);
    g_nb[g_nb_n].port  = (int)port;
    g_nb[g_nb_n].flags = flags;
    g_nb[g_nb_n].fd    = -1;
    g_nb_n++;
    return 1;
}

int netperm_has_implicit(void){
    for (int i = 0; i < g_np_n; i++) if (g_np[i].implicit) return 1;
    return 0;
}
void netperm_reset(void){ g_np_n = 0; }

/* Core's token names. Only noban is enforced; the others are listed so the
 * error can say "recognised but not enforced" rather than "unknown", which
 * are different problems for whoever wrote the config. */
/* forward: defined below, used by both netperm_add and the whitebind
 * parser. Declared rather than moved -- shuffling function bodies to
 * satisfy an ordering constraint is how the previous edit broke it. */
static int parse_perms(const char* s, unsigned* flags, const char** err);

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


unsigned netperm_for(const char* ip){
    if (!ip || !*ip || g_np_n == 0) return 0;
    unsigned out = 0;
    for (int i = 0; i < g_np_n; i++)
        if (subnet_covers(&g_np[i].net, ip)) out |= g_np[i].flags;
    return out;
}
