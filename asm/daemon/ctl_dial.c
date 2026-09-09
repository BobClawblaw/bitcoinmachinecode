/* daemon/ctl_dial.c -- see ctl_dial.h */
#include <stdio.h>
#include <string.h>
#include "ctl_dial.h"
typedef struct { char host[64]; int persistent; long long next_try; int backoff_s; int used; } ent_t;
static ent_t g_e[CTL_DIAL_MAX];
static int find(const char* host){ for (int i = 0; i < CTL_DIAL_MAX; i++) if (g_e[i].used && !strcmp(g_e[i].host, host)) return i; return -1; }
int ctl_dial_add(const char* host, int persistent, long long now){
    if (!host || !host[0] || strlen(host) >= sizeof g_e[0].host) return -1;
    int i = find(host);
    if (i >= 0){ if (persistent) g_e[i].persistent = 1; return 0; }
    for (i = 0; i < CTL_DIAL_MAX; i++) if (!g_e[i].used) break;
    if (i == CTL_DIAL_MAX) return -1;
    memset(&g_e[i], 0, sizeof g_e[i]); snprintf(g_e[i].host, sizeof g_e[i].host, "%s", host);
    g_e[i].persistent = persistent ? 1 : 0; g_e[i].next_try = now; g_e[i].backoff_s = CTL_DIAL_RETRY_S; g_e[i].used = 1;
    return 1;
}
int ctl_dial_remove(const char* host){ int i = find(host); if (i < 0) return 0; g_e[i].used = 0; return 1; }
int ctl_dial_count(void){ int n = 0; for (int i = 0; i < CTL_DIAL_MAX; i++) n += g_e[i].used; return n; }
int ctl_dial_listed(const char* host){ int i = find(host); return i >= 0 && g_e[i].persistent; }
const char* ctl_dial_next(long long now, int (*connected)(const char* host)){
    for (int i = 0; i < CTL_DIAL_MAX; i++){
        ent_t* e = &g_e[i]; if (!e->used || e->next_try > now) continue;
        if (connected && connected(e->host)){ e->next_try = now + CTL_DIAL_RETRY_S; continue; }   /* already a leg: look again later */
        if (!e->persistent){ e->used = 0; static char once[64]; memcpy(once, e->host, sizeof once); return once; }
        e->next_try = now + e->backoff_s;   /* provisional: report() adjusts */
        return e->host;
    }
    return 0;
}
void ctl_dial_report(const char* host, int ok, long long now){
    int i = find(host); if (i < 0) return; ent_t* e = &g_e[i];
    if (ok){ e->backoff_s = CTL_DIAL_RETRY_S; e->next_try = now + CTL_DIAL_RETRY_S; return; }
    e->next_try = now + e->backoff_s; e->backoff_s = e->backoff_s * 2 > CTL_DIAL_RETRY_MAX_S ? CTL_DIAL_RETRY_MAX_S : e->backoff_s * 2;
}
void ctl_dial_reset(void){ memset(g_e, 0, sizeof g_e); }
