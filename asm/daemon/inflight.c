/* daemon/inflight.c -- see inflight.h */
#include <string.h>
#include "inflight.h"
void inflight_init(inflight_t* t){ memset(t, 0, sizeof *t); }
static inflight_ent_t* find(inflight_t* t, const unsigned char hash[32]){
    for (int i = 0; i < INFLIGHT_MAX; i++) if (t->e[i].used && !memcmp(t->e[i].hash, hash, 32)) return &t->e[i];
    return 0;
}
int inflight_claim(inflight_t* t, const unsigned char hash[32], int leg, long long now){
    inflight_ent_t* e = find(t, hash);
    if (e){
        if (e->leg == leg) return 1;
        if (now - e->since < INFLIGHT_STALE_S){ t->refused++; return 0; }
        e->leg = leg; e->since = now; t->claims++; return 1;   /* a stale claim: the pass that held it never came back */
    }
    for (int i = 0; i < INFLIGHT_MAX; i++) if (!t->e[i].used){ e = &t->e[i]; break; }
    if (!e){   /* full: take the oldest -- never refuse a fetch for lack of table space */
        e = &t->e[0]; for (int i = 1; i < INFLIGHT_MAX; i++) if (t->e[i].since < e->since) e = &t->e[i];
    }
    memcpy(e->hash, hash, 32); e->leg = leg; e->since = now; e->used = 1; t->claims++;
    return 1;
}
void inflight_release(inflight_t* t, const unsigned char hash[32]){ inflight_ent_t* e = find(t, hash); if (e){ e->used = 0; t->released++; } }
void inflight_release_leg(inflight_t* t, int leg){ for (int i = 0; i < INFLIGHT_MAX; i++) if (t->e[i].used && t->e[i].leg == leg){ t->e[i].used = 0; t->released++; } }
int inflight_count(const inflight_t* t){ int n = 0; for (int i = 0; i < INFLIGHT_MAX; i++) if (t->e[i].used) n++; return n; }
