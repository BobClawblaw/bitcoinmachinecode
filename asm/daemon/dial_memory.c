/* daemon/dial_memory.c -- see dial_memory.h */
#include <string.h>
#include <stdio.h>
#include "dial_memory.h"
size_t dialmem_bytes(int cap){ return sizeof(dm_table_t) + (size_t)(cap > 0 ? cap : 1) * sizeof(dm_ent_t); }
void dialmem_init(void* mem, int cap){ dm_table_t* t = mem; memset(t, 0, dialmem_bytes(cap)); t->cap = cap; }
void dialmem_key(char* out, size_t n, const char* host_port){
    snprintf(out, n, "%s", host_port ? host_port : "?");
    char* c = strrchr(out, ':'); if (c && strchr(out, '.')) *c = 0;   /* strip :port; an IPv6 literal keeps its colons */
}
long dialmem_backoff_s(int streak){
    if (streak <= 0) return 0;
    long s = DM_BASE_S; for (int i = 1; i < streak && s < DM_MAX_S; i++) s *= 2;
    return s > DM_MAX_S ? DM_MAX_S : s;
}
static dm_ent_t* dm_find(dm_table_t* t, const char* key){
    int n = t->n; if (n > t->cap) n = t->cap;
    for (int i = 0; i < n; i++) if (t->e[i].used && !strcmp(t->e[i].host, key)) return &t->e[i];
    return 0;
}
int dialmem_allowed(dm_table_t* t, const char* host_port, long long now){
    if (!t) return 1;
    char k[64]; dialmem_key(k, sizeof k, host_port);
    dm_ent_t* e = dm_find(t, k);
    if (!e) return 1;
    if (e->permanent || now < e->next_ok){ __sync_fetch_and_add(&t->skips, 1ULL); return 0; }
    return 1;
}
long dialmem_note_failure(dm_table_t* t, const char* host_port, int kind, long long now){
    if (!t) return 0;
    char k[64]; dialmem_key(k, sizeof k, host_port);
    dm_ent_t* e = dm_find(t, k);
    if (!e){
        int n = t->n;
        if (n < t->cap){ int slot = __sync_fetch_and_add(&t->n, 1); if (slot < t->cap) e = &t->e[slot]; else __sync_fetch_and_sub(&t->n, 1); }
        if (!e){   /* full: take the slot whose backoff ended longest ago (never a permanent one) */
            long long best = 0; int bi = -1;
            for (int i = 0; i < t->cap; i++) if (!t->e[i].permanent && (bi < 0 || t->e[i].next_ok < best)){ best = t->e[i].next_ok; bi = i; }
            if (bi < 0) return 0;
            e = &t->e[bi];
        }
        memset(e, 0, sizeof *e); snprintf(e->host, sizeof e->host, "%s", k); e->used = 1;
    }
    __sync_fetch_and_add(&t->notes, 1ULL);
    e->last = now;
    if (kind == DM_NO_WITNESS){ e->permanent = 1; e->next_ok = now + DM_MAX_S; return -1; }
    if (e->permanent) return -1;   /* a later failure on a permanent entry does not shorten it (or mislabel it as minutes) */
    if (e->streak < 30) e->streak++;
    long s = dialmem_backoff_s(e->streak);
    e->next_ok = now + s;
    return s;
}
void dialmem_note_success(dm_table_t* t, const char* host_port){
    if (!t) return;
    char k[64]; dialmem_key(k, sizeof k, host_port);
    dm_ent_t* e = dm_find(t, k);
    if (e && !e->permanent){ e->streak = 0; e->next_ok = 0; }
}
int dialmem_count(const dm_table_t* t){ if (!t) return 0; int n = t->n; return n > t->cap ? t->cap : n; }
