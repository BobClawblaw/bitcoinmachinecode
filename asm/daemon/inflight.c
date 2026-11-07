/* daemon/inflight.c -- see inflight.h */
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "inflight.h"
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/* The lock word holds the holder's pid. Every section under it is a scan of
 * 64 entries, so a waiter spins briefly; a holder that died inside one (a
 * pass helper killed on its budget) is found by kill(pid, 0) and its lock
 * taken over, so no process can wedge the table for the others. Nothing
 * here calls back into the table, so the lock is never re-entered. */
static void lk(const inflight_t* ct){
    inflight_t* t = (inflight_t*)ct;
    int me = (int)getpid();
    for (unsigned spins = 1;; spins++){
        int expect = 0;
        if (__atomic_compare_exchange_n(&t->lock, &expect, me, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return;
        if ((spins & 1023) == 0){
            if (kill(expect, 0) != 0 && errno == ESRCH)
                __atomic_compare_exchange_n(&t->lock, &expect, 0, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED);
            else usleep(50);
        }
    }
}
static void ul(const inflight_t* ct){ __atomic_store_n(&((inflight_t*)ct)->lock, 0, __ATOMIC_RELEASE); }

void inflight_init(inflight_t* t){ memset(t, 0, sizeof *t); }
inflight_t* inflight_shared(void){
    void* p = mmap(0, sizeof(inflight_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return 0;
    inflight_init((inflight_t*)p);
    return (inflight_t*)p;
}
/* a stored mark past INFLIGHT_DONE_S is free space */
static int live(const inflight_ent_t* e, long long now){ return e->used && !(e->stored && now - e->since >= INFLIGHT_DONE_S); }
static inflight_ent_t* find(inflight_t* t, const unsigned char hash[32], long long now){
    for (int i = 0; i < INFLIGHT_MAX; i++) if (live(&t->e[i], now) && !memcmp(t->e[i].hash, hash, 32)) return &t->e[i];
    return 0;
}
/* a free slot, else the oldest entry -- never refuse a fetch for lack of table space */
static inflight_ent_t* slot(inflight_t* t, long long now){
    for (int i = 0; i < INFLIGHT_MAX; i++) if (!live(&t->e[i], now)) return &t->e[i];
    inflight_ent_t* e = &t->e[0];
    for (int i = 1; i < INFLIGHT_MAX; i++) if (t->e[i].since < e->since) e = &t->e[i];
    return e;
}
int inflight_claim(inflight_t* t, const unsigned char hash[32], int leg, long long now){
    lk(t);
    int r = 1;
    inflight_ent_t* e = find(t, hash, now);
    if (e && e->stored){ t->refused++; t->refused_stored++; r = 0; }
    else if (e){
        if (e->leg != leg){
            if (now - e->since < INFLIGHT_STALE_S){ t->refused++; r = 0; }
            else { e->leg = leg; e->since = now; t->claims++; }   /* a stale claim: the pass that held it never came back */
        }
    } else {
        e = slot(t, now);
        memcpy(e->hash, hash, 32); e->leg = leg; e->since = now; e->used = 1; e->stored = 0; t->claims++;
    }
    ul(t);
    return r;
}
/* inflight_claim's answer without taking the claim: 1 = `leg` could fetch the
 * block now (free, its own, or a stale claim), 0 = another leg holds it or it
 * was just stored. */
int inflight_would_allow(const inflight_t* t, const unsigned char hash[32], int leg, long long now){
    lk(t);
    int r = 1;
    for (int i = 0; i < INFLIGHT_MAX; i++){
        const inflight_ent_t* e = &t->e[i];
        if (!live(e, now) || memcmp(e->hash, hash, 32)) continue;
        r = e->stored ? 0 : (e->leg == leg || now - e->since >= INFLIGHT_STALE_S);
        break;
    }
    ul(t);
    return r;
}
void inflight_mark_stored(inflight_t* t, const unsigned char hash[32], long long now){
    lk(t);
    inflight_ent_t* e = find(t, hash, now);
    if (!e){ e = slot(t, now); memcpy(e->hash, hash, 32); e->used = 1; }
    e->stored = 1; e->leg = -1; e->since = now;
    ul(t);
}
void inflight_forget_stored(inflight_t* t){
    lk(t);
    for (int i = 0; i < INFLIGHT_MAX; i++) if (t->e[i].used && t->e[i].stored){ t->e[i].used = 0; t->e[i].stored = 0; }
    ul(t);
}
void inflight_release(inflight_t* t, const unsigned char hash[32]){
    lk(t);
    for (int i = 0; i < INFLIGHT_MAX; i++)
        if (t->e[i].used && !t->e[i].stored && !memcmp(t->e[i].hash, hash, 32)){ t->e[i].used = 0; t->released++; }
    ul(t);
}
void inflight_release_leg(inflight_t* t, int leg){
    lk(t);
    for (int i = 0; i < INFLIGHT_MAX; i++)
        if (t->e[i].used && !t->e[i].stored && t->e[i].leg == leg){ t->e[i].used = 0; t->released++; }
    ul(t);
}
int inflight_count(const inflight_t* t){
    lk(t);
    int n = 0;
    for (int i = 0; i < INFLIGHT_MAX; i++) if (t->e[i].used && !t->e[i].stored) n++;
    ul(t);
    return n;
}
