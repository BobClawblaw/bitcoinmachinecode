#include <string.h>
#include "hdr_lowwork.h"
extern void block_work(unsigned char work[16], unsigned bits);
extern void chainwork_add(unsigned char out[16], const unsigned char a[16], const unsigned char b[16]);
extern int  reorg_work_meets_minimum(const unsigned char work[16]);
static int (*g_floor)(const unsigned char[16]) = reorg_work_meets_minimum;
void lowwork_set_floor_fn(int (*fn)(const unsigned char work[16])){ g_floor = fn ? fn : reorg_work_meets_minimum; }
static unsigned bits_of(const unsigned char* h){ return h[72] | (h[73] << 8) | (h[74] << 16) | ((unsigned)h[75] << 24); }
void lowwork_cum_from_store(unsigned char out[16], void* hst, long upto, int (*get_at)(void*, unsigned long long, void*)){
    memset(out, 0, 16); unsigned char rec[112], w[16];
    for (long h = 0; h <= upto; h++){
        if (get_at(hst, (unsigned long long)h, rec) != 1) break;
        block_work(w, bits_of(rec)); chainwork_add(out, out, w);
    }
}
void lowwork_begin(lowwork_t* l, const unsigned char cum_at_fork[16], int armed){
    memset(l, 0, sizeof *l); l->armed = armed; memcpy(l->cum, cum_at_fork, 16);
}
void lowwork_clear(lowwork_t* l){ l->held = 0; }
int lowwork_page(lowwork_t* l, const unsigned char* hdrs, unsigned long cnt, long pos, const unsigned char prev[32], const unsigned char last_hash[32]){
    unsigned char w[16];
    for (unsigned long i = 0; i < cnt; i++){ block_work(w, bits_of(hdrs + i * 81)); chainwork_add(l->cum, l->cum, w); }
    if (!l->armed) return LOWWORK_APPEND;                               /* pre-CC-5 behaviour */
    if (g_floor(l->cum)) return l->held ? LOWWORK_RELEASE : LOWWORK_APPEND;
    if (cnt < LOWWORK_PAGE_MAX) return LOWWORK_APPEND;                   /* a short page ends the chain: bounded, Core appends it */
    if (l->held >= LOWWORK_HOLD_PAGES) return LOWWORK_ABANDON;
    memcpy(l->hold[l->held], hdrs, cnt * 81); l->held_cnt[l->held] = cnt; l->held_pos[l->held] = pos;
    memcpy(l->held_prev[l->held], prev, 32); memcpy(l->tail_hash, last_hash, 32); l->tail_height = pos + (long)cnt - 1; l->held++;
    return LOWWORK_HOLD;
}
int lowwork_held(const lowwork_t* l, int i, const unsigned char** hdrs, unsigned long* cnt, long* pos, const unsigned char** prev){
    if (i < 0 || i >= l->held) return 0;
    *hdrs = l->hold[i]; *cnt = l->held_cnt[i]; *pos = l->held_pos[i]; *prev = l->held_prev[i]; return 1;
}
int lowwork_tail(const lowwork_t* l, unsigned char hash[32], long* height){
    if (!l->held) return 0;
    memcpy(hash, l->tail_hash, 32); *height = l->tail_height; return 1;
}
