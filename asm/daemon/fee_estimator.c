/* daemon/fee_estimator.c -- see fee_estimator.h. A port of Core's
 * policy/fees/block_policy_estimator.cpp (v31.99): same constants, same
 * arithmetic order, same early-outs, so that the regtest differential can
 * compare estimatesmartfee/estimaterawfee byte for byte. */
#include "fee_estimator.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#define FEST_MAGIC        0x54534546u     /* "FEST" */
#define FEST_MAXB         240             /* 100 .. 1e7 at x1.05 is 237 boundaries + INF */
#define FEST_MAX_PERIODS  42
#define FEST_MAX_CONFIRMS 1008
#define SHORT_BLOCK_PERIODS 12
#define SHORT_SCALE 1
#define MED_BLOCK_PERIODS 24
#define MED_SCALE 2
#define LONG_BLOCK_PERIODS 42
#define LONG_SCALE 24
#define OLDEST_ESTIMATE_HISTORY (6u * 1008u)
#define SHORT_DECAY 0.962
#define MED_DECAY 0.9952
#define LONG_DECAY 0.99931
#define HALF_SUCCESS_PCT 0.6
#define SUCCESS_PCT 0.85
#define DOUBLE_SUCCESS_PCT 0.95
#define SUFFICIENT_FEETXS 0.1
#define SUFFICIENT_TXS_SHORT 0.5
#define MIN_BUCKET_FEERATE 100.0
#define MAX_BUCKET_FEERATE 1e7
#define FEE_SPACING 1.05
#define INF_FEERATE 1e99
#define FEST_FILE_VERSION 1u

typedef struct {
    double   decay;
    unsigned scale, periods, max_confirms;
    double   txct[FEST_MAXB];
    double   favg[FEST_MAXB];
    double   conf[FEST_MAX_PERIODS][FEST_MAXB];
    double   fail[FEST_MAX_PERIODS][FEST_MAXB];
    int      unconf[FEST_MAX_CONFIRMS][FEST_MAXB];
    int      old_unconf[FEST_MAXB];
} fest_stats_t;

typedef struct {
    unsigned char txid[32];
    unsigned height, bucket;
    double   feerate;
    unsigned used, pad;
} fest_ent_t;

typedef struct {
    unsigned magic, nbuckets;
    double   buckets[FEST_MAXB];
    unsigned best_seen, first_recorded, hist_first, hist_best;
    unsigned tracked, untracked;
    unsigned in_block, block_ok;
    unsigned counted, _pad;
    unsigned long map_cap, map_n;
    fest_stats_t s[3];       /* FEST_SHORT, FEST_MED, FEST_LONG */
} fest_t;

static fest_ent_t* ents(const fest_t* f){ return (fest_ent_t*)((const char*)f + sizeof(fest_t)); }

unsigned long fest_state_size(unsigned long map_cap){
    unsigned long c = 1024; while (c < map_cap) c <<= 1;
    return sizeof(fest_t) + c * sizeof(fest_ent_t);
}
int fest_valid(const void* st){ return st && ((const fest_t*)st)->magic == FEST_MAGIC; }

static void stats_init(fest_stats_t* s, unsigned periods, double decay, unsigned scale){
    memset(s, 0, sizeof *s);
    s->decay = decay; s->scale = scale; s->periods = periods; s->max_confirms = scale * periods;
}

int fest_init(void* stv, unsigned long map_cap){
    if (!stv) return 0;
    unsigned long c = 1024; while (c < map_cap) c <<= 1;
    fest_t* f = (fest_t*)stv;
    memset(f, 0, fest_state_size(c));
    f->magic = FEST_MAGIC;
    /* Core's constructor: bucketBoundary *= FEE_SPACING iteratively -- same
     * floating-point sequence, so the boundaries are bit-identical. */
    unsigned n = 0;
    for (double b = MIN_BUCKET_FEERATE; b <= MAX_BUCKET_FEERATE; b *= FEE_SPACING) f->buckets[n++] = b;
    f->buckets[n++] = INF_FEERATE;
    f->nbuckets = n;
    stats_init(&f->s[FEST_SHORT], SHORT_BLOCK_PERIODS, SHORT_DECAY, SHORT_SCALE);
    stats_init(&f->s[FEST_MED],   MED_BLOCK_PERIODS,   MED_DECAY,   MED_SCALE);
    stats_init(&f->s[FEST_LONG],  LONG_BLOCK_PERIODS,  LONG_DECAY,  LONG_SCALE);
    f->map_cap = c; f->map_n = 0;
    return 1;
}

/* bucketMap.lower_bound(feerate): index of the first boundary >= feerate */
static unsigned bucket_of(const fest_t* f, double feerate){
    unsigned lo = 0, hi = f->nbuckets - 1;
    while (lo < hi){ unsigned mid = (lo + hi) / 2; if (f->buckets[mid] < feerate) lo = mid + 1; else hi = mid; }
    return lo;
}

/* ---- tracked-tx map (open addressing, backward-shift delete) ---------- */
static unsigned long h_of(const unsigned char* t){ unsigned long h; memcpy(&h, t, 8); return h; }
static long map_find(const fest_t* f, const unsigned char* txid){
    fest_ent_t* e = ents(f); unsigned long m = f->map_cap - 1, i = h_of(txid) & m;
    for (unsigned long p = 0; p <= m; p++, i = (i + 1) & m){
        if (!e[i].used) return -1;
        if (!memcmp(e[i].txid, txid, 32)) return (long)i;
    }
    return -1;
}
static fest_ent_t* map_insert(fest_t* f, const unsigned char* txid){
    if (f->map_n + 1 >= f->map_cap) return 0;
    fest_ent_t* e = ents(f); unsigned long m = f->map_cap - 1, i = h_of(txid) & m;
    while (e[i].used) i = (i + 1) & m;
    memcpy(e[i].txid, txid, 32); e[i].used = 1; f->map_n++;
    return &e[i];
}
static void map_erase(fest_t* f, long idx){
    fest_ent_t* e = ents(f); unsigned long m = f->map_cap - 1, i = (unsigned long)idx, j = i;
    for (;;){
        j = (j + 1) & m;
        if (!e[j].used) break;
        unsigned long k = h_of(e[j].txid) & m;
        /* does entry j belong at or before i (cyclically)? then shift it back */
        if ((i <= j) ? (k <= i || k > j) : (k <= i && k > j)){ e[i] = e[j]; i = j; }
    }
    memset(&e[i], 0, sizeof e[i]);
    f->map_n--;
}

/* ---- TxConfirmStats ---------------------------------------------------- */
static void st_clear_current(fest_stats_t* s, unsigned nb, unsigned height){
    unsigned bin = height % s->max_confirms;
    for (unsigned j = 0; j < nb; j++){ s->old_unconf[j] += s->unconf[bin][j]; s->unconf[bin][j] = 0; }
}
static void st_record(fest_stats_t* s, int blocks_to_confirm, unsigned bucket, double feerate){
    if (blocks_to_confirm < 1) return;
    int periods = (blocks_to_confirm + (int)s->scale - 1) / (int)s->scale;
    for (unsigned i = (unsigned)periods; i <= s->periods; i++) s->conf[i - 1][bucket] += 1;
    s->txct[bucket] += 1;
    s->favg[bucket] += feerate;
}
static void st_update_averages(fest_stats_t* s, unsigned nb){
    for (unsigned j = 0; j < nb; j++){
        for (unsigned i = 0; i < s->periods; i++){ s->conf[i][j] *= s->decay; s->fail[i][j] *= s->decay; }
        s->favg[j] *= s->decay; s->txct[j] *= s->decay;
    }
}
static unsigned st_new_tx(fest_stats_t* s, unsigned height, unsigned bucket){
    s->unconf[height % s->max_confirms][bucket]++;
    return bucket;
}
static void st_remove_tx(fest_stats_t* s, unsigned entry_height, unsigned best_seen, unsigned bucket, int in_block){
    int blocks_ago = (int)(best_seen - entry_height);
    if (best_seen == 0) blocks_ago = 0;
    if (blocks_ago < 0) return;
    if (blocks_ago >= (int)s->max_confirms){
        if (s->old_unconf[bucket] > 0) s->old_unconf[bucket]--;
    } else {
        unsigned bin = entry_height % s->max_confirms;
        if (s->unconf[bin][bucket] > 0) s->unconf[bin][bucket]--;
    }
    if (!in_block && (unsigned)blocks_ago >= s->scale){
        unsigned periods_ago = (unsigned)blocks_ago / s->scale;
        for (unsigned i = 0; i < periods_ago && i < s->periods; i++) s->fail[i][bucket] += 1;
    }
}

static double st_estimate_median(const fest_stats_t* s, const fest_t* f, int conf_target, double sufficient_tx_val,
                                 double success_break_point, unsigned height, fest_result_t* result){
    double nConf = 0, totalNum = 0; int extraNum = 0; double failNum = 0;
    const int periodTarget = (conf_target + (int)s->scale - 1) / (int)s->scale;
    const int maxbucketindex = (int)f->nbuckets - 1;
    unsigned curNearBucket = (unsigned)maxbucketindex, bestNearBucket = (unsigned)maxbucketindex;
    unsigned curFarBucket = (unsigned)maxbucketindex, bestFarBucket = (unsigned)maxbucketindex;
    double partialNum = 0; int foundAnswer = 0;
    unsigned bins = s->max_confirms;
    int newBucketRange = 1, passing = 1;
    fest_bucket_t passBucket = { -1, -1, 0, 0, 0, 0 }, failBucket = { -1, -1, 0, 0, 0, 0 };
    const unsigned maxconf = s->max_confirms;
    for (int bucket = maxbucketindex; bucket >= 0; --bucket){
        if (newBucketRange){ curNearBucket = (unsigned)bucket; newBucketRange = 0; }
        curFarBucket = (unsigned)bucket;
        nConf += s->conf[periodTarget - 1][bucket];
        partialNum += s->txct[bucket];
        totalNum += s->txct[bucket];
        failNum += s->fail[periodTarget - 1][bucket];
        for (unsigned confct = (unsigned)conf_target; confct < maxconf; confct++)
            extraNum += s->unconf[(height - confct) % bins][bucket];
        extraNum += s->old_unconf[bucket];
        if (partialNum < sufficient_tx_val / (1 - s->decay)){
            continue;
        } else {
            partialNum = 0;
            double curPct = nConf / (totalNum + failNum + extraNum);
            if (curPct < success_break_point){
                if (passing){
                    unsigned failMinBucket = curNearBucket < curFarBucket ? curNearBucket : curFarBucket;
                    unsigned failMaxBucket = curNearBucket > curFarBucket ? curNearBucket : curFarBucket;
                    failBucket.start = failMinBucket ? f->buckets[failMinBucket - 1] : 0;
                    failBucket.end = f->buckets[failMaxBucket];
                    failBucket.within_target = nConf;
                    failBucket.total_confirmed = totalNum;
                    failBucket.in_mempool = extraNum;
                    failBucket.left_mempool = failNum;
                    passing = 0;
                }
                continue;
            } else {
                failBucket.start = -1; failBucket.end = -1; failBucket.within_target = 0;
                failBucket.total_confirmed = 0; failBucket.in_mempool = 0; failBucket.left_mempool = 0;
                foundAnswer = 1; passing = 1;
                passBucket.within_target = nConf; nConf = 0;
                passBucket.total_confirmed = totalNum; totalNum = 0;
                passBucket.in_mempool = extraNum;
                passBucket.left_mempool = failNum; failNum = 0; extraNum = 0;
                bestNearBucket = curNearBucket; bestFarBucket = curFarBucket;
                newBucketRange = 1;
            }
        }
    }
    double median = -1, txSum = 0;
    unsigned minBucket = bestNearBucket < bestFarBucket ? bestNearBucket : bestFarBucket;
    unsigned maxBucket = bestNearBucket > bestFarBucket ? bestNearBucket : bestFarBucket;
    for (unsigned j = minBucket; j <= maxBucket; j++) txSum += s->txct[j];
    if (foundAnswer && txSum != 0){
        txSum = txSum / 2;
        for (unsigned j = minBucket; j <= maxBucket; j++){
            if (s->txct[j] < txSum) txSum -= s->txct[j];
            else { median = s->favg[j] / s->txct[j]; break; }
        }
        passBucket.start = minBucket ? f->buckets[minBucket - 1] : 0;
        passBucket.end = f->buckets[maxBucket];
    }
    if (passing && !newBucketRange){
        unsigned failMinBucket = curNearBucket < curFarBucket ? curNearBucket : curFarBucket;
        unsigned failMaxBucket = curNearBucket > curFarBucket ? curNearBucket : curFarBucket;
        failBucket.start = failMinBucket ? f->buckets[failMinBucket - 1] : 0;
        failBucket.end = f->buckets[failMaxBucket];
        failBucket.within_target = nConf;
        failBucket.total_confirmed = totalNum;
        failBucket.in_mempool = extraNum;
        failBucket.left_mempool = failNum;
    }
    if (result){ result->pass = passBucket; result->fail = failBucket; result->decay = s->decay; result->scale = s->scale; }
    return median;
}

/* ---- CBlockPolicyEstimator --------------------------------------------- */
static int remove_tx_i(fest_t* f, const unsigned char* txid, int in_block){
    long i = map_find(f, txid);
    if (i < 0) return 0;
    fest_ent_t* e = &ents(f)[i];
    for (int h = 0; h < 3; h++) st_remove_tx(&f->s[h], e->height, f->best_seen, e->bucket, in_block);
    map_erase(f, i);
    return 1;
}

void fest_process_transaction(void* stv, const unsigned char txid[32], unsigned long long fee,
                              unsigned long long vsize, unsigned height, int valid){
    fest_t* f = (fest_t*)stv;
    if (!fest_valid(f) || !vsize) return;
    if (map_find(f, txid) >= 0) return;            /* already being tracked */
    if (height != f->best_seen) return;
    if (!valid){ f->untracked++; return; }
    f->tracked++;
    /* CFeeRate(fee, vsize).GetFeePerK(): integer sat/kvB, truncating */
    double feerate = (double)((fee * 1000ULL) / vsize);
    fest_ent_t* e = map_insert(f, txid);
    if (!e) return;                                 /* table full: untracked (Core's map is unbounded) */
    e->height = height;
    e->feerate = feerate;
    unsigned b = bucket_of(f, feerate);
    e->bucket = b;
    for (int h = 0; h < 3; h++) st_new_tx(&f->s[h], height, b);
}

int fest_block_begin(void* stv, unsigned height){
    fest_t* f = (fest_t*)stv;
    if (!fest_valid(f)) return 0;
    f->in_block = 1; f->block_ok = 0;
    if (height <= f->best_seen) return 0;
    f->best_seen = height;
    for (int h = 0; h < 3; h++){ st_clear_current(&f->s[h], f->nbuckets, height); st_update_averages(&f->s[h], f->nbuckets); }
    f->block_ok = 1;
    return 1;
}
int fest_block_tx(void* stv, const unsigned char txid[32]){
    fest_t* f = (fest_t*)stv;
    if (!fest_valid(f)) return 0;
    long i = map_find(f, txid);
    if (i < 0) return 0;
    if (!f->block_ok){ map_erase(f, i); return 0; }  /* stale block: forget (Core leaks the entry) */
    fest_ent_t* e = &ents(f)[i];
    unsigned entry_h = e->height, b = e->bucket; double fr = e->feerate;
    for (int h = 0; h < 3; h++) st_remove_tx(&f->s[h], entry_h, f->best_seen, b, 1);
    map_erase(f, i);
    int blocks_to_confirm = (int)(f->best_seen - entry_h);
    if (blocks_to_confirm <= 0) return 0;
    for (int h = 0; h < 3; h++) st_record(&f->s[h], blocks_to_confirm, b, fr);
    f->counted++;
    return 1;
}

void fest_block_end(void* stv){
    fest_t* f = (fest_t*)stv;
    if (!fest_valid(f)) return;
    if (f->block_ok){
        if (f->first_recorded == 0 && f->counted > 0) f->first_recorded = f->best_seen;
        f->tracked = 0; f->untracked = 0;
    }
    f->counted = 0; f->in_block = 0; f->block_ok = 0;
}
int fest_remove_tx(void* stv, const unsigned char txid[32]){
    fest_t* f = (fest_t*)stv;
    if (!fest_valid(f)) return 0;
    return remove_tx_i(f, txid, 0);
}

static unsigned block_span(const fest_t* f){
    if (f->first_recorded == 0) return 0;
    return f->best_seen - f->first_recorded;
}
static unsigned historical_block_span(const fest_t* f){
    if (f->hist_first == 0) return 0;
    if (f->best_seen - f->hist_best > OLDEST_ESTIMATE_HISTORY) return 0;
    return f->hist_best - f->hist_first;
}
static unsigned max_usable_estimate(const fest_t* f){
    unsigned bs = block_span(f), hs = historical_block_span(f);
    unsigned m = (bs > hs ? bs : hs) / 2;
    unsigned lm = f->s[FEST_LONG].max_confirms;
    return lm < m ? lm : m;
}

unsigned fest_highest_target(const void* stv, int horizon){
    const fest_t* f = (const fest_t*)stv;
    if (!fest_valid(f) || horizon < 0 || horizon > 2) return 0;
    return f->s[horizon].max_confirms;
}
unsigned fest_best_height(const void* stv){ const fest_t* f = (const fest_t*)stv; return fest_valid(f) ? f->best_seen : 0; }
unsigned long fest_tracked(const void* stv){ const fest_t* f = (const fest_t*)stv; return fest_valid(f) ? f->map_n : 0; }

unsigned long long fest_estimate_raw(const void* stv, int conf_target, double threshold, int horizon, fest_result_t* res){
    const fest_t* f = (const fest_t*)stv;
    if (res) memset(res, 0, sizeof *res);
    if (!fest_valid(f) || horizon < 0 || horizon > 2) return 0;
    const fest_stats_t* s = &f->s[horizon];
    double sufficient = horizon == FEST_SHORT ? SUFFICIENT_TXS_SHORT : SUFFICIENT_FEETXS;
    if (conf_target <= 0 || (unsigned)conf_target > s->max_confirms) return 0;
    if (threshold > 1) return 0;
    double median = st_estimate_median(s, f, conf_target, sufficient, threshold, f->best_seen, res);
    if (median < 0) return 0;
    return (unsigned long long)(median + 0.5)   /* llround for a positive value */;
}

static double estimate_combined(const fest_t* f, unsigned conf_target, double success, int check_shorter, fest_result_t* result){
    double estimate = -1;
    const fest_stats_t *sh = &f->s[FEST_SHORT], *md = &f->s[FEST_MED], *lg = &f->s[FEST_LONG];
    if (conf_target >= 1 && conf_target <= lg->max_confirms){
        if (conf_target <= sh->max_confirms)
            estimate = st_estimate_median(sh, f, (int)conf_target, SUFFICIENT_TXS_SHORT, success, f->best_seen, result);
        else if (conf_target <= md->max_confirms)
            estimate = st_estimate_median(md, f, (int)conf_target, SUFFICIENT_FEETXS, success, f->best_seen, result);
        else
            estimate = st_estimate_median(lg, f, (int)conf_target, SUFFICIENT_FEETXS, success, f->best_seen, result);
        if (check_shorter){
            fest_result_t tmp;
            if (conf_target > md->max_confirms){
                double medMax = st_estimate_median(md, f, (int)md->max_confirms, SUFFICIENT_FEETXS, success, f->best_seen, &tmp);
                if (medMax > 0 && (estimate == -1 || medMax < estimate)){ estimate = medMax; if (result) *result = tmp; }
            }
            if (conf_target > sh->max_confirms){
                double shortMax = st_estimate_median(sh, f, (int)sh->max_confirms, SUFFICIENT_TXS_SHORT, success, f->best_seen, &tmp);
                if (shortMax > 0 && (estimate == -1 || shortMax < estimate)){ estimate = shortMax; if (result) *result = tmp; }
            }
        }
    }
    return estimate;
}
static double estimate_conservative(const fest_t* f, unsigned double_target, fest_result_t* result){
    double estimate = -1; fest_result_t tmp;
    const fest_stats_t *sh = &f->s[FEST_SHORT], *md = &f->s[FEST_MED], *lg = &f->s[FEST_LONG];
    if (double_target <= sh->max_confirms)
        estimate = st_estimate_median(md, f, (int)double_target, SUFFICIENT_FEETXS, DOUBLE_SUCCESS_PCT, f->best_seen, result);
    if (double_target <= md->max_confirms){
        double longEstimate = st_estimate_median(lg, f, (int)double_target, SUFFICIENT_FEETXS, DOUBLE_SUCCESS_PCT, f->best_seen, &tmp);
        if (longEstimate > estimate){ estimate = longEstimate; if (result) *result = tmp; }
    }
    return estimate;
}

unsigned long long fest_estimate_smart(const void* stv, int conf_target, int conservative, int* returned_target, fest_result_t* res){
    const fest_t* f = (const fest_t*)stv;
    if (returned_target) *returned_target = conf_target;
    if (res) memset(res, 0, sizeof *res);
    if (!fest_valid(f)) return 0;
    double median = -1; fest_result_t tmp;
    if (conf_target <= 0 || (unsigned)conf_target > f->s[FEST_LONG].max_confirms) return 0;
    if (conf_target == 1) conf_target = 2;
    unsigned max_usable = max_usable_estimate(f);
    if ((unsigned)conf_target > max_usable) conf_target = (int)max_usable;
    if (returned_target) *returned_target = conf_target;
    if (conf_target <= 1) return 0;
    double halfEst = estimate_combined(f, (unsigned)conf_target / 2, HALF_SUCCESS_PCT, 1, &tmp);
    if (res) *res = tmp;
    median = halfEst;
    double actualEst = estimate_combined(f, (unsigned)conf_target, SUCCESS_PCT, 1, &tmp);
    if (actualEst > median){ median = actualEst; if (res) *res = tmp; }
    double doubleEst = estimate_combined(f, 2u * (unsigned)conf_target, DOUBLE_SUCCESS_PCT, !conservative, &tmp);
    if (doubleEst > median){ median = doubleEst; if (res) *res = tmp; }
    if (conservative || median == -1){
        double consEst = estimate_conservative(f, 2u * (unsigned)conf_target, &tmp);
        if (consEst > median){ median = consEst; if (res) *res = tmp; }
    }
    if (median < 0) return 0;
    return (unsigned long long)(median + 0.5)   /* llround for a positive value */;
}

void fest_flush_unconfirmed(void* stv){
    fest_t* f = (fest_t*)stv;
    if (!fest_valid(f)) return;
    fest_ent_t* e = ents(f);
    for (unsigned long i = 0; i < f->map_cap && f->map_n; i++){
        while (i < f->map_cap && e[i].used){      /* erase shifts a later entry into i: re-check it */
            unsigned char t[32]; memcpy(t, e[i].txid, 32);
            remove_tx_i(f, t, 0);
        }
    }
}

/* ---- persistence -------------------------------------------------------
 * file: "BMCFEST\1" | u32 version | u32 best_seen | u32 hist_first |
 * u32 hist_best | u32 nbuckets | double buckets[n] | 3 x { double decay,
 * u32 scale, u32 periods, double favg[n], double txct[n],
 * double conf[periods][n], double fail[periods][n] }. Same content as
 * Core's Write (the in-memory unconfirmed counters are not persisted;
 * Core flushes them into failure stats first -- fest_flush_unconfirmed). */
static int wr(FILE* fp, const void* p, unsigned long n){ return fwrite(p, 1, n, fp) == n; }
static int rd(FILE* fp, void* p, unsigned long n){ return fread(p, 1, n, fp) == n; }
static int st_write(FILE* fp, const fest_stats_t* s, unsigned nb){
    if (!wr(fp, &s->decay, 8) || !wr(fp, &s->scale, 4) || !wr(fp, &s->periods, 4)) return 0;
    if (!wr(fp, s->favg, 8ul * nb) || !wr(fp, s->txct, 8ul * nb)) return 0;
    for (unsigned i = 0; i < s->periods; i++) if (!wr(fp, s->conf[i], 8ul * nb)) return 0;
    for (unsigned i = 0; i < s->periods; i++) if (!wr(fp, s->fail[i], 8ul * nb)) return 0;
    return 1;
}
static int st_read(FILE* fp, fest_stats_t* s, unsigned nb, unsigned want_periods, unsigned want_scale){
    double decay; unsigned scale, periods;
    if (!rd(fp, &decay, 8) || !rd(fp, &scale, 4) || !rd(fp, &periods, 4)) return 0;
    if (decay <= 0 || decay >= 1 || scale == 0 || periods == 0 || periods > FEST_MAX_PERIODS) return 0;
    if (scale != want_scale || periods != want_periods) return 0;
    unsigned maxconf = scale * periods;
    if (maxconf > 6 * 24 * 7) return 0;
    fest_stats_t* t = (fest_stats_t*)malloc(sizeof *t);
    if (!t) return 0;
    stats_init(t, periods, decay, scale);
    int ok = rd(fp, t->favg, 8ul * nb) && rd(fp, t->txct, 8ul * nb);
    for (unsigned i = 0; ok && i < periods; i++) ok = rd(fp, t->conf[i], 8ul * nb);
    for (unsigned i = 0; ok && i < periods; i++) ok = rd(fp, t->fail[i], 8ul * nb);
    if (ok) memcpy(s, t, sizeof *s);
    free(t);
    return ok;
}
int fest_write_file(const void* stv, const char* path){
    const fest_t* f = (const fest_t*)stv;
    if (!fest_valid(f) || !path) return 0;
    char tmp[512]; snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE* fp = fopen(tmp, "wb");
    if (!fp) return 0;
    unsigned ver = FEST_FILE_VERSION, first, best;
    if (block_span(f) > historical_block_span(f) / 2){ first = f->first_recorded; best = f->best_seen; }
    else { first = f->hist_first; best = f->hist_best; }
    int ok = wr(fp, "BMCFEST\1", 8) && wr(fp, &ver, 4) && wr(fp, &f->best_seen, 4) && wr(fp, &first, 4) && wr(fp, &best, 4)
          && wr(fp, &f->nbuckets, 4) && wr(fp, f->buckets, 8ul * f->nbuckets)
          && st_write(fp, &f->s[FEST_MED], f->nbuckets) && st_write(fp, &f->s[FEST_SHORT], f->nbuckets) && st_write(fp, &f->s[FEST_LONG], f->nbuckets);
    if (ok) ok = fflush(fp) == 0 && fsync(fileno(fp)) == 0;
    if (fclose(fp) != 0) ok = 0;
    if (ok && rename(tmp, path) != 0) ok = 0;
    if (!ok) unlink(tmp);
    return ok;
}
int fest_read_file(void* stv, const char* path, long max_age_hours){
    fest_t* f = (fest_t*)stv;
    if (!fest_valid(f) || !path) return 0;
    struct stat sb;
    if (stat(path, &sb) != 0) return 0;                       /* not found: continue anyway */
    if (max_age_hours >= 0){
        long age_h = (long)((time(NULL) - sb.st_mtime) / 3600);
        if (age_h > max_age_hours) return -1;                 /* too old: not used (Core MAX_FILE_AGE) */
    }
    FILE* fp = fopen(path, "rb");
    if (!fp) return 0;
    char magic[8]; unsigned ver, best_seen, hfirst, hbest, nb;
    int ok = rd(fp, magic, 8) && !memcmp(magic, "BMCFEST\1", 8) && rd(fp, &ver, 4) && ver == FEST_FILE_VERSION
          && rd(fp, &best_seen, 4) && rd(fp, &hfirst, 4) && rd(fp, &hbest, 4) && rd(fp, &nb, 4);
    if (ok && (hfirst > hbest || hbest > best_seen || nb != f->nbuckets)) ok = 0;
    double fb[FEST_MAXB];
    if (ok) ok = rd(fp, fb, 8ul * nb) && !memcmp(fb, f->buckets, 8ul * nb);
    fest_stats_t* ns = ok ? (fest_stats_t*)malloc(3 * sizeof(fest_stats_t)) : 0;
    if (ok && !ns) ok = 0;
    if (ok) ok = st_read(fp, &ns[FEST_MED], nb, MED_BLOCK_PERIODS, MED_SCALE)
              && st_read(fp, &ns[FEST_SHORT], nb, SHORT_BLOCK_PERIODS, SHORT_SCALE)
              && st_read(fp, &ns[FEST_LONG], nb, LONG_BLOCK_PERIODS, LONG_SCALE);
    fclose(fp);
    if (ok){
        memcpy(&f->s[FEST_SHORT], &ns[FEST_SHORT], sizeof(fest_stats_t));
        memcpy(&f->s[FEST_MED],   &ns[FEST_MED],   sizeof(fest_stats_t));
        memcpy(&f->s[FEST_LONG],  &ns[FEST_LONG],  sizeof(fest_stats_t));
        f->best_seen = best_seen; f->hist_first = hfirst; f->hist_best = hbest;
    }
    free(ns);
    return ok ? 1 : -2;                                       /* -2: corrupt/unreadable (non-fatal) */
}
