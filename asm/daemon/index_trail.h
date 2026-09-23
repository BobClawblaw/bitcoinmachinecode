/* daemon/index_trail.h -- an index that builds itself DURING the sync (2026-09-16).
 *
 * index_repair.h's supervisor makes one whole-chain build after initial
 * block download and adopts it. This one keeps an index of sorted RUNS
 * (index_runs.h) trailing the applied height by a fixed safety margin, from
 * the first blocks of a fresh sync to the end of the node's life: every
 * `run_blocks` heights it spawns the builder over the next range into a new
 * run file, tells the caller (so the unsorted tail can drop what the run now
 * covers), and when the runs pile up it spawns the merger to fold them into
 * one. There is nothing to do "after IBD" because there was never a phase
 * that waited for it.
 *
 * One child at a time per index, nice 10, reaped at the heartbeat. A failed
 * child (non-zero exit) is retried after a backoff, without an attempt cap:
 * this is a standing job on a node that runs for months, not a one-shot
 * repair, and the failure is logged every time it happens. The spawn is a
 * seam so tests drive the state machine with a stub. */
#ifndef BMC_INDEX_TRAIL_H
#define BMC_INDEX_TRAIL_H
#include <sys/types.h>
enum { IT_IDLE = 0, IT_CURRENT, IT_BUILDING, IT_MERGING, IT_BACKOFF, IT_DISABLED, IT_NO_BUILDER };
#define IT_BACKOFF_S 600L
typedef struct {
    char name[32];          /* the run set's name and the log tag: "txindex" */
    char builder[600];      /* <builder> <chaindir> <from> <to> <runfile> */
    char merger[600];       /* <merger> <chaindir> <name>  (optional: "") */
    char chaindir[512];
    char chain[32];         /* BMC_CHAIN for the child */
    long run_blocks;        /* build a run once this many heights are ready */
    long safety;            /* stay this far below the applied height */
    int  merge_at;          /* merge when the run count reaches this (0 = never) */
    int  enabled, configured;
    pid_t pid; int kind;    /* kind: 1 build, 2 merge */
    long from, to;          /* the running child's range */
    long long started, next_allowed;
    int  failures;          /* consecutive */
    long runs_built, merges;
    int  state; char why[240];
} itrail_t;
void it_configure(itrail_t* t, const char* name, const char* builder, const char* merger,
                  const char* chaindir, const char* chain, long run_blocks, long safety, int merge_at, int enabled);
/* One tick. covered = the highest height the runs reach (-1 none); nruns =
 * how many runs there are; applied = the engine's applied height. on_run is
 * called once for every run that a build child committed, with its to
 * height, so the caller can rotate the tail. Returns the state. */
int  it_tick(itrail_t* t, long covered, int nruns, long applied, long long now,
             void (*on_run)(long to, void* ctx), void* ctx);
const char* it_status(const itrail_t* t);
extern pid_t (*it_spawn_hook)(const itrail_t* t, int kind, long from, long to);
#endif
