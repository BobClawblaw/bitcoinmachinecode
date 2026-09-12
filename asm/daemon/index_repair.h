/* daemon/index_repair.h -- an index that repairs itself (2026-09-10, CORE_DIVERGENCES row 2)
 *
 * Core builds and repairs txindex, coinstatsindex and blockfilterindex inside
 * the daemon. Here the coinstats history has had a repair supervisor since
 * 2026-09-08 (coinstats_index.c): when the base is absent or broken the
 * daemon spawns the offline builder beside its own executable, at nice 10,
 * with a backoff and an attempt cap, and adopts the result. The block filter
 * index and the address history needed an operator. This is that supervisor
 * as a module, one instance per index: the caller says whether the index
 * needs a build and to what height; this decides whether to spawn, reaps,
 * backs off, and words the state for the log and the RPC. Pure enough for
 * tests/test_index_repair.c to drive with a stub builder. */
#ifndef BMC_INDEX_REPAIR_H
#define BMC_INDEX_REPAIR_H
#include <sys/types.h>
enum { IR_IDLE = 0, IR_OK, IR_RUNNING, IR_BACKOFF, IR_GAVE_UP, IR_DISABLED, IR_IBD, IR_NO_BUILDER, IR_WAIT_LOCK };
#define IR_MAX_ATTEMPTS 3
#define IR_BACKOFF_S (6L * 3600L)
typedef struct {
    char name[32];          /* the log tag: "bfilter", "addrhist" */
    char builder[600];      /* absolute path of the builder binary */
    char chaindir[512];     /* the builder's <datadir> argument */
    char chain[32];         /* BMC_CHAIN for the child */
    char lockpath[600];     /* a lock file another builder may hold (optional: "") */
    int enabled, configured;
    int state, attempts;
    pid_t pid;
    long long started, next_allowed;
    long to;
    char why[200];          /* the last line worth showing */
} ir_t;
void ir_configure(ir_t* r, const char* name, const char* builder, const char* chaindir, const char* chain, const char* lockpath, int enabled);
/* one tick: needed = the index needs a (re)build; target = the height the
 * build should reach; in_ibd = do not build during initial block download.
 * Returns the state. The caller runs it once per heartbeat. */
int  ir_tick(ir_t* r, int needed, long target, int in_ibd, long long now);
const char* ir_status(const ir_t* r);   /* one line */
/* the spawn is a seam so the test can watch it without a real builder */
extern pid_t (*ir_spawn_hook)(const ir_t* r, long to);
#endif
