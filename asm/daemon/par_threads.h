/* daemon/par_threads.h -- Core's -par, exactly.
 *
 * Core (node/chainstatemanager_args.cpp):
 *     script_threads = -par;                      // default 0
 *     if (script_threads <= 0) script_threads += GetNumCores();
 *     worker_threads_num = script_threads - 1;    // the main thread counts too
 * So -par is the TOTAL number of threads doing script checks, the calling
 * thread included: 0 = every core, -n = leave n cores free, 1 = the caller
 * alone.
 *
 * 2026-09-06: this node parsed `par`, printed it at boot, and then used it for
 * the DOWNLOAD chunk-worker count, while both script-verify pools sized
 * themselves from sysconf() and never read it. par=8 therefore gave a node
 * that still verified on every core AND halved its download parallelism --
 * the opposite of the ask, in both halves. The download count is
 * bmc.catchupworkers now. Its own file so a test can link it alone. */
#ifndef PAR_THREADS_H
#define PAR_THREADS_H
void par_set(int par);          /* the configured -par, verbatim */
int  par_get(void);
int  par_script_threads(void);  /* threads that will do script checks, caller included; >= 1 */
#endif
