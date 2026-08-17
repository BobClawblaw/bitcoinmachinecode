/* daemon/chainctl.c -- full-chain download/audit orchestrator for the
 * single-directory (pre-sized positional index) archive.
 *
 * Each pass:
 *   1. find the real archive tip = highest NON-ZERO index record (the pre-sized
 *      positional index has zero-fill holes for not-yet-fetched heights, so the
 *      size-based tip is wrong -- scan for the last real record).
 *   2. ask the header source for the current header count (headers.dat).
 *   3. run unified_ibd for the next bounded CHUNK [tip+1, min(tip+CHUNK, headers-1)]
 *      (bounded so each segment completes in reasonable time and self-resumes).
 *   4. run check_chain to audit the segment (dups/gaps/corruption).
 *   5. loop until the archive reaches the header tip, then follow new blocks.
 *
 * Usage: chainctl <dir> <num_workers> [chunk] [sleep_sec]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

extern long idxscan_tip(void);

static long archive_tip(const char* dir){
    /* highest height with a non-zero 48-byte index record (positional format).
     * Was a per-record fseek+fread backward scan; idxscan_tip (bitcoin_idx-
     * scan.asm) does the same buffered-pread64 scan already used by the
     * live daemon's dl_catchup. idxscan_tip operates on "index.dat" in CWD,
     * so chdir into dir for the call and restore CWD afterward (nothing
     * else in this file depends on staying in a particular directory --
     * every other path is built explicitly from dir or absolute). */
    char cwd[600]; if(!getcwd(cwd,sizeof cwd)) return -1;
    if(chdir(dir)!=0) return -1;
    long mh = idxscan_tip();
    if(chdir(cwd)!=0) { perror("chdir back"); }
    return mh;
}
static long header_count(const char* dir){
    char p[600]; snprintf(p,sizeof p,"%s/headers.dat",dir);
    struct stat sb; if(stat(p,&sb)) return -1;
    return (long)(sb.st_size/112);
}
int main(int argc,char**argv){
    setbuf(stdout,NULL);
    if(argc<3){ fprintf(stderr,"usage: %s <dir> <num_workers> [chunk] [sleep_sec]\n",argv[0]); return 2; }
    const char* dir=argv[1];
    int nw=atoi(argv[2]);
    long chunk = argc>3? atol(argv[3]) : 8000;
    int sleep_sec = argc>4? atoi(argv[4]) : 30;
    char cwd[600]; getcwd(cwd,sizeof cwd);
    time_t t_start=time(NULL); long first_tip=-1;
    for(int pass=1;;pass++){
        long tip=archive_tip(dir);
        long nh=header_count(dir);
        if(first_tip<0) first_tip=tip>0?tip:0;
        long t_el=time(NULL)-t_start;
        double secs_per_block = (t_el>0 && tip>first_tip)? (double)t_el/(tip-first_tip) : 0;
        printf("\n[pass %d] archive tip=%ld headers=%ld (need %ld more) elapsed=%lds",
               pass, tip, nh, nh-1-tip, t_el);
        if(secs_per_block>0){
            long rem=nh-1-tip;
            double eta_s=secs_per_block*rem;
            printf("  ~%d blk/s  ETA ~%dh%02dm", (int)(1.0/secs_per_block), (int)(eta_s/3600), ((int)eta_s/60)%60);
        }
        printf("\n");
        if(nh<0){ printf("[pass %d] no headers yet; retry in %ds\n",pass,sleep_sec); sleep(sleep_sec); continue; }
        if(tip<nh-1){
            long end = tip+chunk < nh-1 ? tip+chunk : nh-1;
            printf("[pass %d] downloading chunk [%ld,%ld] (%ld blocks)\n", pass, tip+1, end, end-tip);
            char cmd[700]; snprintf(cmd,sizeof cmd,"./daemon/unified_ibd %s %d %ld %ld", dir, nw, tip+1, end);
            printf("[pass %d] $ %s\n", pass, cmd);
            fflush(stdout);
            int rc=system(cmd);
            printf("[pass %d] unified_ibd rc=%d; auditing...\n", pass, rc);
            fflush(stdout);
            char acmd[700]; snprintf(acmd,sizeof acmd,"./daemon/check_chain %s", dir);
            system(acmd);
        } else if(tip>=nh-1){
            printf("[pass %d] archive is current at the chain tip (block %ld). Following for new blocks...\n", pass, tip);
        }
        sleep(sleep_sec);
    }
    return 0;
}
