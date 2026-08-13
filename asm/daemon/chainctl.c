/* daemon/chainctl.c -- follow-to-tip orchestrator for the unified store.
 *
 * Continuously keeps ONE unified archive (<dir>/blk00000.dat.. + index.dat) in
 * sync with the chain tip. Each pass:
 *   1. reads the current store tip (getblockcount) via the asm store.
 *   2. asks the header source for the current header count (headers.dat).
 *   3. runs the parallel unified_ibd for exactly [tip+1, header_count-1].
 *   4. sleeps briefly and loops, so new blocks that arrive are fetched too.
 * Thus an archive node keeps following the live chain rather than downloading a
 * fixed range once.
 *
 * Usage: chainctl <dir> <num_workers> [sleep_seconds]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>

extern int  store_init(void* st);
extern int  store_reload(void* st);
static long archive_tip(const char* dir){
    /* The unified store has index.dat: 48 bytes per height. tip = records-1. */
    char p[600]; snprintf(p,sizeof p,"%s/index.dat",dir);
    struct stat sb; if(stat(p,&sb)) return -1;
    return (long)(sb.st_size/48) - 1;
}
static long header_count(const char* dir){
    /* headers.dat: 112 bytes per header (80 hdr + 32 hash). */
    char p[600]; snprintf(p,sizeof p,"%s/headers.dat",dir);
    struct stat sb; if(stat(p,&sb)) return -1;
    return (long)(sb.st_size/112);
}
int main(int argc,char**argv){
    setbuf(stdout,NULL);
    if(argc<3){ fprintf(stderr,"usage: %s <dir> <num_workers> [sleep_sec]\n",argv[0]); return 2; }
    const char* dir=argv[1];
    int nw=atoi(argv[2]); int sleep_sec= argc>3? atoi(argv[3]) : 30;
    char cwd[600]; getcwd(cwd,sizeof cwd);
    for(int pass=1;;pass++){
        long tip=archive_tip(dir);
        long nh=header_count(dir);
        printf("[pass %d] archive tip=%ld headers=%ld\n", pass, tip, nh);
        if(nh<0){ printf("[pass %d] no headers yet; retry in %ds\n",pass,sleep_sec); sleep(sleep_sec); continue; }
        if(tip<nh-1){
            printf("[pass %d] downloading [%ld,%ld] (%ld blocks)\n", pass, tip+1, nh-1, nh-1-tip);
            chdir(cwd);
            char cmd[700]; snprintf(cmd,sizeof cmd,"./daemon/unified_ibd %s %d %ld %ld", dir, nw, tip+1, nh-1);
            printf("[pass %d] $ %s\n", pass, cmd);
            fflush(stdout);
            if(system(cmd)!=0){ printf("[pass %d] unified_ibd returned error; retry in %ds\n",pass,sleep_sec); }
        } else {
            printf("[pass %d] archive is current (tip=%ld >= headers-1=%ld); ... %ds\n", pass, tip, nh-1, sleep_sec);
        }
        sleep(sleep_sec);
    }
    return 0;
}
