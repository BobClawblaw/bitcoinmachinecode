/* daemon/merge_only.c -- consolidate a set of paribd_asm worker shard stores
 * (w0..w7) into a single rolling multi-file archive (blk00000.dat + index.dat)
 * using the ASM store_append, exactly like paribd_asm's merge phase. Lets us
 * snapshot + re-serve the downloaded blocks at any moment while the full
 * download is still running.
 *
 * Usage: merge_only <src_dir> <dst_dir> <nw> <start_h> <end_h>
 *   reads src_dir/w<0..nw-1>/{blk00000.dat,index.dat}; writes the merged store
 *   into dst_dir via asm store_append (rolls blk files at 128MiB).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

extern int  store_init(void* st);
extern long store_append(void* st, const unsigned char hash[32], const void* raw, unsigned long long len);

int main(int argc, char** argv){
    if(argc<3){ fprintf(stderr,"usage: %s <src_dir> <dst_dir> [nw] [start_h] [end_h]\n",argv[0]); return 2; }
    const char* src=argv[1];
    const char* dst=argv[2];
    int nw = argc>3? atoi(argv[3]) : 8;
    long start_h = argc>4? atol(argv[4]) : 0;
    long end_h   = argc>5? atol(argv[5]) : 962260;
    mkdir(dst,0755);
    if(chdir(dst)!=0){ perror("chdir dst"); return 1; }

    static unsigned char mst[4096];
    store_init(mst);                       /* opens CWD index.dat + blk00000.dat */
    static unsigned char combuf[64<<20];
    long written=0; long long totalbytes=0;
    for(int w=0; w<nw; w++){
        long lo_w = start_h + (long)((long long)(end_h-start_h+1)*w/nw);
        char wip[512]; snprintf(wip,sizeof wip,"%s/w%d/index.dat",src,w);
        FILE* wx=fopen(wip,"rb"); if(!wx) continue;
        char wp[512]; snprintf(wp,sizeof wp,"%s/w%d/blk00000.dat",src,w);
        FILE* wf=fopen(wp,"rb"); if(!wf){ fclose(wx); continue; }
        unsigned char rec[48]; long local=0;
        while(fread(rec,1,48,wx)==48){
            /* worker index (asm store): hash[0..31] file_no u32[32..35]
               data_pos u64[36..43] data_size u32[44..47] */
            unsigned len=(unsigned)(rec[44]|rec[45]<<8|rec[46]<<16|rec[47]<<24);
            if(len==0 || len>64u<<20){ local++; continue; }   /* stub / torn read */
            unsigned long long off=0;
            for(int k=0;k<8;k++) off |= (unsigned long long)rec[36+k]<<(8*k);
            if(fseek(wf,(long)(off+8),SEEK_SET)!=0){ local++; continue; }
            if(fread(combuf,1,len,wf)!=(size_t)len){ local++; continue; }
            long nh=store_append(mst, rec, combuf, len);
            if(nh<0){ fclose(wf); fclose(wx); printf("store_append failed w%d/%ld\n",w,local); return 1; }
            written++; totalbytes += 8+len; local++;
        }
        fclose(wf); fclose(wx);
        printf("merged worker w%d: %ld blocks\n", w, local);
    }
    int nfiles=0; while(1){ struct stat sb; char nm[64]; snprintf(nm,sizeof nm,"blk%05u.dat",(unsigned)nfiles);
        if(stat(nm,&sb)!=0) break; nfiles++; }
    printf("merged %ld real blocks (%lld bytes) across %d blk*.dat files in %s\n",
           written, totalbytes, nfiles, dst);
    return 0;
}
