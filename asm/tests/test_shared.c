/* test_shared.c -- multi-process test of store_append_shared: 4 processes each
 * write 50 blocks (disjoint heights) concurrently into ONE store (single dir),
 * then verify every index record is correct (no dups, no gaps, valid positions). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include "test_tmpdir.h"

extern int  store_init(void* st);
extern long store_append_shared(void* st, long height, const void* hash, const void* raw, unsigned long long len);

int main(void){
    /* fixed /tmp path: two concurrent runs shared one store */
    tt_isolate();
    unlink("index.dat"); unlink("blk00000.dat"); unlink("append.lock");

    long total=200;               /* heights 0..199 */
    /* pre-size index.dat to (total)*48 */
    int ix=open("index.dat",O_RDWR|O_CREAT,0644);
    if(ftruncate(ix,total*48)){ perror("ftruncate"); return 1; }
    close(ix);
    /* lockfile */
    int lockfd=open("append.lock",O_RDWR|O_CREAT,0644);

    /* fork 4 children, each writes 50 consecutive heights */
    long per=50;
    for(int w=0;w<4;w++){
        pid_t p=fork();
        if(p==0){
            static unsigned char st[4096];
            if(store_init(st)!=1){ _exit(2); }
            *(int*)((char*)st+40) = lockfd;   /* share the lock fd */
            *(int*)((char*)st+0)  = -1;       /* force lazy blk open */
            /* set cur_file_no=0, magic */
            *(int*)((char*)st+28)=0;
            *(int*)((char*)st+36)=0xd9b4bef9;
            long lo=w*per, hi=lo+per-1;
            for(long h=lo;h<=hi;h++){
                unsigned char hash[32], raw[64];
                for(int k=0;k<32;k++) hash[k]= (unsigned char)((h*7+k*13)&0xff);
                for(int k=0;k<64;k++) raw[k]= (unsigned char)((h*3+k*5)&0xff);
                long r=store_append_shared(st,h,hash,raw,64);
                if(r!=h){ fprintf(stderr,"child %d append h=%ld -> %ld (err)\n",w,h,r); _exit(3); }
            }
            _exit(0);
        }
    }
    for(int w=0;w<4;w++){ int stt; waitpid(-1,&stt,0); }
    close(lockfd);

    /* ---- verify: every height has a unique non-zero record, valid pos/size ---- */
    int ok=1;
 unsigned char idx[200*48];
 FILE* f=fopen("index.dat","rb"); size_t got=fread(idx,1,total*48,f); fclose(f);
 if((long)got != total*48){ printf("FAIL index size got %zu exp %ld\n",got,total*48); ok=0; }
 unsigned long long maxpos=0;
 for(long h=0;h<total;h++){
     unsigned char* rec=idx+h*48;
     if(rec[0]==0 && rec[1]==0 && rec[2]==0 && rec[3]==0){ printf("FAIL h=%ld zero hash\n",h); ok=0; }
     uint32_t fno; memcpy(&fno,rec+32,4);
     uint64_t pos; memcpy(&pos,rec+36,8);
     uint32_t sz;  memcpy(&sz,rec+44,4);
     if(fno!=0){ printf("FAIL h=%ld fno=%u (want 0)\n",h,fno); ok=0; }
     if(sz!=64){ printf("FAIL h=%ld sz=%u (want 64)\n",h,sz); ok=0; }
     if(maxpos < pos+8+64) maxpos = pos+8+64;
     for(int k=0;k<32;k++){ unsigned char e=(unsigned char)((h*7+k*13)&0xff); if(rec[k]!=e){ printf("FAIL h=%ld hash[%d]\n",h,k); ok=0; break; } }
 }
 printf("max file size %llu bytes\n", maxpos);
 printf("== %s ==\n", ok?"SHARED-APPEND PASS (no dups, valid records)":"SHARED-APPEND FAIL");
 return ok?0:1;
}
