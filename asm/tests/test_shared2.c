/* test_shared2.c -- stronger: verify the ACTUAL blk bytes at each index-record
 * position match the expected raw payload (h*3+k*5)&0xff. This catches
 * overlapping writes that index-only checks miss. */
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
extern int store_init(void* st);
extern long store_append_shared(void* st, long height, const void* hash, const void* raw, unsigned long long len);
int main(void){
    /* fixed /tmp path: two concurrent runs shared one store */
    tt_isolate();
    unlink("index.dat"); unlink("blk00000.dat"); unlink("append.lock");
    long total=400; long per=100;
    int ix=open("index.dat",O_RDWR|O_CREAT,0644); if(ftruncate(ix,total*48)){perror("ftruncate");return 1;} close(ix);
    int lockfd=open("append.lock",O_RDWR|O_CREAT,0644); close(lockfd); /* create it */
    for(int w=0;w<4;w++){
        pid_t p=fork();
        if(p==0){
            /* EACH child opens its OWN lockfile fd -> its own open file
             * description, so flock contends correctly across processes
             * (fork-shared fds would share the description and bypass flock). */
            int lfd=open("append.lock",O_RDWR,0644);
            static unsigned char st[4096]; store_init(st);
            *(int*)((char*)st+40)=lfd; *(int*)((char*)st+0)=-1;
            *(int*)((char*)st+28)=0; *(int*)((char*)st+36)=0xd9b4bef9;
            long lo=w*per;
            for(long h=lo;h<lo+per;h++){
                unsigned char hash[32],raw[64];
                for(int k=0;k<32;k++)hash[k]=(unsigned char)((h*7+k*13)&0xff);
                for(int k=0;k<64;k++)raw[k]=(unsigned char)((h*3+k*5)&0xff);
                if(store_append_shared(st,h,hash,raw,64)!=h)_exit(3);
            }
            _exit(0);
        }
    }
    for(int w=0;w<4;w++){int s;waitpid(-1,&s,0);}
    int ok=1;
    /* read all records, verify blk bytes at each pos */
    unsigned char* idx=malloc(total*48);
    FILE* f=fopen("index.dat","rb"); if(fread(idx,1,total*48,f)!=(size_t)(total*48)){printf("FAIL index.dat short read\n");ok=0;} fclose(f);
    FILE* b=fopen("blk00000.dat","rb");
    long minpos=1000000000000LL, maxpos=0;
    for(long h=0;h<total;h++){
        unsigned char* rec=idx+h*48;
        uint64_t pos; memcpy(&pos,rec+36,8); uint32_t sz; memcpy(&sz,rec+44,4);
        if(pos<minpos)minpos=pos;
        if(pos+8+sz>maxpos)maxpos=pos+8+sz;
        /* read frame header then raw and compare raw to expected */
        fseek(b,(long)pos+8,SEEK_SET);
        unsigned char got[64]; if(fread(got,1,64,b)!=64){printf("FAIL h=%ld read\n",h);ok=0;continue;}
        for(int k=0;k<64;k++){unsigned char e=(unsigned char)((h*3+k*5)&0xff);if(got[k]!=e){printf("FAIL h=%ld raw[%d] %02x!=%02x (pos=%llu)\n",h,k,got[k],e,(unsigned long long)pos);ok=0;break;}}
    }
    fclose(b);
    printf("total unique blk span: min=%ld max=%ld expect ~%ld bytes\n", minpos, maxpos, total*(8+64));
    printf("== %s ==\n", ok?"SHARED-APPEND BYTES PASS":"SHARED-APPEND BYTES FAIL (overlap/corruption)");
    free(idx);
    return ok?0:1;
}
