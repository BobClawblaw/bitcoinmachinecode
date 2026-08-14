#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern long store_init(void*);
extern long store_reload(void*);
extern long node_serve_block(void* st, long h, void* out, long cap);
int main(int argc,char**argv){
    if(argc<2) return 2;
    chdir(argv[1]);
    static unsigned char st[4096];
    if(store_init(st)!=1){printf("init fail\n"); return 1;}
    long r=store_reload(st);
    printf("reload=%ld idx_fd(st+8)=%ld idx_len(st+16)=%ld tip=%d\n",
        r, *(long*)(st+8), *(long*)(st+16), *(int*)(st+24));
    static unsigned char out[1<<22];
    int fail_at=-1, ok=0;
    for(int h=0;h<=3200;h++){
        long L=node_serve_block(st,h,out,(long)sizeof out);
        if(L<80){ fail_at=h; printf("FAIL at h=%d (L=%ld)\n",h,L); break; }
        ok++;
    }
    printf("node_serve_block ok through %d heights\n", ok);
    /* also directly try high heights */
    for(int h=1018;h<=1020;h++){
        long L=node_serve_block(st,h,out,(long)sizeof out);
        printf("h=%d -> L=%ld\n", h,L);
    }
    /* probe store_get_at + file fd for the failing heights */
    extern long store_get_at(void*,long,void*);
    extern long store_get_file_fd(void*,int);
    for(int h=1019;h<=1020;h++){
        long meta[3];
        long rc=store_get_at(st,h,meta);
        printf("store_get_at h=%d rc=%ld pos=%ld size=%ld file=%ld\n",h,rc,meta[0],meta[1],meta[2]);
        if(rc==1){ long fd=store_get_file_fd(st,(int)meta[2]); printf("  store_get_file_fd(%d)=%ld\n",(int)meta[2],fd); }
    }
    return 0;
}
