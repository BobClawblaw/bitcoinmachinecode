/* t_roll.c -- exercise the store file-rollover path (128MB barrier) that the
 * unit test cannot reach: init, force cur_file_pos near MAX_FILE, append a
 * block, confirm it lands in blk00001.dat at data_pos 0 with proper framing. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

typedef unsigned long long u64;
typedef unsigned int u32;

/* layout mirror */
struct St { u64 cur_blk_fd, idx_fd, idx_len; int tip_height, cur_file_no, cur_file_pos, magic, pad, pad2, prune_height; };
extern int store_init(void*);
extern int store_append(void* st, const void* hash, const void* raw, u64 len);
extern int store_get_at(void* st, u64 height, u64* meta);

int main(void){
    /* do it in a temp dir we control */
    char d[64]; snprintf(d,sizeof d,"/tmp/troll_%d",getpid());
    mkdir(d,0700); if(chdir(d)) return 2;
    struct St st; memset(&st,0,sizeof st);
    if(store_init(&st)!=1){ printf("FAIL init\n"); return 1; }
    /* append one small block normally -> file 0 */
    unsigned char h0[32]={0}; unsigned char raw0[40]; memset(raw0,1,sizeof raw0);
    if(store_append(&st,h0,raw0,40)!=0){ printf("FAIL append0\n"); return 1; }
    /* simulate a full current file: pos == MAX so pos+8+len strictly exceeds */
    st.cur_file_pos = 0x08000000;
    /* now append a 64-byte block -> must roll to blk00001.dat, pos 0 */
    unsigned char h1[32]={1}; unsigned char raw1[64]; memset(raw1,2,sizeof raw1);
    int hgt = store_append(&st,h1,raw1,64);
    printf("append_height=%d cur_file_no=%d cur_file_pos=%d\n", hgt, st.cur_file_no, st.cur_file_pos);
    if(hgt!=1) { printf("FAIL append rolled height\n"); return 1; }
    if(st.cur_file_no!=1 || st.cur_file_pos!=72){ printf("FAIL rollover state\n"); return 1; }
    /* read it back: height 1 should be in file 1 at pos 0 */
    u64 meta[3];
    if(store_get_at(&st,1,meta)!=1){ printf("FAIL get_at h1\n"); return 1; }
    printf("meta pos=%llu size=%llu file=%llu\n",meta[0],meta[1],meta[2]);
    if(meta[0]!=0 || meta[1]!=64 || meta[2]!=1){ printf("FAIL rolled meta\n"); return 1; }
    /* check blk00001.dat framing on disk */
    FILE*f=fopen("blk00001.dat","rb");
    if(!f){ printf("FAIL no blk00001.dat\n"); return 1; }
    unsigned char b[80]; size_t n=fread(b,1,sizeof b,f); fclose(f);
    u32 len=b[0]|(b[1]<<8)|(b[2]<<16)|(b[3]<<24);
    u32 magic=b[4]|(b[5]<<8)|(b[6]<<16)|(b[7]<<24);
    printf("blk00001.dat frame len=%u magic=%08x raw0=%d n=%zu\n",len,magic,b[8],n);
    if(n!=72 || len!=64 || magic!=0xd9b4bef9 || b[8]!=2){ printf("FAIL rolled framing\n"); return 1; }
    printf("ROLLOVER OK\n");
    char cmd[256]; snprintf(cmd,sizeof cmd,"rm -rf %s",d); system(cmd);
    return 0;
}
