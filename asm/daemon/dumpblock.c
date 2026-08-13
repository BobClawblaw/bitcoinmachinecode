/* daemon/dumpblock.c -- dump a block from the single-directory archive.
 * Reads index.dat record (hash,file_no,pos,size) for a height, seeks into
 * blkNNNNN.dat, and prints the raw block (or a header summary).
 * Usage: dumpblock <dir> <height> [summary|raw]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
int main(int argc,char**argv){
    if(argc<3){ fprintf(stderr,"usage: %s <dir> <height> [raw]\n",argv[0]); return 2; }
    const char* dir=argv[1]; long h=atol(argv[2]); int raw= argc>3;
    char ip[640]; snprintf(ip,sizeof ip,"%s/index.dat",dir);
    FILE* f=fopen(ip,"rb");
    if(!f||fseek(f,h*48,SEEK_SET)!=0){ perror("index"); return 1; }
    unsigned char rec[48]; if(fread(rec,1,48,f)!=48){ printf("height %ld out of range\n",h); return 1; }
    fclose(f);
    if(rec[0]==0&&rec[1]==0&&rec[2]==0&&rec[3]==0){ printf("height %ld: NOT STORED (hole)\n",h); return 1; }
    uint32_t fno; memcpy(&fno,rec+32,4);
    uint64_t pos; memcpy(&pos,rec+36,8);
    uint32_t sz;  memcpy(&sz,rec+44,4);
    char bn[80]; snprintf(bn,sizeof bn,"%s/blk%05u.dat",dir,(unsigned)fno);
    FILE* b=fopen(bn,"rb");
    if(!b||fseek(b,(long)(pos+8),SEEK_SET)!=0){ perror("blk"); return 1; }
    unsigned char* blk=malloc(sz+1); if(fread(blk,1,sz,b)!=(size_t)sz){ printf("read fail\n"); return 1; }
    fclose(b);
    if(raw){ fwrite(blk,1,sz,stdout); }
    else {
        unsigned char hh[32]; block_hash(hh,blk);
        int ver; memcpy(&ver,blk,4);
        printf("height %ld  size %u  file%u@%llu\n", h, sz, (unsigned)fno, (unsigned long long)pos);
        printf("  hash      %s\n", (hh[0]|hh[1]|hh[2])? "?" : "?");
        printf("  hash(hex) ");
        for(int i=0;i<32;i++) printf("%02x",hh[i]); printf("\n");
        printf("  version   %d\n", ver);
        printf("  prev      ");
        for(int i=4;i<36;i++) printf("%02x",blk[i]); printf("\n");
        printf("  merkle    ");
        for(int i=36;i<68;i++) printf("%02x",blk[i]); printf("\n");
        uint32_t time,mbits,nonce; memcpy(&time,blk+68,4); memcpy(&mbits,blk+72,4); memcpy(&nonce,blk+76,4);
        printf("  time      %u (UTC %zu)\n", time, (size_t)time);
        printf("  nbits     %08x\n", (unsigned)mbits);
        printf("  nonce     %u\n", (unsigned)nonce);
        printf("  tx count  (varint at +80)\n");
        switch(blk[80]){ case 0xfd: printf("  -> %u txs (2-byte)\n",(unsigned)(blk[81]|blk[82]<<8)); break;
                         case 0xfe: printf("  -> %u txs (4-byte)\n",(unsigned)(blk[81]|blk[82]<<8|blk[83]<<16|blk[84]<<24)); break;
                         default: printf("  -> %u txs\n",(unsigned)blk[80]); }
    }
    free(blk);
    return 0;
}
