/* Reproduce the daemon exactly: script_flags_for_block then sv_verify_script
 * for every input of the block's tx1. Keeps flags=0 AND daemon-flags rows. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern int sv_verify_script(const unsigned char* ss, unsigned long ssl,
    const unsigned char* spk, unsigned long spl, unsigned long long flags,
    unsigned long nin, const unsigned char* tx, unsigned long txlen,
    unsigned char* work, unsigned long workcap);
extern unsigned long long script_flags_for_block(unsigned long long height, const unsigned char hash32[32]);
static unsigned char hexv(char c){ return (c<='9')?c-'0': (c<='F')?c-'A'+10: c-'a'+10; }
int main(int argc,char**argv){
    unsigned long long height = argc>1? strtoull(argv[1],0,10) : 0;
    unsigned char hash[32]; for(int i=0;i<32;i++) hash[i]=0;
    unsigned long long fl=script_flags_for_block(height, hash);
    printf("script_flags_for_block(%llu) = 0x%llx\n", height, fl);
    static unsigned char txb[100000], ssv[64][2000], spkv[64][2000];
    FILE*f=fopen("/tmp/tx5807.json","r"); char* line=NULL; size_t cap=0;
    char txh[100000]=""; char ssh[64][2000]={{0}}; char spkh[64][2000]={{0}}; int nins=0;
    while(getline(&line,&cap,f)>0){
        if(!strncmp(line,"TX ",3)){ char*p=strstr(line,"TX ")+3; p[strcspn(p,"\r\n")]=0; strcpy(txh,p); }
        else if(!strncmp(line,"IN",2)){ int idx=atoi(line+2);
            if(strstr(line," SS")){ char*q=strstr(line,"SS ")+3; q[strcspn(q,"\r\n")]=0; strncpy(ssh[idx],q,1999); if(idx+1>nins)nins=idx+1;}
            else if(strstr(line,"SPK")){ char*q=strstr(line,"SPK ")+4; q[strcspn(q,"\r\n")]=0; strncpy(spkh[idx],q,1999); if(idx+1>nins)nins=idx+1;} }
    }
    free(line); fclose(f);
    size_t txlen=strlen(txh)/2;
    for(size_t i=0;i<strlen(txh);i+=2) txb[i/2]=(hexv(txh[i])<<4)|hexv(txh[i+1]);
    for(int i=0;i<nins;i++){
        size_t ssl=strlen(ssh[i])/2, spl=strlen(spkh[i])/2;
        for(size_t j=0;j<strlen(ssh[i]);j+=2) ssv[i][j/2]=(hexv(ssh[i][j])<<4)|hexv(ssh[i][j+1]);
        for(size_t j=0;j<strlen(spkh[i]);j+=2) spkv[i][j/2]=(hexv(spkh[i][j])<<4)|hexv(spkh[i][j+1]);
    }
    static unsigned char work[8<<20];
    printf("txlen=%zu nins=%d\n", txlen, nins);
    int g0=0, gf=0;
    for(int i=0;i<nins;i++){
        int r0=sv_verify_script(ssv[i], strlen(ssh[i])/2, spkv[i], strlen(spkh[i])/2, 0ULL, i, txb, txlen, work, sizeof work);
        int rf=sv_verify_script(ssv[i], strlen(ssh[i])/2, spkv[i], strlen(spkh[i])/2, fl, i, txb, txlen, work, sizeof work);
        printf("input %2d: flags0=%d daemon=%d%s\n", i, r0, rf, (rf&&fl!=0)?"  <-- daemon-flags fail":(fl==0&&r0?"  <-- flags0 fail":""));
        if(r0) g0++; if(rf) gf++;
    }
    printf("fail flags0: %d, fail daemon-flags: %d\n", g0, gf);
    return 0;
}
