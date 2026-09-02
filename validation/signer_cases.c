/* scratch: produce signed txs for every new script form via rpc_dispatch and
 * print "<label>|<prevtx-json>|<signed-hex>|<complete>" lines for the Core
 * regtest differential (Core's VerifyScript is the judge). */
#include <stdio.h>
#include <string.h>
#include "../asm/rpc_commands.h"
#include "../asm/rpc_json.h"
typedef unsigned char u8;
extern void scalar_to_pubkey(u8 pub[33], const u8 priv[32]);
extern void hash160(u8 out[20], const void* in, long long len);
extern void sha256_full(u8 out[32], const void* msg, unsigned long len);
extern void base58check_encode(char* out, const u8* payload, long long paylen);
extern int  bip32_xonly_tweak_add(const u8 x[32], const u8 t[32], u8 out_x[32]);
static void hexs(char* o, const u8* b, int n){ for (int i=0;i<n;i++) sprintf(o+2*i,"%02x",b[i]); o[2*n]=0; }
static rj_val* call(const char* m, const char* pj, long* ec, const char** em){ rj_val* p=rj_parse(pj,strlen(pj)); rj_val* r=NULL; rpc_wallet w; memset(&w,0,sizeof w); rpc_dispatch(m,p,&w,&r,ec,em); rj_free(p); return r; }
#define UNSIGNED "020000000101000000000000000000000000000000000000000000000000000000000000000000000000fdffffff01605af405000000001976a914fc7250a211deddc70ee5a2738de5f07817351cef88ac00000000"
static void run(const char* label, const char* keys_json, const char* prevtx, const char* sht){
    char p[4000]; snprintf(p,sizeof p,"[\"%s\",%s,[%s]%s%s%s]", UNSIGNED, keys_json, prevtx, sht?",\"":"", sht?sht:"", sht?"\"":"");
    long ec; const char* em; rj_val* r=call("signrawtransactionwithkey",p,&ec,&em);
    rj_val* hex=r?rj_obj_get(r,"hex"):NULL; rj_val* comp=r?rj_obj_get(r,"complete"):NULL; rj_val* errs=r?rj_obj_get(r,"errors"):NULL;
    printf("%s|%s|%s|%s|%s\n", label, prevtx, hex&&hex->typ==RJ_STR?hex->str:"-", comp?comp->str:"?", errs&&errs->nitems?rj_obj_get(errs->items[0],"error")->str:"");
    rj_free(r);
}
int main(void){
    u8 priv[3][32], pub[3][33]; char wif[3][64], pubh[3][67];
    for (int k=0;k<3;k++){ for (int i=0;i<32;i++) priv[k][i]=(u8)(0x11*(k+1)); scalar_to_pubkey(pub[k],priv[k]); hexs(pubh[k],pub[k],33);
        u8 pay[34]; pay[0]=0x80; memcpy(pay+1,priv[k],32); pay[33]=1; base58check_encode(wif[k],pay,34); }
    char keys2[200]; snprintf(keys2,sizeof keys2,"[\"%s\",\"%s\"]",wif[0],wif[1]);
    char keys1[100]; snprintf(keys1,sizeof keys1,"[\"%s\"]",wif[0]);
    char keys3[300]; snprintf(keys3,sizeof keys3,"[\"%s\",\"%s\",\"%s\"]",wif[0],wif[1],wif[2]);
    /* 2-of-3 CHECKMULTISIG */
    u8 ms[110]; int o=0; ms[o++]=0x52; for (int k=0;k<3;k++){ ms[o++]=33; memcpy(ms+o,pub[k],33); o+=33; } ms[o++]=0x53; ms[o++]=0xae; int msl=o;
    char msh[300]; hexs(msh,ms,msl);
    u8 wsh[32]; sha256_full(wsh,ms,msl); char wshh[65]; hexs(wshh,wsh,32);
    char prev[1200];
    snprintf(prev,sizeof prev,"{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"0020%s\",\"amount\":1.0,\"witnessScript\":\"%s\"}",wshh,msh);
    run("p2wsh-2of3-2keys", keys2, prev, NULL);
    run("p2wsh-2of3-1key-partial", keys1, prev, NULL);
    run("p2wsh-2of3-3keys", keys3, prev, NULL);
    /* P2SH-P2WSH */
    u8 rd[34]; rd[0]=0; rd[1]=0x20; memcpy(rd+2,wsh,32); u8 rh[20]; hash160(rh,rd,34); char rhh[41]; hexs(rhh,rh,20); char rdh[70]; hexs(rdh,rd,34);
    snprintf(prev,sizeof prev,"{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"a914%s87\",\"amount\":1.0,\"redeemScript\":\"%s\",\"witnessScript\":\"%s\"}",rhh,rdh,msh);
    run("p2sh-p2wsh-2of3", keys2, prev, NULL);
    /* legacy P2SH 2-of-2 */
    u8 ms2[80]; o=0; ms2[o++]=0x52; for (int k=0;k<2;k++){ ms2[o++]=33; memcpy(ms2+o,pub[k],33); o+=33; } ms2[o++]=0x52; ms2[o++]=0xae; int ms2l=o;
    char ms2h[200]; hexs(ms2h,ms2,ms2l); u8 r2[20]; hash160(r2,ms2,ms2l); char r2h[41]; hexs(r2h,r2,20);
    snprintf(prev,sizeof prev,"{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"a914%s87\",\"amount\":1.0,\"redeemScript\":\"%s\"}",r2h,ms2h);
    run("p2sh-legacy-2of2", keys2, prev, NULL);
    run("p2sh-legacy-2of2-1key-partial", keys1, prev, NULL);
    /* P2WSH single-key CHECKSIG */
    u8 cs[35]; cs[0]=33; memcpy(cs+1,pub[0],33); cs[34]=0xac; u8 csh[32]; sha256_full(csh,cs,35); char cshh[65]; hexs(cshh,csh,32); char csx[80]; hexs(csx,cs,35);
    snprintf(prev,sizeof prev,"{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"0020%s\",\"amount\":1.0,\"witnessScript\":\"%s\"}",cshh,csx);
    run("p2wsh-pk-checksig", keys1, prev, NULL);
    /* P2TR key path: Q = tweak(P) with no tree */
    u8 th[32]; sha256_full(th,"TapTweak",8); u8 tb[96]; memcpy(tb,th,32); memcpy(tb+32,th,32); memcpy(tb+64,pub[0]+1,32); u8 t[32]; sha256_full(t,tb,96);
    u8 q[32]; bip32_xonly_tweak_add(pub[0]+1,t,q); char qh[65]; hexs(qh,q,32);
    snprintf(prev,sizeof prev,"{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"5120%s\",\"amount\":1.0}",qh);
    run("p2tr-keypath-default", keys1, prev, NULL);
    run("p2tr-keypath-all", keys1, prev, "ALL");
    run("p2tr-keypath-single-acp", keys1, prev, "SINGLE|ANYONECANPAY");
    run("p2tr-keypath-wrongkey", "[\"" "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1" "\"]", prev, NULL);

    /* P2TR script path (2026-09-01): internal key = key 2; leaf A = pk(x0),
     * leaf B = multi_a(2, x0, x1); tree {A, B}. Core verifies the control
     * block (with the output-key parity bit) and the tapscript witness. */
    { extern int bip32_xonly_tweak_add_par(const u8*, const u8*, u8*, int*);
      u8 la[34]; la[0]=0x20; memcpy(la+1,pub[0]+1,32); la[33]=0xac;
      u8 lb[70]; int lo=0; lb[lo++]=0x20; memcpy(lb+lo,pub[0]+1,32); lo+=32; lb[lo++]=0xac; lb[lo++]=0x20; memcpy(lb+lo,pub[1]+1,32); lo+=32; lb[lo++]=0xba; lb[lo++]=0x52; lb[lo++]=0x9c;
      u8 tl[32]; sha256_full(tl,"TapLeaf",7);
      u8 ha[32], hb[32];
      { u8 b[64+1+1+34]; memcpy(b,tl,32); memcpy(b+32,tl,32); b[64]=0xc0; b[65]=34; memcpy(b+66,la,34); sha256_full(ha,b,66+34); }
      { u8 b[64+1+1+70]; memcpy(b,tl,32); memcpy(b+32,tl,32); b[64]=0xc0; b[65]=(u8)lo; memcpy(b+66,lb,lo); sha256_full(hb,b,66+lo); }
      u8 tbr[32]; sha256_full(tbr,"TapBranch",9); u8 root[32];
      { u8 b[128]; memcpy(b,tbr,32); memcpy(b+32,tbr,32); if (memcmp(ha,hb,32)<=0){ memcpy(b+64,ha,32); memcpy(b+96,hb,32);} else { memcpy(b+64,hb,32); memcpy(b+96,ha,32);} sha256_full(root,b,128); }
      u8 tt[32]; { u8 b[128]; memcpy(b,th,32); memcpy(b+32,th,32); memcpy(b+64,pub[2]+1,32); memcpy(b+96,root,32); sha256_full(tt,b,128); }
      u8 Q[32]; int odd=0; bip32_xonly_tweak_add_par(pub[2]+1,tt,Q,&odd); char Qh[65]; hexs(Qh,Q,32);
      u8 ca[65]; ca[0]=(u8)(0xc0|odd); memcpy(ca+1,pub[2]+1,32); memcpy(ca+33,hb,32);   /* control for A: sibling = B */
      u8 cb[65]; cb[0]=(u8)(0xc0|odd); memcpy(cb+1,pub[2]+1,32); memcpy(cb+33,ha,32);
      char lah[80], lbh[160], cah[140], cbh[140], rooth[65], ikh[65]; hexs(lah,la,34); hexs(lbh,lb,lo); hexs(cah,ca,65); hexs(cbh,cb,65); hexs(rooth,root,32); hexs(ikh,pub[2]+1,32);
      snprintf(prev,sizeof prev,"{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"5120%s\",\"amount\":1.0,\"tapLeafScript\":\"%s\",\"tapControlBlock\":\"%s\"}",Qh,lah,cah);
      run("p2tr-scriptpath-pk", keys1, prev, NULL);
      run("p2tr-scriptpath-pk-all", keys1, prev, "ALL");
      run("p2tr-scriptpath-pk-wrongkey", "[\"" "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1" "\"]", prev, NULL);
      snprintf(prev,sizeof prev,"{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"5120%s\",\"amount\":1.0,\"tapLeafScript\":\"%s\",\"tapControlBlock\":\"%s\"}",Qh,lbh,cbh);
      run("p2tr-scriptpath-multi_a-2of2", keys2, prev, NULL);
      run("p2tr-scriptpath-multi_a-partial", keys1, prev, NULL);
      snprintf(prev,sizeof prev,"{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"5120%s\",\"amount\":1.0,\"tapMerkleRoot\":\"%s\",\"tapInternalKey\":\"%s\"}",Qh,rooth,ikh);
      run("p2tr-keypath-with-tree", keys3, prev, NULL);
      snprintf(prev,sizeof prev,"{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"5120%s\",\"amount\":1.0}",Qh);
      run("p2tr-keypath-with-tree-noroot", keys3, prev, NULL); }
    return 0;
}
