#include <stdio.h>
#include <string.h>
typedef unsigned long long u64;
extern void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
static int failures=0;
static void toaff(u64 ox[4], u64 oy[4], const u64 j[12]){
    u64 zi[4],z2[4],z3[4];
    fe_inv(zi,&j[8]); fe_sqr(z2,zi); fe_mul(z3,z2,zi);
    fe_mul(ox,&j[0],z2); fe_mul(oy,&j[4],z3);
}
static void ck(const char*l,const u64 g[4],const u64 e[4]){
    if(!g) return;
    if(memcmp(g,e,32)==0) printf("PASS %s\n",l);
    else{printf("FAIL %s\n got %016llx %016llx %016llx %016llx\n exp %016llx %016llx %016llx %016llx\n",l,g[0],g[1],g[2],g[3],e[0],e[1],e[2],e[3]); failures++;}
}
static const u64 Gaff[8]={
    0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL};
int main(void){
    u64 r[12], ax[4], ay[4];
    /* 1G = G */
    u64 k1[4]={1,0,0,0};
    point_scalar_mul(r, Gaff, k1); toaff(ax,ay,r);
    ck("1G.x", ax, (u64[]){Gaff[0],Gaff[1],Gaff[2],Gaff[3]});
    ck("1G.y", ay, (u64[]){Gaff[4],Gaff[5],Gaff[6],Gaff[7]});
    /* 2G */
    u64 k2[4]={2,0,0,0};
    point_scalar_mul(r, Gaff, k2); toaff(ax,ay,r);
    ck("2G.x", ax, (u64[]){0xABAC09B95C709EE5ULL,0x5C778E4B8CEF3CA7ULL,0x3045406E95C07CD8ULL,0xC6047F9441ED7D6DULL});
    ck("2G.y", ay, (u64[]){0x236431A950CFE52AULL,0xF7F632653266D0E1ULL,0xA3C58419466CEAEEULL,0x1AE168FEA63DC339ULL});
    /* 3G */
    u64 k3[4]={3,0,0,0};
    point_scalar_mul(r, Gaff, k3); toaff(ax,ay,r);
    ck("3G.x", ax, (u64[]){0x8601F113BCE036F9ULL,0xB531C845836F99B0ULL,0x49344F85F89D5229ULL,0xF9308A019258C310ULL});
    ck("3G.y", ay, (u64[]){0x6CB9FD7584B8E672ULL,0x6500A99934C2231BULL,0x0FE337E62A37F356ULL,0x388F7B0F632DE814ULL});
    /* big 128-bit scalar kG (k=0x1234567890abcdef1234567890abcdef) */
    u64 kbig[4]={0x1234567890ABCDEFULL,0x1234567890ABCDEFULL,0,0};
    point_scalar_mul(r, Gaff, kbig); toaff(ax,ay,r);
    ck("kbig.x", ax, (u64[]){0xDF502B61290BBF5EULL,0x094C533603687850ULL,0x911BF9E8C067BCF6ULL,0x9377C312145A5AFBULL});
    ck("kbig.y", ay, (u64[]){0xCAF6144B679779FBULL,0xDC7BB61E3AB527CEULL,0x2DCCCB176E7C8F9BULL,0x742BA607D6AE1FC8ULL});
    /* nG should be infinity (Z=0) */
    u64 n[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
    point_scalar_mul(r, Gaff, n);
    if(r[8]==0 && r[9]==0 && r[10]==0 && r[11]==0) printf("PASS nG==infinity\n");
    else{printf("FAIL nG!=infinity (Z=%llx %llx %llx %llx)\n",r[8],r[9],r[10],r[11]); failures++;}
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
