#include <stdio.h>
#include <string.h>
typedef unsigned long long u64;
extern void point_double(u64 r[12], const u64 p[12]);
extern void point_add_mixed(u64 r[12], const u64 p[12], const u64 xy[8]);
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
    if(memcmp(g,e,32)==0) printf("PASS %s\n",l);
    else{printf("FAIL %s\n got %016llx %016llx %016llx %016llx\n exp %016llx %016llx %016llx %016llx\n",l,g[0],g[1],g[2],g[3],e[0],e[1],e[2],e[3]); failures++;}
}
static const u64 G[12]={
    0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL,
    1,0,0,0};
static const u64 Gaff[8]={
    0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL};
int main(void){
    u64 two[12], three[12], ax[4], ay[4];
    u64 e3x[4]={0x8601F113BCE036F9ULL,0xB531C845836F99B0ULL,0x49344F85F89D5229ULL,0xF9308A019258C310ULL};
    u64 e3y[4]={0x6CB9FD7584B8E672ULL,0x6500A99934C2231BULL,0x0FE337E62A37F356ULL,0x388F7B0F632DE814ULL};
    point_double(two, G);
    point_add_mixed(three, two, Gaff);
    toaff(ax, ay, three);
    ck("point_add_mixed(2G,G)=3G.x", ax, e3x);
    ck("point_add_mixed(2G,G)=3G.y", ay, e3y);
    /* also test G + G must double (same point): add_mixed(G,G) = 2G */
    u64 two2[12];
    point_add_mixed(two2, G, Gaff);
    toaff(ax,ay,two2);
    u64 e2x[4]={0xABAC09B95C709EE5ULL,0x5C778E4B8CEF3CA7ULL,0x3045406E95C07CD8ULL,0xC6047F9441ED7D6DULL};
    u64 e2y[4]={0x236431A950CFE52AULL,0xF7F632653266D0E1ULL,0xA3C58419466CEAEEULL,0x1AE168FEA63DC339ULL};
    ck("point_add_mixed(G,G)=2G.x", ax, e2x);
    ck("point_add_mixed(G,G)=2G.y", ay, e2y);
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
