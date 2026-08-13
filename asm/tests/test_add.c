#include <stdio.h>
#include <string.h>
typedef unsigned long long u64;
extern void point_double(u64 r[12], const u64 p[12]);
extern void point_add_mixed(u64 r[12], const u64 p[12], const u64 xy[8]);
extern void point_add(u64 r[12], const u64 p[12], const u64 q[12]);
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
static void ck(const char*l,u64 g0,u64 g1,u64 g2,u64 g3,const u64 e[4]){
    u64 g[4]={g0,g1,g2,g3};
    if(memcmp(g,e,32)==0) printf("PASS %s\n",l);
    else{printf("FAIL %s\n got %016llx %016llx %016llx %016llx\n exp %016llx %016llx %016llx %016llx\n",l,g[0],g[1],g[2],g[3],e[0],e[1],e[2],e[3]); failures++;}
}
static const u64 Gaf[8]={
    0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL};
static const u64 G12[12]={
    0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL,
    1,0,0,0};
int main(void){
    u64 two[12], three[12], five[12], seven[12], ax[4], ay[4];
    u64 k2[4]={2,0,0,0}, k3[4]={3,0,0,0}, k7[4]={7,0,0,0};
    /* 2G and 3G via scalar_mul (Jacobian) */
    point_scalar_mul(two, Gaf, k2);
    point_scalar_mul(three, Gaf, k3);
    /* 2G+3G = 5G */
    point_add(five, two, three);
    toaff(ax,ay,five);
    ck("add(2G,3G)=5G.x",ax[0],ax[1],ax[2],ax[3],(u64[]){0xCBA8D569B240EFE4ULL,0xE88B84BDDC619AB7ULL,0x55B4A7250A5C5128ULL,0x2F8BDE4D1A072093ULL});
    ck("add(2G,3G)=5G.y",ay[0],ay[1],ay[2],ay[3],(u64[]){0xDCA87D3AA6AC62D6ULL,0xF788271BAB0D6840ULL,0xD4DBA9DDA6C9C426ULL,0xD8AC222636E5E3D6ULL});
    /* G+G = 2G (equal -> double path) */
    point_add(seven, G12, G12);
    toaff(ax,ay,seven);
    ck("add(G,G)=2G.x",ax[0],ax[1],ax[2],ax[3],(u64[]){0xABAC09B95C709EE5ULL,0x5C778E4B8CEF3CA7ULL,0x3045406E95C07CD8ULL,0xC6047F9441ED7D6DULL});
    ck("add(G,G)=2G.y",ay[0],ay[1],ay[2],ay[3],(u64[]){0x236431A950CFE52AULL,0xF7F632653266D0E1ULL,0xA3C58419466CEAEEULL,0x1AE168FEA63DC339ULL});
    /* 2G+5G = 7G : build 5G via scalar_mul */
    u64 k5[4]={5,0,0,0};
    point_scalar_mul(five, Gaf, k5);
    point_add(seven, two, five);
    toaff(ax,ay,seven);
    ck("add(2G,5G)=7G.x",ax[0],ax[1],ax[2],ax[3],(u64[]){0xE92BDDEDCAC4F9BCULL,0x3D419B7E0330E39CULL,0xA398F365F2EA7A0EULL,0x5CBDF0646E5DB4EAULL});
    ck("add(2G,5G)=7G.y",ay[0],ay[1],ay[2],ay[3],(u64[]){0xA5082628087264DAULL,0xA813D0B813FDE7B5ULL,0xA3178D6D861A54DBULL,0x6AEBCA40BA255960ULL});
    /* G + (-G) = infinity (opposite -> inf path): -G jac = (Gx, -Gy, 1) */
    u64 negG[12]={Gaf[0],Gaf[1],Gaf[2],Gaf[3],
                  0x63B82F6F04EF2777ULL,0x02E84BB7597AABE6ULL,0xA25B0403F1EEF757ULL,0xB7C52588D95C3B9AULL,
                  1,0,0,0};
    u64 sum[12];
    point_add(sum, G12, negG);
    if(sum[8]==0&&sum[9]==0&&sum[10]==0&&sum[11]==0) printf("PASS add(G,-G)=infinity\n");
    else{printf("FAIL add(G,-G)!=inf (Z=%llx %llx %llx %llx)\n",sum[8],sum[9],sum[10],sum[11]); failures++;}
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
