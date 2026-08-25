#include <stdio.h>
typedef unsigned long long u64;
extern int sc_inv_var(u64 r[4], const u64 a[4]);
extern void sc_mul(u64 r[4], const u64 a[4], const u64 b[4]);
int main(void){
    u64 r[4], p[4]={3,0,0,0}, q[4];
    int ok=sc_inv_var(r,p);
    printf("inv(3) ret=%d r=%016llx %016llx %016llx %016llx\n", ok,r[0],r[1],r[2],r[3]);
    sc_mul(q,r,p); /* r*p mod n should == 1 */
    printf("inv(3)*3 mod n = %016llx %016llx %016llx %016llx (want 1 0 0 0)\n",q[0],q[1],q[2],q[3]);
    u64 z[4]={0,0,0,0};
    ok=sc_inv_var(r,z);
    printf("inv(0) ret=%d (want 0)\n", ok);
    u64 a[4]={0xBFD25E8CD0364140ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL}; /* n-1 */
    ok=sc_inv_var(r,a);
    sc_mul(q,r,a);
    printf("inv(n-1) ret=%d; (n-1)*inv = %016llx %016llx %016llx %016llx (want 1)\n",ok,q[0],q[1],q[2],q[3]);
    return 0;
}
