/* throwaway: prove utxo_del's lazy "mark slot empty" (no tombstone) breaks
 * open-addressing probe chains for any key displaced past a later-deleted
 * collision. Uses a 4-slot table and three (txid,index) pairs chosen to
 * collide on the same base slot (index%4==0 for all three, and utxo_hash's
 * fold is (fnv1a(txid) XOR index) & mask, which for mask=3 only depends on
 * index&3 -- so index=0,4,8 hash identically regardless of the txid). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8;
typedef unsigned long u64;
typedef unsigned int u32;

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_count(void* u);
extern long utxo_put(void* u, const u8 txid[32], u64 index, u64 value, const u8* script, u64 slen);
extern long utxo_get(void* u, const u8 txid[32], u64 index, u64* value, const u8** script, u64* slen);
extern long utxo_del(void* u, const u8 txid[32], u64 index);

int main(void){
    u8 txid[32]; memset(txid, 0xAB, 32);
    u8 script[4] = {0xde,0xad,0xbe,0xef};

    long slots = 4;
    long sz = utxo_struct_size(slots);
    void* u = malloc(sz);
    u8 blob[4096];
    utxo_init(u, slots, blob, sizeof blob);

    long r0 = utxo_put(u, txid, 0, 100, script, 4);
    long r4 = utxo_put(u, txid, 4, 400, script, 4);
    long r8 = utxo_put(u, txid, 8, 800, script, 4);
    printf("put(idx=0)=%ld put(idx=4)=%ld put(idx=8)=%ld  (all should be 1)\n", r0, r4, r8);
    printf("count after 3 puts = %ld (expect 3)\n", utxo_count(u));

    long rdel = utxo_del(u, txid, 0);
    printf("del(idx=0) = %ld (expect 1)\n", rdel);
    printf("count after del = %ld (expect 2)\n", utxo_count(u));

    u64 val; const u8* sp; u64 sl;
    long g4 = utxo_get(u, txid, 4, &val, &sp, &sl);
    long g8 = utxo_get(u, txid, 8, &val, &sp, &sl);
    printf("get(idx=4) after deleting idx=0 = %ld  (BUG if 0: idx=4 is still in the table but probe stops at the deleted slot)\n", g4);
    printf("get(idx=8) after deleting idx=0 = %ld  (BUG if 0, same reason)\n", g8);

    if (g4 == 1 && g8 == 1) {
        printf("RESULT: no tombstone bug observed (probe correctly skipped the empty slot)\n");
    } else {
        printf("RESULT: CONFIRMED BUG -- deleting one colliding key hides other still-live keys from get()\n");
    }
    return 0;
}
