/* throwaway: verify tx_parse/tx_txid preserve callee-saved registers per the
 * System V AMD64 ABI (rbx, rbp, r12-r15). probe_tx_parse/probe_tx_txid (in
 * debug_regsave.asm) load sentinel values into those registers immediately
 * before calling in, then dump them back out immediately after -- so any
 * ABI violation in the target function shows up as a direct mismatch. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8;
typedef unsigned long u64;

extern void probe_tx_parse(void* info, const void* tx, u64 txlen, u64 out[7]);
extern void probe_tx_txid(void* out32, const void* tx, u64 txlen, void* buf, u64 buflen, u64 regs_out[6]);

static u8 tx[] = {
    0x01,0x00,0x00,0x00,
    0x01,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0xff,0xff,0xff,0xff,
    0x01, 0x00,
    0xff,0xff,0xff,0xff,
    0x01,
    0x00,0xe1,0xf5,0x05,0x00,0x00,0x00,0x00,
    0x00,
    0x00,0x00,0x00,0x00
};

int main(void){
    static u8 info[64];
    static u8 outid[32];
    static u8 txidbuf[128];
    const u64 SENT[6] = {0x1111111111111111UL,0x2222222222222222UL,0x3333333333333333UL,
                          0x4444444444444444UL,0x5555555555555555UL,0x6666666666666666UL};
    const char* names[6]={"rbx","rbp","r12","r13","r14","r15"};

    u64 r1[7]; memset(r1,0,sizeof r1);
    probe_tx_parse(info, tx, sizeof tx, r1);
    printf("tx_parse: ok=%lu\n", r1[6]);
    for (int i=0;i<6;i++) printf("  %s: sent=%016lx got=%016lx %s\n", names[i], SENT[i], r1[i], SENT[i]==r1[i]?"OK":"CLOBBERED");

    u64 r2[6]; memset(r2,0,sizeof r2);
    probe_tx_txid(outid, tx, sizeof tx, txidbuf, sizeof txidbuf, r2);
    printf("tx_txid:\n");
    for (int i=0;i<6;i++) printf("  %s: sent=%016lx got=%016lx %s\n", names[i], SENT[i], r2[i], SENT[i]==r2[i]?"OK":"CLOBBERED");

    return 0;
}
