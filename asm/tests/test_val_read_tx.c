/* tests/test_val_read_tx.c -- val_read_tx must walk the OUTPUT section.
 *
 * THE REGRESSION, and it is a consensus one. Phase 0.15 of apply_block_inner
 * (the VAL-1/VAL-2 remediation for the 2026-09-03 audit) calls val_read_tx on
 * every transaction in a block and rejects the whole block when it returns 0:
 *
 *     if (!val_read_tx(txs[t].ptr, txs[t].len, &vix) || vix.null_prevout){
 *         g_last_reject = "bad-txns-prevout-null"; return 0; }
 *
 * val_read_tx walked version, the marker, the inputs -- and then jumped
 * straight to the witness sections, never skipping the outputs. The wire
 * order is
 *     version | [marker flag] | n_in | inputs | n_out | outputs |
 *     [witness] | locktime
 * so `p` was left pointing at the output COUNT. Consequences, both real:
 *   - SEGWIT transaction: the witness walk tries to decode the output section
 *     as witness stacks, runs off the end, and returns bad_shape -- so Phase
 *     0.15 REJECTS EVERY BLOCK CONTAINING A SEGWIT TRANSACTION, i.e. every
 *     mainnet block since 481,824.
 *   - LEGACY transaction: it parses, but vi->locktime is read from the first
 *     four bytes of the output section instead of the locktime. Latent today
 *     (nothing consumes vi->locktime yet) and a wrong answer the moment
 *     VAL-4's IsFinalTx lands on top of it.
 *
 * WHY NO EXISTING TEST CAUGHT IT: nothing in the suite drives a real segwit
 * block through Phase 0.15. test_val_connect, test_blk_dryrun,
 * test_witness_commitment and test_cross_tx_verify all pass against the
 * broken walk. That is the audit's own section 8 -- "the test suite pins
 * happy paths" -- landing on the remediation for that same audit.
 *
 * THE VECTORS are real mainnet transactions, INLINED rather than kept as a
 * fixture file. tests/fixtures/ is gitignored (large block fixtures are
 * fetched on demand), and these are 2.5 KB of hex, so inlining makes the test
 * hermetic -- it needs no Core oracle and no network, which is the direction
 * the audit's BLD-2 asks the gate to move in.
 *
 * They are deliberately chosen with NONZERO locktimes so the locktime
 * assertion can fail: a corpus of locktime-0 transactions passes against a
 * walk that reads the wrong four bytes whenever those bytes happen to be
 * zero. Both segwit and legacy shapes, across three eras (500k, 700k, 840k),
 * including multi-input and multi-output.
 *
 * To regenerate against a synced Core:
 *   bitcoin-cli getblock $(bitcoin-cli getblockhash <H>) 2
 * and take, per block, the first segwit and first legacy transaction whose
 * locktime is not zero, with its hex, locktime, vin count and vout count.
 *
 * Usage: ./test_val_read_tx
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned char u8;
typedef unsigned long long u64;
typedef unsigned int u32;

/* val_txinfo_t's real layout, mirrored. The test links utxo_live.c, which is
 * where the struct and the function live; the fields read here are the ones
 * the walk is responsible for. */
typedef struct {
    const u8* in0_script; u64 in0_slen;
    int coinbase_shape;
    int null_prevout;
    int bad_shape;
    u64 in_count;
    u64 out_count;
    u32 locktime;
    u32 version;
    const u32* seqs; u32 nseqs;
} val_txinfo_t;

extern int val_read_tx_probe(const u8* tx, u64 txlen, val_txinfo_t* vi);

long mempool_resolve_confirmed_utxo(void* u, const u8* t, unsigned long i,
                                    u64* v, const u8** s, unsigned long* l){
    (void)u;(void)t;(void)i;(void)v;(void)s;(void)l;
    fprintf(stderr, "unexpected mempool_resolve_confirmed_utxo\n"); abort();
}

static int fails = 0, checks = 0;
static void ck(const char* w, int c){
    checks++;
    if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; }
}

static const struct {
    const char* kind; unsigned height; unsigned long locktime;
    unsigned nin, nout; const char* hex;
} VECTORS[] = {
    { "SEGWIT", 700038, 700036, 1, 2,
      "02000000000101545461dccaba1f4e6a3d16b0b64bcb6af4cc6445f195694d42eee38942"
      "9bff430100000000fdffffff02eed0010000000000160014b3869df6828ceb64c06e3588"
      "49eb14b2390de7fd9e45200000000000160014c1b390ca99aa1eedb680cab2150f7a6143"
      "280cff0247304402204ec54e8ee2121e90fe6122a210314d6ec433de9daa24705aaef551"
      "c954455ad0022004e853ed6c69c093379e16bb4408fdcb654a939eb26dc39a2fc3db493c"
      "6d20ed012103cec16d9c111ff924a2e7933331dc9e707d4d54caa14cf2de304f65e38ffa"
      "5b3b84ae0a00" },
    { "LEGACY", 700038, 700036, 1, 3,
      "0200000001731250dfe062b82d2f6a1938a9a05e45d6040b8b26af2fd0d729e1079f580e"
      "0d010000006a47304402205310691c42b1ea74296c9d2e0f1f904945d2d059e5ee2e2fb2"
      "e7d8e150ee98cf0220140da7930e37132f3c6240b8bad6ea14601557336232eb584e9adc"
      "f90ed4c5d4012103058bc647b5260655a59201e636bf0ceae51f9a6462cada915085fa69"
      "51cbf552fdffffff0348c02900000000001976a914bebc6cc28d60f52877ce59e37d07db"
      "1facbcfcf988ac12b52e00000000001976a91421673b34291bba64857b7f81fc50840438"
      "4cf27f88ac54d53000000000001976a9143eeee23dd837e1dedf8ab67887108868b0d9ce"
      "7b88ac84ae0a00" },
    { "SEGWIT", 840000, 839999, 1, 3,
      "0200000000010177d935289cc2842f174134a04bb4874a2918e5008a8d84f2a8d02c281b"
      "af49c90000000000050000000349080000000000002251205de2a22fff8aa73e310ac705"
      "c04e77c1788a967eea36b5b0f756254190324d6e10270000000000002251208bbcb4f001"
      "d794f0cde45ceef5656bd8a2a84e01324693a5def24247e85c4d20000000000000000028"
      "6a5d25020504f39fdba984daf4f31a011203840105b12d06808080c0f09fa18d9cf2abd6"
      "bd08160103408363b7051dc2ad41add531d887d71a5010632ded2fcd84b434b3edf6c968"
      "4b04e5a761244b8f66a125c2c0bc7355d9ac21b5d054a741db1b5169b77cb055667c3720"
      "73d24818d7e0153a2beaf7c49fa2f91e6b3cbc0393606a86509e57752bf44ab4ac006303"
      "6f7264010200010d08f3cf3645d0d2e71a6821c073d24818d7e0153a2beaf7c49fa2f91e"
      "6b3cbc0393606a86509e57752bf44ab43fd10c00" },
    { "LEGACY", 840000, 839994, 1, 3,
      "02000000014345700245ae5a4dafd275af35f00096e65ddee779cfa1033469a2caaa6d0d"
      "34030000006a4730440220692cab87be8d7deb3809e66add0194cba4031942e95ba0780b"
      "4d045487dbed690220132a3916143e6925172993470cd58ee7f937280f8078ab88b41f2d"
      "45d43517f7012103f5bfb47437ea45f76fbf16c83e95c1a578dbed3f35d0c118d1fc083a"
      "aafb98d6fdffffff0392100300000000001976a9146f2cc54a14f14195aa51e0aea4737d"
      "6a900f7ba988ac30c40700000000001976a914714e963814df67a41b178d08144b900d42"
      "a34da688acf0adc600000000001976a9140dc745fda37ac42883dc8dcfaa35a3c8e202d7"
      "9d88ac3ad10c00" },
    { "SEGWIT", 500000, 499999, 3, 2,
      "020000000001030641e403935fc70c30bcffafd0bbd024f4cc73e65e0c8e15e015a30b50"
      "17e20500000000171600142ec0e073e8b9617b288425467476f1f12edb19b8feffffffeb"
      "eae261ecfcfd0f544b2c325ed1ac8391abcea579d0d951b356e6e67fe24e8a0000000017"
      "1600143744ee1462cc36ff8997a1da29efb1aab713cc43feffffffef7a0bedef725c5145"
      "c72380aca328c4512fd284b0b8ca7fc8fafcd461878eda00000000171600147327f8bb4c"
      "4d48e5dac1904f85aec557cf3babfefeffffff0231bd0800000000001976a9143827d26f"
      "52cd3d8d25a9011228e6d9e6856f945888ac0b0a0d00000000001976a91462856e64f2a6"
      "023d29a6d8a2f406951637e5947988ac024830450221009bf26aa1d7d29412cf504f6c7d"
      "656261bea6b61a76973b2f83f0b0164211c90e022023e78e02d4a404139fed6820b0e3a1"
      "4d0633d79375022dbc1bd4f5277f6caf7f012103bce3d3cb984092a1c2200c2549eaa9a5"
      "1f6cc18e397f2fadbcd786357fefa8460247304402206c9f8c9b9f719d4755a66b49a26d"
      "82cd87f2cd431af7376ba463d02c186819b1022078fc4c48cff4101097d1c5cc0a194d2a"
      "859177182f21dc8993cff94ad6338de3012103f5290b98f4e6f2ec114fe4517388742a2a"
      "df83784866e5737b6851d96c3b5a670247304402205ac88d7137cf696569683fd4177d48"
      "f027d8532f7dd14f257132961fc9adf0ea02205745b63ab265406e2cb31848d6d4a99ed9"
      "2f89c025ea4dcc4103f7b50b8ffcc5012102790f97673d3ea3b3f06c45d23df99115ea07"
      "01134eaae2c95da5c495232c96021fa10700" },
    { "LEGACY", 500000, 499989, 2, 1,
      "020000000200f0b766f005a605f5f9537e726b4b1749a87ac34fae1edfe5a3b1a121bc6c"
      "0d000000006a47304402203f198d9695a293c41d2124e790d473e68f4b35a09ece5517c7"
      "adfffc797f91760220304feb1cc2829d3c937665bcb4b7f9735acbcac50e9169bc53c9e6"
      "89ce20b3bc0121025743bce4e775bb754e784dd2cfdc8dabc2023154eee539bb15561210"
      "1a583e7efeffffffe9d3b1736f598fd7d936cbcd5eef0db543b295b44c707d2381ee509d"
      "2798c4aa010000006b483045022100b763b986b17beddac1ac96c3656fa7af188a28cfac"
      "fc87390e1e796b7fdbc0d102201e76f77db6093306028e681e2fe6354ae12649afb5c27c"
      "549243b67d505a1bb601210349ebb9d180938ab3a571d8c2e9771fb4fecb9f4484c337bb"
      "35d8fd8b48283ca9feffffff0110440a01000000001976a914d63cc1e3b6009e31d03bd5"
      "f8046cbe0f7e37e8c088ac15a10700" },
};

int main(void){
    static u8 tx[1 << 16];
    int n_seen = 0, n_segwit = 0, n_legacy = 0;

    for (unsigned v = 0; v < sizeof VECTORS / sizeof VECTORS[0]; v++){
        const char* hex = VECTORS[v].hex;
        size_t hl = strlen(hex), tl = 0;
        for (size_t i = 0; i + 1 < hl; i += 2){
            unsigned b; sscanf(hex + i, "%2x", &b); tx[tl++] = (u8)b;
        }

        val_txinfo_t vi;
        int r = val_read_tx_probe(tx, (u64)tl, &vi);

        const char* kind = VECTORS[v].kind;
        unsigned height  = VECTORS[v].height;
        unsigned nin     = VECTORS[v].nin, nout = VECTORS[v].nout;
        unsigned long lt = VECTORS[v].locktime;
        char lbl[192];
        int is_sw = !strcmp(kind, "SEGWIT");
        n_seen++; if (is_sw) n_segwit++; else n_legacy++;

        snprintf(lbl, sizeof lbl, "%s h=%u (%u in, %u out, %zu bytes) parses at all",
                 kind, height, nin, nout, tl);
        ck(lbl, r == 1 && !vi.bad_shape);
        if (r != 1) continue;

        snprintf(lbl, sizeof lbl, "  %s h=%u input count is %u", kind, height, nin);
        ck(lbl, vi.in_count == nin);

        snprintf(lbl, sizeof lbl, "  %s h=%u OUTPUT count is %u (the section that was skipped)",
                 kind, height, nout);
        ck(lbl, vi.out_count == nout);

        snprintf(lbl, sizeof lbl, "  %s h=%u locktime is %lu, not four bytes of the output section",
                 kind, height, lt);
        ck(lbl, (unsigned long)vi.locktime == lt);
        if ((unsigned long)vi.locktime != lt)
            printf("        got locktime %lu, want %lu\n", (unsigned long)vi.locktime, lt);
    }

    ck("the vectors carried both segwit and legacy shapes", n_segwit > 0 && n_legacy > 0);
    ck("the vector table was not empty", n_seen >= 4);
    printf("      %d transactions (%d segwit, %d legacy)\n", n_seen, n_segwit, n_legacy);

    printf("\n%s (%d checks, %d failures)\n",
           fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
