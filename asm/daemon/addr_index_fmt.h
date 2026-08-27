/* daemon/addr_index_fmt.h -- the ONE definition of how a scriptPubKey is
 * classified into an address-index key, shared by the offline snapshot
 * builder (build_addr_index.c) and the live tail (addr_index_tail.c).
 *
 * Two implementations of this classification existed briefly during
 * development and this project has been bitten twice by duplicated logic
 * rotting apart (node_config.c's own header note); the classifier moved
 * here so the offline and live indexes CANNOT disagree about what an
 * address is.
 *
 * Key: (type_tag, hash[32]) -- 20-byte hashes zero-padded. type_tag values
 * deliberately mirror wallet_core.c's WAL_ADDR_* enum (P2PKH=1, P2WPKH=2,
 * P2SH=3, P2WSH=4, P2TR=5) so an RPC-decoded address maps 1:1 onto index
 * keys. Anything else (OP_RETURN, bare multisig, non-standard) has no
 * address and is not indexed -- the same set Core's own listunspent
 * addresses cover.
 *
 * TAIL RECORD (addrindex.tail, fixed 82-byte grid -- fixed so a torn final
 * record can be truncated back onto the grid, tx_index_tail.c's argument):
 *   op(1) | type_tag(1) | hash(32) | txid(32) | vout(4 LE) | value(8 LE) | height(4 LE)
 *   op 1 = ADD    a new output owned by (type_tag,hash); txid/vout/value = the output
 *   op 2 = DEL    that output was spent; txid/vout name the SPENT outpoint
 *   op 3 = TOUCH  the SPENDING transaction's own txid, for history queries
 *                 (a DEL carries the spent outpoint so it can cancel its ADD;
 *                  the spender's txid would not fit the same record, so it
 *                  travels as its own op)
 */
#ifndef ADDR_INDEX_FMT_H
#define ADDR_INDEX_FMT_H

#include <string.h>
#include <stdint.h>

enum { AXF_INVALID = 0, AXF_P2PKH = 1, AXF_P2WPKH = 2,
       AXF_P2SH = 3, AXF_P2WSH = 4, AXF_P2TR = 5 };

enum { AXF_OP_ADD = 1, AXF_OP_DEL = 2, AXF_OP_TOUCH = 3 };

#define AXF_TAIL_FILE "addrindex.tail"
#define AXF_TAIL_REC  82

static inline int axf_classify(const uint8_t* s, uint32_t slen, uint8_t hash_out[32]) {
    if (slen == 25 && s[0]==0x76 && s[1]==0xa9 && s[2]==0x14 && s[23]==0x88 && s[24]==0xac) {
        memset(hash_out, 0, 32); memcpy(hash_out, s+3, 20); return AXF_P2PKH;
    }
    if (slen == 22 && s[0]==0x00 && s[1]==0x14) {
        memset(hash_out, 0, 32); memcpy(hash_out, s+2, 20); return AXF_P2WPKH;
    }
    if (slen == 23 && s[0]==0xa9 && s[1]==0x14 && s[22]==0x87) {
        memset(hash_out, 0, 32); memcpy(hash_out, s+2, 20); return AXF_P2SH;
    }
    if (slen == 34 && s[0]==0x00 && s[1]==0x20) {
        memcpy(hash_out, s+2, 32); return AXF_P2WSH;
    }
    if (slen == 34 && s[0]==0x51 && s[1]==0x20) {
        memcpy(hash_out, s+2, 32); return AXF_P2TR;
    }
    return AXF_INVALID;
}

#endif
