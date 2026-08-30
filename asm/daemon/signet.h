/* daemon/signet.h -- BIP325 signet block-solution validation.
 *
 * A signet block carries a SIGNATURE over the block, tucked inside the
 * coinbase's witness-commitment output. Validating it is not optional
 * decoration: on signet the signature IS the consensus rule, in place of
 * meaningful proof of work. A node that selected chain=signet without
 * checking it would accept any block anyone offered -- strictly worse than
 * this node's current behaviour, which is to refuse to start on signet at
 * all. So the check exists before the chain becomes selectable.
 */
#ifndef BMC_SIGNET_H
#define BMC_SIGNET_H

/* The 4-byte tag that marks the signet solution inside the commitment. */
#define SIGNET_HEADER_0 0xec
#define SIGNET_HEADER_1 0xc7
#define SIGNET_HEADER_2 0xda
#define SIGNET_HEADER_3 0xa2

/* Index of the coinbase output holding the witness commitment, or -1.
 * Core's rule: the LAST output whose scriptPubKey is at least 38 bytes and
 * begins OP_RETURN 0x24 aa21a9ed. Later outputs win, which matters -- a block
 * may carry more than one and only the last is the commitment. */
int signet_commitment_index(const unsigned char* const* spks,
                            const unsigned long* spk_lens, long nout);

/* Split a witness-commitment scriptPubKey into (a) the signet solution and
 * (b) the script with the solution REMOVED, which is what the modified
 * merkle root is computed over.
 *
 * The removal keeps the 4-byte header push and drops only the data after it,
 * exactly as Core's FetchAndClearCommitmentSection does -- the header push
 * stays, shortened.
 *
 * Returns 1 if a solution was found (out_* filled), 0 if none -- which is NOT
 * an error: a trivial challenge such as OP_TRUE needs no solution. -1 on a
 * malformed script.
 */
int signet_extract_solution(const unsigned char* spk, unsigned long spk_len,
                            unsigned char* out_solution, unsigned long* out_solution_len,
                            unsigned char* out_stripped, unsigned long* out_stripped_len,
                            unsigned long cap);

/* ------------------------------------------------------------------ layer 2
 * The two synthetic transactions BIP325 defines. The block signature is made
 * over `to_sign`, which spends a `to_spend` output whose scriptPubKey is the
 * network's challenge -- so the pair is what turns "is this block signed?"
 * into an ordinary script-verification question the existing interpreter can
 * answer.
 */

/* Witness items a solution may carry.
 *
 * Core imposes no explicit cap here beyond MAX_SIZE, but a solution with more
 * than 1000 items cannot verify under Core either: the interpreter's
 * MAX_STACK_SIZE (1000) is checked after every executed opcode, and a script
 * executing no opcodes leaves the whole initial stack behind and fails
 * CLEANSTACK. Refusing above 1000 therefore rejects nothing Core accepts.  */
#define SIGNET_MAX_WIT 1000

/* Points INTO the caller's solution buffer; it must outlive this struct. */
typedef struct {
    const unsigned char* script_sig;
    unsigned long        script_sig_len;
    unsigned long        nwit;
    const unsigned char* wit[SIGNET_MAX_WIT];
    unsigned long        witlen[SIGNET_MAX_WIT];
} signet_solution_t;

/* Read the solution as Core does: a length-prefixed scriptSig, then a witness
 * stack, then NOTHING. Trailing bytes are a parse failure, not slack -- Core
 * checks `!v.empty()` and returns nullopt, so accepting them would let a
 * block carry data this node ignores and Core rejects.
 * Returns 0, or -1 on a malformed, truncated, non-canonically-encoded or
 * over-long solution. An EMPTY solution is valid: it parses to an empty
 * scriptSig and an empty stack. */
int signet_parse_solution(const unsigned char* sol, unsigned long sol_len,
                          signet_solution_t* out);

/* The modified merkle root: the ordinary root, over a leaf list whose first
 * entry is the txid of the coinbase WITH THE SOLUTION STRIPPED. This is the
 * value the signature commits to, which is what makes the signature cover the
 * block without covering itself.
 *
 * DESTROYS `leaves` -- merkle_root (bitcoin_hash.asm) reduces in place. Pass
 * a scratch copy, never the caller's own leaf array. */
void signet_merkle_root(unsigned char out32[32], unsigned char* leaves,
                        unsigned long nleaves);

/* Serialise to_spend: version 0, locktime 0, one input spending the NULL
 * outpoint (all-zero hash, index 0xFFFFFFFF -- Core's default COutPoint, not
 * index 0) with scriptSig `OP_0 <block_data>`, one 0-value output paying the
 * challenge. block_data is nVersion || hashPrevBlock || signet_merkle ||
 * nTime, in serialised (internal) byte order.
 * Returns the length written, or -1 if it does not fit. */
long signet_build_to_spend(unsigned char* out, unsigned long cap,
                           int nversion, const unsigned char prev32[32],
                           const unsigned char signet_merkle32[32],
                           unsigned int ntime,
                           const unsigned char* challenge,
                           unsigned long challenge_len);

/* Serialise to_sign: version 0, locktime 0, one input spending to_spend:0
 * with the solution's scriptSig and witness, one 0-value OP_RETURN output.
 * Serialised WITH the witness marker/flag only when the stack is non-empty,
 * matching CTransaction::Serialize's HasWitness() test.
 * Returns the length written, or -1 if it does not fit. */
long signet_build_to_sign(unsigned char* out, unsigned long cap,
                          const unsigned char to_spend_txid32[32],
                          const signet_solution_t* sol);

/* sha256d, exposed because the caller needs to_spend's txid to link the pair
 * and there is no reason to make it link a second hashing path to get it. */
void signet_txid(unsigned char out32[32], const unsigned char* tx,
                 unsigned long txlen);
#endif
