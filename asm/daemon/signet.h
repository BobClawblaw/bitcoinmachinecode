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
#endif
