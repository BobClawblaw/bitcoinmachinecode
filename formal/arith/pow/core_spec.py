"""Bitcoin Core v31.1 PoW arithmetic, transcribed into claripy bit-vector terms.

Line mapping (src/arith_uint256.cpp, src/pow.cpp, src/chain.cpp):

  SetCompact(nCompact, &fNegative, &fOverflow)          set_compact()
    int nSize = nCompact >> 24;                           size = bits >> 24
    uint32_t nWord = nCompact & 0x007fffff;               word = bits & 0x7fffff
    if (nSize <= 3) { nWord >>= 8*(3-nSize); *this=nWord; }
    else { *this = nWord; *this <<= 8*(nSize-3); }        (mod 2^256: bits past 256 discarded)
    fNegative = nWord != 0 && (nCompact & 0x00800000)    (nWord AFTER the size<=3 shift)
    fOverflow = nWord != 0 && (nSize > 34 ||
                (nWord > 0xff && nSize > 33) || (nWord > 0xffff && nSize > 32))

  DeriveTarget(nBits, pow_limit)                          derive_target_ok()
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > pow_limit) -> none
  CheckProofOfWorkImpl(hash, nBits)                       check_pow()
    UintToArith256(hash) > bnTarget -> false             (hash bytes little-endian)

  GetBlockProof (chain.cpp):                              block_proof()
    if (fNegative || fOverflow || bnTarget == 0) return 0;
    return (~bnTarget / (bnTarget + 1)) + 1;              (all mod 2^256)

The shift operator<<= in arith_uint256.cpp drops bits beyond 256 and yields 0
for shifts >= 256, which is exactly bit-vector ShL semantics on 256 bits.
"""
import angr.rustylib.claripy as claripy

# Core chainparams.cpp consensus.powLimit, as 256-bit integers
POW_LIMIT_FULL = {
    0x1d00ffff: int("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),  # main/testnet4
    0x1e0377ae: int("00000377ae000000000000000000000000000000000000000000000000000000", 16),  # signet
    0x207fffff: int("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),  # regtest
}


def set_compact(bits):
    """bits: 32-bit BV. Returns (target256, negative, overflow, word_after_shift32)."""
    size = claripy.LShR(bits, 24)                                   # 32-bit, 0..255
    word0 = bits & 0x007FFFFF
    small = claripy.ULE(size, 3)
    shr = (claripy.BVV(3, 32) - size) * 8                           # only used when size<=3
    word = claripy.If(small, claripy.LShR(word0, shr), word0)
    shl = claripy.ZeroExt(224, (size - 3) * 8)                      # only used when size>3
    big = claripy.ZeroExt(224, word0) << shl
    target = claripy.If(small, claripy.ZeroExt(224, word), big)
    nz = word != 0
    negative = claripy.And(nz, (bits & 0x00800000) != 0)
    overflow = claripy.And(nz, claripy.Or(claripy.UGT(size, 34),
                                          claripy.And(claripy.UGT(word, 0xFF), claripy.UGT(size, 33)),
                                          claripy.And(claripy.UGT(word, 0xFFFF), claripy.UGT(size, 32))))
    return target, negative, overflow, word


def derive_target_ok(bits, pow_limit_full):
    t, neg, ovf, _ = set_compact(bits)
    lim = claripy.BVV(pow_limit_full, 256)
    ok = claripy.Not(claripy.Or(neg, t == 0, ovf, claripy.UGT(t, lim)))
    return ok, t


def check_pow(hash256, bits, pow_limit_full):
    ok, t = derive_target_ok(bits, pow_limit_full)
    return claripy.And(ok, claripy.ULE(hash256, t))


def block_proof(bits):
    t, neg, ovf, _ = set_compact(bits)
    zero = claripy.Or(neg, ovf, t == 0)
    w = claripy.UDiv(~t, t + 1) + 1
    return claripy.If(zero, claripy.BVV(0, 256), w)
