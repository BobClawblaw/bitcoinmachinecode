// validation/muhash_oracle.cpp -- ground-truth generator for MuHash3072.
//
// Links against Bitcoin Core's OWN crypto library (libbitcoin_crypto.a, which
// contains muhash.cpp and chacha20.cpp) and prints the intermediate values our
// asm implementation must reproduce, at every layer:
//
//   KS   <hex key32> <hex 384 bytes>        ChaCha20Aligned keystream
//   ELEM <hex data>  <hex 384 bytes>        MuHash3072::ToNum3072
//   MUL  <hex a384> <hex b384> <hex 384>    Num3072::Multiply
//   SET  <n> <hex 32>                       MuHash of a deterministic n-element
//                                            set, finalized
//
// Printed, never hand-copied: validation/gen_muhash_vectors.py compiles and
// runs this, and writes tests/muhash_vectors.h from the output. Re-run it
// after a Core upgrade -- the same discipline as
// validation/gen_script_error_defines.py (ENGINEERING_RULES.md 1 and 4).
//
// Deliberately layer-by-layer rather than end-to-end only: if the top-level
// set hash ever disagrees, these say WHICH layer diverged instead of leaving
// a 32-byte value with no diagnostic in it.

#include <crypto/muhash.h>
#include <crypto/chacha20.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <uint256.h>
#include <span.h>

#include <cstdio>
#include <cstring>
#include <vector>

static void hexout(const unsigned char* p, size_t n)
{
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
}

// A cheap deterministic byte generator, so the vectors are reproducible from
// this file alone and do not need a committed blob of random input.
struct Splitmix {
    unsigned long long s;
    explicit Splitmix(unsigned long long seed) : s(seed) {}
    unsigned long long next()
    {
        s += 0x9E3779B97F4A7C15ULL;
        unsigned long long z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }
    void fill(unsigned char* p, size_t n)
    {
        for (size_t i = 0; i < n; ++i) p[i] = (unsigned char)(next() & 0xff);
    }
};

int main()
{
    SHA256AutoDetect();

    // ---- ChaCha20 keystream, key-only, nonce 0, counter 0 ----
    {
        Splitmix rng(1);
        for (int t = 0; t < 4; ++t) {
            unsigned char key[32];
            if (t == 0) memset(key, 0, sizeof key);
            else if (t == 1) memset(key, 0xff, sizeof key);
            else rng.fill(key, sizeof key);
            unsigned char out[Num3072::BYTE_SIZE];
            ChaCha20Aligned{MakeByteSpan(key)}.Keystream(MakeWritableByteSpan(out));
            printf("KS ");
            hexout(key, sizeof key);
            printf(" ");
            hexout(out, sizeof out);
            printf("\n");
        }
    }

    // ---- ToNum3072 over variable-length elements ----
    {
        Splitmix rng(2);
        static const size_t lens[] = {0, 1, 32, 55, 56, 64, 65, 100, 1000};
        for (size_t li = 0; li < sizeof(lens) / sizeof(lens[0]); ++li) {
            std::vector<unsigned char> data(lens[li]);
            if (!data.empty()) rng.fill(data.data(), data.size());
            // MuHash3072 with a single element: its numerator IS ToNum3072(x),
            // and serializing the object exposes numerator then denominator.
            MuHash3072 mh{std::span<const unsigned char>(data.data(), data.size())};
            // Re-derive the residue the same way muhash.cpp does, since
            // ToNum3072 itself is private.
            unsigned char tmp[Num3072::BYTE_SIZE];
            uint256 hashed_in{(HashWriter{} << std::span<const unsigned char>(data.data(), data.size())).GetSHA256()};
            ChaCha20Aligned{MakeByteSpan(hashed_in)}.Keystream(MakeWritableByteSpan(tmp));
            printf("ELEM ");
            if (data.empty()) printf("-");
            else hexout(data.data(), data.size());
            printf(" ");
            hexout(tmp, sizeof tmp);
            printf("\n");
        }
    }

    // ---- Num3072::Multiply, including the reduction corner cases ----
    {
        Splitmix rng(3);
        for (int t = 0; t < 6; ++t) {
            unsigned char ab[Num3072::BYTE_SIZE], bb[Num3072::BYTE_SIZE];
            if (t == 0) {
                // 1 * 1
                memset(ab, 0, sizeof ab); ab[0] = 1;
                memset(bb, 0, sizeof bb); bb[0] = 1;
            } else if (t == 1) {
                // (modulus-1) * (modulus-1): the largest legal operands, which
                // is where the second reduction pass carries.
                memset(ab, 0xff, sizeof ab);
                unsigned long long lo = ~0ULL - 1103717ULL - 1ULL;
                memcpy(ab, &lo, 8);
                memcpy(bb, ab, sizeof bb);
            } else if (t == 2) {
                // An operand at exactly the modulus: IsOverflow() is true, so
                // Multiply's trailing FullReduce has to fire.
                memset(ab, 0xff, sizeof ab);
                unsigned long long lo = ~0ULL - 1103717ULL + 1ULL;
                memcpy(ab, &lo, 8);
                memset(bb, 0, sizeof bb); bb[0] = 2;
            } else {
                rng.fill(ab, sizeof ab);
                rng.fill(bb, sizeof bb);
            }
            Num3072 a{ab}, b{bb};
            a.Multiply(b);
            unsigned char outb[Num3072::BYTE_SIZE];
            a.ToBytes(outb);
            printf("MUL ");
            hexout(ab, sizeof ab);
            printf(" ");
            hexout(bb, sizeof bb);
            printf(" ");
            hexout(outb, sizeof outb);
            printf("\n");
        }
    }

    // ---- Whole-set hashes, and the same set inserted in reverse order ----
    // The reverse-order line is the property the whole choice of MuHash rests
    // on; a test that only checked one order would not have exercised it.
    {
        static const int sizes[] = {0, 1, 2, 17, 200};
        for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); ++si) {
            int n = sizes[si];
            MuHash3072 fwd, rev;
            for (int i = 0; i < n; ++i) {
                unsigned char e[40];
                Splitmix r((unsigned long long)i * 1000003ULL + 7ULL);
                r.fill(e, sizeof e);
                fwd.Insert(std::span<const unsigned char>(e, sizeof e));
            }
            for (int i = n - 1; i >= 0; --i) {
                unsigned char e[40];
                Splitmix r((unsigned long long)i * 1000003ULL + 7ULL);
                r.fill(e, sizeof e);
                rev.Insert(std::span<const unsigned char>(e, sizeof e));
            }
            uint256 hf, hr;
            fwd.Finalize(hf);
            rev.Finalize(hr);
            if (memcmp(hf.begin(), hr.begin(), 32) != 0) {
                fprintf(stderr, "muhash_oracle: order dependence at n=%d -- impossible, aborting\n", n);
                return 1;
            }
            printf("SET %d ", n);
            hexout(hf.begin(), 32);
            printf("\n");
        }
    }

    return 0;
}
