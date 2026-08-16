/*
 * cuda_sha256.cu -- CUDA-accelerated batch SHA-256 / SHA-256d for the
 * Bitcoin Machine Code node.
 *
 * PURPOSE & FIT
 *   The assembly core already has a CPUID-gated SHA-NI accelerator for the
 *   *sequential* single-block path (see sha256.asm :sha256_block_shani:).
 *   A GPU does NOT beat SHA-NI on one hash at a time -- the launch + memcpy
 *   overhead dwarfs a single 64-round block. The GPU wins ONLY when we
 *   amortize that overhead over a large BATCH of *independent* hashes:
 *
 *     - PoW candidate scanning  (test many nonces; each nonce = 1 sha256d)
 *     - block-body validation during IBD  (thousands of blocks / txs at once)
 *     - batch address/utxo index building (hash160 over many keys)
 *     - re-index / verify-txid heavy analytics
 *
 *   So this file exposes a BATCHED ABI. It is deliberately a 1-thread-per-message
 *   scalar implementation of FIPS 180-4 so it can be verified byte-exact against
 *   the repo's own assembly oracle and FIPS vectors -- correctness first. The
 *   engineering analysis (WORKING.md) documents how to push it further.
 *
 * SECURITY NOTE
 *   Output is bit-for-bit identical to FIPS 180-4. A GPU SHA-256 must produce
 *   EXACTLY the same digest as the CPU path -- there is no tolerance for a
 *   "fast but wrong" hash. This kernel is validated against the asm oracle over
 *   the repo KAT vectors + random inputs (see cuda_verify.cu).
 */

#include <cuda_runtime.h>
#include <stdint.h>
#include <string.h>
#include "cuda_sha256.h"

// Device-side memcpy (CUDA kernels can't call host memcpy).
__device__ __forceinline__ void kmemcpy(uint8_t *d, const uint8_t *s, uint64_t n) {
    for (uint64_t i = 0; i < n; i++) d[i] = s[i];
}

// FIPS 180-4 round constants.
__constant__ __device__ uint32_t c_sha256_K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,
    0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
    0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,
    0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,
    0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,
    0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u,
};

__device__ __forceinline__ uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32u - n));
}

// Compress a single 512-bit (64-byte) block into H[8].
__device__ __forceinline__ void sha256_compress(uint32_t H[8],
                                                const uint8_t block[64]) {
    uint32_t W[64];
    for (int i = 0; i < 16; i++) {
        uint32_t v = ((uint32_t)block[4*i]   << 24)
                   | ((uint32_t)block[4*i+1] << 16)
                   | ((uint32_t)block[4*i+2] << 8)
                   | ((uint32_t)block[4*i+3]);
        W[i] = v;
    }
    for (int i = 16; i < 64; i++) {
        uint32_t w1 = W[i-15];
        uint32_t w2 = W[i-2];
        uint32_t s0 = rotr32(w1,7) ^ rotr32(w1,18) ^ (w1 >> 3);
        uint32_t s1 = rotr32(w2,17) ^ rotr32(w2,19) ^ (w2 >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    uint32_t a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + c_sha256_K[i] + W[i];
        uint32_t S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d; H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h;
}

// One full SHA-256 of an arbitrary-length message (FIPS 180-4 padding).
__device__ void sha256_full(uint8_t out[32], const uint8_t *msg, uint64_t len) {
    uint32_t H[8] = {
        0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
        0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u,
    };
    uint64_t full = len >> 6;      // complete 64-byte blocks in-place
    uint64_t rem  = len & 63;      // remaining bytes after full blocks

    // Process all complete blocks straight from msg.
    for (uint64_t b = 0; b < full; b++)
        sha256_compress(H, msg + b*64);

    // Build the final padding block.
    uint8_t block[64];
    kmemcpy(block, msg + full*64, rem);
    block[rem] = 0x80;
    rem += 1;
    if (rem > 56) {
        // length spillover: zeros fill this block; bit-length goes in a new block.
        kmemcpy(block + rem, (const uint8_t*)"\0", 64 - rem);
        sha256_compress(H, block);
        memset(block, 0, 64);
        uint64_t bits = len << 3;
        for (int i = 0; i < 8; i++)
            block[56 + i] = (uint8_t)(bits >> (56 - 8*i));
        sha256_compress(H, block);
    } else {
        memset(block + rem, 0, 56 - rem);
        uint64_t bits = len << 3;
        for (int i = 0; i < 8; i++)
            block[56 + i] = (uint8_t)(bits >> (56 - 8*i));
        sha256_compress(H, block);
    }

    // Store big-endian.
    for (int i = 0; i < 8; i++) {
        out[4*i+0] = (uint8_t)(H[i] >> 24);
        out[4*i+1] = (uint8_t)(H[i] >> 16);
        out[4*i+2] = (uint8_t)(H[i] >> 8);
        out[4*i+3] = (uint8_t)(H[i]);
    }
}

/*
 * BATCHED SHA-256 kernel: hashes `count` independent messages.
 *
 *   msgs : contiguous byte blob holding all messages' payloads
 *   idx  : count x 2 array of uint64 {data_offset, len} into msgs
 *   outd : count x 32 bytes of digests
 *   which: 0 = single SHA-256, 1 = SHA-256d (double hash, Bitcoin's sha256d)
 */
extern "C" __global__ void sha256_batch_kernel(const uint8_t *msgs,
                                               const uint64_t *idx,
                                               uint8_t *outd,
                                               uint64_t count,
                                               int which) {
    uint64_t i = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    if (i >= count) return;
    const uint8_t *m = msgs + idx[2*i + 0];
    uint64_t len = idx[2*i + 1];
    uint8_t tmp[32];
    sha256_full(tmp, m, len);
    if (which == 0) {
        for (int k = 0; k < 32; k++) outd[i*32 + k] = tmp[k];
    } else {
        sha256_full(outd + i*32, tmp, 32);
    }
}

// ---------------------------------------------------------------------------
// Host-side batch launcher (the ABI the node / harness links against).
// ---------------------------------------------------------------------------

typedef struct {
    uint8_t  *d_msgs;
    uint8_t  *d_out;
    uint64_t *d_idx;
    uint64_t count;
    int which;
    cudaStream_t stream;
} cudaShaBatch;

// Stage host buffers onto the device. Returns 0 on success, CUDA error enum on failure.
int cuda_sha256_batch_init(void *batch, const uint8_t *msgs_host,
                           const uint64_t *idx_host, uint64_t count, int which) {
    cudaShaBatch *b = (cudaShaBatch*)batch;
    memset(b, 0, sizeof(*b));
    b->count = count;
    b->which = which;
    uint64_t maxoff = 0;
    for (uint64_t i = 0; i < count; i++) {
        uint64_t e = idx_host[2*i+0] + idx_host[2*i+1];
        if (e > maxoff) maxoff = e;
    }
    size_t idx_bytes  = count * 2 * sizeof(uint64_t);
    size_t out_bytes  = count * 32;
    cudaError_t err;
    err = cudaMalloc((void**)&b->d_idx, idx_bytes);      if (err) return err;
    err = cudaMalloc((void**)&b->d_out, out_bytes);      if (err) return err;
    err = cudaMalloc((void**)&b->d_msgs, maxoff ? maxoff : 1);
    if (err) return err;
    if (maxoff) {
        err = cudaMemcpy(b->d_msgs, msgs_host, maxoff, cudaMemcpyHostToDevice);
        if (err) return err;
    }
    err = cudaMemcpy(b->d_idx, idx_host, idx_bytes, cudaMemcpyHostToDevice);
    if (err) return err;
    err = cudaStreamCreate(&b->stream);
    if (err) return err;
    return 0;
}

// Launch the kernel asynchronously on the batch's stream.
int cuda_sha256_batch_launch(void *batch) {
    cudaShaBatch *b = (cudaShaBatch*)batch;
    int threads = 256;
    uint64_t blocks = (b->count + threads - 1) / threads;
    sha256_batch_kernel<<<blocks, threads, 0, b->stream>>>(
        b->d_msgs, b->d_idx, b->d_out, b->count, b->which);
    return (int)cudaGetLastError();
}

// Sync + (optionally) copy count*32 digest bytes back to a host buffer.
int cuda_sha256_batch_sync(void *batch, uint8_t *out_host) {
    cudaShaBatch *b = (cudaShaBatch*)batch;
    if (out_host) {
        cudaError_t e = cudaMemcpyAsync(out_host, b->d_out, b->count*32,
                                        cudaMemcpyDeviceToHost, b->stream);
        if (e) return (int)e;
    }
    cudaError_t e = cudaStreamSynchronize(b->stream);
    return (int)e;
}

void cuda_sha256_batch_free(void *batch) {
    cudaShaBatch *b = (cudaShaBatch*)batch;
    if (b->d_msgs) cudaFree(b->d_msgs);
    if (b->d_out)  cudaFree(b->d_out);
    if (b->d_idx)  cudaFree(b->d_idx);
    if (b->stream) cudaStreamDestroy(b->stream);
    memset(b, 0, sizeof(*b));
}
