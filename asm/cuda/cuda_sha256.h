/*
 * cuda_sha256.h -- batched SHA-256 / SHA-256d CUDA acceleration ABI.
 *
 * Included by cuda_sha256.cu (definition) and the harness/bench TUs so that C++
 * name mangling (nvcc) is identical across translation units. All batch handles
 * are opaque (void*), which also lets plain C callers link if this is ever
 * promoted into an auditor/verification tool. Not yet wired into the assembly
 * node itself -- see ../WORKING.md for the integration plan.
 */
#ifndef CUDA_SHA256_H
#define CUDA_SHA256_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Stage a batch of `count` independent messages.
 *   msgs_host : contiguous blob of all messages' payload bytes
 *   idx_host  : count x 2 array of uint64 {data_offset, len} into msgs_host
 *   which     : 0 = single SHA-256, 1 = SHA-256d (Bitcoin double hash)
 * Returns 0 on success, a CUDA error code otherwise.
 */
int  cuda_sha256_batch_init(void *batch, const uint8_t *msgs_host,
                            const uint64_t *idx_host, uint64_t count, int which);

/* Launch the kernel asynchronously. Returns CUDA error code. */
int  cuda_sha256_batch_launch(void *batch);

/* Sync + (optionally) copy count*32 digest bytes back to out_host. */
int  cuda_sha256_batch_sync(void *batch, uint8_t *out_host);

/* Release device buffers + stream. */
void cuda_sha256_batch_free(void *batch);

#ifdef __cplusplus
}
#endif

#endif /* CUDA_SHA256_H */
