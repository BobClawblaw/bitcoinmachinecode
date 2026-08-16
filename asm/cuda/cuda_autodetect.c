/*
 * cuda_autodetect.c -- auto-detecting, fallback-safe batch SHA-256d dispatcher
 * for the Bitcoin Machine Code node.
 *
 * GOAL
 *   "If CUDA is detected and usable, use it; otherwise fall back to the proven
 *   assembly crypto." This is the single entrypoint used to hash a batch of
 *   independent messages:
 *
 *       int bmc_sha256d_batch(uint8_t *out, const uint8_t *msgs,
 *                             const uint64_t *idx, uint64_t count)
 *
 *   Runtime decision, mirroring the product's CPUID->SHA-NI seam but with a
 *   device probe instead of cpuid:
 *
 *     1. A shared object libbmc_cuda.so (CUDA batch kernels + host launcher,
 *        links libcudart) is dlopen'd on FIRST call. If that fails, or libcudart
 *        cannot be loaded, or cudaGetDeviceCount() requests ANY usable device
 *        and returns 0 -> we cache cuda_available=0.
 *     2. We route to CUDA only when ALL hold:
 *          - cuda_available, and
 *          - count >= CUDA_MIN_BATCH (amortize launch+copy), and
 *          - not disabled by env BMC_CUDA=0.
 *     3. On ANY CUDA error we fall through to the proven assembly sha256d loop.
 *
 *   A build with no CUDA installed, or a platform without an NVIDIA GPU, is
 *   byte-for-byte identical behavior via the CPU path. The node never requires
 *   a GPU.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

/* The proven assembly oracle (bit-exact CPU fallback); System-V AMD64. */
extern void sha256d(void *out, const void *msg, unsigned long len);

typedef int  (*init_fn)(void *batch, const uint8_t *msgs, const uint64_t *idx,
                        uint64_t count, int which);
typedef int  (*launch_fn)(void *batch);
typedef int  (*sync_fn)(void *batch, uint8_t *out);
typedef void (*free_fn)(void *batch);
typedef int  (*devcount_fn)(int *);

typedef struct {
    int       probed;
    int       cuda_available;
    int       last_used_cuda;  /* which path serviced the most recent batch */
    void     *handle;      /* dlopen handle of libbmc_cuda.so */
    init_fn   init;
    launch_fn launch;
    sync_fn   sync;
    free_fn   free;
} cuda_state;

/* Threshold below which the launch+copy overhead makes the CPU path win. */
#define CUDA_MIN_BATCH 512

static cuda_state st = {0};

static void probe_cuda(void)
{
    if (st.probed) return;
    st.probed = 1;

    const char *disable = getenv("BMC_CUDA");
    if (disable && disable[0] == '0') { st.cuda_available = 0; return; }

    const char *libpath = getenv("BMC_CUDA_LIB");
    if (!libpath) libpath = "libbmc_cuda.so";
    st.handle = dlopen(libpath, RTLD_NOW | RTLD_GLOBAL);
    if (!st.handle) { st.cuda_available = 0; return; }

    st.init   = (init_fn)  dlsym(st.handle, "cuda_sha256_batch_init");
    st.launch = (launch_fn)dlsym(st.handle, "cuda_sha256_batch_launch");
    st.sync   = (sync_fn)  dlsym(st.handle, "cuda_sha256_batch_sync");
    st.free   = (free_fn)  dlsym(st.handle, "cuda_sha256_batch_free");
    if (!st.init || !st.launch || !st.sync || !st.free) {
        st.cuda_available = 0; return;
    }

    /* Genuine usable-device probe: cudaGetDeviceCount from the loaded runtime. */
    devcount_fn getcount = (devcount_fn)dlsym(st.handle, "cudaGetDeviceCount");
    if (!getcount) { st.cuda_available = 0; return; }
    int ndev = 0;
    if (getcount(&ndev) != 0 || ndev < 1) { st.cuda_available = 0; return; }

    st.cuda_available = 1;
}

/*
 * Hash `count` independent messages (sha256d each).
 *   out  : count*32 bytes of digests (caller-allocated)
 *   msgs : contiguous blob of all message payloads
 *   idx  : count x 2 uint64 {data_offset, len} into msgs
 * Returns 0 on success. On failure, output is undefined in the CUDA branch
 * (caller that needs guaranteed output should treat a nonzero return as "use
 * the per-item CPU APIs").
 */
int bmc_sha256d_batch(uint8_t *out, const uint8_t *msgs,
                      const uint64_t *idx, uint64_t count)
{
    probe_cuda();

    if (st.cuda_available && count >= CUDA_MIN_BATCH) {
        /* Opaque handle: the lib casts our void* to its own struct, so we give
         * it a zeroed buffer larger than any internal struct it uses. */
        void *batch = calloc(1, 256);
        if (batch) {
            int rc = 0;
            if ((rc = st.init(batch, msgs, idx, count, 1)) == 0) {
                if ((rc = st.launch(batch)) == 0) {
                    rc = st.sync(batch, out);
                }
                st.free(batch);
            }
            free(batch);
            if (rc == 0) { st.last_used_cuda = 1; return 0; }
            /* else fall through to CPU on any CUDA error */
        }
    }

    for (uint64_t i = 0; i < count; i++)
        sha256d(out + i*32, msgs + idx[2*i+0], idx[2*i+1]);
    st.last_used_cuda = 0;
    return 0;
}

/* Introspection for tests/tooling: 1 if the last batch used the CUDA path. */
int bmc_cuda_was_used(void) { return st.last_used_cuda; }

/* 1 if a usable CUDA device is present (forces a probe). */
int bmc_cuda_detected(void) { probe_cuda(); return st.cuda_available; }
