# CUDA acceleration workbench for bitcoinmachinecode
#
#   make all     : verify + bench + autodetect (builds libbmc_cuda.so + probes)
#   make verify  : correctness gate (CUDA == asm oracle)
#   make bench   : GPU/CPU throughput comparison
#   make detect  : build + exercise the auto-detect dispatcher in all modes
#   make clean   : remove artifacts
#
# Needs nvcc (CUDA toolkit) + the repo's assembly objects (sha256.o,
# bitcoin_hash.o) for the CPU oracle/fallback. The auto-detect dispatcher
# dlopens libbmc_cuda.so, so a build without the GPU still links and falls back
# to CPU at runtime.

NVCC      := nvcc
ARCH      := -arch=sm_120
COMMON    := $(ARCH) -O3 -std=c++17 --expt-relaxed-constexpr
ORACLE    := ../sha256.o ../bitcoin_hash.o

.PHONY: all verify bench detect poc clean

all: verify bench detect

# txid-offload proof-of-concept (Python; needs libbmc_cuda.so + Core RPC for a
# real block, uses the proven consensus_shim as the trusted txid oracle). This is
# a NEGATIVE result for per-block offload: it proves correctness (CUDA sha256d ==
# asm tx_txid byte-for-byte) but that a SINGLE block's txid batch is too small to
# amortize GPU launch/transfer. See WORKING.md "cons_verify txid-offload PoC".
poc: libbmc_cuda.so
	python3 cuda_txid_poc.py

# The runtime-loaded CUDA backend: kernels + host launchers as a shared object.
# Exported C symbols (from cuda_sha256.h extern "C") so the dispatcher can
# dlsym them. Links libcudart -> needs a GPU stack to actually run, but the .so
# can be absent or fail to dlopen and the dispatcher just falls back to CPU.
libbmc_cuda.so: cuda_sha256.cu cuda_sha256.h
	$(NVCC) $(COMMON) -shared -Xcompiler -fPIC -o $@ cuda_sha256.cu -lcudart

verify: cuda_verify
	./cuda_verify

bench: cuda_bench
	./cuda_bench 1000000

# Auto-detect dispatcher + oauth test harness (plain C, links assembly oracle
# for the CPU fallback path).
cuda_autodetect_test: cuda_autodetect_test.c cuda_autodetect.c $(ORACLE)
	$(CC) -O2 -o $@ cuda_autodetect_test.c cuda_autodetect.c $(ORACLE) -ldl

detect: libbmc_cuda.so cuda_autodetect_test
	LD_LIBRARY_PATH=. ./cuda_autodetect_test

cuda_verify: cuda_verify.cu cuda_sha256.cu $(ORACLE)
	$(NVCC) $(COMMON) -o $@ cuda_verify.cu cuda_sha256.cu $(ORACLE)

cuda_bench: cuda_bench.cu cuda_sha256.cu $(ORACLE)
	$(NVCC) $(COMMON) -o $@ cuda_bench.cu cuda_sha256.cu $(ORACLE)

clean:
	rm -f cuda_verify cuda_bench cuda_autodetect_test libbmc_cuda.so
