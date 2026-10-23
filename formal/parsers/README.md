# formal/parsers: bounded model checking of the untrusted-input parsers

CBMC proofs of memory safety and absence of undefined behaviour, plus
documented postconditions and Core-equivalence checks, for the C code in
`asm/` that parses bytes from the network or from disk. Code under
verification: the security integration branch `integ/2026-10-23-sec-all`
(b841251b). Core reference: Bitcoin Core v31.1.

Tools: CBMC 6.11.0 (`$FORMAL_TOOLS/cbmc/usr/bin/cbmc`, `FORMAL_TOOLS`
defaults to `$HOME/.local/opt/formal`), gcc for the concrete confirmations.

## Reproduce

    formal/parsers/run.sh            # every proof, cover run, mutant and divergence
    formal/parsers/run.sh 'P-INV|LOC'  # a subset (bash regex on the entry names)
    formal/parsers/confirm/run.sh    # the concrete reproductions of the findings

`run.sh` exits 0 only if every proof verifies, every cover goal is reached,
every mutant is caught and every divergence still reproduces. Each CBMC
process runs under `flock` (one at a time) inside
`systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0`, niced, with a
timeout, and only while `free -g` reports at least 25 GB available.

Every check flag is on for every entry (`--bounds-check --pointer-check
--signed-overflow-check --unsigned-overflow-check --pointer-overflow-check
--conversion-check --div-by-zero-check --memory-leak-check
--float-overflow-check --nan-check --unwinding-assertions`), except where an
entry's tokens say otherwise:

* `@nouov` drops `--unsigned-overflow-check` (wrap-around is defined C; the
  harness then asserts the consequence that matters explicitly).
* `@noconv` drops `--conversion-check` where the code narrows on purpose
  (byte extraction, a u64 field read back as int64); proofs.sh says why.
* `@relwaive` (P-BWTX only): `bw_walk_tx` bounds-checks by forming a pointer
  past its object (`p + 36 > end`), undefined by the letter of C11 6.5.6p8 but
  never dereferenced; the entry passes when the only failed properties are
  those eight "pointer arithmetic/relation: pointer outside object bounds in
  p + k" relations (block_witness.c lines 33, 36, 39, 63, 69, 75, 114).

Entry kinds (see `proofs.sh`): `proof` (must verify; its cover run must reach
every goal: the vacuity check), `proofm` (a proof over a scratch copy with a
stated model change), `mutant`/`mutanth` (a scratch copy of the source or a
header with one injected defect: CBMC must fail, on the named property),
`diverge` (Core's rule asserted under `-DFP_CORE_STRICT` on the unmodified
code: CBMC must report it violated; each is a finding, confirmed concretely
in `confirm/`).

## Method

Each harness (`harness/*.c`) `#include`s the product source, so its static
functions are visible, and calls the parser on a buffer of nondeterministic
content and nondeterministic length up to a bound N. Input buffers are
tail-aligned in a constant-size object (`nd_tail`): any read past the input's
end leaves the object and is caught, while the object's size stays concrete
for the solver. Only environmental functions are stubbed (I/O, the clock,
crypto primitives and NASM routines with a stated contract); each stub checks
the spans it is handed. Unwinding assertions are on everywhere, so an
insufficient bound is reported, never hidden.

## Results

RESULTS_TABLE

## Findings (each confirmed on the compiled code by `confirm/run.sh`)

FINDINGS

## Assumptions and trusted base

TRUSTED

## Not covered

NOTCOVERED
