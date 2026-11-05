# scriptnum: CScriptNum and the numeric opcodes against Core v31.1

`./run.sh` runs the whole group: 8 checks, 0 failures, about 15 s. It
builds the real objects into `.build/` (`build.sh`). Every run goes through
runlib's `_lim`, one at a time.

Tools: angr 10.0.5 / pyvex 10.0.5 with z3-solver 5.3.1.0 (claripy backend),
NASM 2.16.01, gcc 13.3.0.

The reference is `core_scriptnum.h`, a line-for-line C port of these Core
functions, with Core's ScriptError numbering (checked against
script/script_error.h: SCRIPTNUM = 4, NUMEQUALVERIFY = 15,
INVALID_STACK_OPERATION = 18, NEGATIVE_LOCKTIME = 21,
UNSATISFIED_LOCKTIME = 22):

- CScriptNum(vch, fRequireMinimal, nMaxNumSize), set_vch and serialize (script/script.h)
- CastToBool (script/interpreter.cpp)
- the numeric opcodes, OP_WITHIN, CLTV/CSV, CheckLockTime and CheckSequence (script/interpreter.cpp)

`sn_lift.py` carries its own claripy transcription of the same three
primitives.

## Results

| ID | bmc code (real) | claim | method / bound | result | time |
|---|---|---|---|---|---|
| SN-lift | `bitcoin_scriptcodec.asm` scriptnum_decode | For every input of length 0..8 (every byte value, every maxsize 0..255, minimal on and off), the overflow/non-minimal flag equals Core's throw, and when Core does not throw the value equals Core's. For lengths 9..12 (maxsize ≤ 8) the throw flag equals Core's. | angr symbolic execution of the real linked object (`lift_bin`) to every `ret`, then z3 on each path. Unbounded in the values. Lengths ≤ 12. The size check is the function's first test, so longer inputs only set the flag (by reading). | PROVED | 3.8 s, all three |
| SN-lift | scriptnum_serialize | For every int64, the bytes and length equal CScriptNum::serialize, including INT64_MIN, the sign byte and the extra 0x00/0x80 byte. | same, all 2^64 values | PROVED | (incl.) |
| SN-lift | cast_to_bool | Equals CastToBool, including negative zero. | same, lengths 0..9 and 16 | PROVED for those lengths | (incl.) |
| SN-ops | `bitcoin_interp.asm` script_eval on OP_1ADD … OP_MAX, OP_WITHIN, CLTV, CSV (one-opcode scripts) | Success, ScriptError and the whole final stack equal Core's. Covers the 4-byte operand limit, the 5-byte CLTV/CSV limit, MINIMALDATA, results above 4 bytes (OP_ADD of two 4-byte operands), negative zero, NUMEQUALVERIFY, negative and unsatisfied locktimes, and the CSV disable/type/version rules. | differential test of the real object vs `core_scriptnum.h`. Exhaustive: 2,503,718 cases (every binary opcode over all operand pairs ≤ 1 byte, every unary opcode over all operands ≤ 2 bytes, both MINIMALDATA settings). Then 1M random cases (operands 0..6 bytes, edge-biased, random flags and tx context) and 1M direct calls to each primitive. | 0 divergences (testing, not proof) | 1.1 s |

Mutants (each must be reported caught):

- **decode:** `jbe .size_ok` → `jb` (rejects len == maxsize), caught at
  lengths 0–8. `test cl, 0x7f` → `0x3f` (minimal-encoding test), caught at
  lengths 1–8.
- **serialize:** the sign OR `0x80` → `0x40`.
- **cast_to_bool:** negative-zero byte `0x80` → `0x81`.
- **interpreter:** OP_WITHIN upper bound `setl` → `setle` (14 divergences in
  200k). CLTV negative check `jns` → `jmp` (1,105 divergences).

## Findings

None. No divergence was found on any input.

## Not covered

- **The opcode semantics are tested, not proved.** Each handler was not
  lifted: the interpreter's dispatch loop and stack memory make whole-function
  symbolic execution expensive. Their arithmetic sits on the proved
  primitives, and the exhaustive phase covers every operand of length ≤ 1
  (pairs) and ≤ 2 (unary). The operand bounds rule out int64 overflow: ≤ 4
  bytes, so |x| < 2^31, and results stay within 2^32.
- **Longer inputs.** cast_to_bool beyond 16 bytes and scriptnum_decode
  beyond 12 bytes were checked by reading only. The loops are uniform.
- **Multi-opcode scripts and opcode interactions** are not covered (only
  single-opcode scripts are tested). Neither are the callers' choice of
  maxsize per opcode beyond those exercised.
- **The `SNUM_MAX 4/5` choices.** Every call site in bitcoin_interp.asm
  passes 4, except CLTV/CSV, which pass 5. Checked by grep.
