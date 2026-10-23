"""P1: bmc pow_check (asm/bitcoin_hash.asm) vs Core CheckProofOfWorkImpl.

Method: the REAL assembled object (.build/bitcoin_hash.o) is loaded by angr,
lifted to VEX, and symbolically executed from pow_check to its return with
  - hdr[80] symbolic except as noted; nBits = hdr[72..75] a free 32-bit BV,
  - block_hash hooked: it writes a free 256-bit value to its out buffer (the
    hash is a free input; SHA-256 itself is trusted, not modelled),
  - pow_pow_limit_bits (.data) set to one concrete chain value (or 0).
Every path that returns is collected; bmc_accept is the disjunction over the
returning paths of (path constraint AND eax==1). Core's predicate comes from
core_spec.py. The solver (claripy's z3 backend) is then asked for any
(bits, hash) that separates them.

usage: p1_pow_check.py <bitcoin_hash.o> [--mutant <obj>] [--expect-fail]
"""
import sys, time, logging, warnings
warnings.simplefilter('ignore', DeprecationWarning)
logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
import angr
import angr.rustylib.claripy as claripy
import core_spec

obj = sys.argv[1]
expect_fail = "--expect-fail" in sys.argv
modes = [int(a, 16) for a in sys.argv[2:] if a.startswith("0x")] or [0x1d00ffff, 0x1e0377ae, 0x207fffff, 0]

proj = angr.Project(obj, auto_load_libs=False, load_options={"main_opts": {"base_addr": 0x400000}})
sym = {s.name: s.rebased_addr for s in proj.loader.main_object.symbols if s.name}
F_POW = sym["pow_check"]; F_BH = sym["block_hash"]; LIM = sym["pow_pow_limit_bits"]

HASH = claripy.BVS("hash", 256)       # Core's UintToArith256(hash): bytes read little-endian


class BlockHash(angr.SimProcedure):
    def run(self, out, hdr):
        # 32 bytes, byte i = bits [8i+7:8i] of HASH (little-endian store)
        self.state.memory.store(out, HASH, endness="Iend_LE")
        return 0


proj.hook(F_BH, BlockHash())

all_ok = True
for lim_bits in modes:
    t0 = time.time()
    MANT = claripy.BVS("mant", 24)
    EXP = claripy.BVS("exp", 8)
    BITS = claripy.Concat(EXP, MANT)
    # The exponent is split into its 256 concrete values (one symbolic run each)
    # so that every memory address the code computes is concrete; angr would
    # otherwise CONCRETIZE a symbolic store address and silently drop cases.
    # The guard below aborts if any address is still symbolic.
    accept = []; n_paths = 0; errs = 0; sym_addr = [0]
    def guard(state):
        w = state.inspect.mem_write_address
        a = w if w is not None else state.inspect.mem_read_address
        # an address AST may mention a variable yet have exactly one value
        # (e.g. (exp||mant)>>24 with exp concrete); only multi-valued ones count
        if a is not None and state.solver.symbolic(a) and len(state.solver.eval_upto(a, 2)) > 1:
            sym_addr[0] += 1
            print("     SYMBOLIC ADDRESS at", hex(state.addr), a)
    for e in range(256):
        st = proj.factory.call_state(F_POW, 0x10000000, add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                                                                       angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
        st.inspect.b("mem_write", when=angr.BP_BEFORE, action=guard)
        st.inspect.b("mem_read", when=angr.BP_BEFORE, action=guard)
        st.memory.store(0x10000000 + 72, claripy.Concat(claripy.BVV(e, 8), MANT), endness="Iend_LE")
        st.memory.store(LIM, claripy.BVV(lim_bits, 32), endness="Iend_LE")
        sm = proj.factory.simulation_manager(st)
        sm.run()
        other = {k: len(v) for k, v in sm.stashes.items() if k not in ("deadended",) and v}
        if sm.errored or other:
            print("     exp", e, "errored", [str(x.error) for x in sm.errored][:2], other)
        errs += len(sm.errored) + sum(other.values())
        for s in sm.deadended:
            n_paths += 1
            c = claripy.And(*s.solver.constraints) if s.solver.constraints else claripy.true()
            accept.append(claripy.And(EXP == e, c, s.regs.eax == 1))
    bmc = claripy.Or(*accept)
    errs += sym_addr[0]
    if lim_bits:
        core = core_spec.check_pow(HASH, BITS, core_spec.POW_LIMIT_FULL[lim_bits])
    else:
        core = core_spec.check_pow(HASH, BITS, (1 << 256) - 1)   # unarmed: compared to "no limit"
    size = claripy.LShR(BITS, 24)
    s = claripy.Solver(timeout=600000)
    # (a) soundness: bmc accepts => Core accepts
    a_cex = s.satisfiable(extra_constraints=[bmc, claripy.Not(core)])
    # (b) completeness except exponent < 3
    b_cex = s.satisfiable(extra_constraints=[core, claripy.Not(bmc), claripy.UGE(size, 3)])
    # (c) the residual divergence: Core accepts, bmc rejects, exponent<3 => hash < 2^15
    c_cex = s.satisfiable(extra_constraints=[core, claripy.Not(bmc), claripy.UGE(HASH, 1 << 15)])
    # (d) vacuity: both accept and both reject are reachable; residual is non-empty
    v1 = s.satisfiable(extra_constraints=[bmc, core])
    v2 = s.satisfiable(extra_constraints=[claripy.Not(bmc), claripy.Not(core)])
    resid = s.satisfiable(extra_constraints=[core, claripy.Not(bmc)])
    dt = time.time() - t0
    tag = f"limit=0x{lim_bits:08x}"
    print(f"[P1] {tag} paths={n_paths} errored={errs} bmc=>core: {'CEX' if a_cex else 'UNSAT(ok)'} "
          f"core&!bmc&exp>=3: {'CEX' if b_cex else 'UNSAT(ok)'} core&!bmc=>hash<2^15: {'CEX' if c_cex else 'UNSAT(ok)'} "
          f"vacuity(both-accept={v1},both-reject={v2}) residual_nonempty={resid} {dt:.1f}s")
    for name, flag, extra in (("bmc&!core", a_cex, [bmc, claripy.Not(core)]),
                              ("core&!bmc&exp>=3", b_cex, [core, claripy.Not(bmc), claripy.UGE(size, 3)])):
        if flag:
            m = s.batch_eval([BITS, HASH], 1, extra_constraints=extra)[0]
            print(f"     counterexample {name}: bits=0x{m[0]:08x} hash=0x{m[1]:064x}")
    if lim_bits == 0:
        # Unarmed mode: report what bmc accepts that a Core node on each chain would refuse.
        for cb, full in core_spec.POW_LIMIT_FULL.items():
            corec = core_spec.check_pow(HASH, BITS, full)
            x = s.satisfiable(extra_constraints=[bmc, claripy.Not(corec)])
            if x:
                m = s.batch_eval([BITS, HASH], 1, extra_constraints=[bmc, claripy.Not(corec)])[0]
                print(f"     unarmed bmc accepts what Core(limit 0x{cb:08x}) rejects, e.g. bits=0x{m[0]:08x} hash=0x{m[1]:064x}")
        ok = (not a_cex) and (not b_cex) and (not c_cex) and v1 and v2 and errs == 0
    else:
        ok = (not a_cex) and (not b_cex) and (not c_cex) and v1 and v2 and errs == 0
    all_ok &= ok

if expect_fail:
    print("[P1] mutant:", "DETECTED (counterexample found)" if not all_ok else "NOT DETECTED")
    sys.exit(0 if not all_ok else 1)
print("[P1] RESULT:", "PROVED" if all_ok else "FAILED")
sys.exit(0 if all_ok else 1)
