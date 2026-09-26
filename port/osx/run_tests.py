#!/usr/bin/env python3
"""run_tests.py -- asm/Makefile's `make test` suite, natively on macOS/arm64.

Takes every ./tests/* command of the `test:` recipe, builds that test from its
own source against port/osx/daemon_out (the Mac daemon objects: AArch64 ports
and C twins standing in for the x86 objects, by symbol), and runs the exact
recipe command from asm/. Use port/osx/run_tests.sh, which builds the daemon
objects, tools and test helpers first; run this directly to skip that.

    run_tests.py [--out DIR] [--timeout SECS] [--list] [NAME ...]

NAME limits the run to those tests (test_foo or tests/test_foo). Exit status
is 0 when every test run is PASS, SKIP or N/A.

HOW A TEST IS LINKED (the Mac-specific part; each rule below was learned the
hard way on 2026-09-25/26, see port/OSX_STATE.md):

  * the source is tests/<name>.c -- or, for a variant with no source of its
    own (test_utxo_crash_recovery_bulk), the tests/*.c and -D flags of its
    Makefile rule;
  * the daemon objects go in as an ARCHIVE, minus main.o and minus any
    daemon .c the test #includes as a translation unit;
  * objects holding a STRONG definition of a symbol that another object
    defines WEAK are linked directly, ahead of the archive: ld64 resolves an
    archive reference with the first member defining it, weak or not
    (tx_accept.o's weak serve_getaddr once hid serve_addr.o). The set is
    computed from the objects each run, not listed;
  * .c files the test's own rule compiles that the daemon link has no object
    for (daemon/txrecon.c, bitcoin_verify.c) are compiled in, from `make -n`
    so the rule's variables are expanded;
  * x86-only test objects/sources in the rule (tests/fe_ref.o, tests/
    bench_abi_guard.S, ...) are replaced by their Mac stand-ins in
    port/osx/test_support/<name>_twin.{c,S}; a tests/<name>.o with a
    tests/<name>.c beside it is compiled from that;
  * the link is tried strict first (unresolved = code only x86 has, reported
    as MISSING), then with -undefined dynamic_lookup;
  * only if every combination fails with a duplicate symbol -- a symbol the
    TEST defines that an archive member it never needed also defines -- are
    the clashing members dropped and the link retried. Last resort: dropping
    a member first loses everything else it provides.

Tests that are x86-only by nature are reported N/A (the list below, with the
reason in port/OSX_STATE.md). Tests needing loopback aliases SKIP themselves
with the command to add them (tests/loopback_alias.h).
"""
import argparse, json, os, re, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
ASM = os.path.normpath(os.path.join(HERE, "..", "..", "asm"))
DOUT = os.path.join(HERE, "daemon_out")
SUPPORT = os.path.join(HERE, "test_support")
CC = ["cc", "-O2", "-arch", "arm64", "-I.", "-Idaemon", "-Itests", "-I../port/osx/compat", "-D_DARWIN_C_SOURCE",
      "-Dst_mtim=st_mtimespec", "-Dst_atim=st_atimespec", "-Dst_ctim=st_ctimespec", "-w"]

# x86 assembly twins checked against the C they were converted from; no
# production code on either platform calls them (port/OSX_STATE.md, 2026-09-26)
X86_ONLY = {
    "test_txv_parse_diff", "test_txv_classify_diff", "test_segwit_classify_diff", "test_txvb_parse_diff",
    "test_txv_pools_diff", "test_tapagg_diff", "test_txv_dispatch_diff", "test_wv0_drv_diff",
    "test_svs_drv_diff", "test_checksig_diff", "test_bip143_diff", "test_taproot_verify_diff",
    "test_bip341_diff", "test_undo_asm_diff",
}
FINAL_OK = {"PASS", "SKIP", "N/A"}


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def gated_commands(makefile):
    """every recipe line of the `test:` target, continuation lines joined"""
    L = open(makefile, encoding="utf-8", errors="replace").read().split("\n")
    i = 0
    while i < len(L) and not L[i].startswith("test:"): i += 1
    while i < len(L) and L[i].rstrip().endswith("\\"): i += 1
    i += 1
    target = re.compile(r"^[^\t#\s][^:=]*:(?!=)")
    runs = []
    while i < len(L):
        line = L[i]
        if line.strip() and not line.startswith("\t"):
            if line.lstrip().startswith("#"): i += 1; continue
            if target.match(line): break
        if line.startswith("\t"):
            c = line[1:].strip()
            while c.endswith("\\") and i + 1 < len(L): i += 1; c = c[:-1] + " " + L[i].strip()
            if c and not c.startswith("#"): runs.append(c)
        i += 1
    return runs


def make_vars(names, workdir):
    """values of Makefile variables (GNU make 3.81 has no --eval: include + print)"""
    mk = os.path.join(workdir, "print.mk")
    with open(mk, "w") as f:
        f.write('include Makefile\nbmc-print-%:\n\t@echo "$($*)"\n')
    return {n: sh(["make", "-s", "--no-print-directory", "-f", mk, f"bmc-print-{n}"]).stdout.strip() for n in names}


def strong_over_weak(objs):
    """objects with a strong definition of a symbol some other object defines weak"""
    weak, strong = {}, {}
    for o in objs:
        for line in sh(["nm", "-m", o]).stdout.splitlines():
            if " external " not in line or "(undefined)" in line: continue
            sym = line.split()[-1]
            (weak if "weak external" in line else strong).setdefault(sym, set()).add(os.path.basename(o))
    out = set()
    for sym in weak:
        out |= strong.get(sym, set())
    return sorted(out - {"main.o"})


class Builder:
    def __init__(self, workdir):
        self.work = workdir
        self.objs = sorted(os.path.join(DOUT, f) for f in os.listdir(DOUT) if f.endswith(".o") and f != "main.o")
        self.obj_names = {os.path.basename(o) for o in self.objs}
        self.strong = strong_over_weak(self.objs)
        self.cache = {}

    def rule_line(self, target):
        dry = sh(["make", "-n", "-B", target]).stdout
        return next((l for l in dry.splitlines() if f"-o {target} " in l), "")

    def build(self, name):
        if name in self.cache: return self.cache[name]
        binp, src, defs = f"tests/{name}", f"tests/{name}.c", []
        rule = self.rule_line(binp)
        if not os.path.exists(src):
            cs = [w for w in rule.split() if w.startswith("tests/") and w.endswith(".c")]
            if not cs:
                self.cache[name] = ("NOSRC", ""); return self.cache[name]
            src = cs[0]
            defs = [w for w in rule.split() if w.startswith("-D") and not w.startswith("-D_FORTIFY")]
        text = open(src, errors="replace").read()
        inc = {os.path.basename(m)[:-2] + ".o" for m in re.findall(r'#include\s+"(?:\.\./)?(?:daemon/)?([a-z0-9_]+\.c)"', text)}
        use = [o for o in self.objs if os.path.basename(o) not in inc]
        arc = os.path.join(self.work, f"lib_{name}.a")

        def archive():
            if os.path.exists(arc): os.unlink(arc)
            sh(["ar", "rcs", arc] + use)
        archive()

        extra = [w for w in rule.split() if w.endswith(".c") and w != src and os.path.exists(w)
                 and os.path.basename(w)[:-2] + ".o" not in self.obj_names]
        for w in rule.split():
            base = os.path.basename(w)[:-2]
            if w.startswith("tests/") and w.endswith(".S"):
                tw = os.path.join(SUPPORT, base + "_twin.S")
                if os.path.exists(tw): extra.append(tw)
            if w.startswith("tests/") and w.endswith(".o"):
                for tw in (os.path.join(SUPPORT, base + "_twin.c"), os.path.join(SUPPORT, base + "_twin.S"), w[:-2] + ".c"):
                    if os.path.exists(tw): extra.append(tw); break

        tail = [os.path.join(DOUT, "addrbook.a"), "-lpthread"]

        def link(direct, ex):
            strict = sh(CC + defs + ["-o", binp, src] + ex + direct + [arc] + tail)
            if strict.returncode == 0: return ("OK", "")
            missing = sorted(set(re.findall(r'^\s+"(_[A-Za-z0-9_]+)"', strict.stderr, re.M)))
            loose = sh(CC + defs + ["-o", binp, src] + ex + direct + [arc] + tail + ["-Wl,-undefined,dynamic_lookup"])
            if loose.returncode != 0:
                err = next((l for l in loose.stderr.splitlines() if "error" in l), loose.stderr[:200])
                return ("BUILD-FAIL", err[:200])
            return ("MISSING", " ".join(m[1:] for m in missing[:8]) + (" ..." if len(missing) > 8 else ""))

        strong = [os.path.join(DOUT, o) for o in self.strong if o not in inc]
        combos = ((strong, extra), (strong, []), ([], extra), ([], []))
        r = ("BUILD-FAIL", "")
        for d, ex in combos:                              # pass 1: nothing dropped
            r = link(d, ex)
            if r[0] != "BUILD-FAIL": break
        if r[0] == "BUILD-FAIL":                          # pass 2: drop clashing members (last resort)
            for d, ex in combos:
                for _ in range(4):
                    probe = sh(CC + defs + ["-o", binp, src] + ex + d + [arc] + tail + ["-Wl,-undefined,dynamic_lookup"]).stderr
                    clash = set(re.findall(r"\.a\[\d+\]\(([A-Za-z0-9_]+\.o)\)", probe)) if "duplicate symbol" in probe else set()
                    clash -= {os.path.basename(x) for x in d}
                    if not clash: break
                    use[:] = [o for o in use if os.path.basename(o) not in clash]
                    archive()
                    r = link(d, ex)
                    if r[0] != "BUILD-FAIL": break
                if r[0] != "BUILD-FAIL": break
        self.cache[name] = r
        return r


def count_of(out):
    m = re.findall(r"(\d+)\s*(?:checks?|tests?|cases?|calls?|vectors?|spends?|/\d+)", out)
    return m[-1] if m else ""


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("names", nargs="*", help="only these tests (test_foo or tests/test_foo)")
    ap.add_argument("--out", help="results directory (default: a new one under $TMPDIR)")
    ap.add_argument("--timeout", type=int, default=900, help="seconds per test command (default 900)")
    ap.add_argument("--list", action="store_true", help="list the gated test commands and exit")
    a = ap.parse_args()

    os.chdir(ASM)
    if not os.path.exists(os.path.join(DOUT, "bmcbitcoind")):
        sys.exit("port/osx/daemon_out is empty: run port/osx/build_daemon.sh (or run_tests.sh) first")
    out = a.out or tempfile.mkdtemp(prefix="bmc_run_tests.", dir=os.environ.get("TMPDIR"))
    os.makedirs(out, exist_ok=True)

    cmds = [c.lstrip("@-") for c in gated_commands("Makefile")]
    cmds = [c for c in cmds if c.startswith("./tests/")]
    used = sorted(set(re.findall(r"\$\(([A-Z_][A-Z0-9_]*)\)", " ".join(cmds))))
    vals = make_vars(used, out) if used else {}
    only = {n.split("/")[-1] for n in a.names} if a.names else None
    if a.list:
        for c in cmds: print(c)
        return 0

    b = Builder(out)
    results = []
    res = open(os.path.join(out, "results.jsonl"), "w")
    print(f"run_tests: {len(cmds)} gated test commands; results in {out}", flush=True)
    for idx, c in enumerate(cmds):
        for k, v in vals.items(): c = c.replace(f"$({k})", v)
        name = c.split()[0][len("./tests/"):]
        if only is not None and name not in only: continue
        rec = {"i": idx, "cmd": c[:200], "name": name}
        if name in X86_ONLY:
            rec.update(status="N/A", note="x86 assembly twin (port/OSX_STATE.md)")
        else:
            bstat, bnote = b.build(name)
            rec.update(build=bstat, build_note=bnote)
            if bstat in ("NOSRC", "BUILD-FAIL"):
                rec["status"] = bstat
            else:
                t0 = time.time()
                p = subprocess.run(["perl", "-e", f"alarm {a.timeout}; exec @ARGV", "/bin/sh", "-c", c],
                                   capture_output=True, text=True, errors="replace", stdin=subprocess.DEVNULL,
                                   env=dict(os.environ, TMPDIR=out))
                text = p.stdout + p.stderr
                lines = [l for l in text.splitlines() if l.strip()]
                rc = p.returncode
                status = ("TIMEOUT" if rc in (142, -14) else
                          "SKIP" if rc == 0 and re.search(r"\bSKIP", text) else
                          "PASS" if rc == 0 else "FAIL")
                rec.update(status=status, rc=rc, secs=round(time.time() - t0, 1), n=count_of(text),
                           last=(lines[-1] if lines else "")[:160],
                           fails=[l[:160] for l in text.splitlines() if re.search(r"\bFAIL", l)][:4])
        results.append(rec)
        res.write(json.dumps(rec) + "\n"); res.flush()
        detail = rec.get("note") or (rec.get("build_note", "")[:60] if rec["status"] not in FINAL_OK else "")
        print(f"[{idx:3d}] {rec['status']:10s} {name} {rec.get('n', '')} {detail}".rstrip(), flush=True)
    res.close()

    counts = {}
    for r in results: counts[r["status"]] = counts.get(r["status"], 0) + 1
    bad = [r for r in results if r["status"] not in FINAL_OK]
    print("\n" + "  ".join(f"{k} {v}" for k, v in sorted(counts.items())) + f"   ({len(results)} commands)")
    for r in bad:
        why = (r.get("fails") or [r.get("last") or r.get("build_note", "")])[0]
        print(f"  {r['status']:10s} {r['name']}: {why}")
        if r.get("build") == "MISSING": print(f"             unresolved at link: {r['build_note']}")
    print(f"results: {os.path.join(out, 'results.jsonl')}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
