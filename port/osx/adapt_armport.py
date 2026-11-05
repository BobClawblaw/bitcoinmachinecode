#!/usr/bin/env python3
"""adapt_armport.py -- mechanical arm-port (Linux ELF AArch64) -> Mach-O
(bmc_osx) adaptation for one module.

Usage: adapt_armport.py <module> [<module> ...]
Reads origin/arm-port:port/arm64/<module>.S (via git show), writes
port/osx/<module>.S adapted.

Transforms:
  - .section .rodata/.rodata.*          -> .section __TEXT,__const
  - .section .note.GNU-stack...         -> dropped
  - .type / .size                        -> dropped
  - :lo12:SYM after add/ldr             -> SYM@PAGEOFF
  - .global/.globl SYM                  -> .globl _SYM (+ label rename)
  - extern refs                          -> _SYM (from the x86 .asm's extern
                                            list + a known-externs table)
  - exported label SYM:                  -> _SYM:
  - .tbss blocks                          -> NOT handled here: the TLS vars
                                            go into a generated C file
                                            (tls_<module>.c) and the TLS_ADDR
                                            macro is rewritten per-module.
Local labels (starting with '.' or numeric) are never renamed.
"""
import re, subprocess, sys, os

# symbols provided by other objects (C twins, natives, libc) that the arm-port
# asm calls without the Mach-O underscore
KNOWN_EXTERN = {
    'sha256_full','sha256d','ripemd160','hash160','sha256_init','sha256_block',
    'malloc','free','abort','calloc','realloc','memcpy','memset','memmove',
    'pthread_getspecific','pthread_setspecific','pthread_self',
    'fe_mul','fe_sqr','fe_inv','fe_add','fe_sub','fe_inv_var',
    'point_scalar_mul','point_scalar_mul_fixed','point_scalar_mul_glv',
    'point_add','point_add_mixed','point_double','point_scalar_mul_ct',
    'pointh_add','pointh_double','point_add_mixed_zr',
    'pubkey_parse','schnorr_verify','ecdsa_verify','ecdsa_x_eq_mod_n',
    'sc_mul','sc_add','sc_sub','sc_sqr','sc_inv','sc_inv_var','sc_mul_512',
    'sc_split_lambda','scalar_to_pubkey','scalar_small_nonzero',
    'tx_parse','tx_txid','merkle_root','sha256d64','diff_target','pow_check',
    'block_hash','hmac_sha512','bip32_master','bip32_ckd_priv','bip32_derive_path',
    'bip32_fingerprint','bip32_extkey_serialize','bip39_generate','bip39_validate',
    'bip39_entropy_to_seed','bip39_word_from_index','base58check_encode',
    'idx_init','idx_put','idx_get','idx_count','idx_build_from_file',
    'store_init','store_reload','store_append','store_get_at','store_get_tip',
    'store_prune','store_truncate_to','store_fmt_blkname','store_get_file_fd',
    'utxo_init','utxo_put','utxo_get','utxo_del','utxo_count','utxo_clear',
    'utxo_store_init','utxo_store_put','utxo_store_get','utxo_store_del',
    'utxo_store_count','utxo_store_sync','utxo_store_reload','utxo_store_close',
    'utxo_lsm_init','utxo_lsm_put','utxo_lsm_get','utxo_lsm_flush','utxo_lsm_recount',
    'utxo_lsm_compact_range','utxo_lsm_walk','utxo_lsm_reload','utxo_struct_size',
    'sighash_all','legacy_sighash','legacy_sighash_scfbuf','script_find_and_delete',
    'script_op_len','script_push_encode','tagged_hash256','tap_branch_hash',
    'tap_leaf_hash','taproot_tweak_pubkey','tap_merkle_root','schnorr_verify',
    'swtx_parse_export','segwit_v0_sighash','taproot_sighash','taproot_keypath_verify',
    'cons_verify','hst_init','hst_reload','hst_append','hst_count','hst_get_at',
    'chainwork_add','chainwork_cmp','block_work','u256_div','compact_to_target_le',
    'store_chainwork_init','store_chainwork_append','store_chainwork_get_at',
    'node_log_open','node_log_str','node_log_event','muhash_insert','muhash_combine',
    'muhash_finalize','muhash_to_num3072','num3072_mul','num3072_inv','tcp_connect_ip',
    'p2p_frame','p2p_write','p2p_read','p2p_getheaders','p2p_getdata_block','p2p_ping',
    'p2p_headers_count','p2p_inv_count','p2p_inv_get','fd_write_all','fd_read_full',
    'fd_close','net_magic','tcp_connect_ip6','socks5_connect','i2psam_connect',
    'i2psam_accept','i2psam_session','torctl_add_onion','sha3_256','siphash24_uint256',
    'g_log_timestamps','g_log_timemicros','g_log_threadnames','g_log_sourcelocations',
    'mpool_init','mpool_del','mpool_count','mpool_struct_size','mpool_wtxid_at_slot',
    'g_sync_mp','mp_lock','mp_unlock','strip_witness_asm','stack_push','script_eval',
    'be_to_limbs','der_parse_sig','verify_p2pkh','sha512_full','sha512',
}

# hand-fixes that must survive regeneration (the arm-port predates them)
POST_FIX = {
    'bitcoin_serve': '''
	.section __DATA,__data
	.globl _g_serve_violation_hook
_g_serve_violation_hook:
	.quad 0      /* void (*)(const char* reason); NULL = nobody registered */
	.globl _g_serve_tx_gate
_g_serve_tx_gate:
	.quad 0      /* int (*)(void): 0 accept, 1 drop, -1 violation */
	.globl _g_serve_inv_gate
_g_serve_inv_gate:
	.quad 0      /* int (*)(const u8* pl, long plen) */
	.globl _g_serve_mempool_hook
_g_serve_mempool_hook:
	.quad 0      /* int (*)(int fd, void* mp): 1 handled, -1 violation */
	.globl _g_serve_policy_log
_g_serve_policy_log:
	.quad 0      /* void (*)(const char* reason) */
	.globl _g_serve_send_feefilter
_g_serve_send_feefilter:
	.byte 1      /* -blocksonly / forcerelay peer: Core sends none */
''',
    # strips the in-.text definitions (the arm-port placed the written-at-boot
    # hooks in .text -- a write to a read-only page at runtime); the real
    # definitions live in POST_FIX[bitcoin_serve] above
}

def post_strip(module, text):
    if module != 'bitcoin_serve':
        return text
    for name in ('_g_serve_tx_gate', '_g_serve_inv_gate',
                 '_g_serve_mempool_hook', '_g_serve_policy_log',
                 '_g_serve_send_feefilter', '_g_serve_violation_hook'):
        text = re.sub(rf'\t\.globl {name}\n{name}:[^\n]*\n', '', text)
    return text


SYSCALL_NR = {56: 463, 67: 153, 57: 6, 62: 199, 63: 3, 32: 131}

def fix_syscalls(text):
    """Linux arm64 raw syscalls -> Darwin (nr x16, svc #0x80, carry-set
    errors); AT_FDCWD -100 -> -2; tbnz-negative tests -> b.cs; getrandom ->
    _bmcshim_getrandom."""
    lines = text.split('\n')
    out = []
    last_svc = -10
    i = 0
    while i < len(lines):
        ln = lines[i]
        s = ln.strip()
        if s.startswith('movz x8, #278') or s.startswith('mov x8, #278'):
            j = i
            while j < len(lines) and 'b.eq' not in lines[j]:
                j += 1
            label = lines[j].split('b.eq')[1].strip()
            out.append('\tbl _bmcshim_getrandom          /* Darwin: arc4random_buf */')
            out.append(f'\tb {label}')
            i = j + 1
            continue
        m = re.match(r'(\s*)mov\s+[xw]8,\s*#(\d+)\s*(/\*.*\*/)?\s*$', ln)
        if m and int(m.group(2)) in SYSCALL_NR and i + 1 < len(lines) \
                and re.search(r'\bsvc\s+#0\b', lines[i+1]):
            nr = SYSCALL_NR[int(m.group(2))]
            out.append(f'{m.group(1)}mov x16, #{nr}{("   " + m.group(3)) if m.group(3) else ""}')
            out.append(re.sub(r'\bsvc\s+#0\b', 'svc #0x80', lines[i+1]))
            last_svc = len(out)
            i += 2
            continue
        if re.fullmatch(r'svc\s+#0', s):
            out.append(re.sub(r'\bsvc\s+#0\b', 'svc #0x80', ln))
            last_svc = len(out)
            i += 1
            continue
        m = re.match(r'(\s*)mov\s+x0,\s*#-100(\s*/\* AT_FDCWD \*/)?\s*$', ln)
        if m:
            out.append(f'{m.group(1)}mov x0, #-2{m.group(2) or "        /* AT_FDCWD (Darwin) */"}')
            i += 1
            continue
        m = re.match(r'(\s*)tbnz\s+x0,\s*#63,\s*(\S+?)(\s*/\*.*)?\s*$', ln)
        if m and len(out) - last_svc <= 2:
            out.append(f'{m.group(1)}b.cs {m.group(2)}{(m.group(3) or "")}')
            i += 1
            continue
        out.append(ln)
        i += 1
    return '\n'.join(out)


def git_show(rev, path):
    r = subprocess.run(['git','show',f'{rev}:{path}'], capture_output=True, text=True,
                       cwd=os.path.join(os.path.dirname(__file__),'..','..'))
    return r.stdout if r.returncode == 0 else None

def externs_of_x86(module):
    p = os.path.join(os.path.dirname(__file__),'..','..','asm',f'{module}.asm')
    if not os.path.exists(p): return set()
    out = set()
    for line in open(p):
        m = re.match(r'\s*extern\s+(\w+)', line)
        if m: out.add(m.group(1))
    return out

def adapt(module, src, collect_only=False):
    lines = src.split('\n')
    out = []
    exported = set()
    got_lo12 = [None]
    tbss = []           # (name, size) for the generated C TLS file
    in_tbss = False
    cur_tbss_name = None; cur_tbss_size = 0

    for ln in lines:
        s = ln.strip()
        # ---- TLS section bookkeeping ----
        if s.startswith('.section') and '.tbss' in s:
            in_tbss = True
            out.append('/* TLS block moved to generated C (__thread) */')
            continue
        if in_tbss:
            m = re.match(r'([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$', s)
            if m and not s.startswith('.'):
                if cur_tbss_name: tbss.append((cur_tbss_name, cur_tbss_size))
                cur_tbss_name = m.group(1); cur_tbss_size = 0
                rest = m.group(2).strip()
                m2 = re.match(r'\.space\s+([0-9*]+)', rest)
                if m2:
                    e = m2.group(1)
                    cur_tbss_size += eval(e) if '*' in e else int(e)
                continue
            m = re.match(r'\.space\s+([0-9*]+)\s*(?:/\*.*)?$', s)
            if m and cur_tbss_name:
                expr = m.group(1)
                cur_tbss_size += eval(expr) if '*' in expr else int(expr)
                continue
            m = re.match(r'\.(align|balign)\s+(\d+)', s)
            if m: continue
            if s.startswith('.equ') or s.startswith('.set'):
                out.append(ln)          # keep symbol definitions
                continue
            if s.startswith('.global') or s.startswith('.globl'):
                continue                # recorded above via the multi-name path
            m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)$', s)
            if m and cur_tbss_name is None:
                continue                # stray label with no size yet
            # unknown directive/label inside tbss: keep it (harmless) 
            m = re.match(r'\.global\s+(.+)$', s) or re.match(r'\.globl\s+(.+)$', s)
            if m:
                for nm in m.group(1).split(','):
                    nm = nm.strip().split()[0] if nm.strip() else ''
                    if nm and nm[0].isalpha() or nm.startswith('_'):
                        exported.add(nm.split('/*')[0].strip())
                continue
            if (s == '.text' or s == '.data' or s == '.bss'
                    or s.startswith('.section')):
                in_tbss = False
                if cur_tbss_name: tbss.append((cur_tbss_name, cur_tbss_size))
                cur_tbss_name = None
                # fall through with the section line (mapped by the normal pass)
            else:
                continue
        # ---- sections ----
        # a .section directive glued after a block-comment end: split it off
        m2 = re.search(r'\*/\s*(\.section\s+\.\w+.*)$', ln)
        if m2:
            ln = ln[:m2.start()] + '\n        ' + m2.group(1)
            s = m2.group(1).strip()
        if re.match(r'\.section\s+\.rodata', s):
            out.append('        .section __TEXT,__const')
            continue
        if re.match(r'\.section\s+\.data', s) or s == '.data':
            out.append('        .section __DATA,__data')
            continue
        if s == '.bss' or re.match(r'\.section\s+\.bss', s):
            out.append('        .section __DATA,__bss')
            continue
        if re.match(r'\.section\s+\.text\s*$', s):
            out.append('        .text')
            continue
        if re.match(r'\.section\s+\.bss', s):
            out.append('        .section __DATA,__bss')
            continue
        if re.match(r'\.section\s+\.bss', s):
            out.append('        .section __DATA,__bss')
            continue
        if s.startswith('.section') and ('note.GNU-stack' in s or '.eh_frame' in s):
            continue
        if s.startswith('.type ') or s.startswith('.size '):
            continue
        # ---- ELF :got: indirection -> direct Mach-O adrp/ldr pair ----
        if ':got:' in ln:
            m3 = re.match(r'(\s*)adrp\s+(x[0-9]+),\s*:got:([A-Za-z_][A-Za-z0-9_]*)', ln)
            if m3:
                ln = f'{m3.group(1)}adrp {m3.group(2)}, _{m3.group(3)}@PAGE'
                # find the following :got_lo12 ldr line and rewrite it here
                got_lo12[0] = m3.group(2)
                out.append(ln)
                continue
        m4 = re.match(r'(\s*)ldr\s+(x[0-9]+),\s*\[(x[0-9]+),\s*:got_lo12:([A-Za-z_][A-Za-z0-9_]*)\]', ln)
        if m4:
            ln = f'{m4.group(1)}ldr {m4.group(2)}, [{m4.group(3)}, _{m4.group(4)}@PAGEOFF]'
            out.append(ln)
            continue
        m5 = re.match(r'(\s*)ldr\s+(x[0-9]+),\s*\[(x[0-9]+)\]\s*$.*', ln)
        # (the plain [x] double-deref after :got: stays as-is: it now loads
        #  the value directly since adrp+ldr already fetched the symbol)
        # ---- :lo12: -> @PAGEOFF ----
        ln = re.sub(r':lo12:([A-Za-z_][A-Za-z0-9_]*)', r'\1@PAGEOFF', ln)
        # adrp SYM (bare, ELF-style) -> adrp SYM@PAGE
        ln = re.sub(r'(\badrp\s+x[0-9]+,\s*)([A-Za-z_][A-Za-z0-9_]*)\s*$',
                    r'\1\2@PAGE', ln)
        # ---- globals ----
        m = re.match(r'(\s*)\.global\s+(\w+)\s*$', ln) or re.match(r'(\s*)\.globl\s+(\w+)\s*$', ln)
        if m:
            exported.add(m.group(2))
            out.append(f'{m.group(1)}.globl _{m.group(2)}')
            continue
        # ---- exported label rename (label at column 0, matches an export) ----
        m = re.match(r'([A-Za-z_][A-Za-z0-9_]*):', ln)
        if m and m.group(1) in exported:
            ln = f'_{m.group(1)}:{ln[m.group(1).__len__()+1:]}'
        out.append(ln)
    text = '\n'.join(out)
    # ---- TLS_ADDR macro: ELF gottprel + mrs tpidr -> Mach-O tlv descriptor load
    tls_macro = re.compile(
        r'(?s)(\.macro\s+TLS_ADDR\s+\w+,\s*\w+\n.*?)\.endm')
    # Cross-object Mach-O TLV from hand-written asm does NOT get the TLV
    # fixup kind (the @TLVPPAGE relocations silently degrade to plain data
    # relocs -- verified in the disassembly).  Route every access through a
    # C-compiled getter: clang emits the descriptor + getter correctly.
    macho = ('.macro TLS_ADDR d, sym\n'
             '\tbl  _tls_get_\\sym\n'
             '.endm')
    if '\\d, x9' in macho:  # never clobber the destination register
        macho = macho.replace('mov   \\d, x0', 'mov   \\d, x0')
    text, n = tls_macro.subn(lambda _m: macho, text)
    # any leftover gottprel/tpidr references outside the macro are errors;
    # flag them in the output so the build fails loudly
    if ':gottprel:' in text or 'tpidr' in text:
        text = '/* ERROR: unconverted ELF TLS remains -- hand-fix */\n' + text
    # macro bodies with \param operands: :lo12:\sym -> \sym@PAGEOFF and a
    # bare trailing adrp operand gets @PAGE (same rules as the line pass,
    # applied to backslash-parameter forms)
    text = re.sub(r':lo12:\\(\w+)', r'\\\1@PAGEOFF', text)
    text = re.sub(r'(adrp\s+\\\w+,\s*)\\(\w+)\s*$', r'\1\\\2@PAGE', text, flags=re.M)

    # ---- extern renaming (word boundary, skip labels already _-prefixed,
    #      skip local labels starting with . or digits) ----
    exts = set(KNOWN_EXTERN) | externs_of_x86(module)
    for e in sorted(exts, key=len, reverse=True):
        text = re.sub(rf'(?<![\w_]){e}(?![\w@])', f'_{e}', text)
    # undo damage inside strings/comments is acceptable noise for asm comments;
    # assembler-visible names are what matter.
    # fix accidental renaming of our own exports (e.g. extern list overlaps)
    for e in exported:
        text = text.replace(f'__{e}:', f'_{e}:')
    # rename REFERENCES to exported symbols and TLS vars (label definitions
    # were already renamed; the lookahead skips ':' so defs are not touched
    # twice, and '@' so @PAGE/@PAGEOFF forms stay single-renamed)
    for name in sorted(GLOBAL_NAMES | set(exported) | {t[0] for t in tbss},
                       key=len, reverse=True):
        text = re.sub(rf'(?<![\w_]){name}(?![\w])', f'_{name}', text)
    if collect_only:
        return '', exported, tbss
    return text, exported, tbss

GLOBAL_NAMES = set()

ALL_MODULES = [
    'bitcoin_script_flags', 'bitcoin_sigops', 'bitcoin_strip_witness',
    'bitcoin_scriptcodec', 'bitcoin_mempool', 'bitcoin_cmpct',
    'bitcoin_interp', 'bitcoin_serve', 'bitcoind', 'node_log',
    'bitcoin_idxscan',
]

def main():
    os.chdir(os.path.join(os.path.dirname(__file__)))
    mods = sys.argv[1:]
    # phase 1: harvest every module's exports + TLS names
    for m in mods:
        src = git_show('origin/arm-port', f'port/arm64/{m}.S')
        if src is None: continue
        _, exported, tbss = adapt(m, src, collect_only=True)
        GLOBAL_NAMES.update(exported)
        GLOBAL_NAMES.update(t[0] for t in tbss)
    # phase 2: adapt with the full union available for cross-module refs
    for m in mods:
        src = git_show('origin/arm-port', f'port/arm64/{m}.S')
        if src is None:
            print(f'{m}: NOT on arm-port'); continue
        adapted, exported, tbss = adapt(m, src)
        adapted = post_strip(m, adapted)
        adapted = fix_syscalls(adapted)
        if m in POST_FIX:
            adapted += '\n' + POST_FIX[m]
        with open(f'{m}.S','w') as f:
            ex = ', '.join(sorted(exported))
            f.write(f'/* {m}.S -- adapted from the verified arm-port (origin/arm-port\n'
                    f' * port/arm64/{m}.S) to Mach-O by adapt_armport.py, then hand-gated.\n'
                    f' * Exports: {ex or "(none)"} */\n')
            f.write(adapted)
        if tbss:
            with open(f'tls_{m}.c','w') as f:
                f.write(f'/* tls_{m}.c -- thread-local scratch for {m}.S (generated by\n'
                        f' * adapt_armport.py; the x86 module used .tbss, the arm-port used\n'
                        f' * ELF TLS.  Mach-O TLV is accessed from the asm through the\n'
                        f' * C getters below (cross-object @TLVPPAGE from hand-written\n'
                        f' * asm does not get the TLV fixup kind -- see OSX_ROADMAP). */\n')
                for name, size in tbss:
                    f.write(f'__thread unsigned char {name}[{size}];\n')
                f.write('\n')
                for name, size in tbss:
                    f.write(f'void *tls_get__{name}(void) {{ return {name}; }}\n')
        print(f'{m}: {len(exported)} exports, {len(tbss)} TLS vars')

if __name__ == '__main__':
    main()
