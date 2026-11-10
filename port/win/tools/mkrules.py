"""mkrules.py -- read build recipes out of asm/Makefile (bmc_win).

Not a make: enough of GNU make's expansion (variables, the functions the
Makefile uses, $@ $< $^) to recover, for one target, the inputs and the
flags of the $(CC) line that links it, so build.py builds exactly what the
Linux gate builds.
"""
import glob
import os
import re
import shlex


class Makefile:
    def __init__(self, path):
        self.dir = os.path.dirname(os.path.abspath(path))
        text = open(path, encoding='utf-8').read().replace('\\\n', ' ')
        self.vars = {}
        self.rules = {}          # target -> list of (prereqs, recipe lines)
        lines = text.split('\n')
        i = 0
        while i < len(lines):
            ln = lines[i]
            i += 1
            if not ln.strip() or ln.lstrip().startswith('#') or ln.startswith('\t'):
                continue
            m = re.match(r'^([A-Za-z_][A-Za-z0-9_.\-]*)\s*(:=|::=|\?=|\+=|=)\s*(.*)$', ln)
            if m:
                name, op, val = m.groups()
                if op in (':=', '::='):
                    self.vars[name] = ('s', self.expand(val))
                elif op == '?=':
                    self.vars.setdefault(name, ('r', val))
                elif op == '+=':
                    kind, old = self.vars.get(name, ('r', ''))
                    self.vars[name] = (kind, old + ' ' + (self.expand(val) if kind == 's' else val))
                else:
                    self.vars[name] = ('r', val)
                continue
            m = re.match(r'^([^:=#]+?)\s*:(?!=)\s*(.*)$', ln)
            if m:
                targets, prereq = m.group(1), m.group(2)
                recipe = []
                while i < len(lines) and (lines[i].startswith('\t') or not lines[i].strip()):
                    if lines[i].startswith('\t'):
                        recipe.append(lines[i][1:])
                    i += 1
                for t in self.expand(targets).split():
                    self.rules.setdefault(t, []).append((prereq, recipe))

    # ---- expansion ----
    def var(self, name):
        kind, val = self.vars.get(name, ('s', os.environ.get(name, '')))
        return val if kind == 's' else self.expand(val)

    def expand(self, s, auto=None, depth=0):
        if depth > 30 or '$' not in s:
            return s
        out = []
        i = 0
        while i < len(s):
            c = s[i]
            if c != '$':
                out.append(c)
                i += 1
                continue
            if i + 1 >= len(s):
                break
            n = s[i + 1]
            if n == '$':
                out.append('$')
                i += 2
            elif n in '({':
                close = ')' if n == '(' else '}'
                j, lvl = i + 2, 1
                while j < len(s) and lvl:
                    if s[j] == n:
                        lvl += 1
                    elif s[j] == close:
                        lvl -= 1
                    j += 1
                body = s[i + 2:j - 1]
                out.append(self.call(body, auto, depth))
                i = j
            else:
                out.append((auto or {}).get(n, '') if n in '@<^?*' else self.var(n))
                i += 2
        return ''.join(out)

    def _args(self, body):
        args, lvl, cur = [], 0, []
        for ch in body:
            if ch == '(':
                lvl += 1
            elif ch == ')':
                lvl -= 1
            if ch == ',' and lvl == 0:
                args.append(''.join(cur))
                cur = []
            else:
                cur.append(ch)
        args.append(''.join(cur))
        return args

    def call(self, body, auto, depth):
        m = re.match(r'^([a-z\-]+)\s+(.*)$', body, re.S)
        if m and m.group(1) in ('patsubst', 'filter', 'filter-out', 'addsuffix', 'addprefix', 'notdir',
                                'sort', 'subst', 'wildcard', 'shell', 'basename', 'strip', 'dir'):
            fn = m.group(1)
            args = [self.expand(a, auto, depth + 1) for a in self._args(m.group(2))]
            if fn == 'patsubst':
                pat, rep, words = args[0].strip(), args[1].strip(), args[2].split()
                return ' '.join(self._pat(pat, rep, w) for w in words)
            if fn in ('filter', 'filter-out'):
                pats = args[0].split()
                keep = fn == 'filter'
                return ' '.join(w for w in args[1].split() if any(self._match(p, w) for p in pats) == keep)
            if fn == 'addsuffix':
                return ' '.join(w + args[0].strip() for w in args[1].split())
            if fn == 'addprefix':
                return ' '.join(args[0].strip() + w for w in args[1].split())
            if fn == 'notdir':
                return ' '.join(os.path.basename(w) for w in args[0].split())
            if fn == 'dir':
                return ' '.join((os.path.dirname(w) or '.') + '/' for w in args[0].split())
            if fn == 'basename':
                return ' '.join(os.path.splitext(w)[0] for w in args[0].split())
            if fn == 'sort':
                return ' '.join(sorted(set(args[0].split())))
            if fn == 'strip':
                return ' '.join(args[0].split())
            if fn == 'subst':
                return args[2].replace(args[0], args[1])
            if fn == 'wildcard':
                res = []
                for p in args[0].split():
                    res += sorted(os.path.relpath(x, self.dir).replace('\\', '/')
                                  for x in glob.glob(os.path.join(self.dir, p)))
                return ' '.join(res)
            return ''   # $(shell ...): nothing the recipes we read depend on
        name = self.expand(body, auto, depth + 1)
        return self.var(name)

    @staticmethod
    def _match(pat, word):
        if '%' not in pat:
            return pat == word
        a, b = pat.split('%', 1)
        return word.startswith(a) and word.endswith(b) and len(word) >= len(a) + len(b)

    @staticmethod
    def _pat(pat, rep, word):
        if '%' not in pat:
            return rep if word == pat else word
        a, b = pat.split('%', 1)
        if word.startswith(a) and word.endswith(b) and len(word) >= len(a) + len(b):
            stem = word[len(a):len(word) - len(b)]
            return rep.replace('%', stem, 1)
        return word

    # ---- recipes ----
    def link_spec(self, target):
        """{'inputs': [...], 'defines': [...], 'includes': [...], 'wraps': [...], 'forced': [...]}"""
        if target not in self.rules:
            raise KeyError('no Makefile rule for ' + target)
        for prereq, recipe in self.rules[target]:
            pre = self.expand(prereq).split()
            auto = {'@': target, '<': pre[0] if pre else '', '^': ' '.join(dict.fromkeys(pre))}
            for line in recipe:
                if '$(CC)' not in line and '$(SANCC)' not in line:
                    continue
                cmd = self.expand(line, auto)
                try:
                    words = shlex.split(cmd)
                except ValueError:
                    words = cmd.split()
                spec = {'inputs': [], 'defines': [], 'includes': [], 'wraps': [], 'forced': []}
                k = 0
                while k < len(words):
                    w = words[k]
                    if w == '-o':
                        k += 2
                        continue
                    if w.startswith('-D'):
                        spec['defines'].append(w if len(w) > 2 else '-D' + words[k + 1])
                        k += 1 if len(w) > 2 else 2
                        continue
                    if w.startswith('-I'):
                        spec['includes'].append(w[2:] if len(w) > 2 else words[k + 1])
                        k += 1 if len(w) > 2 else 2
                        continue
                    if w == '-include':
                        spec['forced'].append(words[k + 1])
                        k += 2
                        continue
                    if w.startswith('-Wl,'):
                        for part in w[4:].split(','):
                            if part.startswith('--wrap='):
                                spec['wraps'].append(part[7:])
                    elif w.endswith(('.c', '.o', '.a', '.asm', '.S')) and not w.startswith('-'):
                        spec['inputs'].append(w)
                    k += 1
                spec['inputs'] = list(dict.fromkeys(spec['inputs']))
                return spec
        # no $(CC) line: fall back to the prerequisites
        pre = self.expand(self.rules[target][0][0]).split()
        return {'inputs': [p for p in pre if p.endswith(('.c', '.o', '.a', '.asm'))],
                'defines': [], 'includes': [], 'wraps': [], 'forced': []}


def obj_spec(mk, target):
    """How a .o is produced: {'src', 'kind': 'nasm'|'cc', 'defines', 'includes'} or None
    when only the %.o pattern rules apply."""
    for prereq, recipe in mk.rules.get(target, []):
        pre = mk.expand(prereq).split()
        auto = {'@': target, '<': pre[0] if pre else '', '^': ' '.join(pre)}
        for line in recipe:
            kind = 'nasm' if '$(NASM)' in line else 'cc' if ('$(CC)' in line and ' -c' in line) else None
            if not kind:
                continue
            words = mk.expand(line, auto).split()
            srcs = [w for w in words if w.endswith(('.asm', '.c')) and not w.startswith('-')]
            if not srcs:
                continue
            defs, incs = [], []
            for k, w in enumerate(words):
                if w.startswith('-D'):
                    defs.append(w if len(w) > 2 else '-D' + words[k + 1])
                elif w.startswith('-I') and kind == 'cc':
                    incs.append(w[2:] if len(w) > 2 else words[k + 1])
            return {'src': srcs[0], 'kind': kind, 'defines': defs, 'includes': incs}
    return None
