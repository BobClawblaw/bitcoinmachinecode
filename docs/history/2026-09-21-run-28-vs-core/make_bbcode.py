#!/usr/bin/env python3
"""RUN28_VS_CORE.md -> bitcointalk BBCode.

Only tags bitcointalk (SMF) renders: [size=Npt], [b], [i], [tt], [quote],
[hr], [list]/[li], [table]/[tr]/[td]. SMF prints [h2]/[h3] literally, so
headings become sized bold text. Rerun after editing the .md:
    python3 make_bbcode.py
"""
import os, re

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, 'RUN28_VS_CORE.md')
OUT = os.path.join(HERE, 'RUN28_VS_CORE.bbcode')
POST_LIMIT = 60000          # bitcointalk refuses posts over 64,000 characters

def inline(t):
    t = t.strip()
    t = re.sub(r'`([^`]+)`', r'[tt]\1[/tt]', t)
    t = re.sub(r'\*\*([^*]+)\*\*', r'[b]\1[/b]', t)
    t = re.sub(r'(?<![*\w])\*([^*]+)\*(?![*\w])', r'[i]\1[/i]', t)
    return t

def cells(row):
    return [c.strip() for c in row.strip().strip('|').split('|')]

lines = open(SRC, encoding='utf-8').read().split('\n')
out, i, n = [], 0, len(lines)
while i < n:
    st = lines[i].strip()
    if not st:
        i += 1; continue
    if st.startswith('# '):
        out.append('[size=16pt][b]' + inline(st[2:]) + '[/b][/size]'); i += 1; continue
    if st.startswith('## '):
        out.append('[hr]\n[size=12pt][b]' + inline(st[3:]) + '[/b][/size]'); i += 1; continue
    if st.startswith('|'):
        rows = []
        while i < n and lines[i].strip().startswith('|'):
            r = cells(lines[i])
            if not all(re.fullmatch(r':?-+:?', c) for c in r):
                rows.append(r)
            i += 1
        tb = ['[table]']
        for k, r in enumerate(rows):
            tds = ''.join('[td]' + ('[b]' + inline(c) + '[/b]' if k == 0 and c else inline(c)) + '[/td]' for c in r)
            tb.append('[tr]' + tds + '[/tr]')
        tb.append('[/table]')
        out.append('\n'.join(tb)); continue
    if st.startswith('> '):
        q = []
        while i < n and lines[i].strip().startswith('>'):
            q.append(inline(lines[i].strip().lstrip('>')))
            i += 1
        out.append('[quote]' + '\n'.join(q) + '[/quote]'); continue
    if st.startswith('- '):
        items = []
        while i < n and lines[i].strip():
            s = lines[i].strip()
            if s.startswith('- '):
                items.append(s[2:])
            else:
                items[-1] += ' ' + s
            i += 1
        out.append('[list]' + ''.join('[li]' + inline(t) + '[/li]' for t in items) + '[/list]'); continue
    para = []
    while i < n and lines[i].strip() and not re.match(r'^(#|\||> |- )', lines[i].strip()):
        para.append(lines[i].strip()); i += 1
    out.append(inline(' '.join(para)))

text = '\n\n'.join(out) + '\n'
open(OUT, 'w', encoding='utf-8').write(text)
print(f'{OUT}: {len(text)} characters' + ('' if len(text) <= POST_LIMIT else ' -- OVER ONE POST, split it'))
