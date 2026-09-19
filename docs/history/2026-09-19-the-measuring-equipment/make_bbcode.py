#!/usr/bin/env python3
"""THE_MEASURING_EQUIPMENT.md -> bitcointalk BBCode, whole and split into posts.

Uses only tags bitcointalk (SMF) renders, as the project's earlier forum posts
do: [size=Npt], [b], [i], [tt], [quote], [code], [hr], [list]/[li],
[list type=decimal], [table]/[tr]/[td], [url]. No [h2]/[h3]: SMF prints those
literally. Rerun after editing the .md (for instance once the [[PENDING]]
figures are filled in):  python3 make_bbcode.py
"""
import re, sys, os

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, 'THE_MEASURING_EQUIPMENT.md')
OUT = os.path.join(HERE, 'THE_MEASURING_EQUIPMENT.bbcode')
POST_LIMIT = 60000          # bitcointalk refuses posts over 64,000 characters; keep a margin

md = open(SRC, encoding='utf-8').read()
lines = md.split('\n')
n = len(lines)

def inline(t):
    t = t.strip()
    t = re.sub(r'`([^`]+)`', r'[tt]\1[/tt]', t)
    t = re.sub(r'\*\*([^*]+)\*\*', r'[b]\1[/b]', t)
    t = re.sub(r'<(https?://[^>]+)>', r'[url=\1]\1[/url]', t)
    t = re.sub(r'(\[\[PENDING[^\]]*\]\])', r'[b]\1[/b]', t)
    return t

HEAD_UPPER = re.compile(r'^(PROLOGUE|PART [IVX]+|APPENDIX [A-Z]):')
HEAD_DUP = re.compile(r'^(Prologue|Part [IVX]+|Appendix [A-Z]): ')
CHAPTER = re.compile(r'^Chapter \d+: ')
BLOCK_START = re.compile(r'^(- |\d+\. |\||    |=+$|Chapter \d+: |<!--)')

blocks = []          # (kind, text); kind 'part' marks a split point
parts_toc = []
i = 0
# title and subtitle
blocks.append(('title', '[size=16pt][b]' + inline(lines[0]) + '[/b][/size]\n[i]' + inline(lines[1]) + '[/i]'))
i = 2
while i < n:
    ln = lines[i]; st = ln.strip()
    if not st or re.match(r'^=+$', st):
        i += 1; continue
    if st == '<!--TOC-->':
        blocks.append(('toc', None)); i += 1; continue
    if HEAD_UPPER.match(st):
        parts_toc.append(st)
        blocks.append(('part', '[hr]\n[size=14pt][b]' + inline(st) + '[/b][/size]'))
        i += 1
        # the book repeats each heading in title case for its PDF bookmarks: drop it
        while i < n and (not lines[i].strip() or re.match(r'^=+$', lines[i].strip())):
            i += 1
        if i < n and HEAD_DUP.match(lines[i].strip()):
            i += 1
        continue
    if CHAPTER.match(st):
        blocks.append(('h', '[size=12pt][b]' + inline(st) + '[/b][/size]')); i += 1; continue
    if st.startswith('|'):
        rows = []
        while i < n and lines[i].strip().startswith('|'):
            r = lines[i].strip()
            if not re.match(r'^\|[\s:|-]+\|$', r):
                rows.append([c.strip() for c in r.strip('|').split('|')])
            i += 1
        out = ['[table]']
        for k, r in enumerate(rows):
            cells = ''.join('[td]' + ('[b]' + inline(c) + '[/b]' if k == 0 and c else inline(c)) + '[/td]' for c in r)
            out.append('[tr]' + cells + '[/tr]')
        out.append('[/table]')
        blocks.append(('table', '\n'.join(out))); continue
    if ln.startswith('    '):
        buf = []
        while i < n and (lines[i].startswith('    ') or (not lines[i].strip() and i + 1 < n and lines[i + 1].startswith('    '))):
            if lines[i].strip():
                buf.append(lines[i][4:])
            i += 1
        if not any('"' in b for b in buf):           # log excerpts, not quotations
            blocks.append(('code', '[code]' + '\n'.join(b.rstrip() for b in buf) + '[/code]')); continue
        out = []
        for b in buf:
            s = b.strip()
            if s.startswith('--'):
                out.append('[i]' + inline(s) + '[/i]')
            elif s.startswith('"') or not out or out[-1].startswith('[i]'):
                out.append(inline(s))
            else:
                out[-1] += ' ' + inline(s)
        blocks.append(('quote', '[quote]' + '\n'.join(out) + '[/quote]')); continue
    m = re.match(r'^(- |\d+\. )', st)
    if m:
        numbered = st[0].isdigit()
        items = []
        while i < n:
            s = lines[i]
            if re.match(r'^(- |\d+\. )', s.strip()) and not s.startswith('    ') and (s.startswith('-') or s[0].isdigit()):
                items.append(re.sub(r'^(- |\d+\. )', '', s.strip()))
            elif s.startswith('  ') and s.strip():
                items[-1] += ' ' + s.strip()
            elif not s.strip() and i + 1 < n and re.match(r'^(- |\d+\. )', lines[i + 1]):
                pass
            else:
                break
            i += 1
        tag = '[list type=decimal]' if numbered else '[list]'
        blocks.append(('list', tag + ''.join('[li]' + inline(it) + '[/li]' for it in items) + '[/list]')); continue
    buf = [st]; i += 1
    while i < n and lines[i].strip() and not BLOCK_START.match(lines[i]) and not HEAD_UPPER.match(lines[i].strip()):
        buf.append(lines[i].strip()); i += 1
    blocks.append(('p', inline(' '.join(buf))))

toc = '[b]Contents[/b]\n[list]' + ''.join('[li]' + inline(p) + '[/li]' for p in parts_toc) + '[/list]'
rendered = [(k, toc if k == 'toc' else t) for k, t in blocks]
whole = '\n\n'.join(t for _, t in rendered) + '\n'
open(OUT, 'w', encoding='utf-8').write(whole)

# split at part boundaries into posts under POST_LIMIT: group the blocks into
# sections (each starts at a part heading), then pack whole sections into posts
sections = []
for k, t in rendered:
    if k == 'part' or not sections:
        sections.append([])
    sections[-1].append(t)
def size(bs): return len('\n\n'.join(bs))
# as few posts as the limit allows, filled evenly rather than front-loaded
import math
total = size([t for sec in sections for t in sec])
target = total / math.ceil(total / (POST_LIMIT - 400))
posts, cur = [], []
for sec in sections:
    if size(sec) > POST_LIMIT - 400:
        sys.exit('a single part exceeds the post limit; split it by chapter')
    if cur and (size(cur + sec) > POST_LIMIT - 400 or size(cur) >= target * 0.97):
        posts.append(cur); cur = []
    cur += sec
posts.append(cur)
N = len(posts)
for f in os.listdir(HERE):
    if re.match(r'THE_MEASURING_EQUIPMENT_post\d+of\d+\.bbcode$', f):
        os.remove(os.path.join(HERE, f))
for p, bs in enumerate(posts, 1):
    body = '\n\n'.join(bs)
    if p > 1:
        body = f'[size=16pt][b]THE MEASURING EQUIPMENT[/b][/size] [i](part {p} of {N})[/i]\n\n' + body
    if p < N:
        body += f'\n\n[hr]\n[i]Continued in the next post ({p + 1} of {N}).[/i]'
    path = os.path.join(HERE, f'THE_MEASURING_EQUIPMENT_post{p}of{N}.bbcode')
    open(path, 'w', encoding='utf-8').write(body + '\n')
    print(f'{os.path.basename(path)}: {len(body):,} chars')
print(f'{os.path.basename(OUT)}: {len(whole):,} chars, {whole.count("[quote]")} quotes, '
      f'{whole.count("[table]")} tables, {whole.count("[list")} lists, {whole.count("[b][[PENDING")} PENDING')
# sanity: every opening tag closes
for tag in ('b', 'i', 'tt', 'quote', 'code', 'table', 'tr', 'td', 'li', 'size', 'url'):
    o = len(re.findall(r'\[' + tag + r'(=[^\]]*)?\]', whole)); c = whole.count('[/' + tag + ']')
    if o != c:
        print(f'UNBALANCED [{tag}]: {o} open, {c} close')
lo = len(re.findall(r'\[list( type=decimal)?\]', whole)); lc = whole.count('[/list]')
if lo != lc:
    print(f'UNBALANCED [list]: {lo} open, {lc} close')
