#!/usr/bin/env python3
"""THE_MEASURING_EQUIPMENT.md -> A4 PDF, styled like "21 FOR 21".

Uses the first report's print stylesheet (/storage/bmc-book/build_book.py) so the
two read as a set: cover, contents with dotted leaders and page numbers, one page
break per part, clickable contents, and a two-level PDF outline (parts,
chapters). Needs python3 + weasyprint + PyMuPDF.   python3 make_pdf.py
"""
import re, html, os, subprocess, sys
import pymupdf

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, 'THE_MEASURING_EQUIPMENT.md')
HTML = os.path.join(HERE, 'THE_MEASURING_EQUIPMENT_print.html')
BASE = os.path.join(HERE, '.base.pdf')
PDF = os.path.join(HERE, 'THE_MEASURING_EQUIPMENT.pdf')

PRINT_CSS = """
@page { size: A4; margin: 22mm 18mm; @bottom-center { content: counter(page); color:#8a8062; font-size:9pt; } }
@page :first { @bottom-center { content: none; } }
body { font-family: ui-monospace, Menlo, Consolas, 'DejaVu Sans Mono', monospace; font-size:10pt; line-height:1.55; color:#2b2415; }
h1.cover { font-size:26pt; letter-spacing:.05em; color:#b46b00; margin-top:40mm; text-align:center; bookmark-level:none; }
p.cover-sub { font-size:12pt; text-align:center; color:#6b5b33; }
p.cover-meta { text-align:center; color:#8a8062; font-size:9pt; margin-top:14mm; }
h2.part { font-size:15pt; color:#b46b00; border-bottom:2px solid #d9c9a3; padding-bottom:4px; margin-top:24px; break-before: page; bookmark-level:1; }
h2.contents { font-size:15pt; color:#b46b00; border-bottom:2px solid #d9c9a3; padding-bottom:4px; bookmark-level:none; }
h3 { font-size:11.5pt; color:#7a5300; margin-top:20px; bookmark-level:2; break-after: avoid; }
p { margin:5px 0; text-align:justify; }
blockquote { border-left:3px solid #f7931a; background:#faf6ec; margin:10px 0 10px 6px; padding:6px 10px; color:#4a3f22; font-size:9.3pt; break-inside: avoid; }
blockquote .src { color:#8a8062; font-style:italic; }
pre { background:#f5efdf; border:1px solid #e3d6b4; padding:8px; font-size:8.6pt; white-space:pre-wrap; word-wrap:break-word; }
.mono { font-family:inherit; background:#f5efdf; padding:0 2px; }
li { margin:3px 0; text-align:justify; }
table { border-collapse:collapse; margin:10px 0; font-size:8.8pt; width:100%; break-inside: avoid; }
th, td { border:1px solid #e3d6b4; padding:3px 6px; text-align:left; vertical-align:top; }
th { background:#f5efdf; color:#7a5300; }
.pending { background:#fde8c4; color:#8a4b00; font-weight:bold; padding:0 2px; }
.pb { break-before: page; }
.toc a { display:block; text-decoration:none; color:#2b2415; margin:2px 0; }
.toc a::after { content: leader('.') target-counter(attr(href), page); color:#8a8062; }
.toc-part { font-weight:bold; color:#b46b00; margin-top:9px; font-size:10.5pt; }
.toc-chap { margin-left:18px; font-size:9pt; }
a { color:#b46b00; }
"""

def slug(s): return re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')[:70]

def inline(t):
    t = html.escape(t.strip(), quote=False)
    spans = []
    def stash(m):
        spans.append(m.group(1)); return '\x00%d\x00' % (len(spans) - 1)
    t = re.sub(r'`([^`]+)`', stash, t)
    t = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', t)
    t = re.sub(r'&lt;(https?://[^&]+)&gt;', r'<a href="\1">\1</a>', t)
    t = re.sub(r'(\[\[PENDING[^\]]*\]\])', r'<span class="pending">\1</span>', t)
    t = re.sub(r'\x00(\d+)\x00', lambda m: '<span class="mono">' + spans[int(m.group(1))] + '</span>', t)
    return t

md = open(SRC, encoding='utf-8').read()
lines = md.split('\n'); n = len(lines)
title, subtitle = lines[0].strip(), lines[1].strip()

HEAD_UPPER = re.compile(r'^(PROLOGUE|PART [IVX]+|APPENDIX [A-Z]):')
HEAD_DUP = re.compile(r'^(Prologue|Part [IVX]+|Appendix [A-Z]): ')
CHAPTER = re.compile(r'^Chapter \d+: ')
BLOCK_START = re.compile(r'^(- |\d+\. |\||    |=+$|Chapter \d+: |<!--)')

front, body = [], []          # intro text before the contents; the report proper
toc = []                       # (level, title, id)
out = front
i = 2
while i < n:
    ln = lines[i]; st = ln.strip()
    if not st or re.match(r'^=+$', st):
        i += 1; continue
    if st == '<!--TOC-->':
        out = body; i += 1; continue
    if HEAD_UPPER.match(st):
        sid = slug(st); toc.append((1, st, sid))
        body.append(f'<h2 class="part" id="{sid}">{inline(st)}</h2>')
        i += 1
        while i < n and (not lines[i].strip() or re.match(r'^=+$', lines[i].strip())): i += 1
        if i < n and HEAD_DUP.match(lines[i].strip()): i += 1
        continue
    if CHAPTER.match(st):
        sid = slug(st); toc.append((2, st, sid))
        out.append(f'<h3 id="{sid}">{inline(st)}</h3>'); i += 1; continue
    if st.startswith('|'):
        rows = []
        while i < n and lines[i].strip().startswith('|'):
            r = lines[i].strip()
            if not re.match(r'^\|[\s:|-]+\|$', r):
                rows.append([c.strip() for c in r.strip('|').split('|')])
            i += 1
        t = ['<table>']
        for k, r in enumerate(rows):
            tag = 'th' if k == 0 else 'td'
            t.append('<tr>' + ''.join(f'<{tag}>{inline(c)}</{tag}>' for c in r) + '</tr>')
        t.append('</table>'); out.append('\n'.join(t)); continue
    if ln.startswith('    '):
        buf = []
        while i < n and (lines[i].startswith('    ') or (not lines[i].strip() and i + 1 < n and lines[i + 1].startswith('    '))):
            if lines[i].strip(): buf.append(lines[i][4:])
            i += 1
        if not any('"' in b for b in buf):
            out.append('<pre>' + html.escape('\n'.join(b.rstrip() for b in buf)) + '</pre>'); continue
        q = []
        for b in buf:
            s = b.strip()
            if s.startswith('--'): q.append('<span class="src">' + inline(s) + '</span>')
            elif s.startswith('"') or not q or q[-1].startswith('<span class="src">'): q.append(inline(s))
            else: q[-1] += ' ' + inline(s)
        out.append('<blockquote>' + '<br>'.join(q) + '</blockquote>'); continue
    if re.match(r'^(- |\d+\. )', st):
        numbered = st[0].isdigit(); items = []
        while i < n:
            s = lines[i]
            if re.match(r'^(- |\d+\. )', s) :
                items.append(re.sub(r'^(- |\d+\. )', '', s.strip()))
            elif s.startswith('  ') and s.strip() and items:
                items[-1] += ' ' + s.strip()
            elif not s.strip() and i + 1 < n and re.match(r'^(- |\d+\. )', lines[i + 1]):
                pass
            else:
                break
            i += 1
        tag = 'ol' if numbered else 'ul'
        out.append(f'<{tag}>' + ''.join(f'<li>{inline(it)}</li>' for it in items) + f'</{tag}>'); continue
    buf = [st]; i += 1
    while i < n and lines[i].strip() and not BLOCK_START.match(lines[i]) and not HEAD_UPPER.match(lines[i].strip()):
        buf.append(lines[i].strip()); i += 1
    out.append('<p>' + inline(' '.join(buf)) + '</p>')

toc_html = ''.join(
    f'<a class="{"toc-part" if lvl == 1 else "toc-chap"}" href="#{sid}">{inline(t)}</a>' for lvl, t, sid in toc)
doc = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{html.escape(title)}</title><style>{PRINT_CSS}</style></head><body>
<h1 class="cover">{inline(title)}</h1>
<p class="cover-sub">{inline(subtitle)}</p>
<p class="cover-meta">A follow-up to "21 FOR 21"<br>Bitcoin Machine Code &nbsp;·&nbsp;
<a href="https://github.com/BobClawblaw/bitcoinmachinecode">github.com/BobClawblaw/bitcoinmachinecode</a></p>
<div class="pb"></div>
{''.join(front)}
<div class="pb"></div>
<h2 class="contents">Contents</h2>
<div class="toc">{toc_html}</div>
{''.join(body)}
</body></html>"""
open(HTML, 'w', encoding='utf-8').write(doc)

r = subprocess.run([sys.executable, '-m', 'weasyprint', HTML, BASE], capture_output=True, text=True)
if r.returncode != 0:
    sys.exit('weasyprint failed:\n' + r.stderr[-3000:])

d = pymupdf.open(BASE)
outline = d.get_toc()
d.set_metadata({'title': title + ' — ' + subtitle,
                'author': 'The Bitcoin Machine Code project',
                'subject': 'A follow-up to "21 FOR 21": Bitcoin Machine Code, 2026-09-02 to 2026-09-19'})
d.save(PDF, garbage=3, deflate=True)
os.remove(BASE)
pend = sum(p.get_text().count('[[PENDING') for p in pymupdf.open(PDF))
print(f'{os.path.basename(PDF)}: {pymupdf.open(PDF).page_count} pages, outline {len(outline)} entries '
      f'({sum(1 for e in outline if e[0] == 1)} parts), {len(toc)} contents links, {pend} PENDING markers')
