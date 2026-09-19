#!/usr/bin/env python3
# CANONICAL pipeline:  python3 build_book.py && python3 -m weasyprint book_print.html book_base.pdf && python3 finalize_pdf.py
# ALWAYS regenerate from the markdown first (MD is the single source of truth).
"""Build a consistent HTML + print-HTML + bookmarked PDF for
"21 Days Raw Bitcoin" from the markdown source."""
import re, html, os, sys, subprocess, urllib.parse

SRC=os.path.join(os.path.dirname(os.path.abspath(__file__)), '21_FOR_21_the_report.md')
OUT_HTML=os.path.join(os.path.dirname(os.path.abspath(__file__)), '21_FOR_21_the_report.html')
OUT_PRINT=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'book_print.html')
OUT_PDF=os.path.join(os.path.dirname(os.path.abspath(__file__)), '21_FOR_21_the_report.pdf')

md=open(SRC).read()
lines=md.split('\n')
# body starts at the first "Prologue: The Premise" line
body=lines[next(i for i,l in enumerate(lines) if l.strip()=='Prologue: The Premise'):]

def esc(s):
    s=html.escape(s, quote=False)
    s=s.replace('\\*','\x01')
    # extract code spans first so emphasis regexes never see their contents
    spans=[]
    def stash(m):
        spans.append(m.group(1)); return '\x00%d\x00' % (len(spans)-1)
    s=re.sub(r'`([^`]+)`', stash, s)
    s=re.sub(r'\*\*([^*\n]+)\*\*', r'<b>\1</b>', s)
    s=re.sub(r'\*([^*]+?)\*', r'<i>\1</i>', s)
    s=re.sub(r'\x00(\d+)\x00', lambda m: '<span class="mono">'+html.escape(spans[int(m.group(1))])+'</span>', s)
    s=s.replace('\x01','*')
    return s
def slug(s):
    return re.sub(r'[^a-z0-9]+','-',s.lower()).strip('-')[:70]

# ---------- parse into structured blocks ----------
blocks=[]           # (kind, text) kind: part|chapter|appendix|hrrule|blank|p|quote|code|li
parts=[]            # (title, slug)
chapters=[]         # (part_slug or None, title, slug)
i=0
cur_part=None
while i<len(body):
    ln=body[i]
    if ln.strip().startswith('```'):
        buf=[]; i+=1
        while i<len(body) and not body[i].strip().startswith('```'):
            buf.append(body[i]); i+=1
        i+=1
        blocks.append(('code','\n'.join(buf))); continue
    if ln.startswith('===='): i+=1; continue
    if ln.startswith('----'):
        blocks.append(('hr','')); i+=1; continue
    # swallow separators that immediately follow a heading (==== / ----)
    m=re.match(r'^(PART [IVX]+(: .*)| — .*|CHAPTER .*)$', ln.strip())
    if m and ln.strip()!='<!--TOC-->':
        t=m.group(1)
        j=i+1
        while j<len(body) and body[j].startswith(('====','----')): j+=1
        cur_part=slug(t); parts.append((t,cur_part))
        blocks.append(('part',t,cur_part)); i=j; continue
    m=re.match(r'^(Chapter \d+\. .*)$', ln.strip())
    if m:
        s=slug(m.group(1)); chapters.append((cur_part,m.group(1),s))
        blocks.append(('chapter',m.group(1),s)); j=i+1
        while j<len(body) and body[j].startswith(('====','----')): j+=1
        i=j; continue
    st=ln.strip()
    if st=='<!--TOC-->': i+=1; continue
    if st=='— END —':
        blocks.append(('end',st)); i+=1; continue
    if re.match(r'^(Epilogue: |Appendix [A-D]: |CHAPTER: )', st):
        cur=slug(st); parts.append((st,cur))
        blocks.append(('part',st,cur)); i+=1; continue
    mli=re.match(r'^(\d+)\.\s+(.*)$', ln.strip())
    stripped=ln.lstrip(' ')
    indent=len(ln)-len(stripped)
    if indent<=2 and (stripped.startswith('- ') or stripped.startswith('* ')):
        blocks.append(('li',stripped[2:])); i+=1; continue
    if mli:
        # collect multi-line numbered items (continuation lines indented deeper)
        txt=mli.group(2); j=i+1
        while j<len(body):
            nxt=body[j]
            ni=len(nxt)-len(nxt.lstrip())
            if ni>indent and not re.match(r'^\d+\.\s+', nxt.strip()):
                txt+=' '+nxt.strip(); j+=1
            else:
                break
        blocks.append(('numli',(int(mli.group(1)),txt))); i=j; continue
    if ln.strip()=='': i+=1; continue
    if ln.startswith('    '):
        buf=[ln[4:].rstrip()]; j=i+1
        while j<len(body) and body[j].startswith('    ') and not body[j].strip().startswith('```'):
            buf.append(body[j][4:].rstrip()); j+=1
        # heuristic: if the line right after the block is a non-empty, non-list,
        # <4-indent line, the source paragraph was hard-wrapped with the first
        # line indented — render as paragraph, not quote.
        if j<len(body) and body[j].strip() and not body[j].startswith('    ') \
           and not body[j].strip().startswith(('- ','* ','> ','```','====','----')):
            cont=body[j].strip(); j+=1
            blocks.append(('p',(buf[0]+'\n'+ '\n'.join(buf[1:]) + ' ' + re.sub(r'\s+',' ',cont)).replace('\n',' ')))
            i=j; continue
        blocks.append(('quote',' '.join(x.strip() for x in buf))); i=j; continue
    # paragraph: join hard-wrapped continuation lines so the PDF wraps at
    # natural spaces, not the source's forced breaks
    buf=[ln]; j=i+1
    while j<len(body):
        nx=body[j]
        if not nx.strip(): break
        if nx.startswith(('    ','- ','* ','====','----','```')): break
        if re.match(r'^(PART [IVX]+(: .*)| — .*|CHAPTER .*)$', nx.strip()): break
        if re.match(r'^Chapter \d+\. ', nx.strip()): break
        if re.match(r'^\*\*[0-9]\.\*\*', nx.strip()): break
        buf.append(nx.strip()); j+=1
    blocks.append(('p',' '.join(buf))); i=j

def render_blocks():
    out=[]; li=False; ni=False
    def close():
        nonlocal li, ni
        if li: out.append('</ul>'); li=False
        if ni: out.append('</ol>'); ni=False
    for b in blocks:
        k=b[0]
        if k!='li': out.append('</ul>') if li else None; li=False
        if k!='numli': out.append('</ol>') if ni else None; ni=False
        if k=='hr': out.append('<hr class="sub">')
        elif k=='part': out.append(f'<h2 class="part" id="{b[2]}">{esc(b[1])}</h2>')
        elif k=='chapter': out.append(f'<h3 class="chapter" id="{b[2]}">{esc(b[1])}</h3>')
        elif k=='li':
            if not li: out.append('<ul>'); li=True
            out.append(f'<li>{esc(b[1])}</li>')
        elif k=='numli':
            n,txt=b[1]
            if not ni: out.append('<ol>'); ni=True
            out.append(f'<li value="{n}">{esc(txt)}</li>')
        elif k=='p': out.append(f'<p>{esc(b[1])}</p>')
        elif k=='quote': out.append('<blockquote>'+esc(b[1]).replace('\n','<br>')+'</blockquote>')
        elif k=='code': out.append('<pre><code>'+html.escape(b[1])+'</code></pre>')
        elif k=='end': out.append(f'<p class="end">{esc(b[1])}</p>')
    if li: out.append('</ul>')
    return '\n'.join(out)

# ---------- TOC (consistent for both editions): every part + ALL its chapters ----------
def toc_html(*_a, **_k):
    out=[]
    byp={}
    for pslug,ctitle,cs in chapters: byp.setdefault(pslug,[]).append((ctitle,cs))
    singles=[(ct,cs) for ps,ct,cs in chapters if ps is None]
    for ptitle,ps in parts:
        out.append(f'<a class="toc-part" href="#{ps}">{esc(ptitle)}</a>')
        for ctitle,cs in byp.get(ps,[]):
            out.append(f'<a class="toc-chap" href="#{cs}">{esc(ctitle)}</a>')
    for ctitle,cs in singles:
        out.append(f'<a class="toc-chap toc-free" href="#{cs}">{esc(ctitle)}</a>')
    return '\n'.join(out)

# ---------- screen HTML ----------
SCREEN_CSS="""
:root{--bg:#12100c;--fg:#d8cfa8;--acc:#f7931a;--dim:#8a8062}
body{background:var(--bg);color:var(--fg);font-family:ui-monospace,Menlo,Consolas,monospace;
line-height:1.65;max-width:56rem;margin:2.5rem auto;padding:0 1.2rem;font-size:15px}
h1{color:var(--acc)}
h2.part{color:var(--acc);letter-spacing:.05em;margin-top:3rem;border-bottom:1px solid #3a3122;padding-bottom:.3rem}
h3{color:#e8b45a;margin-top:2.2rem}
p{margin:.55rem 0}
blockquote{border-left:3px solid var(--acc);margin:1rem 0 1rem .5rem;padding:.2rem 0 .2rem 1rem;color:#c4b98c;background:#181410}
pre{background:#1c1810;padding:1rem;overflow-x:auto;border:1px solid #2e2718}
code{font-family:inherit;color:#e8dcae}
li{margin:.3rem 0}
hr{border:none;border-top:3px double #3a3122;margin:3rem 0}
hr.sub{border-top:1px solid #2e2718;margin:2rem 0}
.toc{margin:2rem 0;border:1px solid #2e2718;padding:1rem 1.4rem;background:#161310}
.toc a{display:block;text-decoration:none;color:#cfc39a;margin:2px 0}
.toc a:hover{color:var(--acc)}
.toc-part{font-weight:bold;color:var(--acc);margin-top:12px;font-size:15px}
.toc-chap{margin-left:22px;font-size:13px;color:#b3a87f}
nav.top{position:sticky;top:0;background:var(--bg);padding:.4rem 0;border-bottom:1px solid #2e2718;font-size:12px;z-index:5}
nav.top a{color:var(--acc);text-decoration:none}
"""
screen=f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>21 FOR 21 — the report</title>
<style>{SCREEN_CSS}</style></head><body>
<nav class="top"><a href="/">&larr; index</a> &nbsp;·&nbsp; <a href="#contents">Contents</a> &nbsp;·&nbsp; 21 days for 21 million sats · 1,023 commits · zero human lines</nav>
<h1>21 FOR 21</h1>
<p style="color:#e8b45a">Twenty-One Days. Twenty-One Million Sats. Zero Human Lines.</p>
<p class="dim" style="color:#8a8062">The complete post-mortem of the Bitcoin Machine Code experiment —
a full validating Bitcoin node written entirely in AI-authored x86-64 assembly, 2026-08-11 .. 09-02.</p>
<h2 id="contents">Contents</h2>
<div class="toc">
{toc_html(None,False)}
</div>
{render_blocks()}
</body></html>"""
open(OUT_HTML,'w').write(screen)
print('screen html ok')

# ---------- print HTML (with page-number leaders) ----------
PRINT_CSS="""
@page { size: A4; margin: 22mm 18mm; @bottom-center { content: counter(page); color:#8a8062; font-size:9pt; } }
body { font-family: ui-monospace, Menlo, Consolas, 'DejaVu Sans Mono', monospace; font-size:10pt; line-height:1.55; color:#2b2415; }
h1.cover { font-size:28pt; letter-spacing:.05em; color:#b46b00; margin-top:26mm; text-align:center; }
p.cover-sub { font-size:12pt; text-align:center; color:#6b5b33; }
p.cover-meta { text-align:center; color:#8a8062; font-size:9pt; }
h2.part { font-size:15pt; color:#b46b00; border-bottom:2px solid #d9c9a3; padding-bottom:4px; margin-top:24px; break-before: page; }
h3 { font-size:11.5pt; color:#7a5300; margin-top:20px; }
hr.sub { border:none; border-top:1px solid #d9c9a3; margin:14px 0; }
p { margin:5px 0; text-align:justify; }
blockquote { border-left:3px solid #f7931a; background:#faf6ec; margin:10px 0 10px 6px; padding:6px 10px; color:#4a3f22; font-size:9.3pt; }
pre { background:#f5efdf; border:1px solid #e3d6b4; padding:8px; font-size:8.6pt; white-space:pre-wrap; word-wrap:break-word; }
code{font-family:inherit}
li{margin:3px 0}
.pb { break-before: page; }
.toc a { display:block; text-decoration:none; color:#2b2415; margin:2px 0; }
.toc a::after { content: leader('.') target-counter(attr(href), page); color:#8a8062; }
/* bookmarks injected post-hoc in a clean, verified pass */
.toc-part { font-weight:bold; color:#b46b00; margin-top:9px; font-size:11pt; }
.toc-chap { margin-left:18px; font-size:9.5pt; }
a{color:#b46b00}
"""
printable=f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>{PRINT_CSS}</style></head><body>
<div>
<h1 class="cover">21 FOR 21</h1>
<p class="cover-sub">Twenty-One Days &nbsp;·&nbsp; Twenty-One Million Sats &nbsp;·&nbsp; Zero Human Lines<br>The complete post-mortem of the Bitcoin Machine Code experiment</p>
<p class="cover-meta">A full validating Bitcoin node written entirely in AI-authored x86-64 assembly<br>
first vectors 2026-08-11 &nbsp;·&nbsp; 21 days of git history to 2026-09-02</p>
</div>
<div class="pb"></div>
<h2 class="part" style="break-before:avoid">Contents</h2>
<div class="toc">
{toc_html(None,True)}
</div>
<div class="pb"></div>
{render_blocks()}
</body></html>"""
open(OUT_PRINT,'w').write(printable)
print('print html ok')
