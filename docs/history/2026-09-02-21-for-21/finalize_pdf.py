#!/usr/bin/env python3
"""Stage 3: clean TOC, two-level outline, deduped full-line clickable links."""
import pymupdf, re, difflib, shutil
SRC='book_base.pdf'; OUT='21_FOR_21_the_report.pdf'
d=pymupdf.open(SRC)

def norm(s): return re.sub(r'\s+',' ',s).strip().lower()

# 1) collect entry texts from TOC pages (title + printed page number), then drop ALL links
toc_texts={}
for pno in (1,2,3):
    page=d[pno]
    words=page.get_text('words')
    rows={}
    for w in words:
        yb=round((w[1]+w[3])/2/4)*4
        rows.setdefault(yb,[]).append(w)
    ys=sorted(rows); i=0
    ent=[]
    while i<len(ys):
        ws=sorted(rows[ys[i]],key=lambda w:w[0]); text=' '.join(w[4] for w in ws)
        m=re.search(r'(\d{1,2})$',text)
        title=None; num=None; cover=[i]
        if m and re.match(r'^(PART |Chapter |Epilogue|WHAT WE LEARNED|Appendix )',text):
            num=int(m.group(1)); title=re.sub(r'(\s*·+\s*\d{1,2}|[\s.]*\d{1,2})$','',text).strip(' .·—')
        elif re.match(r'^(PART |Chapter |Epilogue|WHAT WE LEARNED|Appendix )',text) and i+1<len(ys):
            nxt=' '.join(w[4] for w in sorted(rows[ys[i+1]],key=lambda w:w[0]))
            m2=re.search(r'(\d{1,2})$',nxt)
            cont=re.sub(r'(\s*·+\s*\d{1,2}|[\s.]*\d{1,2})$','',nxt).strip(' .·—')
            if m2 and not re.match(r'^(PART |Chapter |Epilogue|WHAT WE LEARNED|Appendix )',cont):
                num=int(m2.group(1)); title=(text.strip(' .·—')+((' '+cont) if cont else '')); cover=[i,i+1]
        if num is not None and title:
            rect=pymupdf.Rect(min(w[0] for w in [x for r in cover for x in rows[ys[r]]]),
                              min(w[1] for w in [x for r in cover for x in rows[ys[r]]]),
                              page.rect.x1-36,
                              max(w[3] for w in [x for r in cover for x in rows[ys[r]]]))
            ent.append((title,num,rect))
            i=cover[-1]+1; continue
        i+=1
    toc_texts[pno]=ent

# 2) body outline entries (clean titles/pages) from weasy's auto outline
auto=d.get_toc()
def is_top(t): return t.startswith(('PART ','Epilogue','Appendix','WHAT WE LEARNED','CHAPTER THE MODELS'))
# title/dates that leak into the outline as top-level: treat as junk below
def is_junk(t):
    tl=t.strip()
    return (tl.startswith('21 FOR') or tl in ('21 DAYSRAW BITCOIN','Contents')
            or tl.startswith('RAW BITCOIN') or tl.startswith('Prologue:')
            or tl.startswith('21 Days'))
entries=[[1 if is_top(t) else 2,t,p] for l,t,p in auto if not is_junk(t)]
d.set_toc(entries)
d.set_metadata({'title':'21 FOR 21 — the Bitcoin Machine Code post-mortem; 21 days, 21 million sats, zero human lines',
                'author':'The Bitcoin Machine Code project',
                'subject':'Post-mortem: a Bitcoin node in 100% AI-authored x86-64 assembly'})

# 3) DELETE all existing links on TOC pages (weasy's partial/dup garbage)
for pno in (1,2,3):
    page=d[pno]
    for l in page.get_links():
        page.delete_link(l)

# 4) re-add ONE full-line link per TOC entry, matched fuzzily to outline targets
added=0; missed=[]
for pno,ent in toc_texts.items():
    page=d[pno]
    for title,num,rect in ent:
        best=None
        for lvl,t,p in entries:
            r=difflib.SequenceMatcher(None,norm(title),norm(t)).ratio()
            # prefer same page target; tie-break by similarity
            score=r+(0.15 if p==num else 0)
            if best is None or score>best[0]: best=(score,r,t,p)
        if best and best[1]>0.5:
            page.insert_link({'kind':pymupdf.LINK_GOTO,'from':rect,'page':best[3]-1,
                              'to':pymupdf.Point(rect.x0,rect.y0)})
            added+=1
        else:
            missed.append(title[:60])
print('outline:',len(entries),'| clickable TOC links:',added,'| missed:',missed)
d.save('tmp.pdf',garbage=3,deflate=True); shutil.move('tmp.pdf',OUT)
