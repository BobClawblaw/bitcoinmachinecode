#!/usr/bin/env python3
"""Convert the report md -> bbcode (forum-style), preserving structure."""
import os, re, html

SRC=os.path.join(os.path.dirname(os.path.abspath(__file__)), '21_FOR_21_the_report.md')
OUT=os.path.join(os.path.dirname(os.path.abspath(__file__)), '21_FOR_21_the_report.bbcode')

md=open(SRC).read()

# ---- tokenize into blocks ----
lines=md.split('\n')
i=0; out=[]
def inline(t):
    t=t.strip()
    # bold
    t=re.sub(r'\*\*([^*]+)\*\*', r'[b]\1[/b]', t)
    # italic
    t=re.sub(r'(?<!\[b\])\*([^*\n]+)\*(?!\])', r'[i]\1[/i]', t)
    # inline code
    t=re.sub(r'`([^`]+)`', r'[code]\1[/code]', t)
    # links <url>
    t=re.sub(r'<(https?://[^>]+)>', r'[url=\1]\1[/url]', t)
    return t

n=len(lines)
while i<n:
    ln=lines[i]
    st=ln.strip()
    # code fence
    if st.startswith('```'):
        buf=[]; i+=1
        while i<n and not lines[i].strip().startswith('```'):
            buf.append(lines[i]); i+=1
        i+=1
        out.append('[code]'+'\n'.join(buf)+'[/code]')
        continue
    # blank
    if st=='':
        i+=1; continue
    # separators
    if re.match(r'^=+$', st) or re.match(r'^-+$', st):
        i+=1; continue
    # headings: parts / chapters / epilogue / appendices / prologue
    m=re.match(r'^(PART [IVX]+(: .*)| — .*)$', st) or re.match(r'^(CHAPTER .*)$', st) \
      or re.match(r'^(Epilogue: .*)$', st) or re.match(r'^(Appendix [A-D]: .*)$', st) \
      or re.match(r'^PROLOGUE: (.*)$', st) or re.match(r'^CONTENTS$', st)
    if m or st in ('CONTENTS','Prologue: The Premise') or re.match(r'^Chapter \d+\. ',st):
        # heading block = line + following separator(s)
        text=st
        j=i+1
        while j<n and re.match(r'^=+$|^-+$', lines[j].strip()): j+=1
        level='h2' if re.match(r'^(PART |CHAPTER |Epilogue|Appendix|PROLOGUE|CONTENTS)',st) else 'h3'
        out.append(f'[{level}]{inline(text)}[/{level}]')
        i=j; continue
    # title block (first two lines): 21 FOR 21 + subtitle
    if i==0:
        out.append('[size=200][b]'+inline(st)+'[/b][/size]')
        if i+1<n and lines[i+1].strip():
            out.append('[size=120][i]'+inline(lines[i+1].strip())+'[/i][/size]')
            i+=2
        else:
            i+=1
        continue
    # quote block (4 spaces)
    if ln.startswith('    '):
        buf=[ln[4:]]; j=i+1
        while j<n and lines[j].startswith('    ') and lines[j].strip():
            buf.append(lines[j][4:]); j+=1
        out.append('[quote]'+inline(' '.join(x.strip() for x in buf))+'[/quote]')
        i=j; continue
    # bullet list
    if st.startswith(('- ','* ')):
        items=[]
        cur=[st[2:]]
        j=i+1
        while j<n:
            s2=lines[j]
            if s2.startswith(('- ','* ')):
                items.append(' '.join(x.strip() for x in cur)); cur=[s2.strip()[2:]]
            elif s2.startswith('  ') and s2.strip():
                cur.append(s2.strip())
            elif s2.strip()=='' :
                nxt=lines[j+1] if j+1<n else ''
                if nxt.startswith(('- ','* ')): j+=1; continue
                break
            else: break
        items.append(' '.join(x.strip() for x in cur))
        out.append('\n'.join('[*] '+inline(it) for it in items))
        i=j; continue
    # paragraph: join hard-wrapped lines
    buf=[st]; j=i+1
    while j<n:
        nx=lines[j]
        if not nx.strip(): break
        if nx.startswith(('    ','- ','* ','====','----','```')): break
        s2=nx.strip()
        if re.match(r'^(PART [IVX]+(: .)| — |CHAPTER |Chapter \d+\. |Epilogue: |Appendix [A-D]: |PROLOGUE|CONTENTS$)', s2): break
        buf.append(s2); j+=1
    out.append(inline(' '.join(buf)))
    i=j

open(OUT,'w').write('\n\n'.join(out)+'\n')
print('bbcode written:', OUT)
# sanity: counts
txt=open(OUT).read()
print('size:', len(txt), 'chars | quotes:', txt.count('[quote]'),
      '| h2:', txt.count('[h2]'), '| h3:', txt.count('[h3]'), '| bold:', txt.count('[b]'))
