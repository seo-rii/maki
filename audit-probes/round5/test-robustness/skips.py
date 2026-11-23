import re,glob,os,sys
S='/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness'
def parse(label):
    res={}
    for f in glob.glob(f'{S}/logs/{label}/*/*.log'):
        pkg=f.split('/')[-2]; binn=os.path.basename(f).split('.')[0]
        txt=open(f,errors='replace').read()
        status=dict(re.findall(r'^test (\S+)(?: - should panic)? \.\.\. (ok|FAILED|ignored)',txt,re.M))
        outs={}
        for m in re.finditer(r'^---- (\S+) stdout ----\n(.*?)(?=^---- \S+ stdout ----|^successes:|^failures:)',txt,re.M|re.S):
            outs[m.group(1)]=m.group(2).strip()
        for t,s in status.items():
            res[(pkg,binn,t)]=(s,outs.get(t,''))
    return res
pat=re.compile(r'skip|needs root|requires root|need root|unavailable|not available|cannot |unsupported|not supported',re.I)
lab=sys.argv[1]
r=parse(lab)
n=0
for k in sorted(r):
    s,o=r[k]
    hits=[l for l in o.split('\n') if pat.search(l)]
    if hits and s=='ok':
        n+=1
        print(f'{k[0]}/{k[1]}::{k[2]}\n      {hits[0][:170]}')
print('total tests',len(r),'skip-like passes',n, file=sys.stderr)
