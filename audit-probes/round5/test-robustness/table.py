import re,glob,os,sys,json
S='/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness'
pat=re.compile(r'skip|needs root|requires root|need root|unavailable; |not installed',re.I)
def stats(label,pkg):
    d=f'{S}/logs/{label}/{pkg}'
    if not os.path.isdir(d): return None
    p=f=i=s=0
    for lf in glob.glob(d+'/*.log'):
        txt=open(lf,errors='replace').read()
        m=re.search(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored',txt)
        if not m: f+=1; continue
        p+=int(m.group(2)); f+=int(m.group(3)); i+=int(m.group(4))
        status=dict(re.findall(r'^test (\S+)(?: - should panic)? \.\.\. (ok|FAILED|ignored)',txt,re.M))
        for mm in re.finditer(r'^---- (\S+) stdout ----\n(.*?)(?=^---- \S+ stdout ----|^successes:|^failures:)',txt,re.M|re.S):
            if status.get(mm.group(1))=='ok' and pat.search(mm.group(2)): s+=1
    return p,f,i,s
pkgs="maki-backing maki-cache maki-control maki-core maki-crypto maki-crypto-grpc maki-crypto-http maki-crypto-local maki-crypto-websocket maki-format maki-nbdkit maki-privileged maki-test-support maki-witness maki maki-attach maki-benchmark maki-check maki-witness-cli".split()
labels=sys.argv[1:]
print('| crate | '+' | '.join(labels)+' |'); print('|---|'+'---|'*len(labels))
tot={l:[0,0,0,0] for l in labels}
for p in pkgs:
    row=[]
    for l in labels:
        st=stats(l,p)
        if st is None: row.append('-'); continue
        for k in range(4): tot[l][k]+=st[k]
        row.append(f'{st[0]}/{st[1]}/{st[3]}' + (f' (+{st[2]} ign)' if st[2] else ''))
    print(f'| {p} | '+' | '.join(row)+' |')
print('| **total** | '+' | '.join(f'{tot[l][0]}/{tot[l][1]}/{tot[l][3]} (+{tot[l][2]} ign)' for l in labels)+' |')
