import re,sys,glob,os
root='/home/user/wt/audit5'
files=[f for pat in ('crates/*/tests/*.rs','bins/*/tests/*.rs','crates/*/src/**/*.rs','bins/*/src/**/*.rs','crates/*/tests/**/*.rs') for f in glob.glob(os.path.join(root,pat),recursive=True)]
files=sorted(set(files))
guard=re.compile(r'geteuid|getuid\(\)|is_root\(\)|skip_unless_root|needs_root|require_root|as_root|running_as_root')
for f in files:
    src=open(f).read()
    if not guard.search(src): continue
    # split into fns
    lines=src.split('\n')
    cur=None; istest=False; out=[]
    fn_re=re.compile(r'^\s*(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?fn\s+([a-zA-Z0-9_]+)')
    pending_test=False
    fns={}
    for i,l in enumerate(lines):
        if re.search(r'#\[(tokio::)?test',l): pending_test=True
        m=fn_re.match(l)
        if m:
            cur=m.group(1); fns[cur]=dict(test=pending_test,lines=[],start=i+1); pending_test=False
        if cur: fns[cur]['lines'].append(l)
    helpers={n for n,d in fns.items() if not d['test'] and guard.search('\n'.join(d['lines']))}
    for n,d in fns.items():
        if not d['test']: continue
        body='\n'.join(d['lines'])
        hit=[h for h in helpers if re.search(r'\b'+h+r'\(',body)]
        direct=guard.search(body)
        if hit or direct:
            # classify sense
            sense=''
            if re.search(r'!=\s*0|!is_root\(\)|skip_unless_root|!running',body): sense='ROOT-ONLY?'
            if re.search(r'==\s*0\s*\{|if is_root\(\)\s*\{',body): sense+=' NONROOT-ONLY?'
            pr='prints' if re.search(r'e?println!\([^)]*(skip|need|root|requires)',body,re.I|re.S) or any(re.search(r'e?println!',' '.join(fns[h]['lines'])) for h in hit) else 'SILENT?'
            print(f"{os.path.relpath(f,root)}:{d['start']} {n} via={','.join(hit) or 'direct'} {sense} {pr}")
