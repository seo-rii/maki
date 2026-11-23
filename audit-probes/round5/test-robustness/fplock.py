import re,glob,os
root='/home/user/wt/audit5'
for f in sorted(glob.glob(root+'/crates/*/tests/*.rs')+glob.glob(root+'/bins/*/tests/*.rs')):
    src=open(f).read()
    if 'failpoints' not in src: continue
    lines=src.split('\n'); fns={}; cur=None; pending=False
    fn_re=re.compile(r'^\s*(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?fn\s+([a-zA-Z0-9_]+)')
    for l in lines:
        if re.search(r'#\[(tokio::)?test',l): pending=True
        m=fn_re.match(l)
        if m and not l.startswith('        '):
            cur=m.group(1); fns[cur]=dict(test=pending,body=[]); pending=False
        if cur: fns[cur]['body'].append(l)
    for d in fns.values(): d['src']='\n'.join(d['body'])
    def trans(pred):
        res={n for n,d in fns.items() if pred(d['src'])}
        changed=True
        while changed:
            changed=False
            for n,d in fns.items():
                if n in res: continue
                if any(re.search(r'\b'+h+r'\s*\(',d['src']) for h in res):
                    res.add(n); changed=True
        return res
    arms=trans(lambda s: re.search(r'failpoints::(set|fail_n_times)\b|[^:]\bfail_n_times\(|FailpointAction',s) is not None)
    locks=trans(lambda s: 'test_lock' in s)
    tests=[n for n,d in fns.items() if d['test']]
    arming=[t for t in tests if t in arms]
    unlocked=[t for t in tests if t not in locks]
    if arming and unlocked:
        names=sorted(set(re.findall(r'"((?:store|journal|checkpoint|discard)\.[a-z_.]+)"',src)))
        print(f"{os.path.relpath(f,root)}: tests={len(tests)} arming={len(arming)} WITHOUT_LOCK={len(unlocked)}")
        print("    failpoints armed in file:",names)
        print("    unlocked tests:",unlocked[:12])
