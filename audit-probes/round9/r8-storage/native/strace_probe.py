import nbd, mk, time, os, random, subprocess
v = mk.Vol("st", discard=True)
try:
    v.create()
    out = os.path.join(v.dir, "strace.out")
    v.start(wrapper=["strace", "-f", "-qq", "-o", out, "-e", "trace=!futex,epoll_wait,epoll_pwait,sched_yield,madvise,mprotect,mmap,munmap,brk,clock_gettime,poll,ppoll,read,recvfrom,sendto,recvmsg,sendmsg,rt_sigprocmask,rt_sigaction,getrandom,nanosleep,clock_nanosleep,epoll_ctl,eventfd2,sigaltstack,set_robust_list,rseq,prctl,gettid,getpid,clone3,clone,exit,mlock,munlock,restart_syscall,accept4,accept,close"])
    h = nbd.NBD(); h.set_strict_mode(0); h.connect_unix(v.sock)
    rng = random.Random(1)
    for i in range(400):
        off = rng.randrange(0, 900) * 4096
        k = rng.random()
        if k < 0.6: h.pwrite(mk.pattern(off, 8192, i+1), off, nbd.CMD_FLAG_FUA if rng.random()<0.2 else 0)
        elif k < 0.75: h.trim(65536, off)
        elif k < 0.85: h.zero(16384, off)
        else: h.flush()
    subprocess.run([mk.MAKI, "checkpoint", v.cfg], capture_output=True)
    h.shutdown()
    v.term()
    import collections, re
    c = collections.Counter()
    for line in open(out):
        m = re.match(r"\d+\s+(\w+)\(", line)
        if m: c[m.group(1)] += 1
    print(sorted(c.items(), key=lambda x: -x[1]))
    # show examples of the less common ones
    seen = set()
    for line in open(out):
        m = re.match(r"\d+\s+(\w+)\(", line)
        if m and m.group(1) not in seen and m.group(1) not in ("pwrite64","pread64","fdatasync","fsync","write","statx","fstat","newfstatat","openat","lseek","fcntl","ioctl","getdents64","statfs","fstatfs"):
            seen.add(m.group(1)); print(line.strip()[:200])
    import shutil; shutil.copy(out, os.path.join(mk.HERE, "logs", "strace-sample.out"))
finally:
    v.cleanup()
