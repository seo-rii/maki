#!/usr/bin/python3
# Approximate MemoryDenyWriteExecute=yes with prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN),
# which is inherited by fork and preserved across execve; prove it is in force, then exec.
import ctypes, mmap, os, sys
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(65, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "PR_SET_MDWE")
try:
    mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    sys.stderr.write("mdwe-exec: W+X mapping still allowed\n"); sys.exit(97)
except PermissionError:
    sys.stderr.write("mdwe-exec: W+X mapping refused (MDWE in force)\n")
os.execv(sys.argv[1], sys.argv[1:])
