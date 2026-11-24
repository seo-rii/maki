#!/usr/bin/python3
# Stand-in for systemd's notification socket: log every datagram with a timestamp.
import os, socket, sys, time
path, log = sys.argv[1], sys.argv[2]
try:
    os.unlink(path)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(path)
os.chmod(path, 0o666)
with open(log, "a", buffering=1) as out:
    out.write(f"{time.time():.3f} listening\n")
    while True:
        data = s.recv(65536)
        out.write(f"{time.time():.3f} {data!r}\n")
