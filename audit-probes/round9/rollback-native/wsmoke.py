#!/usr/bin/python3.12
"""Smoke: maki-witness init/serve/inspect with generated certificates."""
import os, sys, shutil, tempfile, json
import mk9 as mk, rw
base = tempfile.mkdtemp(prefix="wsmoke-", dir="/tmp")
a = rw.Authority(base, os.path.join(base, "state"))
print(a.init().stdout.strip())
a.start()
print(a.inspect())
print(a.inspect("admin")["fence"])
a.kill9()
print(sorted(os.listdir(a.state)))
shutil.rmtree(base)
