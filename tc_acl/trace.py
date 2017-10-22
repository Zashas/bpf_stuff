from bcc import BPF
from pyroute2 import IPRoute
import subprocess, shlex

ipr = IPRoute()

idx = ipr.link_lookup(ifname="lo")[0]
try:
    ipr.tc("add", "clsact", idx)

    cmd = "sudo tc filter add dev lo egress bpf da obj class.o sec cls"
    subprocess.check_output(shlex.split(cmd))

    print("Starting tracing ...")
    b = BPF(text="int foo() {return 0;}")
    b.trace_print()

finally:
    ipr.tc("del", "clsact", idx)
