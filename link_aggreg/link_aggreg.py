#!/usr/bin/python3

from bcc import BPF
from pyroute2 import IPRoute
import sys, logging, signal, socket, os, socket, math
from daemonize import Daemonize
import ctypes as ct
from time import sleep

PID = "/tmp/link_aggreg_{}.pid"
prefix,iface,sid1,sid1,w1,w2 = None, None, None, None, None, None

def install_rt(bpf_file):
    b = BPF(src_file=bpf_file)
    fn = b.load_func("LB", BPF.LWT_IN)

    fds = []
    fds.append(b["sids"].map_fd)
    fds.append(b["weights"].map_fd)
    fds.append(b["wrr"].map_fd)

    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=iface)[0]
    
    encap = {'type':'bpf', 'in':{'fd':fn.fd, 'name':fn.name}}
    ipr.route("add", dst=prefix, oif=idx, encap=encap)
    
    return b, fds

def remove_rt(sig, fr):
    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=iface)[0]
    ipr.route("del", dst=prefix, oif=idx)
    sys.exit(0)

def run_daemon(bpf):
    signal.signal(signal.SIGTERM, remove_rt)
    signal.signal(signal.SIGINT, remove_rt)

    ct_ip = ct.c_ubyte * 16
    bpf["sids"][0] = ct_ip.from_buffer_copy(socket.inet_pton(socket.AF_INET6, sid1))
    bpf["sids"][1] = ct_ip.from_buffer_copy(socket.inet_pton(socket.AF_INET6, sid2))
    bpf["weights"][0] = ct.c_int(w1)
    bpf["weights"][1] = ct.c_int(w2)
    bpf["wrr"][0] = ct.c_int(-1)
    bpf["wrr"][1] = ct.c_int(0)
    bpf["wrr"][2] = ct.c_int(math.gcd(w1, w2))

    while 1:
        # TODO refresh maps
        sleep(1)

if len(sys.argv) != 7:
    print("Format: ./link_aggreg.py PREFIX DEV SID1 WEIGHT1 SID2 WEIGHT2")
    sys.exit(1)

prefix, iface, sid1, w1, sid2, w2 = sys.argv[1:7]
w1, w2 = int(w1), int(w2)
bpf, fds = install_rt('link_aggreg_bpf.c')
rt_name = prefix.replace('/','-')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.propagate = False
fh = logging.FileHandler("/tmp/link_aggreg_{}.log".format(rt_name), "a")
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)
fds.append(fh.stream.fileno())
formatter = logging.Formatter("%(asctime)s: %(message)s",
                                              "%b %e %H:%M:%S")
fh.setFormatter(formatter)

daemon = Daemonize(app="link_aggreg", pid=PID.format(rt_name), action=lambda: run_daemon(bpf),
        keep_fds=fds, logger=logger)

print("Link aggregation daemon forked to background.")
daemon.start()
