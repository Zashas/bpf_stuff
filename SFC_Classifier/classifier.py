#!/usr/bin/python3

from bcc import BPF
from pyroute2 import IPRoute
import sys, logging, signal, socket
from daemonize import Daemonize
import ctypes as ct
from time import sleep

PID = "/tmp/seg6_classifier_{}.pid"
PERF_EVENT_FREQ = 0
dst, iface = None, None

class Stats:
    nb_drops = 0

def print_skb_event(cpu, data, size):
    class SkbEvent(ct.Structure):
        _fields_ =  [ ("id", ct.c_uint32),
                      ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32))) ]

    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
    if skb_event.raw[0] >> 4 == 0x6: # IPv6
        src_ip = socket.inet_ntop(socket.AF_INET6, bytes(skb_event.raw[8:24]))
        dst_ip = socket.inet_ntop(socket.AF_INET6, bytes(skb_event.raw[24:40]))
        nh = skb_event.raw[6]

        if nh == 6:
            proto = "TCP"
        elif nh == 17:
            proto = "UDP"
        else:
            proto = "unknown proto"

        args = ""
        if proto in ("TCP", "UDP"):
            p = skb_event.raw[40:44]
            sport = socket.ntohs(p[1] << 8 | p[0])
            dport = socket.ntohs(p[3] << 8 | p[2])
            args = "({}, {})".format(sport, dport)

        logger.info("Dropped IPv6 pkt #{}: {} -> {} / {} {}".format(skb_event.id, src_ip, dst_ip, proto,args))
    else:
        logger.info("Dropped non-IPv6 pkt #{}".format(skb_event.id))

def install_rt(bpf_file):
    b = BPF(src_file=bpf_file)
    fn = b.load_func("classifier", BPF.LWT_IN)

    fds = []
    fds.append(b["nb_pkts"].map_fd)
    fds.append(b["dropped_pkts"].map_fd)

    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=iface)[0]
    
    encap = {'type':'bpf', 'in':{'fd':fn.fd, 'name':fn.name}}
    ipr.route("add", dst=dst, oif=idx, encap=encap)
    
    return b, fds

def remove_rt(sig, fr):
    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=iface)[0]
    ipr.route("del", dst=dst, oif=idx)
    sys.exit(0)

def run_daemon(bpf):
    signal.signal(signal.SIGTERM, remove_rt)
    signal.signal(signal.SIGINT, remove_rt)
    bpf["dropped_pkts"].open_perf_buffer(print_skb_event, page_cnt=1024)
    while 1:
        bpf.kprobe_poll()
        sleep(0.01) # tune polling frequency here

if len(sys.argv) < 4:
    print("Format: ./classifier.py BPF PREFIX DEV")
    sys.exit(1)

dst, iface = sys.argv[2:4]
bpf, fds = install_rt(sys.argv[1])
rt_name = dst.replace('/','-')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.propagate = False
fh = logging.FileHandler("/tmp/seg6_classifier_{}.log".format(rt_name), "a")
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)
fds.append(fh.stream.fileno())
formatter = logging.Formatter("%(asctime)s : %(message)s",
                                              "%b %e %H:%M:%S")
fh.setFormatter(formatter)

daemon = Daemonize(app="seg6_classifier", pid=PID.format(rt_name), action=lambda: run_daemon(bpf),
        keep_fds=fds, logger=logger)
print("SRv6 classifier logger forked to background.")
daemon.start()
