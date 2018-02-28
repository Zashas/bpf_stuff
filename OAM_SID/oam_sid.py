#!/usr/bin/python3

from bcc import BPF
from pyroute2 import IPRoute
import sys, logging, signal, socket
from daemonize import Daemonize
import ctypes as ct
from time import sleep

PID = "/tmp/oam_sid_{}.pid"
PERF_EVENT_FREQ = 0
sid, iface = None, None

def print_oam_request(cpu, data, size):
    class OAMRequest(ct.Structure):
        _fields_ =  [ ("req_type", ct.c_uint8),
                      ("req_args", ct.c_ubyte * 16),
                      ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_ubyte * 16) - ct.sizeof(ct.c_uint8))) ]

    oam_request = ct.cast(data, ct.POINTER(OAMRequest)).contents
    logger.info("request type {}".format(oam_reqest.req_type.value))
    
def install_rt(bpf_file):
    b = BPF(src_file=bpf_file)
    fn = b.load_func("OAM_SID", BPF.SOCK_OPS)
    #fn = b.load_func("OAM_SID", BPF.LWT_SEG6LOCAL)

    fds = []
    fds.append(b["oam_requests"].map_fd)

    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=iface)[0]
    
    encap = {'type':'seg6local', 'action':'bpf', 'bpf':{'fd':fn.fd, 'name':fn.name}}
    ipr.route("add", dst=sid, oif=idx, encap=encap)
    
    return b, fds

def remove_rt(sig, fr):
    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=iface)[0]
    ipr.route("del", dst=sid, oif=idx)
    sys.exit(0)

def run_daemon(bpf):
    signal.signal(signal.SIGTERM, remove_rt)
    signal.signal(signal.SIGINT, remove_rt)
    bpf["oam_requests"].open_perf_buffer(print_oam_request, page_cnt=1024)
    while 1:
        bpf.kprobe_poll()
        sleep(0.01) # tune polling frequency here

if len(sys.argv) < 3:
    print("Format: ./oam_sid.py SID DEV")
    sys.exit(1)

sid,iface = sys.argv[1:3]
bpf, fds = install_rt('oam_sid_bpf.c')
rt_name = sid.replace('/','-')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.propagate = False
fh = logging.FileHandler("/tmp/oam_sid_{}.log".format(rt_name), "a")
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)
fds.append(fh.stream.fileno())
formatter = logging.Formatter("%(asctime)s : %(message)s",
                                              "%b %e %H:%M:%S")
fh.setFormatter(formatter)

daemon = Daemonize(app="oam_sid", pid=PID.format(rt_name), action=lambda: run_daemon(bpf),
        keep_fds=fds, logger=logger)
print("OAM SID forked to background.")
daemon.start()
