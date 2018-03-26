#!/usr/bin/python3

from bcc import BPF
from pyroute2 import IPRoute
import sys, logging, signal, socket
from daemonize import Daemonize
import ctypes as ct
from time import sleep

PID = "/tmp/oam_ecmp_{}.pid"
PERF_EVENT_FREQ = 0
sid, iface = None, None

REQ_DUMP_ROUTES = 0

def find_value(l, name):
    for i in l:
        if i[0] == name:
            return i[1]

    return None

def print_oam_request(cpu, data, size):
    class OAMRequest(ct.Structure):
        _fields_ =  [ ("req_type", ct.c_uint8),
                      ("req_args", ct.c_ubyte * 16),
                      ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_ubyte * 16) - ct.sizeof(ct.c_uint8))) ]

    oam_request = ct.cast(data, ct.POINTER(OAMRequest)).contents
    if oam_request.req_type == REQ_DUMP_ROUTES:
        ip = IPRoute()

        server_addr = socket.inet_ntop(socket.AF_INET6, oam_request.req_args)

        for r in ip.get_routes(family=socket.AF_INET6):
            if find_value(r['attrs'], 'RTA_DST') == server_addr:
                logger.info("route found to "+server_addr)

                gws = []
                paths = find_value(r['attrs'], 'RTA_MULTIPATH')
                if isinstance(paths, list):
                    for p in paths:
                        gws.append(find_value(p['attrs'], 'RTA_GATEWAY'))
                else:
                    gws = [find_value(r['attrs'], 'RTA_GATEWAY')]

                gws = [x for x in gws if x != None]
                logger.info("routes to {}: {}".format(server_addr, ", ".join(gws)))

                return

        logger.warn("No route found to {}".format(server_addr))

    else:
        logger.error("Received unknown OAM request type "+oam_request.req_type)
    
def install_rt(bpf_file):
    b = BPF(src_file=bpf_file)
    fn = b.load_func("OAM_ECMP", 17) # TODO

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
bpf, fds = install_rt('oam_ecmp_bpf.c')
rt_name = sid.replace('/','-')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.propagate = False
fh = logging.FileHandler("/tmp/oam_ecmp_{}.log".format(rt_name), "a")
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)
fds.append(fh.stream.fileno())
formatter = logging.Formatter("%(asctime)s: %(message)s",
                                              "%b %e %H:%M:%S")
fh.setFormatter(formatter)

daemon = Daemonize(app="oam_ecmp", pid=PID.format(rt_name), action=lambda: run_daemon(bpf),
        keep_fds=fds, logger=logger)
print("OAM ECMP daemon forked to background.")

daemon.start()
