#!/usr/bin/python3

from bcc import BPF
from pyroute2 import IPRoute
import sys, logging, signal, socket
from daemonize import Daemonize
import ctypes as ct
from time import sleep

PID = "/tmp/seg6_oam_{}.pid"
PERF_EVENT_FREQ = 0
sid, iface = None, None

REQ_DUMP_ROUTES = 1

def find_value(l, name):
    for i in l:
        if i[0] == name:
            return i[1]

    return None

def oam_dump_rt(target, uro_ip, uro_port):
    ip = IPRoute()

    target_addr = socket.inet_ntop(socket.AF_INET6, target)

    for r in ip.get_routes(family=socket.AF_INET6):
        if find_value(r['attrs'], 'RTA_DST') == target_addr:
            gws = []
            paths = find_value(r['attrs'], 'RTA_MULTIPATH')
            if isinstance(paths, list):
                for p in paths:
                    gws.append(find_value(p['attrs'], 'RTA_GATEWAY'))
            else:
                gws = [find_value(r['attrs'], 'RTA_GATEWAY')]

            gws = [x for x in gws if x != None]
            logger.info("RTDUMP: routes to {} asked: {}".format(target_addr, ", ".join(gws)))

            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                payload = bytes(target)
                payload += bytes(ct.c_uint8(len(gws)))
                payload += b"".join(map(lambda x: socket.inet_pton(socket.AF_INET6, x), gws))
                sock.connect((uro_ip, uro_port))
                sock.send(payload)
                sock.close()
            except Exception as e:
                logger.error("Could not sent out-of-band DM reply to ({}, {}): {}".format(uro_ip, uro_port, e))

            return

    logger.warn("RTDUMP: routes to {} asked, but none found.".format(target_addr))


def handle_oam_request(cpu, data, size):
    class OAMRequest(ct.Structure):
        _fields_ =  [ ("req_tlv_type", ct.c_uint8),
                      ("req_tlv_len", ct.c_uint8),
                      ("req_type", ct.c_uint8),
                      ("req_params", ct.c_uint8),
                      ("req_args", ct.c_ubyte * 16),
                      ("uro_type", ct.c_ubyte),
                      ("uro_len", ct.c_ubyte),
                      ("uro_dport", ct.c_ushort),
                      ("uro_daddr", ct.c_ubyte * 16),
                      ("skb", ct.c_ubyte * (size - ct.sizeof(ct.c_ubyte * 40))) ]

    req = ct.cast(data, ct.POINTER(OAMRequest)).contents
    uro_port = socket.ntohs(req.uro_dport)
    uro_ip = socket.inet_ntop(socket.AF_INET6, bytes(req.uro_daddr))

    if req.req_type == REQ_DUMP_ROUTES:
        oam_dump_rt(req.req_args, uro_ip, uro_port)
    else:
        logger.error("Received unknown OAM request type {}".format(req.req_type))
    
def install_rt(bpf_file):
    b = BPF(src_file=bpf_file)
    fn = b.load_func("SEG6_OAM", 17) # TODO

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
    bpf["oam_requests"].open_perf_buffer(handle_oam_request)
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
fh = logging.FileHandler("/tmp/seg6_oam_{}.log".format(rt_name), "a")
fh.setLevel(logging.DEBUG)
logger.addHandler(fh)
fds.append(fh.stream.fileno())
formatter = logging.Formatter("%(asctime)s: [%(levelname)s] %(message)s", "%b %e %H:%M:%S")
fh.setFormatter(formatter)

daemon = Daemonize(app="seg6-oam", pid=PID.format(rt_name), action=lambda: run_daemon(bpf),
        keep_fds=fds, logger=logger)
print("SRv6 OAM daemon forked to background.")

daemon.start()
