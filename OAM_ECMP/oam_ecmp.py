#!/usr/bin/python3

from bcc import BPF
from pyroute2 import IPRoute
import sys, logging, signal, socket, icmp, struct
from daemonize import Daemonize
import ctypes as ct
from time import sleep

import traceback

# Needed for the simulation in our virtualized network (validation.sh).
# A real use-case would ask the routing daemon for the neighbors' global addresses
LOCAL_GLOBAL_MAP = {
    'fe80::23b':'fc00::3:0',
    'fe80::24b':'fc00::4:0',
    'fe80::35b':'fc00::5:0',
    'fe80::36b':'fc00::6:0',
}

PID = "/tmp/seg6_oam_{}.pid"
PERF_EVENT_FREQ = 0
sid, iface = None, None

REQ_DUMP_ROUTES = 1

def find_value(l, name):
    for i in l:
        if i[0] == name:
            return i[1]

    return None

def oam_dump_rt(target, skb):
    ip = IPRoute()

    target_addr = socket.inet_ntop(socket.AF_INET6, target)
    gws = []
    #TODO: the following approach to fetch the routes is too simple, it should :
    # - Do a longest prefix match instead of an exact match
    # - Take into account the weights of the ECMP routes, and the metrics
    for r in ip.get_routes(family=socket.AF_INET6):
        if find_value(r['attrs'], 'RTA_DST') == target_addr:
            gws = []
            paths = find_value(r['attrs'], 'RTA_MULTIPATH')
            if isinstance(paths, list):
                for p in paths:
                    gws.append(find_value(p['attrs'], 'RTA_GATEWAY'))
            else:
                gws = [find_value(r['attrs'], 'RTA_GATEWAY')]

            try:
                gws = [LOCAL_GLOBAL_MAP[x] for x in gws if x != None]
            except KeyError:
                logger.error("RTDUMP: do not have a global address for each of the following links".format(" ,".join(gws)))
            break

    if gws:
        logger.info("RTDUMP: routes to {} asked: {}".format(target_addr, ", ".join(gws)))
    else:
        logger.warn("RTDUMP: routes to {} asked, but none found.".format(target_addr))

    try:
        srh_hdrlen = (skb[41] + 1) << 3
        srh = skb[40:40+srh_hdrlen]
        last_seg = socket.inet_ntop(socket.AF_INET6, bytes(srh[8:24]))
        icmp_payload_len = int.from_bytes(skb[4:6], byteorder='big') - srh_hdrlen - 4 #assuming there are no other ext. headers than the SRH
        icmp_data = skb[40+srh_hdrlen+4:40+srh_hdrlen+4+icmp_payload_len]
        logger.info(' '.join('{:02x}'.format(x) for x in bytes(icmp_data)))
        icmp_data[2] += 1 # incrementing the number of sub-replies

        #srh[3]+1: SRH Last Entry, corresponding to the SID of this action, since End.BPF already advanced to the next segment
        sub_reply = struct.pack('!BBBB', srh[3] + 1, 0, len(gws), 0)
        sub_reply += b"".join(map(lambda x: socket.inet_pton(socket.AF_INET6, x), gws))
        icmp_data = bytes(icmp_data)
        icmp_data += sub_reply

        src = socket.inet_pton(socket.AF_INET6, sid.split('/')[0])
        src = src[:-2] + b'\x00\x00'
        src = socket.inet_ntop(socket.AF_INET6, src)

        icmp.send(src, last_seg, 100, 0, icmp_data, srh=bytes(srh))
    except Exception as e:
        logger.error("RTDUMP: could not add ICMP sub-reply and send back: {}".format(e))
        logger.error(traceback.format_exc())

def handle_oam_request(cpu, data, size):
    class OAMRequest(ct.Structure):
        _fields_ =  [ ("req_tlv_type", ct.c_uint8),
                      ("req_tlv_len", ct.c_uint8),
                      ("req_type", ct.c_uint8),
                      ("reserved", ct.c_uint8),
                      ("session_id", ct.c_ushort),
                      ("reserved", ct.c_ushort),
                      ("req_params", ct.c_ubyte * 16),
                      ("skb", ct.c_ubyte * (size - ct.sizeof(ct.c_ubyte * 24))) ]

    req = ct.cast(data, ct.POINTER(OAMRequest)).contents
    if req.req_type == REQ_DUMP_ROUTES:
        oam_dump_rt(req.req_params, req.skb)
    else:
        logger.error("Received unknown OAM request type {} from {}".format(req.req_type, sender))
    
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
