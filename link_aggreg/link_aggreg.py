#!/usr/bin/python3

import sys, logging, signal, socket, os, socket, math, struct
import ctypes as ct
from daemonize import Daemonize
from pyroute2 import IPRoute
from functools import reduce
from time import sleep
from bcc import BPF

PID = "/tmp/link_aggreg_{}.pid"
prefix, iface, N1, N2, dm_prefix, logger = None, None, None, None, None, None

class DM_TLV(ct.Structure):
    _pack_ = 1 
    _fields_ =  [ ("type", ct.c_uint8),
                  ("len", ct.c_uint8),
                  ("reserved", ct.c_ushort),

                  ("version", ct.c_uint8, 4),
                  ("flags", ct.c_uint8, 4),
                  ("cc", ct.c_uint8),
                  ("reserved2", ct.c_ushort),

                  ("qtf", ct.c_uint8, 4),
                  ("rtf", ct.c_uint8, 4),
                  ("rtpf", ct.c_uint32, 4),
                  ("reserved3", ct.c_uint32, 20),

                  ("session_id", ct.c_uint32, 24),
                  ("tc", ct.c_uint32, 8),

                  ("timestamp1", ct.c_uint64),
                  ("timestamp2", ct.c_uint64),
                  ("timestamp3", ct.c_uint64),
                  ("timestamp4", ct.c_uint64) ]

class Node:
    sid, sid_bytes = "", b""
    otp_sid, otp_sid_bytes = "", b""
    weight = 0
    delay_down, delay_up = 0, 0

    def __init__(self, sid, otp_sid, weight):
        self.sid, self.otp_sid = sid, otp_sid
        self.otp_sid_bytes = socket.inet_pton(socket.AF_INET6, otp_sid)
        self.sid_bytes = socket.inet_pton(socket.AF_INET6, sid)
        self.weight = int(weight)

    def update_delays(self, delay_down, delay_up):
        self.delay_down, self.delay_up = delay_down, delay_up

def send_delay_probe(node):
    src_rcv = dm_prefix.split('/')[0]
    segments = (bytes(16), node.otp_sid_bytes, node.sid_bytes)

    dm = DM_TLV()
    dm.type = 7
    dm.len = 46
    dm.version = 1
    dm.cc = 0
    dm.qtf = 3
    dm.timestamp1 = 42
    dm.session_id = 10

    hdrlen = (len(bytes(dm)) + len(segments) * 16) >> 3
    srh_base = struct.pack("!BBBBBBH", 0, hdrlen, 4, len(segments) - 1, len(segments) - 1, 0, 0)
    srh = srh_base + reduce(lambda x,y: x+y, segments) + bytes(dm)
    
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RTHDR, srh)

    sock.bind(('', 9999))
    sock.sendto(b"", (src_rcv, 9999))

def handle_dm_reply(cpu, data, size):
    class Timestamp:
        val = 0

        def __init__(self, bits):
            self.val = float(int.from_bytes(bits[0:4], byteorder='big'))
            self.val += float(int.from_bytes(bits[4:8], byteorder='big')) / 10**9

        def __sub__(self, other):
            return self.val - other.val

    dm = ct.cast(data, ct.POINTER(DM_TLV)).contents
    logger.info('{} {} {} {}'.format(dm.timestamp1, dm.timestamp2, dm.timestamp3, dm.timestamp4))

def install_rt(prefix, bpf_file, bpf_func, maps):
    b = BPF(src_file=bpf_file)
    fn = b.load_func(bpf_func, BPF.LWT_IN)

    fds = []
    for m in maps:
        fds.append(b[m].map_fd)

    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=iface)[0]
    
    encap = {'type':'bpf', 'in':{'fd':fn.fd, 'name':fn.name}}
    ipr.route("add", dst=prefix, oif=idx, encap=encap)
    
    return b, fds

def remove_rt(sig, fr):
    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=iface)[0]
    ipr.route("del", dst=prefix, oif=idx)
    ipr.route("del", dst=dm_prefix, oif=idx)
    sys.exit(0)

def run_daemon(bpf_aggreg, bpf_dm):
    signal.signal(signal.SIGTERM, remove_rt)
    signal.signal(signal.SIGINT, remove_rt)

    ct_ip = ct.c_ubyte * 16
    bpf_aggreg["sids"][0] = ct_ip.from_buffer_copy(N1.sid_bytes)
    bpf_aggreg["sids"][1] = ct_ip.from_buffer_copy(N2.sid_bytes)
    bpf_aggreg["weights"][0] = ct.c_int(N1.weight)
    bpf_aggreg["weights"][1] = ct.c_int(N2.weight)
    bpf_aggreg["wrr"][0] = ct.c_int(-1)
    bpf_aggreg["wrr"][1] = ct.c_int(0)
    bpf_aggreg["wrr"][2] = ct.c_int(math.gcd(N1.weight, N2.weight))

    bpf_dm["dm_messages"].open_perf_buffer(handle_dm_reply)

    send_delay_probe(N1)
    while 1:
        bpf_dm.kprobe_poll()
        sleep(0.01) # tune polling frequency here

def get_logger():
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    fh = logging.FileHandler("/tmp/link_aggreg_{}.log".format(rt_name), "a")
    fh.setLevel(logging.DEBUG)
    logger.addHandler(fh)
    formatter = logging.Formatter("%(asctime)s: %(message)s",
                                                  "%b %e %H:%M:%S")
    fh.setFormatter(formatter)
    return logger, fh.stream.fileno()

if __name__ == '__main__':
    if len(sys.argv) != 10:
        print("Format: ./link_aggreg.py PREFIX DEV SID1 SID1-OTP WEIGHT1 SID2 SID2-OTP WEIGHT2 DM-PREFIX")
        sys.exit(1)

    prefix, iface, sid1, sid1_otp, w1, sid2, sid2_otp, w2, dm_prefix = sys.argv[1:10]
    N1 = Node(sid1, sid1_otp, w1)
    N2 = Node(sid2, sid2_otp, w2)

    bpf_aggreg, fds_aggreg = install_rt(prefix, 'link_aggreg_bpf.c', 'LB', ('sids', 'weights', 'wrr'))
    rt_name = prefix.replace('/','-')

    bpf_dm, fds_dm = install_rt(dm_prefix, 'dm_recv_bpf.c', 'DM_recv', ('dm_messages',))

    logger, fd_logger = get_logger()
    keep_fds = [fd_logger] + fds_aggreg + fds_dm
    daemon = Daemonize(app="link_aggreg", pid=PID.format(rt_name), action=lambda: run_daemon(bpf_aggreg, bpf_dm),
            keep_fds=keep_fds, logger=logger)

    print("Link aggregation daemon forked to background.")
    daemon.start()
