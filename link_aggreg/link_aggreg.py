#!/usr/bin/python3

import sys, logging, signal, socket, os, socket, math
import struct, time, subprocess, threading, collections
import ctypes as ct
from daemonize import Daemonize
from pyroute2 import IPRoute
from functools import reduce
from bcc import BPF

PID = "/tmp/link_aggreg_{}.pid"
ROOT_QDISC = 1
PROBES_FREQ = 2 # in sec

prefix, N1, N2, dm_prefix, logger = None, None, None, None, None
daemon_running = True
probes_thread = None

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

                  ("timestamp1_sec", ct.c_uint32),
                  ("timestamp1_nsec", ct.c_uint32),
                  ("timestamp2_sec", ct.c_uint32),
                  ("timestamp2_nsec", ct.c_uint32),
                  ("timestamp3_sec", ct.c_uint32),
                  ("timestamp3_nsec", ct.c_uint32),
                  ("timestamp4_sec", ct.c_uint32),
                  ("timestamp4_nsec", ct.c_uint32) ]

class DM_Session:
    node, batch, batch_id, delay_down, delay_up, tc_delay = None, None, None, None, None, None

    def __init__(self, node, batch, batch_id, tc_delay):
        self.node = node
        self.batch = batch
        self.batch_id = batch_id
        self.tc_delay = tc_delay

    def has_reply(self):
        if self.delay_down and self.delay_up:
            return True
        return False

    def store_delays(self, down, up):
        self.delay_down = down
        self.delay_up = up

class Node:
    id = 0
    sid, sid_bytes = "", b""
    otp_sid, otp_sid_bytes = "", b""
    weight = 0
    delay_down, delay_up, tc_delay_down = 0, 0, 0
    current_dm_sess_id_recv = -1
    tc_classid, tc_handle = "", ""

    # global vars
    nb_nodes = 0
    dm_sessions = collections.OrderedDict() # id -> (Node, batch_id, delay_down, delay_up)
    current_dm_sess_id_sent = 0
    last_batch_completed = -1

    def __init__(self, sid, otp_sid, weight):
        self.id = Node.nb_nodes
        Node.nb_nodes +=1

        self.sid, self.otp_sid = sid, otp_sid
        self.otp_sid_bytes = socket.inet_pton(socket.AF_INET6, otp_sid)
        self.sid_bytes = socket.inet_pton(socket.AF_INET6, sid)
        self.weight = int(weight)

        self.tc_classid = "{}:{}".format(ROOT_QDISC, self.id + 2) # class ids must start at 2
        self.tc_handle = "1{}:".format(self.id + 2)
        self.install_tc()

    def update_delays(self, sess_id, delay_down, delay_up):
        if sess_id <= self.current_dm_sess_id_recv:
            return False

        self.delay_down = delay_down - self.tc_delay_down
        self.delay_up = delay_up
        self.current_dm_sess_id_recv = sess_id
        return True

    def set_tc_delay(self, delay):
        self.tc_delay_down = delay
        delay_ms = "{}ms".format(int(delay*1000))
        #tc qdisc change dev veth7 parent 1:3 handle 13: netem delay 10ms
        for iface in ifaces:
            ret = subprocess.run(["tc", "qdisc", "change", "dev", iface, "parent", self.tc_classid, "handle", self.tc_handle, "netem", "delay", delay_ms])
            if ret.returncode:
                raise Node.ConfigError("Could not change tc qdisc netem for dev {}: {}".format(iface, " ".join(ret.args)))

    def install_tc(self):
        parent = "{}:".format(ROOT_QDISC)

        #ip netns exec ns2 tc class add dev veth7 parent 1: classid 1:2 htb rate 1000Mbps
        for iface in ifaces:
            ret = subprocess.run(["tc", "class", "add", "dev", iface, "parent", parent, "classid", self.tc_classid, "htb", "rate", "1000Mbps"])
            if ret.returncode:
                raise Node.ConfigError("Could not set tc class for dev {}: {}".format(iface, " ".join(ret.args)))

            #tc filter add dev veth7 protocol ipv6 parent 1: prio 1 u32 match ip6 dst fc00::3a flowid 1:2
            ret = subprocess.run(["tc", "filter", "add", "dev", iface, "protocol", "ipv6", "parent", parent, "prio", "1", "u32", "match", "ip6", "dst", self.sid, "flowid", self.tc_classid])
            if ret.returncode:
                raise Node.ConfigError("Could not set tc filter for dev {}: {}".format(iface, " ".join(ret.args)))

            #tc qdisc add dev veth7 parent 1:2 handle 12: netem delay 15ms
            ret = subprocess.run(["tc", "qdisc", "add", "dev", iface, "parent", self.tc_classid, "handle", self.tc_handle, "netem", "delay", "0ms"])
            if ret.returncode:
                raise Node.ConfigError("Could not set tc qdisc netem for dev {}: {}".format(iface, " ".join(ret.args)))

    def remove_tc(self):
        parent = "{}:".format(ROOT_QDISC)

        #ip netns exec ns2 tc class add dev veth7 parent 1: classid 1:2 htb rate 1000Mbps
        for iface in ifaces:
            ret = subprocess.run(["tc", "class", "delete", "dev", iface, "parent", parent, "classid", self.tc_classid, "htb", "rate", "1000Mbps"])
            if ret.returncode:
                logger.error("Could not delete tc class for dev {}: {}".format(iface, " ".join(ret.args)))

            ret = subprocess.run(["tc", "filter", "delete", "dev", iface, "protocol", "ipv6", "parent", parent, "prio", "1", "u32", "match", "ip6", "dst", self.sid, "flowid", self.tc_classid])
            if ret.returncode:
                logger.error("Could not delete tc filter for dev {}: {}".format(iface, " ".join(ret.args)))


    class ConfigError(Exception):
        pass

def send_delay_probe(node):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind(('', 9999))

    src_rcv = dm_prefix.split('/')[0]
    segments = (bytes(16), node.otp_sid_bytes, node.sid_bytes)

    hdrlen = (48 + len(segments) * 16) >> 3
    srh_base = struct.pack("!BBBBBBH", 0, hdrlen, 4, len(segments) - 1, len(segments) - 1, 0, 0)

    dm = DM_TLV()
    dm.type = 7
    dm.len = 46
    dm.version = 1
    dm.cc = 0
    dm.qtf = 3
    
    ts = time.time()
    dm.timestamp1_sec = socket.htonl(int(ts))
    dm.timestamp1_nsec = socket.htonl(int((ts % 1) * 10**9))

    dm.session_id = Node.current_dm_sess_id_sent
    Node.current_dm_sess_id_sent = (Node.current_dm_sess_id_sent + 1) % (2**24)

    srh = srh_base + reduce(lambda x,y: x+y, segments) + bytes(dm)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RTHDR, srh)
    sock.sendto(b"", (src_rcv, 9999))
    sock.close()

    return dm.session_id

def probes_sender():
    current_batch_id = 0
    while daemon_running:
        batch = []

        for node in (N1, N2):
            sessid = send_delay_probe(node)
            session = DM_Session(node, batch, current_batch_id, node.tc_delay_down)
            batch.append(session)
            Node.dm_sessions[sessid] = session

        current_batch_id += 1

        # remove unanswered probes older than 3 batches
        for k,v in Node.dm_sessions.items():
            if current_batch_id > v.batch_id + 3:
                del Node.dm_sessions[k]

        time.sleep(PROBES_FREQ)

def handle_dm_reply(cpu, data, size):
    t4 = time.time()
    def ieee_to_float(sec, nsec):
        val = float(socket.ntohl(sec))
        val += float(socket.ntohl(nsec)) / 10**9
        return val

    dm = ct.cast(data, ct.POINTER(DM_TLV)).contents
    if not dm.session_id in Node.dm_sessions:
        return
    session = Node.dm_sessions[dm.session_id]

    t1 = ieee_to_float(dm.timestamp1_sec, dm.timestamp1_nsec)
    t2 = ieee_to_float(dm.timestamp2_sec, dm.timestamp2_nsec)
    t3 = ieee_to_float(dm.timestamp3_sec, dm.timestamp3_nsec)
    session.store_delays(t2 - t1, t4 - t3)

    if session.batch_id > Node.last_batch_completed and all(map(lambda x: x.has_reply(), session.batch)):
        update_tc_delays(session.batch_id, session.batch)

def update_tc_delays(batch_id, batch):
    Node.last_batch_completed = batch_id

    delay1 = batch[0].delay_down - batch[0].tc_delay
    delay2 = batch[1].delay_down - batch[1].tc_delay
    if delay1 < delay2:
        node_fast = batch[0].node
        node_slow = batch[1].node
        diff_delay = delay2 - delay1
    else:
        node_fast = batch[1].node
        node_slow = batch[0].node
        diff_delay = delay1 - delay2

    node_fast.set_tc_delay(diff_delay)
    node_slow.set_tc_delay(0)
    logger.info("new delay on {}: {}".format(node_slow.sid, diff_delay))

def install_rt(prefix, bpf_file, bpf_func, maps):
    b = BPF(src_file=bpf_file)
    fn = b.load_func(bpf_func, BPF.LWT_IN)

    fds = []
    for m in maps:
        fds.append(b[m].map_fd)

    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=ifaces[0])[0]
    
    encap = {'type':'bpf', 'in':{'fd':fn.fd, 'name':fn.name}}
    ipr.route("add", dst=prefix, oif=idx, encap=encap)
    
    return b, fds

def remove_setup(sig, fr):
    daemon_running = False
    #probes_thread.join()
    N1.remove_tc() # TODO fail
    N2.remove_tc()

    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=ifaces[0])[0]
    ipr.route("del", dst=prefix, oif=idx)
    ipr.route("del", dst=dm_prefix, oif=idx)

    sys.exit(0)

def run_daemon(bpf_aggreg, bpf_dm):
    signal.signal(signal.SIGTERM, remove_setup)
    signal.signal(signal.SIGINT, remove_setup)

    ct_ip = ct.c_ubyte * 16
    bpf_aggreg["sids"][0] = ct_ip.from_buffer_copy(N1.sid_bytes)
    bpf_aggreg["sids"][1] = ct_ip.from_buffer_copy(N2.sid_bytes)
    bpf_aggreg["weights"][0] = ct.c_int(N1.weight)
    bpf_aggreg["weights"][1] = ct.c_int(N2.weight)
    bpf_aggreg["wrr"][0] = ct.c_int(-1)
    bpf_aggreg["wrr"][1] = ct.c_int(0)
    bpf_aggreg["wrr"][2] = ct.c_int(math.gcd(N1.weight, N2.weight))

    bpf_dm["dm_messages"].open_perf_buffer(handle_dm_reply)

    probes_thread = threading.Thread(target=probes_sender)
    probes_thread.start()

    while 1:
        bpf_dm.kprobe_poll()
        #time.sleep(0.01) # tune polling frequency here

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
    if len(sys.argv) < 10:
        print("Format: ./link_aggreg.py PREFIX SID1 SID1-OTP WEIGHT1 SID2 SID2-OTP WEIGHT2 DM-PREFIX DEV1 [DEV2 ...]")
        sys.exit(1)

    prefix, sid1, sid1_otp, w1, sid2, sid2_otp, w2, dm_prefix, *ifaces = sys.argv[1:11]
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
