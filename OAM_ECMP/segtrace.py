#!/usr/bin/python3
import socket, struct, queue, enum, random, sys, icmp
import ctypes as ct

ICMP_ECHO_REQ = 128
ICMP_OAM_REQ = 100
TRACERT_PORT = 33434
RTHDR_TYPE = 4
TLV_OAM_TYPE = 8
SRH_FLAG_OAM = 32
TLV_OAM_RD = 1
TRIES_PER_PROBE = 1

# Build the GNU timeval struct (seconds, microseconds)
TIMEOUT = struct.pack("ll", 3, 0)
MAX_HOPS = 8

class NodeType(enum.Enum):
    UNKNOWN = 0
    IPV6 = 1 # Regular IPv6 node
    SEG6 = 2 # SRv6 + OAM ECMP

    def __str__(self):
        if self.value == 1:
            return 'IP'
        elif self.value == 2:
            return 'SR'
        
        return 'UNKNOWN'
    
class Node:
    type = NodeType.UNKNOWN
    addr = ''
    name = None
    error = False

    def __init__(self, type, addr=addr):
        self.type = type
        self.addr = addr

        try:
            self.name = socket.gethostbyaddr(addr)[0]
        except socket.error as e:
            self.name = None

    def __eq__(self, other):
        _ = lambda x: socket.inet_pton(socket.AF_INET6, x)
        if isinstance(other, str):
            if self.type == NodeType.UNKNOWN:
                return False
            return (_(self.addr) == _(other))

        if self.type != other.type:
            return False

        return (_(self.addr) == _(other.addr))

    def __str__(self):
        if self.type == NodeType.UNKNOWN:
            return "*"

        if self.name:
            return "{} ({} / {})".format(self.name, self.addr, str(self.type))
        else:
            return "{} ({})".format(self.addr, str(self.type))

    def __repr__(self):
        return "<Node: {}>".format(self.__str__())

def build_srh(dst, segments):
    segments = [dst] + segments[::-1]
    ct_segments = ct.c_ubyte * 16 * len(segments)

    class SRH(ct.Structure):
        _fields_ =  [ ("nh", ct.c_uint8),
                      ("hdr_len", ct.c_uint8),
                      ("type", ct.c_uint8),
                      ("segleft", ct.c_uint8),
                      ("lastentry", ct.c_uint8),
                      ("flags", ct.c_ubyte),
                      ("tag", ct.c_ushort),
                      ("segments", ct_segments) ]

    srh = SRH(type=RTHDR_TYPE, segleft=len(segments)-1, lastentry=len(segments)-1)
    srh.hdr_len = (len(bytes(srh)) >> 3) - 1
    srh.segments = ct_segments.from_buffer_copy(b''.join([socket.inet_pton(socket.AF_INET6, s) for s in segments]))
    return srh


def send_oam_probe(src, dst, target, segments):
    oam_dst = socket.inet_pton(socket.AF_INET6, dst) # for the replier, regular SID -> OAM SID
    oam_dst = oam_dst[:-2] + b'\x00\x08'
    oam_dst = socket.inet_ntop(socket.AF_INET6, oam_dst)
    segments = [src, oam_dst] + segments[::-1]
    ct_segments = ct.c_ubyte * 16 * len(segments)

    class SRH_OAM_RD(ct.Structure):
        _fields_ =  [ ("nh", ct.c_uint8),
                      ("hdr_len", ct.c_uint8),
                      ("type", ct.c_uint8),
                      ("segleft", ct.c_uint8),
                      ("lastentry", ct.c_uint8),
                      ("flags", ct.c_ubyte),
                      ("tag", ct.c_ushort),
                      ("segments", ct_segments),
                      ("tlv_type", ct.c_uint8),
                      ("tlv_len", ct.c_uint8),
                      ("oam_type", ct.c_uint8),
                      ("oam_reserved", ct.c_uint8),
                      ("oam_sessid", ct.c_ushort),
                      ("oam_reserved2", ct.c_ushort),
                      ("oam_target", ct.c_ubyte * 16) ]

    
    srh = SRH_OAM_RD(type=RTHDR_TYPE, segleft=len(segments)-1, lastentry=len(segments)-1, flags=SRH_FLAG_OAM,
                     tlv_type=TLV_OAM_TYPE, tlv_len=22, oam_type=TLV_OAM_RD)
    srh.hdr_len = (len(bytes(srh)) >> 3) - 1
    srh.segments = ct_segments.from_buffer_copy(b''.join([socket.inet_pton(socket.AF_INET6, s) for s in segments]))
    #srh.segment2 = (ct.c_ubyte * 16).from_buffer_copy(socket.inet_pton(socket.AF_INET6, oam_dst))
    srh.oam_target = (ct.c_ubyte * 16).from_buffer_copy(socket.inet_pton(socket.AF_INET6, target))
    sessid = random.randrange(0, 65535)
    srh.sessid = sessid    
    payload = struct.pack('!HBB', sessid, 0, 0)

    icmp.send(src, segments[0], ICMP_OAM_REQ, 0, payload, srh=bytes(srh))
    return sessid

def send_udp_probe(src, target, hops):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.bind((src, 0))
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, hops)
    sock.sendto(b"", (target, TRACERT_PORT))
    sock.close()

#https://github.com/certator/pyping/blob/master/pyping/core.py

def parse_oam_reply(reply, req_sessid):
    if len(reply) < 6:
        return []
    type, code, checksum, sessid, nb_sub, _ = struct.unpack('!BBHHBB', reply[0:8])

    if req_sessid != sessid: # received a reply we were not waiting on
        print("Received OAM reply with other session ID.")
        return []

    if nb_sub < 1:
        print("Received OAM reply without sub-replies.")
        return []

    nb_hops = reply[10] # we expect only one sub-reply
    if len(reply) != 12 + (nb_hops * 16):
        print("Received invalid OAM reply.")
        return []

    hops = [reply[12+i*16:28+i*16] for i in range(nb_hops)]
    return list(map(lambda x: Node(NodeType.IPV6, socket.inet_ntop(socket.AF_INET6, x)), hops))

def new_recv_icmp_sock(allowed=None):
    rcv_icmp = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    rcv_icmp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, TIMEOUT)

    if allowed:
        # icmp6_filter is a bitmap, ICMP packets of type 1 are passing if the first bit is set to 0, etc..
        icmp6_filter = [255]*32 # by default, block all
        for type in allowed:
            icmp6_filter[type >> 3] &= ~(1 << ((type) & 7))

        # socket.ICMPV6_FILTER is not defined, but its value is 1 as of Linux 4.16
        rcv_icmp.setsockopt(socket.IPPROTO_ICMPV6, 1, bytes(icmp6_filter))

    return rcv_icmp
    
def segtrace(src, target):
    paths = queue.Queue()
    paths.put([])
    final_paths = []

    while not paths.empty(): # unfinished paths
        path = paths.get()
        nexthops = []
        segments = [n.addr for n in path if n.type != NodeType.UNKNOWN]

        # Sending SRv6 OAM DR probes
        if len(path) > 0 and path[-1].type != NodeType.UNKNOWN:
            tries = TRIES_PER_PROBE
            sock = new_recv_icmp_sock(allowed=(ICMP_OAM_REQ,))
            try:
                sessid = send_oam_probe(src, path[-1].addr, target, segments)
            except OSError as e:
                tries = 0
                
            while not nexthops and tries > 0:
                try:
                    reply, replier = sock.recvfrom(512)
                    nexthops = parse_oam_reply(reply, sessid)
                    path[-1].type = NodeType.SEG6
                except socket.error as e:
                    pass

                tries -= 1
            sock.close()

        # If the next hops are still not discovered, sending ICMP Echo Request probes
        tries = TRIES_PER_PROBE
        sock = new_recv_icmp_sock(allowed=(1,3,129))
        while not nexthops and tries > 0:
            icmp.send(src, target, ICMP_ECHO_REQ, 0, b"\x42\x42\x00\x01", hops=len(path) + 1, \
                      srh=build_srh(target, segments) if segments else None)
            try:
                reply, replier = sock.recvfrom(512)
                nexthops = [Node(NodeType.IPV6, replier[0])]
            except socket.error as e:
                pass

            tries -= 1
        sock.close()

        if not nexthops: # if still no data, we put it as unknown and keep going
            nexthops = [Node(NodeType.UNKNOWN)]

        for node in nexthops:
            new_path = path + [node]
            if node == target or len(new_path) >= MAX_HOPS:
                final_paths.append(new_path)
            else:
                paths.put(new_path)

    for p in final_paths:
        print("\n -> ".join(map(str, p)))
        print("")

if __name__ == "__main__":
    src,dst = None, None
    if len(sys.argv) >= 3:
        _src, _dst = sys.argv[1:3]
        try:
            socket.inet_pton(socket.AF_INET6, _src)
            socket.inet_pton(socket.AF_INET6, _dst)
            src, dst = _src, _dst
        except:
            pass

    if not src or not dst:
        print("Usage: segtrace.py bindaddr target")
        sys.exit(1)

    segtrace(src, dst)
