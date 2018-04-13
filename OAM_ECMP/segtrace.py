#!/usr/bin/python3
import socket, struct, queue, enum, random, sys, icmp
import ctypes as ct

ICMP_ECHO_REQ = 128
TRACERT_PORT = 33434
RTHDR_TYPE = 4
TLV_OAM_TYPE = 8
SRH_FLAG_OAM = 32
TLV_OAM_RD = 1

# Build the GNU timeval struct (seconds, microseconds)
TIMEOUT = struct.pack("ll", 3, 0)
MAX_HOPS = 30


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
        if isinstance(other, str):
            return (self.addr == other)

        return (self.addr == other.addr)

    def __str__(self):
        if self.type == NodeType.UNKNOWN:
            return "*"

        if self.name:
            return "{} ({} / {})".format(self.name, self.addr, str(self.type))
        else:
            return "{} ({})".format(self.addr, str(self.type))

    def __repr__(self):
        return "<Node: {}>".format(self.__str__())

def send_oam_probe(src, dst, target):
    class SRH_OAM_RD(ct.Structure):
        _fields_ =  [ ("nh", ct.c_uint8),
                      ("hdr_len", ct.c_uint8),
                      ("type", ct.c_uint8),
                      ("segleft", ct.c_uint8),
                      ("lastentry", ct.c_uint8),
                      ("flags", ct.c_ubyte),
                      ("tag", ct.c_ushort),
                      ("segment1", ct.c_ubyte * 16),
                      ("segment2", ct.c_ubyte * 16),
                      ("tlv_type", ct.c_uint8),
                      ("tlv_len", ct.c_uint8),
                      ("oam_type", ct.c_uint8),
                      ("oam_reserved", ct.c_uint8),
                      ("oam_sessid", ct.c_ushort),
                      ("oam_reserved2", ct.c_ushort),
                      ("oam_target", ct.c_ubyte * 16) ]

    srh = SRH_OAM_RD(type=RTHDR_TYPE, segleft=1, lastentry=1, flags=SRH_FLAG_OAM,
                     tlv_type=TLV_OAM_TYPE, tlv_len=22, oam_type=TLV_OAM_RD)
    srh.hdr_len = (len(bytes(srh)) >> 3) - 1
    srh.segment1 = (ct.c_ubyte * 16).from_buffer_copy(socket.inet_pton(socket.AF_INET6, dst))
    srh.segment2 = (ct.c_ubyte * 16).from_buffer_copy(socket.inet_pton(socket.AF_INET6, src))
    srh.oam_target = (ct.c_ubyte * 16).from_buffer_copy(socket.inet_pton(socket.AF_INET6, target))
    sessid = random.randrange(0, 65535)
    srh.sessid = sessid    

    payload = struct.pack('!HBB', sessid, 0, 0)
    icmp.send(src, dst, 100, 0, payload, srh=bytes(srh))

    """
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RTHDR, bytes(srh))
    sock.bind((src, 0))
    sock.sendto(b"", (dst, TRACERT_PORT))
    sock.close()
    """

    return sessid

def send_udp_probe(src, target, hops):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.bind((src, 0))
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, hops)
    sock.sendto(b"", (target, TRACERT_PORT))
    sock.close()

#https://github.com/certator/pyping/blob/master/pyping/core.py

def parse_oam_reply(reply, sessid):
    if len(reply) < 6:
        return []

    if reply[0] != 100: # ICMPv6 msg type
        return []

    print("got reply TODO")
    """
    reply_sessid = (reply[5] << 8) | reply[4]
    if reply_sessid != sessid: # received another reply
        return []

    nb_hops = reply[6]
    if len(reply) != 8 + (nb_hops * 16):
        raise ValueError("Received invalid OAM reply.")

    hops = [reply[8+i:24+i] for i in range(nb_hops)]
    return map(lambda x: socket.inet_ntop(socket.AF_INET6, x), hops)
    """

def segtrace(src, target):
    paths = queue.Queue()
    paths.put([])
    final_paths = []

    while not paths.empty(): # unfinished paths
        path = paths.get()
        nexthops = []

        rcv_icmp = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        rcv_icmp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, TIMEOUT)

        # Sending SRv6 OAM DR probes
        if len(path) > 0 and path[-1].type != NodeType.UNKNOWN:
            tries = 3
            while not nexthops and tries > 0:
                sessid = send_oam_probe(src, path[-1].addr, target)
                try:
                    reply, replier = rcv_icmp.recvfrom(512)
                    if replier[0] == path[-1].addr:
                        nexthops = parse_oam_reply(reply, sessid)
                        if nexthops:
                            path[-1].type = NodeType.SEG6
                except socket.error as e:
                    pass

                tries -= 1

        # If the next hops are still not discovered, sending ICMP Echo Request probes
        tries = 3
        while not nexthops and tries > 0:
            icmp.send(src, target, ICMP_ECHO_REQ, 0, b"\x42\x42\x00\x01", hops=len(path) + 1)
            try:
                reply, replier = rcv_icmp.recvfrom(512)
                nexthops = [replier[0]]
            except socket.error as e:
                pass

            tries -= 1

        rcv_icmp.close()

        if not nexthops: # if still no data, we put it as unknown and keep going
            nexthops = [Node(NodeType.UNKNOWN)]

        for hop in nexthops:
            node = Node(NodeType.IPV6, addr=hop)
            new_path = path + [node]
            if hop == target or len(new_path) >= MAX_HOPS:
                final_paths.append(new_path)
            else:
                paths.put(new_path)

    for p in final_paths:
        print(" -> ".join(map(str, p)))

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
