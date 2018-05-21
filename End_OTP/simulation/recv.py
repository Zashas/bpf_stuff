#!/usr/bin/env python3

import socket, sys
from threading import Timer

class Timestamp:
    val = 0

    def __init__(self, bits):
        self.val = float(int.from_bytes(bits[0:4], byteorder='big'))
        self.val += float(int.from_bytes(bits[4:8], byteorder='big')) / 10**9

    def __sub__(self, other):
        return self.val - other.val

def exit():
    print("ERROR: no response received")
    sys.exit(1)

UDP_IP = "fb00::1"
UDP_PORT = 9000

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

for i in range(1,6):
    for j in range(1,21):
        data, addr = sock.recvfrom(48)
        t1 = Timestamp(data[16:24])
        t2 = Timestamp(data[24:32])
        print("{}".format(t2 - t1))

sys.exit(0)
