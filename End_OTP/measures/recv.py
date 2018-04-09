#!/usr/bin/env python

import socket, sys
from threading import Timer

class Timestamp:
    val = 0

    def __init__(self, bits):
        self.val = float(int.from_bytes(bits[0:4], byteorder='big'))
        self.val += float(int.from_bytes(bits[4:8], byteorder='big')) / 10**9


def exit():
    print("no response received")
    sys.exit(1)

UDP_IP = "fb00::1"
UDP_PORT = 9000

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

t = Timer(5, exit)
t.start()

data, addr = sock.recvfrom(48)
t.cancel()
print("received message:", len(data), addr)
t1 = Timestamp(data[16:24])
t2 = Timestamp(data[24:32])
print("1W delay: {}".format(t2.val - t1.val))
sys.exit(0)
