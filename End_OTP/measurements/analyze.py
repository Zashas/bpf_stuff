import sys, dpkt, struct, numpy
import binascii

def to_hex(b):
    return binascii.hexlify(bytearray(b))

def extract_ts(buf):
    eth = dpkt.ethernet.Ethernet(buf)
    ip6 = eth.data
    srh = ip6.extension_hdrs[dpkt.ip.IP_PROTO_ROUTING]
    tlv = srh.data[32:]
    t3 = struct.unpack('!II', tlv[32:40])
    #t3_s = int.from_bytes(t3[0:8], byteorder='big')
    ##t3_ns = int.from_bytes(t3[8:16], byteorder='big')
    ##print(to_hex(t3[0:8]))

    return t3[0] + t3[1]/10**9

def get_samples_pcap(f):
    samples = []

    pcap = dpkt.pcap.Reader(f)
    pkts = iter(pcap)
    for ts, buf in pkts:
        sample = {}
        sample['T2'] = float(ts)

        ts, buf = next(pkts)
        sample['T3'] = float(ts)
        sample['TLV'] = extract_ts(buf)
        samples.append(sample)

    return samples

def get_samples_txt(f):
    samples = []

    for l in f.readlines():
        tstamps = map(float, [x.split(':')[1] for x in l.split('\t')])
        sample = {'T1':next(tstamps), 'T4':next(tstamps)}
        samples.append(sample)

    return samples

if len(sys.argv) < 3:
    print("Usage: read_pcap.py PCAP_FILE TXT_FILE")
    sys.exit(1)

try:
    f1 = open(sys.argv[1], 'rb')
except FileNotFoundError:
    print("Could not open {}.".format(sys.argv[1]))

try:
    f2 = open(sys.argv[2], 'r')
except FileNotFoundError:
    print("Could not open {}.".format(sys.argv[2]))

samples_pcap = get_samples_pcap(f1)
samples_txt = get_samples_txt(f2)

samples = [{**x, **y} for x,y in zip(samples_pcap, samples_txt)]

diff1 = [] 
diff2 = []
for sample in samples:
    diff1.append(sample['TLV'] - sample['T2'])
    diff2.append(sample['T3'] - sample['TLV'])
    #print('\t'.join(['{}:{}'.format(k, v) for k,v in sample.items()]))
    #print('TLV - T2:{}'.format(sample['TLV'] - sample['T2']))
    #print('T3 - TLV:{}'.format(sample['T3'] - sample['TLV']))
    #print('')

print('TLV - T2: mean={}, std={}'.format(numpy.mean(diff1), numpy.std(diff1)))
print('T3 - TLV: mean={}, std={}'.format(numpy.mean(diff2), numpy.std(diff2)))
