#!/bin/bash

BW1=50
BW2=10

LATENCY1=10
LATENCY2=10

cleanup()
{
	if [ "$?" = "0" ]; then
		echo "selftests: test_lwt_seg6local [PASS]";
	else
		echo "selftests: test_lwt_seg6local [FAILED]";
	fi

	set +e
	ip netns del ns1 2> /dev/null
	ip netns del ns2 2> /dev/null
	ip netns del ns3 2> /dev/null
	ip netns del ns4 2> /dev/null
    pkill -F /tmp/link_aggreg_fc00::4-128.pid
}

set -e

ip netns add ns1
ip netns add ns2
ip netns add ns3
ip netns add ns4

trap cleanup 0 2 3 6 9

ip link add veth1 type veth peer name veth2
ip link add veth3 type veth peer name veth4
ip link add veth5 type veth peer name veth6
ip link add veth7 type veth peer name veth8

ip link set veth1 netns ns1
ip link set veth2 netns ns2
ip link set veth3 netns ns2
ip link set veth4 netns ns3
ip link set veth5 netns ns3
ip link set veth6 netns ns4
ip link set veth7 netns ns2
ip link set veth8 netns ns3

ip netns exec ns1 ip link set dev veth1 up
ip netns exec ns2 ip link set dev veth2 up
ip netns exec ns2 ip link set dev veth3 up
ip netns exec ns3 ip link set dev veth4 up
ip netns exec ns3 ip link set dev veth5 up
ip netns exec ns4 ip link set dev veth6 up
ip netns exec ns2 ip link set dev veth7 up
ip netns exec ns3 ip link set dev veth8 up

# All link scope addresses and routes required between veths
ip netns exec ns1 ip -6 addr add fe80::12/10 dev veth1 scope link
ip netns exec ns1 ip -6 route add fe80::21 dev veth1 scope link
ip netns exec ns2 ip -6 addr add fe80::21/10 dev veth2 scope link
ip netns exec ns2 ip -6 route add fe80::12 dev veth2 scope link
ip netns exec ns2 ip -6 addr add fe80::34/10 dev veth3 scope link
ip netns exec ns2 ip -6 route add fe80::43 dev veth3 scope link
ip netns exec ns3 ip -6 route add fe80::65 dev veth5 scope link
ip netns exec ns3 ip -6 addr add fe80::43/10 dev veth4 scope link
ip netns exec ns3 ip -6 addr add fe80::56/10 dev veth5 scope link
ip netns exec ns3 ip -6 route add fe80::34 dev veth4 scope link
ip netns exec ns4 ip -6 addr add fe80::65/10 dev veth6 scope link
ip netns exec ns4 ip -6 route add fe80::56/10 dev veth6 scope link

ip netns exec ns2 ip -6 addr add fe80::78/10 dev veth7 scope link
ip netns exec ns2 ip -6 route add fe80::87 dev veth7 scope link
ip netns exec ns3 ip -6 addr add fe80::87/10 dev veth8 scope link
ip netns exec ns3 ip -6 route add fe80::78 dev veth8 scope link

ip netns exec ns1 ip -6 addr add fc00::1/16 dev lo
ip netns exec ns2 ip -6 addr add fc00::2/16 dev lo
ip netns exec ns3 ip -6 addr add fc00::3/16 dev lo
ip netns exec ns3 ip -6 addr add fc00::3a/16 dev lo
ip netns exec ns3 ip -6 addr add fc00::3b/16 dev lo
ip netns exec ns4 ip -6 addr add fc00::4/16 dev lo

ip netns exec ns1 ip -6 route add fc00::4 dev veth1 via fe80::21
ip netns exec ns4 ip -6 route add fc00::1 dev veth6 via fe80::56

ip netns exec ns2 ip sr tunsrc set fc00::2
ip netns exec ns2 ip -6 route add fc00::1 dev veth2 via fe80::12
#ip netns exec ns2 ip -6 route add fc00::4 dev veth3 via fe80::43
#ip netns exec ns2 ip -6 route add fc00::4 encap seg6 mode encap segs fc00::3b dev veth3
ip netns exec ns2 ./link_aggreg.py fc00::4/128 veth3 fc00::3a $BW1 fc00::3b $BW2
ip netns exec ns2 ip -6 route add fc00::3 dev veth3 via fe80::43
ip netns exec ns2 ip -6 route add fc00::3a dev veth3 via fe80::43
ip netns exec ns2 ip -6 route add fc00::3b dev veth7 via fe80::87

ip netns exec ns3 ip -6 route add fc00::4 dev veth5 via fe80::65
ip netns exec ns3 ip -6 route add fc00::1 dev veth4 via fe80::34
ip netns exec ns3 ip -6 route add fc00::2 dev veth4 via fe80::34

ip netns exec ns2 tc qdisc add dev veth3 handle 1: root htb default 11
ip netns exec ns2 tc class add dev veth3 parent 1: classid 1:1 htb rate 1000Mbps
ip netns exec ns2 tc class add dev veth3 parent 1:1 classid 1:11 htb rate ${BW1}Mbit
ip netns exec ns2 tc qdisc add dev veth3 parent 1:11 handle 10: netem delay ${LATENCY1}ms
#ip netns exec ns2 tc filter add dev veth3 protocol ip6 parent 1:0 prio 1 u32 match ip dst 10.0.0.1/32 

ip netns exec ns2 tc qdisc add dev veth7 handle 2: root htb default 11
ip netns exec ns2 tc class add dev veth7 parent 2: classid 2:1 htb rate 1000Mbps
ip netns exec ns2 tc class add dev veth7 parent 2:1 classid 2:11 htb rate ${BW2}Mbit
ip netns exec ns2 tc qdisc add dev veth7 parent 2:11 handle 10: netem delay ${LATENCY2}ms

ip netns exec ns2 sysctl net.ipv6.conf.all.forwarding=1 > /dev/null
ip netns exec ns3 sysctl net.ipv6.conf.all.forwarding=1 > /dev/null

ip netns exec ns2 sysctl net.ipv6.conf.all.seg6_enabled=1 > /dev/null
ip netns exec ns2 sysctl net.ipv6.conf.lo.seg6_enabled=1 > /dev/null
ip netns exec ns2 sysctl net.ipv6.conf.veth2.seg6_enabled=1 > /dev/null

ip netns exec ns3 sysctl net.ipv6.conf.all.seg6_enabled=1 > /dev/null
ip netns exec ns3 sysctl net.ipv6.conf.lo.seg6_enabled=1 > /dev/null
ip netns exec ns3 sysctl net.ipv6.conf.veth4.seg6_enabled=1 > /dev/null
ip netns exec ns3 sysctl net.ipv6.conf.veth8.seg6_enabled=1 > /dev/null

sleep 5
ip netns exec ns1 ping -c 10 -I fc00::1 fc00::4

ip netns exec ns4 iperf -s -V -D
sleep 1
echo "Running client"
ip netns exec ns1 iperf -V -t 15 -b 100M -l 1350 -M 1350 -B fc00::1 -c fc00::4 -e

killall iperf
#ip netns exec ns6 nc -l -6 -u -d 7330 > $TMP_FILE &
#ip netns exec ns1 bash -c "echo 'foobar' | nc -w0 -6 -u -p 2121 -s fe80::1 fe80::6 7330"
#sleep 5 # wait enough time to ensure the UDP datagram arrived to the last segment
#kill -INT $!

#if [[ $(< $TMP_FILE) != "foobar" ]]; then
#	exit 1
#fi

exit 0
