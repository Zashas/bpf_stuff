#!/bin/bash

BW_SOUTH=10
BW_NORTH=10

LATENCY_SOUTH=20
LATENCY_NORTH=20

cleanup()
{
	if [ "$?" = "0" ]; then
		echo "selftests: test_lwt_seg6local [PASS]";
	else
		echo "selftests: test_lwt_seg6local [FAILED]";
	fi

	set +e
	pkill -F /tmp/link_aggreg_fc00::4-128.pid
	ip netns del ns1 2> /dev/null
	ip netns del ns2 2> /dev/null
	ip netns del ns3 2> /dev/null
	ip netns del ns4 2> /dev/null
	ip netns del ns2N 2> /dev/null
	ip netns del ns2S 2> /dev/null
}

set -e
#set -x

ip netns add ns1
ip netns add ns2
ip netns add ns3
ip netns add ns4
ip netns add ns2N
ip netns add ns2S

trap cleanup 0 2 3 6 9

ip link add veth1 type veth peer name veth2
ip link add veth3 type veth peer name veth3bis
ip link add veth4 type veth peer name veth4bis
ip link add veth5 type veth peer name veth6
ip link add veth7 type veth peer name veth7bis
ip link add veth8 type veth peer name veth8bis

ip link set veth1 netns ns1
ip link set veth2 netns ns2
ip link set veth3 netns ns2
ip link set veth4 netns ns3
ip link set veth5 netns ns3
ip link set veth6 netns ns4
ip link set veth7 netns ns2
ip link set veth8 netns ns3
ip link set veth3bis netns ns2S
ip link set veth4bis netns ns2S
ip link set veth7bis netns ns2N
ip link set veth8bis netns ns2N

ip netns exec ns1 ip link set dev veth1 up
ip netns exec ns2 ip link set dev veth2 up
ip netns exec ns2 ip link set dev veth3 up
ip netns exec ns3 ip link set dev veth4 up
ip netns exec ns3 ip link set dev veth5 up
ip netns exec ns4 ip link set dev veth6 up
ip netns exec ns2 ip link set dev veth7 up
ip netns exec ns3 ip link set dev veth8 up

ip netns exec ns2S ip link set dev veth3bis up
ip netns exec ns2S ip link set dev veth4bis up
ip netns exec ns2N ip link set dev veth7bis up
ip netns exec ns2N ip link set dev veth8bis up

ip netns exec ns2S ip link add name brS type bridge
ip netns exec ns2S ip link set brS up
ip netns exec ns2S ip link set veth3bis master brS
ip netns exec ns2S ip link set veth4bis master brS

ip netns exec ns2N ip link add name brN type bridge
ip netns exec ns2N ip link set brN up
ip netns exec ns2N ip link set veth7bis master brN
ip netns exec ns2N ip link set veth8bis master brN

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
ip netns exec ns2 ip -6 route add fc00::3 dev veth3 via fe80::43
ip netns exec ns2 ip -6 route add fc00::3a dev veth3 via fe80::43
ip netns exec ns2 ip -6 route add fc00::3b dev veth7 via fe80::87

ip netns exec ns3 ip -6 route add fc00::4 dev veth5 via fe80::65
ip netns exec ns3 ip -6 route add fc00::1 dev veth4 via fe80::34
ip netns exec ns3 ip -6 route add fc00::2 dev veth4 via fe80::34
ip netns exec ns3 ip -6 route add fc00::2a dev veth4 via fe80::34

set +e
rm /sys/fs/bpf/ip/globals/end_otp_delta
set -e

./netns.py ns3 /home/math/shared/iproute2/ip/ip -6 route add fc00::3c encap seg6local action End.BPF obj tiny_end_otp/end_otp_bpf.o section end_otp dev veth4
./netns.py ns3 tiny_end_otp/end_otp_usr

ip netns exec ns2S tc qdisc add dev veth4bis handle 1: root htb default 11
ip netns exec ns2S tc class add dev veth4bis parent 1: classid 1:1 htb rate 1000Mbps
ip netns exec ns2S tc class add dev veth4bis parent 1:1 classid 1:11 htb rate ${BW_SOUTH}Mbit
ip netns exec ns2S tc qdisc add dev veth4bis parent 1:11 handle 10: netem delay ${LATENCY_SOUTH}ms

ip netns exec ns2 tc qdisc add dev veth3 root handle 1: htb default 42 # default non-classified traffic goes to 1:12
ip netns exec ns2 tc class add dev veth3 parent 1: classid 1:1 htb rate 1000Mbps
ip netns exec ns2 tc class add dev veth3 parent 1: classid 1:2 htb rate 1000Mbps
ip netns exec ns2 tc class add dev veth3 parent 1: classid 1:3 htb rate 1000Mbps
ip netns exec ns2 tc filter add dev veth3 protocol all parent 1: prio 2 u32 match u32 0 0 flowid 1:1
ip netns exec ns2 tc filter add dev veth3 protocol ipv6 parent 1: prio 1 u32 match ip6 dst fc00::3a flowid 1:2
ip netns exec ns2 tc filter add dev veth3 protocol ipv6 parent 1: prio 1 u32 match ip6 dst fc00::3b flowid 1:3
ip netns exec ns2 tc qdisc add dev veth3 parent 1:1 handle 20: sfq
ip netns exec ns2 tc qdisc add dev veth3 parent 1:2 handle 12: netem delay 15ms
ip netns exec ns2 tc qdisc add dev veth3 parent 1:3 handle 13: netem delay 20ms

ip netns exec ns2 tc qdisc add dev veth7 root handle 1: htb default 42 # default non-classified traffic goes to 1:12
ip netns exec ns2 tc class add dev veth7 parent 1: classid 1:1 htb rate 1000Mbps
ip netns exec ns2 tc class add dev veth7 parent 1: classid 1:2 htb rate 1000Mbps
ip netns exec ns2 tc class add dev veth7 parent 1: classid 1:3 htb rate 1000Mbps
ip netns exec ns2 tc filter add dev veth7 protocol all parent 1: prio 2 u32 match u32 0 0 flowid 1:1
ip netns exec ns2 tc filter add dev veth7 protocol ipv6 parent 1: prio 1 u32 match ip6 dst fc00::3a flowid 1:2
ip netns exec ns2 tc filter add dev veth7 protocol ipv6 parent 1: prio 1 u32 match ip6 dst fc00::3b flowid 1:3
ip netns exec ns2 tc qdisc add dev veth7 parent 1:1 handle 20: sfq
ip netns exec ns2 tc qdisc add dev veth7 parent 1:2 handle 12: netem delay 15ms
ip netns exec ns2 tc qdisc add dev veth7 parent 1:3 handle 13: netem delay 20ms
ip netns exec ns2 tc qdisc change dev veth7 parent 1:3 handle 13: netem delay 10ms

ip netns exec ns2N tc qdisc add dev veth8bis handle 2: root htb default 11
ip netns exec ns2N tc class add dev veth8bis parent 2: classid 2:1 htb rate 1000Mbps
ip netns exec ns2N tc class add dev veth8bis parent 2:1 classid 2:11 htb rate ${BW_NORTH}Mbit
ip netns exec ns2N tc qdisc add dev veth8bis parent 2:11 handle 10: netem delay ${LATENCY_NORTH}ms

ip netns exec ns2 sysctl net.ipv6.conf.all.forwarding=1 > /dev/null
ip netns exec ns2N sysctl net.ipv6.conf.all.forwarding=1 > /dev/null
ip netns exec ns2S sysctl net.ipv6.conf.all.forwarding=1 > /dev/null
ip netns exec ns3 sysctl net.ipv6.conf.all.forwarding=1 > /dev/null

ip netns exec ns2 sysctl net.ipv6.conf.all.seg6_enabled=1 > /dev/null
ip netns exec ns2 sysctl net.ipv6.conf.lo.seg6_enabled=1 > /dev/null
ip netns exec ns2 sysctl net.ipv6.conf.veth2.seg6_enabled=1 > /dev/null

ip netns exec ns3 sysctl net.ipv6.conf.all.seg6_enabled=1 > /dev/null
ip netns exec ns3 sysctl net.ipv6.conf.lo.seg6_enabled=1 > /dev/null
ip netns exec ns3 sysctl net.ipv6.conf.veth4.seg6_enabled=1 > /dev/null
ip netns exec ns3 sysctl net.ipv6.conf.veth8.seg6_enabled=1 > /dev/null

sleep 3
ip netns exec ns2 ./link_aggreg.py fc00::4/128 veth3 fc00::3a fc00::3c $BW_SOUTH fc00::3b fc00::3c $BW_NORTH fc00::2a/128
sleep 1
ip netns exec ns1 ping -c 10 -I fc00::1 fc00::4

#ip netns exec ns4 iperf -s -V -D
#sleep 1
#ip netns exec ns1 iperf -V -t 3 -l 1350 -M 1350 -B fc00::1 -c fc00::4 -e
##ip netns exec ns1 iperf -b 150M -V -t 15 -l 1350 -M 1350 -B fc00::1 -c fc00::4 -e -u

#killall iperf

exit 0
