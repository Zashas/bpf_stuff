#!/bin/bash

cleanup()
{
	if [ "$?" = "0" ]; then
		echo "End.OTP [PASS]";
	else
		echo "End.OTP [FAILED]";
	fi

	set +e
	ip netns del ns0 2> /dev/null
	ip netns del ns1 2> /dev/null
	ip netns del ns2 2> /dev/null
	ip netns del ns3 3> /dev/null
	pkill -F /tmp/end_otp_fb00::2b-128.pid
}

#set -x
set -e
trap cleanup 0 2 3 6 9

ip netns add ns0
ip netns add ns1
ip netns add ns2
ip netns add ns3

ip link add veth0 type veth peer name veth0b
ip link add veth1 type veth peer name veth2
ip link add veth3 type veth peer name veth4

ip link set veth0 netns ns0
ip link set veth0b netns ns1
ip link set veth1 netns ns1
ip link set veth2 netns ns2
ip link set veth3 netns ns2
ip link set veth4 netns ns3

ip netns exec ns0 ip link set dev veth0 up
ip netns exec ns1 ip link set dev veth0b up
ip netns exec ns1 ip link set dev veth1 up
ip netns exec ns2 ip link set dev veth2 up
ip netns exec ns2 ip link set dev veth3 up
ip netns exec ns3 ip link set dev veth4 up
ip netns exec ns1 ip link set dev lo up
ip netns exec ns2 ip link set dev lo up

ip netns exec ns1 sysctl net.ipv6.conf.all.forwarding=1
ip netns exec ns1 sysctl net.ipv6.conf.veth1.forwarding=1
ip netns exec ns1 sysctl net.ipv6.conf.veth0b.forwarding=1

ip netns exec ns2 sysctl net.ipv6.conf.all.forwarding=1
ip netns exec ns2 sysctl net.ipv6.conf.veth2.forwarding=1
#ip netns exec ns2 sysctl net.ipv6.conf.all.seg6_enabled=1
#ip netns exec ns2 sysctl net.ipv6.conf.veth2.seg6_enabled=1
#ip netns exec ns2 sysctl net.ipv6.conf.veth3.seg6_enabled=1
ip netns exec ns2 sysctl net.ipv6.conf.lo.seg6_enabled=1

# All link scope addresses and routes required between veths
ip netns exec ns0 ip -6 addr add fe80::100 dev veth0
ip netns exec ns0 ip -6 route add fe80::10 dev veth0
ip netns exec ns1 ip -6 addr add fe80::10/16 dev veth0b
ip netns exec ns1 ip -6 route add fe80::100 dev veth0b
ip netns exec ns1 ip -6 addr add fe80::12/16 dev veth1
ip netns exec ns1 ip -6 route add fe80::21 dev veth1
ip netns exec ns2 ip -6 addr add fe80::21/16 dev veth2
ip netns exec ns2 ip -6 route add fe80::12 dev veth2
ip netns exec ns2 ip -6 addr add fe80::23/16 dev veth3
ip netns exec ns2 ip -6 route add fe80::32 dev veth3
ip netns exec ns3 ip -6 addr add fe80::32/16 dev veth4
ip netns exec ns3 ip -6 route add fe80::23 dev veth4

ip netns exec ns0 ip -6 addr add fb00::0 dev lo
ip netns exec ns1 ip -6 addr add fb00::1 dev lo
ip netns exec ns2 ip -6 addr add fb00::2 dev lo
ip netns exec ns3 ip -6 addr add fb00::3 dev lo
ip netns exec ns3 ip -6 addr add fc00::21 dev lo

ip netns exec ns1 ip sr tunsrc set fb00::1
ip netns exec ns1 tc qdisc add dev veth1 root netem delay 1ms

ip netns exec ns2 ./end_otp.py fb00::2b/128 veth2
#ip netns exec ns2 ip -6 addr add fb00::2b dev veth2
ip netns exec ns0 ip -6 route add fb00::1 via fe80::10 dev veth0
ip netns exec ns0 ip -6 route add fb00::2 via fe80::10 dev veth0
ip netns exec ns0 ip -6 route add fc00::21 via fe80::10 dev veth0
ip netns exec ns1 ip -6 route add fb00::0 via fe80::100 dev veth0b
ip netns exec ns1 ip -6 route add fb00::2b via fe80::21 dev veth1
ip netns exec ns1 ip -6 route add fb00::2 via fe80::21 dev veth1
ip netns exec ns2 ip -6 route add fb00::1 via fe80::12 dev veth2
ip netns exec ns2 ip -6 route add fb00::0 via fe80::12 dev veth2
ip netns exec ns2 ip -6 route add fb00::3 via fe80::32 dev veth3
ip netns exec ns2 ip -6 route add fc00::/16 via fe80::32 dev veth3
ip netns exec ns3 ip -6 route add fb00::0 via fe80::23 dev veth4

#ip netns exec ns1 ip -6 route add fc00::/16 via fb00::21 dev veth1
#ip netns exec ns1 ip -6 rule add fwmark 1 table 150
#simulation/netns.py ns1 ip -6 route add fc00::/16 table 150 encap bpf in obj dm_injector_bpf.o sec main dev veth1
#ip netns exec ns1 ip6tables -t mangle -A PREROUTING -d fc00::/16 -m statistic --mode nth --every 5 --packet 0 -j MARK --set-mark 1

simulation/netns.py ns1 ip -6 route add fc00::/16 encap bpf out obj dm_injector_bpf.o sec main via fe80::21 dev veth1

simulation/netns.py ns1 ./dm_injector_usr fb00::2b 5 fb00::3 9000

#ip netns exec ns1 ip -6 route
#ip netns exec ns1 ip -6 route show table 150
#ip netns exec ns1 ip rule
#ip netns exec ns1 ip6tables -L -t nat

# needed so fb00::1 and fb00::2 both have the other MAC address in cache
# otherwise the first measure is flawed
ip netns exec ns0 ping -I fb00:: fb00::2 -c 3

sleep 1
read -p "Press enter to start measuring"

ip netns exec ns3 bash -c "simulation/recv.py &"
sleep 1
for i in {0..4}
  do
     delay="$((10 ** $i))"
     delay="$(($delay / 10))"
     ip netns exec ns1 tc qdisc change dev veth1 root netem delay ${delay}ms
     echo "delay: $delay"
     set +e
     ip netns exec ns0 ping -I fb00::0 fc00::21 -c 10 -i 0.2
     set -e
 done

exit 1
