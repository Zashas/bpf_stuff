#!/bin/bash
NB_NODES=10
NB_LINKS=11

cleanup()
{
	if [ "$?" = "0" ]; then
		echo "segtrace [PASS]";
	else
		echo "segtrace [FAILED]";
	fi

	set +e
    for i in {1..11}
    do
        ip netns del ns${i} 2> /dev/null
    done
}


# set_link(link, node1, node2)
set_link()
{
    ip link set veth${1}a netns ns${2}
    ip link set veth${1}b netns ns${3}
    ip netns exec ns${2} ip link set dev veth${1}a up
    ip netns exec ns${3} ip link set dev veth${1}b up

    ip netns exec ns${2} ip -6 addr add fb00::${2}${3}a/16 dev veth${1}a scope link
    ip netns exec ns${2} ip -6 route add fb00::${2}${3}b dev veth${1}a scope link

    ip netns exec ns${3} ip -6 addr add fb00::${2}${3}b/16 dev veth${1}b scope link
    ip netns exec ns${3} ip -6 route add fb00::${2}${3}a dev veth${1}b scope link
    echo "Link #$1 created between nodes $2 and $3"
}

set -e
trap cleanup 0 2 3 6 9

for i in {1..10}
do
    ip netns add ns${i}
    ip netns exec ns${i} ip link set dev lo up
    ip netns exec ns${i} ip -6 addr add fc00::${i}:0000/16 dev lo
    ip netns exec ns${i} sysctl net.ipv6.conf.all.forwarding=1 > /dev/null
    echo "NS #$i created"
done

for i in {1..11}
do
    ip link add veth${i}a type veth peer name veth${i}b
done

set_link 1 1 2
set_link 2 2 4
set_link 3 4 7
set_link 4 7 9
set_link 5 9 10
set_link 6 2 3
set_link 7 3 5
set_link 8 3 6
set_link 9 5 8
set_link 10 6 8
set_link 11 8 10

# Poor's man OSPF ...

ip netns exec ns1 ip -6 route add fc00:0000::/32 dev veth1a via fb00::12b
ip netns exec ns2 ip -6 route add fc00::10:0000 dev veth2a via fb00::24b
ip netns exec ns4 ip -6 route add fc00:0000::/32 dev veth3a via fb00::47b
ip netns exec ns7 ip -6 route add fc00:0000::/32 dev veth4a via fb00::79b
ip netns exec ns9 ip -6 route add fc00:0000::/32 dev veth5a via fb00::910b

ip netns exec ns2 ip -6 route add fc00::4:0000 dev veth2a via fb00::24b
ip netns exec ns2 ip -6 route add fc00::7:0000 dev veth2a via fb00::24b
ip netns exec ns2 ip -6 route add fc00::9:0000 dev veth2a via fb00::24b

ip netns exec ns10 ip -6 route add fc00::1:0000 dev veth5b via fb00::910a
ip netns exec ns9  ip -6 route add fc00::1:0000 dev veth4b via fb00::79a
ip netns exec ns7  ip -6 route add fc00::1:0000 dev veth3b via fb00::47a
ip netns exec ns4  ip -6 route add fc00::1:0000 dev veth2b via fb00::24a
ip netns exec ns2  ip -6 route add fc00::1:0000 dev veth1b via fb00::12a

ip netns exec ns2 ip -6 route add    fc00:0000::/32 dev veth6a via fb00::23b
ip netns exec ns2 ip -6 route append fc00::10:0000 dev veth6a via fb00::23b
ip netns exec ns3 ip -6 route add    fc00:0000::/32 dev veth7a via fb00::35b
ip netns exec ns3 ip -6 route append fc00::10:0000 dev veth8a via fb00::36b
ip netns exec ns3 ip -6 route append fc00::6:0000/112 dev veth8a via fb00::36b

ip netns exec ns5 ip -6 route add fc00::10:0000 dev veth9a via fb00::58b
ip netns exec ns5 ip -6 route add fc00::8:0000/112 dev veth9a via fb00::58b
ip netns exec ns6 ip -6 route add fc00::10:0000 dev veth10a via fb00::68b
ip netns exec ns8 ip -6 route add fc00::10:0000 dev veth11a via fb00::810b

ip netns exec ns3 ip -6 route add fc00::1:0000 dev veth6b via fb00::23a
ip netns exec ns5 ip -6 route add fc00::1:0000 dev veth7b via fb00::35a
ip netns exec ns6 ip -6 route add fc00::1:0000 dev veth8b via fb00::36a
ip netns exec ns8 ip -6 route add fc00::1:0000 dev veth9b via fb00::58a

# "unit tests": making sure fc00::1:0000 can communicate with all other nodes
ip netns exec ns1 ping -I fc00::1:0000 fc00::10:0000 -c 1 > /dev/null
ip netns exec ns1 ping -I fc00::1:0000 fc00::2:0000 -c 1 > /dev/null
ip netns exec ns1 ping -I fc00::1:0000 fc00::3:0000 -c 1 > /dev/null
ip netns exec ns1 ping -I fc00::1:0000 fc00::4:0000 -c 1 > /dev/null
ip netns exec ns1 ping -I fc00::1:0000 fc00::5:0000 -c 1 > /dev/null
ip netns exec ns1 ping -I fc00::1:0000 fc00::6:0000 -c 1 > /dev/null
ip netns exec ns1 ping -I fc00::1:0000 fc00::7:0000 -c 1 > /dev/null
ip netns exec ns1 ping -I fc00::1:0000 fc00::8:0000 -c 1 > /dev/null
ip netns exec ns1 ping -I fc00::1:0000 fc00::9:0000 -c 1 > /dev/null
echo "Network is launched!"

exit 0
