#include <stdint.h>
#include "proto.h"
#include "bpf_api.h"

/* Packet parsing state machine helpers. */
#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })


struct bpf_elf_map __section_maps map_acl = {
   .type           =       BPF_MAP_TYPE_ARRAY,
   .id             =       42,
   .size_key       =       sizeof(uint32_t),
   .size_value     =       sizeof(uint64_t),
   .max_elem       =       3, // Tag - Seg Low - Seg High 
   .pinning    = PIN_GLOBAL_NS,
};

__section("cls")
int acl(struct __sk_buff *skb) {
    int key=0;

    uint16_t *TAG_DROP;
    TAG_DROP = map_lookup_elem(&map_acl, &key); //42
    key++;

    uint64_t *ADDR_LOW_DROP, *ADDR_HIGH_DROP;
    ADDR_HIGH_DROP = map_lookup_elem(&map_acl, &key);
    key++;
    ADDR_LOW_DROP = map_lookup_elem(&map_acl, &key);

    // Because of segway using a tun device, the packet in skb->data is an IP packet (no Ethernet header)
    uint8_t *ipver;
    void *data_end = (void *)(long)skb->data_end;
    void *cursor   = (void *)(long)skb->data;
    ipver = (uint8_t*) cursor;

    if ((void *)ipver + sizeof(*ipver) > data_end) // Check needed otherwise filter not accepted by the kernel
        goto EOP;

    if ((*ipver >> 4) != 6) // We only care about IPv6 packets
        goto EOP;

    struct ip6_t *ip;
    ip = cursor_advance(cursor, sizeof(*ip));
    if ((void *)ip + sizeof(*ip) > data_end) 
        goto EOP;

    if (ip->next_header != 43) // We only care about IPv6 packets with the Routing header
        goto EOP;

    struct ip6_srh_t *srh;
    srh = cursor_advance(cursor, sizeof(*srh));
    if ((void *)srh + sizeof(*srh) > data_end)
        goto EOP;

    if (srh->type != 4) // We only care about SRv6 packets
        goto EOP;

    struct in6_addr *seg = srh->segments;
    if ((void *)seg + sizeof(*seg) > data_end)
        goto EOP;

    //printt("nxthdr: %u, hdrlen: %u, type:%u\n", srh->nexthdr, srh->hdrlen, srh->type);
    //printt("SL: %u, first seg: %u, flags: %u\n", srh->segments_left, srh->first_segment, srh->flags);
    //printt("Tag: %u / Last seg: %llx %llx\n", ntohs(srh->tag), ntohll(seg->hi), ntohll(seg->lo));
    if (TAG_DROP) {
        if (ntohs(srh->tag) == *TAG_DROP)
            goto DROP;
    }
    else {
        goto EOP;
    }

    if (ADDR_LOW_DROP && ADDR_HIGH_DROP) {
        if (seg->lo == *ADDR_LOW_DROP && seg->hi == *ADDR_HIGH_DROP)
            goto DROP;
    }
    else {
        goto EOP;
    }

EOP:
    return TC_ACT_OK; // packet continues
DROP:
    return TC_ACT_SHOT; // packet is dropped
}

char __license[] __section("license") = "GPL";

/*
   struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
};
*/
