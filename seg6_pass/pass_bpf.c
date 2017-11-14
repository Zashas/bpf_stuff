#include <stdint.h>
#include <stddef.h>
#include "bpf_api.h"
#include "proto.h"

#define SEG6_FLAGS 0 // TODO define proper uapi headers ?
#define SEG6_TAG 1

#define SEG6_FLAG_ALERT (1 << 4)

/* Packet parsing state machine helpers. */
#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

struct ip6_srh_t *get_srh(struct __sk_buff *skb) {
    uint8_t *ipver;
    void *data_end = (void *)(long)skb->data_end;
    void *cursor   = (void *)(long)skb->data;
    ipver = (uint8_t*) cursor;

    // TODO we can remove some checks for seg6local as we know we have an IPv6 packet with valid SRH 
    if ((void *)ipver + sizeof(*ipver) > data_end) // Check needed otherwise filter not accepted by the kernel
        return NULL;

    if ((*ipver >> 4) != 6) // We only care about IPv6 packets
        return NULL;

    struct ip6_t *ip;
    ip = cursor_advance(cursor, sizeof(*ip));
    if ((void *)ip + sizeof(*ip) > data_end) 
        return NULL;

    if (ip->next_header != 43) // We only care about IPv6 packets with the Routing header
        return NULL;

    struct ip6_srh_t *srh;
    srh = cursor_advance(cursor, sizeof(*srh));
    if ((void *)srh + sizeof(*srh) > data_end)
        return NULL;

    if (srh->type != 4) // We only care about SRv6 packets
        return NULL;

    return srh;
}

__section("pass")
int do_pass(struct __sk_buff *skb) {
    return BPF_OK; // packet continues
}

__section("drop")
int do_drop(struct __sk_buff *skb) {
    return BPF_DROP; // packet dropped
}

__section("inc")
int do_inc(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    uint16_t tag = ntohs(srh->tag);
    tag = htons(tag+1);
    seg6_change_field(skb, SEG6_TAG, (uint32_t) tag);
    return BPF_OK;
}

__section("alert")
int do_alert(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    seg6_change_field(skb, SEG6_FLAGS, (uint32_t) srh->flags | SEG6_FLAG_ALERT);
    return BPF_OK;
}



char __license[] __section("license") = "GPL";
