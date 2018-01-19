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

struct sr6_tlv_nsh {
    unsigned char type;
    unsigned char len;
    unsigned char flags;
    unsigned char data[5];
} BPF_PACKET_HEADER;

struct sr6_tlv_128 {
    unsigned char type;
    unsigned char len;
    unsigned char reserved;
    unsigned char flags;
    unsigned char data[16];
} BPF_PACKET_HEADER;

struct sr6_tlv_hmac {
    unsigned char type;
    unsigned char len;
    unsigned short reserved;
    unsigned int keyid;
    unsigned char hmac[32];
} BPF_PACKET_HEADER;

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

__section("add_8")
int do_add_8(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv_nsh tlv;
    tlv.type = 6; // NSH
    tlv.len = 6;
    tlv.flags = 0;
    tlv.data[0] = 1;
    tlv.data[1] = 2;
    tlv.data[2] = 3;
    tlv.data[3] = 4;
    tlv.data[4] = 5;
    int ret = skb_seg6_add_tlv(skb, (srh->hdrlen+1) << 3, (struct sr6_tlv *)&tlv);

    if (ret == 0)
        return BPF_OK;
    return BPF_OK;
}

__section("add_6")
int do_add_6(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv_nsh tlv;
    tlv.type = 6; // NSH
    tlv.len = 4;
    tlv.flags = 0;
    tlv.data[0] = 1;
    tlv.data[1] = 2;
    tlv.data[2] = 3;
    int ret = skb_seg6_add_tlv(skb, (srh->hdrlen+1) << 3, (struct sr6_tlv *)&tlv);

    if (ret == 0)
        return BPF_OK;
    return BPF_OK;
}


__section("add_ingr")
int do_add_ingr(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv_128 tlv;
    tlv.type = 1;
    tlv.len = 18;
    tlv.flags = 0;
    tlv.reserved = 0;
    memset(tlv.data, 0, 16);
    tlv.data[15] = 1;
    tlv.data[0] = 0xfc;
    int ret = skb_seg6_add_tlv(skb, (srh->hdrlen+1) << 3, (struct sr6_tlv *)&tlv);

    if (ret == 0)
        return BPF_OK;
    return BPF_OK;
}

__section("add_ingr_no_offset")
int do_add_ingr_no_offset(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv_128 tlv;
    tlv.type = 1;
    tlv.len = 18;
    tlv.flags = 0;
    tlv.reserved = 0;
    memset(tlv.data, 0, 16);
    tlv.data[15] = 1;
    tlv.data[0] = 0xfc;
    int ret = skb_seg6_add_tlv(skb, 0, (struct sr6_tlv *)&tlv);

    if (ret == 0)
        return BPF_OK;
    return BPF_DROP;
}

__section("add_ingr_mid")
int do_add_ingr_mid(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv_128 tlv;
    tlv.type = 1;
    tlv.len = 18;
    tlv.flags = 0;
    tlv.reserved = 0;
    memset(tlv.data, 0, 16);
    tlv.data[15] = 0xef;
    tlv.data[14] = 0xbe;
    tlv.data[0] = 0xfc;
    int ret = skb_seg6_add_tlv(skb, 8 + (srh->first_segment+1)*16 + 20, (struct sr6_tlv *)&tlv);
    printt("ret=%d\n",ret);
    if (ret == 0)
        return BPF_OK;
    return BPF_DROP;
}



__section("add_wrong_offset")
int do_add_ingr_wrong_offset(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv_128 tlv;
    tlv.type = 1;
    tlv.len = 18;
    tlv.flags = 0;
    tlv.reserved = 0;
    memset(tlv.data, 0, 16);
    tlv.data[15] = 1;
    tlv.data[0] = 0xfc;
    int ret = skb_seg6_add_tlv(skb, 11, (struct sr6_tlv *)&tlv);
    if (ret == 0)
        return BPF_OK;
    return BPF_DROP;
}

__section("add_opaq_begin")
int do_add_opaq_begin(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv_128 tlv;
    tlv.type = 3;
    tlv.len = 18;
    tlv.flags = 0;
    tlv.reserved = 0;
    memset(tlv.data, 0, 16);
    tlv.data[15] = 0x42;
    int ret = skb_seg6_add_tlv(skb, 8+(srh->first_segment+1)*16, (struct sr6_tlv *)&tlv);

    if (ret == 0)
        return BPF_OK;
    return BPF_DROP;
}

#define SEG6_FLAGS 0
#define SEG6_FLAG_HMAC		(1 << 3)

__section("add_hmac")
int do_add_hmac(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    int ret = skb_seg6_change_field(skb, SEG6_FLAGS, srh->flags | SEG6_FLAG_HMAC);
    if (ret != 0)
        return BPF_DROP;

    struct sr6_tlv_hmac tlv;
    tlv.type = 5;
    tlv.len = 38;
    tlv.reserved = 0;
    tlv.keyid = htonl(1042);
    memset(tlv.hmac, 0, 32);
    ret = skb_seg6_add_tlv(skb, 0, (struct sr6_tlv *)&tlv);

    if (ret == 0)
        return BPF_OK;
    return BPF_DROP;
}

__section("del_first")
int do_del_first(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    void *data_end = (void *)(long)skb->data_end;
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv *tlv = (struct sr6_tlv *)((char *)srh+8+(srh->first_segment+1)*16);
    if ((void *)tlv > data_end) // Check needed otherwise filter not accepted by the kernel
        return BPF_OK;

    int ret = skb_seg6_delete_tlv(skb, tlv);
    if (ret == 0)
        return BPF_OK;
    return BPF_DROP;
}

__section("del_20")
int do_del_20(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    void *data_end = (void *)(long)skb->data_end;
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv *tlv = (struct sr6_tlv *)((char *)srh+8+(srh->first_segment+1)*16+20);
    if ((void *)tlv > data_end) // Check needed otherwise filter not accepted by the kernel
        return BPF_OK;

    int ret = skb_seg6_delete_tlv(skb, tlv);
    if (ret == 0)
        return BPF_OK;
    return BPF_DROP;
}

__section("del_24")
int do_del_24(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    void *data_end = (void *)(long)skb->data_end;
    if (srh == NULL)
        return BPF_DROP;

    struct sr6_tlv *tlv = (struct sr6_tlv *)((char *)srh+8+(srh->first_segment+1)*16+24);
    if ((void *)tlv > data_end) // Check needed otherwise filter not accepted by the kernel
        return BPF_OK;

    int ret = skb_seg6_delete_tlv(skb, tlv);
    if (ret == 0)
        return BPF_OK;
    return BPF_DROP;
}


char __license[] __section("license") = "GPL";
