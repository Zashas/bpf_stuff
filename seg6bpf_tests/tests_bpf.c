#include "bpf_seg6/all.h"

inline __attribute__((always_inline)) struct ip6_srh_t *get_srh(struct __sk_buff *skb) {
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

__section("inc_tag")
int do_inc_tag(struct __sk_buff *skb) {
	struct ip6_srh_t *srh = get_srh(skb);
	int offset = (char *)srh - (char *)(long)skb->data;
	if (srh == NULL)
		return BPF_DROP;

	uint16_t tag = ntohs(srh->tag);
	tag = htons(tag+1);
	skb_seg6_store_bytes(skb, offset + offsetof(struct ip6_srh_t, tag), (void *) &tag, sizeof(srh->tag));
	return BPF_OK;
}

__section("alert")
int do_alert(struct __sk_buff *skb) {
	struct ip6_srh_t *srh = get_srh(skb);
	int offset = (char *)srh - (char *)(long)skb->data;
	if (srh == NULL)
		return BPF_DROP;

	uint8_t flags = srh->flags | SR6_FLAG_ALERT;
	skb_seg6_store_bytes(skb, offset + offsetof(struct ip6_srh_t, flags), (void *) &flags, sizeof(flags));
	return BPF_OK;
}

__section("end_x")
int do_end_x(struct __sk_buff *skb) {
	struct ip6_addr addr;
	unsigned long long hi = 0xfc42000000000000;
	unsigned long long lo = 0x1;
	addr.lo = htonll(lo);
	addr.hi = htonll(hi);
	skb_seg6_action(skb, SEG6_LOCAL_ACTION_END_X, (void *)&addr); // End.X to fc00::14
	return BPF_REDIRECT;
}

__section("end_t")
int do_end_t(struct __sk_buff *skb)
{
	int table = 42;
	skb_seg6_action(skb, SEG6_LOCAL_ACTION_END_T, (void *)&table);
	return BPF_REDIRECT;
}

__section("end_b6")
int do_end_b6(struct __sk_buff *skb) {
	char srh_buf[40]; // room for two segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->hdrlen = 4;
	srh->type = 4;
	srh->segments_left = 1;
	srh->first_segment = 1;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr *seg0 = (struct ip6_addr *)((char*) srh + sizeof(*srh));
	struct ip6_addr *seg1 = (struct ip6_addr *)((char*) seg0 + sizeof(*seg1));
	unsigned long long hi = 0xfc00000000000000;
	unsigned long long lo = 0x1;
	seg0->lo = htonll(lo);
	seg0->hi = htonll(hi);

	seg1->hi = seg0->hi;
	lo = 0x2;
	seg1->lo = htonll(lo);

	int ret = skb_push_encap(skb, 1, (void *)srh, sizeof(srh_buf));
	if (ret != 0)
		return BPF_DROP;
	return BPF_REDIRECT;
}

__section("end_b6_wrong")
int do_end_b6_wrong(struct __sk_buff *skb) {
	char srh_buf[40]; // room for two segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->hdrlen = 4;
	srh->type = 4;
	srh->segments_left = 2;
	srh->first_segment = 1;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr *seg0 = (struct ip6_addr *)((char*) srh + sizeof(*srh));
	struct ip6_addr *seg1 = (struct ip6_addr *)((char*) seg0 + sizeof(*seg1));
	unsigned long long hi = 0xfc00000000000000;
	unsigned long long lo = 0x1;
	seg0->lo = htonll(lo);
	seg0->hi = htonll(hi);

	seg1->hi = seg0->hi;
	lo = 0x2;
	seg1->lo = htonll(lo);

	int ret = skb_push_encap(skb, 1, (void *)srh, sizeof(srh_buf));
	if (ret != 0)
		return BPF_DROP;

	return BPF_REDIRECT;
}

__section("encap_push")
int do_encap_push(struct __sk_buff *skb) {
	char srh_buf[40]; // room for two segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->hdrlen = 4;
	srh->type = 4;
	srh->segments_left = 1;
	srh->first_segment = 1;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr *seg0 = (struct ip6_addr *)((char*) srh + sizeof(*srh));
	struct ip6_addr *seg1 = (struct ip6_addr *)((char*) seg0 + sizeof(*seg1));
	unsigned long long hi = 0xfc00000000000000;
	unsigned long long lo = 0x1;
	seg0->lo = htonll(lo);
	seg0->hi = htonll(hi);

	seg1->hi = seg0->hi;
	lo = 0x2;
	seg1->lo = htonll(lo);

	int ret = skb_push_encap(skb, 0, (void *)srh, sizeof(srh_buf));
	if (ret != 0)
		return BPF_DROP;
	return BPF_REDIRECT;
}

__section("long_encap_push")
int do_long_encap_push(struct __sk_buff *skb) {
	char srh_buf[88]; // room for 5 segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->hdrlen = 10;
	srh->type = 4;
	srh->segments_left = 4;
	srh->first_segment = 4;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr *seg0 = (struct ip6_addr *)((char*) srh + sizeof(*srh));
	struct ip6_addr *seg1 = (struct ip6_addr *)((char*) seg0 + sizeof(*seg0));
	struct ip6_addr *seg2 = (struct ip6_addr *)((char*) seg1 + sizeof(*seg1));
	struct ip6_addr *seg3 = (struct ip6_addr *)((char*) seg2 + sizeof(*seg2));
	struct ip6_addr *seg4 = (struct ip6_addr *)((char*) seg3 + sizeof(*seg3));
	unsigned long long hi = 0xfc00000000000000;
	unsigned long long lo = 0x1;
	seg0->lo = htonll(lo);
	seg0->hi = htonll(hi);

	seg1->hi = seg0->hi;
	lo = 0x2;
	seg1->lo = htonll(lo);

	seg2->hi = seg0->hi;
	lo = 0x3;
	seg2->lo = htonll(lo);

	seg3->hi = seg0->hi;
	lo = 0x4;
	seg3->lo = htonll(lo);

	seg4->hi = seg0->hi;
	lo = 0x5;
	seg4->lo = htonll(lo);

	int ret = skb_push_encap(skb, 0, (void *)srh, sizeof(srh_buf));
	if (ret != 0)
		return BPF_DROP;
	return BPF_REDIRECT;
}

char __license[] __section("license") = "GPL";
