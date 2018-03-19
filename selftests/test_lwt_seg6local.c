#include "bpf_seg6/all.h"

inline __attribute__((always_inline)) struct ip6_srh_t *get_srh(struct __sk_buff *skb) {
    uint8_t *ipver;
    void *data_end = (void *)(long)skb->data_end;
    void *cursor   = (void *)(long)skb->data;
    ipver = (uint8_t*) cursor;

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

__attribute__((always_inline)) int update_padding(struct __sk_buff *skb, uint32_t new_pad, uint32_t old_pad, uint32_t pad_off)
{
	int err;
	if (new_pad != old_pad) {
		err = lwt_seg6_adjust_srh(skb, pad_off, (int) new_pad - (int) old_pad);
		if (err != 0) {
			return 0;
		}
	}
	if (new_pad > 0) {
		char pad_tlv_buf[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		struct sr6_tlv *pad_tlv = (struct sr6_tlv *) pad_tlv_buf;
		pad_tlv->type = SR6_TLV_PADDING;
		pad_tlv->len = new_pad - 2;

		err = lwt_seg6_store_bytes(skb, pad_off, (void *)pad_tlv_buf, new_pad);
		if (err != 0)
			return 0;
	}
	return 1;

}
__attribute__((always_inline)) int add_tlv(struct __sk_buff *skb, struct ip6_srh_t *srh, uint32_t tlv_offset, struct sr6_tlv *itlv, uint8_t tlv_size)
{
	uint32_t pad_size = 0;
	uint32_t pad_offset = 0;
	int srh_offset = (char *)srh - (char *)(long)skb->data;
	if (tlv_offset != -1)
		tlv_offset += srh_offset;

	int offset_valid = 0;

	if (itlv->type == SR6_TLV_PADDING || itlv->type == SR6_TLV_HMAC)
		return 0;

	// cur_off = end of segments, start of possible TLVs
	int cur_off = srh_offset + sizeof(*srh) + sizeof(struct in6_addr) * (srh->first_segment + 1);

	#pragma clang loop unroll(full)
	for(int i=0; i < 10; i++) { // TODO limitation
		if (cur_off == tlv_offset)
			offset_valid = 1;

		if (cur_off >= srh_offset + ((srh->hdrlen + 1) << 3))
			break;

		struct sr6_tlv tlv;
		if (skb_load_bytes(skb, cur_off, &tlv, sizeof(tlv)))
			return 0;
		
		if (tlv.type == SR6_TLV_PADDING) {
			pad_size = tlv.len + sizeof(tlv);
			pad_offset = cur_off;
			
			if (tlv_offset == srh_offset) {
				tlv_offset = cur_off;
				offset_valid = 1;
			}
			break;
			
		} else if (tlv.type == SR6_TLV_HMAC) {
			break; // TODO consider this end of pkt
		}

		cur_off += sizeof(tlv) + tlv.len;
	}
	if (pad_offset == 0)
		pad_offset = cur_off;

	if (tlv_offset == -1)
		tlv_offset = cur_off;
	else if (!offset_valid)
		return 0;

	int err = lwt_seg6_adjust_srh(skb, tlv_offset, sizeof(*itlv) + itlv->len);
	if (err != 0) {
		return 0;
	}

	err = lwt_seg6_store_bytes(skb, tlv_offset, (void *)itlv, tlv_size);
	if (err != 0)
		return 0;

	pad_offset += sizeof(*itlv) + itlv->len;
	uint32_t partial_srh_len = pad_offset - srh_offset;
	uint8_t len_remaining = partial_srh_len % 8;
	uint8_t new_pad = 8 - len_remaining;
	if (new_pad == 1) // cannot pad for 1 byte only
		new_pad = 9;
	else if (new_pad == 8)
		new_pad = 0;

	return update_padding(skb, new_pad, pad_size, pad_offset);
}

__attribute__((always_inline)) int delete_tlv(struct __sk_buff *skb, struct ip6_srh_t *srh, uint32_t tlv_offset)
{
	uint32_t pad_size = 0;
	uint32_t pad_offset = 0;
	int srh_offset = (char *)srh - (char *)(long)skb->data;
	tlv_offset += srh_offset;

	int offset_valid = 0;

	// cur_off = end of segments, start of possible TLVs
	int cur_off = srh_offset + sizeof(*srh) + sizeof(struct in6_addr) * (srh->first_segment + 1);

	#pragma clang loop unroll(full)
	for(int i=0; i < 10; i++) { // TODO limitation
		if (cur_off == tlv_offset)
			offset_valid = 1;

		if (cur_off >= srh_offset + ((srh->hdrlen + 1) << 3))
			break;

		struct sr6_tlv tlv;
		if (skb_load_bytes(skb, cur_off, &tlv, sizeof(tlv)))
			return 0;

		//printt("TLV type %d found at offset %d\n", tlv.type, cur_off);
		
		if (tlv.type == SR6_TLV_PADDING) {
			pad_size = tlv.len + sizeof(tlv);
			pad_offset = cur_off;
			
			if (tlv_offset == srh_offset) {
				tlv_offset = cur_off;
				offset_valid = 1;
			}
			break;
			
		} else if (tlv.type == SR6_TLV_HMAC) {
			break; // TODO consider this end of pkt
		}

		cur_off += sizeof(tlv) + tlv.len;
	}
	if (pad_offset == 0)
		pad_offset = cur_off;

	if (tlv_offset == -1)
		tlv_offset = cur_off;
	else if (!offset_valid)
		return 0;

	struct sr6_tlv tlv;
	if (skb_load_bytes(skb, tlv_offset, &tlv, sizeof(tlv)))
		return 0;

	int err = lwt_seg6_adjust_srh(skb, tlv_offset, -(sizeof(tlv) + tlv.len));
	if (err != 0)
		return 0;
	
	pad_offset -= sizeof(tlv) + tlv.len;
	uint32_t partial_srh_len = pad_offset - srh_offset;
	uint8_t len_remaining = partial_srh_len % 8;
	uint8_t new_pad = 8 - len_remaining;
	if (new_pad == 1) // cannot pad for 1 byte only
		new_pad = 9;
	else if (new_pad == 8)
		new_pad = 0;

	return update_padding(skb, new_pad, pad_size, pad_offset);
}

static __attribute__((always_inline)) int has_egr_tlv(struct __sk_buff *skb, struct ip6_srh_t *srh) {
	int srh_offset = (char *)srh - (char *)(long)skb->data;
	int tlv_offset = srh_offset + ((srh->first_segment + 1) << 4);

	struct sr6_tlv_128 tlv;
	if (bpf_skb_load_bytes(skb, tlv_offset, &tlv, sizeof(struct sr6_tlv)))
		return 0;
	
	if (tlv.type == SR6_TLV_EGRESS && tlv.len == 18) {
		int tlv_payload_offset = tlv_offset + sizeof(struct sr6_tlv);
		if (bpf_skb_load_bytes(skb, cur_off+2, tlv.value, 16))
			return 0;

		if (tlv.value[0] == 0xfc00 && tlv.value[15] == 0x4) // got correct egress TLV
			return 1
		else
			return 0;
	}
}

// This function will push a SRH with segments fc00::1, fc00::2, fc00::3,
// fc00::4
__section("encap_srh")
int __encap_srh(struct __sk_buff *skb) {
	char srh_buf[72]; // room for 4 segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->nexthdr = 0;
	srh->hdrlen = 8;
	srh->type = 4;
	srh->segments_left = 3;
	srh->first_segment = 3;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr *seg0 = (struct ip6_addr *)((char*) srh + sizeof(*srh));
	struct ip6_addr *seg1 = (struct ip6_addr *)((char*) seg0 + sizeof(*seg0));
	struct ip6_addr *seg2 = (struct ip6_addr *)((char*) seg1 + sizeof(*seg1));
	struct ip6_addr *seg3 = (struct ip6_addr *)((char*) seg2 + sizeof(*seg2));
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

	int ret = lwt_push_encap(skb, 0, (void *)srh, sizeof(srh_buf));
	if (ret != 0)
		return BPF_DROP;
	return BPF_REDIRECT;
}

// Add an Egress TLV fc00::4, add the flag A,
// and apply End.X action to fc00::42
__section("add_egr_x")
int __add_egr_x(struct __sk_buff *skb) {
	struct ip6_srh_t *srh = get_srh(skb);
	if (srh == NULL)
		return BPF_DROP;

	struct sr6_tlv_128 tlv;
	tlv.type = 2;
	tlv.len = 18;
	tlv.flags = 0;
	tlv.reserved = 0;
	memset(tlv.value, 0, 16);
	tlv.value[15] = 4;
	tlv.value[0] = 0xfc;
	int ok = add_tlv(skb, srh, (srh->hdrlen+1) << 3, (struct sr6_tlv *)&tlv, 20);
	if (!ok)
		return BPF_DROP;

	uint8_t flags = SR6_FLAG_ALERT;
	int offset = sizeof(struct ip6_t) + offsetof(struct ip6_srh_t, flags);
	int err = lwt_seg6_store_bytes(skb, offset, (void *) &flags, sizeof(flags));
	if (err)
		return BPF_DROP;

	struct ip6_addr addr;
	unsigned long long hi = 0xfc00;
	unsigned long long lo = 0x42;
	addr.lo = htonll(lo);
	addr.hi = htonll(hi);
	err = lwt_seg6_action(skb, SEG6_LOCAL_ACTION_END_X, (void *)&addr,sizeof(addr)); // End.X to fc00::14
	if (err)
		return BPF_DROP;
	return BPF_REDIRECT;
}

__section("pop_egr_t")
int __pop_egr_t(struct __sk_buff *skb) {
	struct ip6_srh_t *srh = get_srh(skb);
	if (srh == NULL)
		return BPF_DROP;

	if (srh->flags != SR6_FLAG_ALERT)
		return BPF_DROP;

	uint8_t flags = 0;
	int offset = sizeof(struct ip6_t) + offsetof(struct ip6_srh_t, flags);
	if (lwt_seg6_store_bytes(skb, offset, (void *) &flags, sizeof(flags)));
		return BPF_DROP;

	uint16_t tag = 2442;
	offset = sizeof(struct ip6_t) + offsetof(struct ip6_srh_t, tag);
	if (lwt_seg6_store_bytes(skb, offset, (void *) &tag, sizeof(tag)));
		return BPF_DROP;

	if (srh->hdrlen != 11) // 4 segments + Egress TLV + Padding TLV
		return BPF_DROP;

	if (!has_egr_tlv(skb srh))
		return BPF_DROP;

	int ok = delete_tlv(skb, srh, 8+(srh->first_segment+1)*16);
	if (!ok)
		return BPF_DROP;
	return (ret) ? BPF_OK : BPF_DROP;

	int table = 42;
	err = lwt_seg6_action(skb, SEG6_LOCAL_ACTION_END_T, (void *)&table, sizeof(table));
	if (err)
		return BPF_DROP;

	return BPF_REDIRECT;
}

__section("inspect_ok")
int __inspect_ok(struct __sk_buff *skb)
{
	struct ip6_srh_t *srh = get_srh(skb);
	if (srh == NULL)
		return BPF_DROP;

	if (srh->flags != 0)
		return BPF_DROP;

	if (srh->tag != 2442)
		return BPF_DROP;

	if (srh->hdrlen != 8) // 4 segments
		return BPF_DROP;

	return BPF_OK;
}

char __license[] __section("license") = "GPL";
