#include "bpf_seg6/all.h"
#include <errno.h>

struct sr6_tlv_nsh {
    unsigned char type;
    unsigned char len;
    unsigned char flags;
    unsigned char value[5];
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

/*
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
__attribute__((always_inline)) int add_tlv(struct __sk_buff *skb, struct ip6_srh_t *srh, uint32_t tlv_off, struct sr6_tlv *itlv, uint8_t tlv_size)
{
	uint32_t pad_size = 0;
	uint32_t pad_off = 0;
	int srh_off = (char *)srh - (char *)(long)skb->data;
	if (tlv_off != -1)
		tlv_off += srh_off;

	int offset_valid = 0;

	if (itlv->type == SR6_TLV_PADDING || itlv->type == SR6_TLV_HMAC)
		return 0;

	// cur_off = end of segments, start of possible TLVs
	int cur_off = srh_off + sizeof(*srh) + sizeof(struct in6_addr) * (srh->first_segment + 1);

	#pragma clang loop unroll(full)
	for(int i=0; i < 10; i++) { // TODO limitation
		if (cur_off == tlv_off)
			offset_valid = 1;

		if (cur_off >= srh_off + ((srh->hdrlen + 1) << 3))
			break;

		struct sr6_tlv tlv;
		if (skb_load_bytes(skb, cur_off, &tlv, sizeof(tlv)))
			return 0;
		
		if (tlv.type == SR6_TLV_PADDING) {
			pad_size = tlv.len + sizeof(tlv);
			pad_off = cur_off;
			
			if (tlv_off == srh_off) {
				tlv_off = cur_off;
				offset_valid = 1;
			}
			break;
			
		} else if (tlv.type == SR6_TLV_HMAC) {
			break; // TODO consider this end of pkt
		}

		cur_off += sizeof(tlv) + tlv.len;
	}
	if (pad_off == 0)
		pad_off = cur_off;

	if (tlv_off == -1)
		tlv_off = cur_off;
	else if (!offset_valid)
		return 0;

	int err = lwt_seg6_adjust_srh(skb, tlv_off, sizeof(*itlv) + itlv->len);
	if (err != 0) {
		return 0;
	}
	printt("went through\n");

	err = lwt_seg6_store_bytes(skb, tlv_off, (void *)itlv, tlv_size);
	if (err != 0)
		return 0;

	printt("went throug againh\n");
	pad_off += sizeof(*itlv) + itlv->len;
	uint32_t partial_srh_len = pad_off - srh_off;
	uint8_t len_remaining = partial_srh_len % 8;
	uint8_t new_pad = 8 - len_remaining;
	if (new_pad == 1) // cannot pad for 1 byte only
		new_pad = 9;
	else if (new_pad == 8)
		new_pad = 0;

	return update_padding(skb, new_pad, pad_size, pad_off);
}

__attribute__((always_inline)) int delete_tlv(struct __sk_buff *skb, struct ip6_srh_t *srh, uint32_t tlv_off)
{
	uint32_t pad_size = 0;
	uint32_t pad_off = 0;
	int srh_off = (char *)srh - (char *)(long)skb->data;
	tlv_off += srh_off;

	int offset_valid = 0;

	// cur_off = end of segments, start of possible TLVs
	int cur_off = srh_off + sizeof(*srh) + sizeof(struct in6_addr) * (srh->first_segment + 1);

	#pragma clang loop unroll(full)
	for(int i=0; i < 10; i++) { // TODO limitation
		if (cur_off == tlv_off)
			offset_valid = 1;

		if (cur_off >= srh_off + ((srh->hdrlen + 1) << 3))
			break;

		struct sr6_tlv tlv;
		if (skb_load_bytes(skb, cur_off, &tlv, sizeof(tlv)))
			return 0;

		//printt("TLV type %d found at offset %d\n", tlv.type, cur_off);
		
		if (tlv.type == SR6_TLV_PADDING) {
			pad_size = tlv.len + sizeof(tlv);
			pad_off = cur_off;
			
			if (tlv_off == srh_off) {
				tlv_off = cur_off;
				offset_valid = 1;
			}
			break;
			
		} else if (tlv.type == SR6_TLV_HMAC) {
			break; // TODO consider this end of pkt
		}

		cur_off += sizeof(tlv) + tlv.len;
	}
	if (pad_off == 0)
		pad_off = cur_off;

	if (tlv_off == -1)
		tlv_off = cur_off;
	else if (!offset_valid)
		return 0;

	struct sr6_tlv tlv;
	if (skb_load_bytes(skb, tlv_off, &tlv, sizeof(tlv)))
		return 0;

	int err = lwt_seg6_adjust_srh(skb, tlv_off, -(sizeof(tlv) + tlv.len));
	printt("err=%d off=%d len=%d\n",err, tlv_off, -(sizeof(tlv) + tlv.len));
	if (err != 0)
		return 0;
	
	pad_off -= sizeof(tlv) + tlv.len;
	uint32_t partial_srh_len = pad_off - srh_off;
	uint8_t len_remaining = partial_srh_len % 8;
	uint8_t new_pad = 8 - len_remaining;
	if (new_pad == 1) // cannot pad for 1 byte only
		new_pad = 9;
	else if (new_pad == 8)
		new_pad = 0;

	return update_padding(skb, new_pad, pad_size, pad_off);
}*/

__attribute__((always_inline))
int update_tlv_pad(struct __sk_buff *skb, uint32_t new_pad,
		   uint32_t old_pad, uint32_t pad_off)
{
	int err;

	if (new_pad != old_pad) {
		err = lwt_seg6_adjust_srh(skb, pad_off,
					  (int) new_pad - (int) old_pad);
		if (err)
			return err;
	}

	if (new_pad > 0) {
		char pad_tlv_buf[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0};
		struct sr6_tlv_t *pad_tlv = (struct sr6_tlv_t *) pad_tlv_buf;

		pad_tlv->type = SR6_TLV_PADDING;
		pad_tlv->len = new_pad - 2;

		err = lwt_seg6_store_bytes(skb, pad_off, (void *)pad_tlv_buf,
					   new_pad);
		if (err)
			return err;
	}

	return 0;
}

__attribute__((always_inline))
int is_valid_tlv_boundary(struct __sk_buff *skb, struct ip6_srh_t *srh,
			  uint32_t *tlv_off, uint32_t *pad_size,
			  uint32_t *pad_off)
{
	uint32_t srh_off, cur_off;
	int offset_valid = 0;
	int err;

	srh_off = (char *)srh - (char *)(long)skb->data;
	// cur_off = end of segments, start of possible TLVs
	cur_off = srh_off + sizeof(*srh) +
		sizeof(struct ip6_addr) * (srh->first_segment + 1);

	*pad_off = 0;

	// we can only go as far as 10 TLVs due to the BPF stack size
	#pragma clang loop unroll(full)
	for (int i = 0; i < 10; i++) {
		struct sr6_tlv_t tlv;

		if (cur_off == *tlv_off)
			offset_valid = 1;

		if (cur_off >= srh_off + ((srh->hdrlen + 1) << 3))
			break;

		err = skb_load_bytes(skb, cur_off, &tlv, sizeof(tlv));
		if (err)
			return err;

		if (tlv.type == SR6_TLV_PADDING) {
			*pad_size = tlv.len + sizeof(tlv);
			*pad_off = cur_off;

			if (*tlv_off == srh_off) {
				*tlv_off = cur_off;
				offset_valid = 1;
			}
			break;

		} else if (tlv.type == SR6_TLV_HMAC) {
			break;
		}

		cur_off += sizeof(tlv) + tlv.len;
	} // we reached the padding or HMAC TLVs, or the end of the SRH

	if (*pad_off == 0)
		*pad_off = cur_off;

	if (*tlv_off == -1)
		*tlv_off = cur_off;
	else if (!offset_valid)
		return -EINVAL;

	return 0;
}

__attribute__((always_inline))
int add_tlv(struct __sk_buff *skb, struct ip6_srh_t *srh, uint32_t tlv_off,
	    struct sr6_tlv *itlv, uint8_t tlv_size)
{
	uint32_t srh_off = (char *)srh - (char *)(long)skb->data;
	uint8_t len_remaining, new_pad;
	uint32_t pad_off = 0;
	uint32_t pad_size = 0;
	uint32_t partial_srh_len;
	int err;

	if (tlv_off != -1)
		tlv_off += srh_off;

	if (itlv->type == SR6_TLV_PADDING || itlv->type == SR6_TLV_HMAC)
		return -EINVAL;

	err = is_valid_tlv_boundary(skb, srh, &tlv_off, &pad_size, &pad_off);
	if (err)
		return err;

	err = lwt_seg6_adjust_srh(skb, tlv_off, sizeof(*itlv) + itlv->len);
	if (err)
		return err;

	err = lwt_seg6_store_bytes(skb, tlv_off, (void *)itlv, tlv_size);
	if (err)
		return err;

	pad_off += sizeof(*itlv) + itlv->len;
	partial_srh_len = pad_off - srh_off;
	len_remaining = partial_srh_len % 8;
	new_pad = 8 - len_remaining;

	if (new_pad == 1) // cannot pad for 1 byte only
		new_pad = 9;
	else if (new_pad == 8)
		new_pad = 0;

	return update_tlv_pad(skb, new_pad, pad_size, pad_off);
}

__attribute__((always_inline))
int delete_tlv(struct __sk_buff *skb, struct ip6_srh_t *srh,
	       uint32_t tlv_off)
{
	uint32_t srh_off = (char *)srh - (char *)(long)skb->data;
	uint8_t len_remaining, new_pad;
	uint32_t partial_srh_len;
	uint32_t pad_off = 0;
	uint32_t pad_size = 0;
	struct sr6_tlv_t tlv;
	int err;

	tlv_off += srh_off;

	err = is_valid_tlv_boundary(skb, srh, &tlv_off, &pad_size, &pad_off);
	if (err)
		return err;

	err = skb_load_bytes(skb, tlv_off, &tlv, sizeof(tlv));
	if (err)
		return err;

	err = lwt_seg6_adjust_srh(skb, tlv_off, -(sizeof(tlv) + tlv.len));
	if (err)
		return err;

	pad_off -= sizeof(tlv) + tlv.len;
	partial_srh_len = pad_off - srh_off;
	len_remaining = partial_srh_len % 8;
	new_pad = 8 - len_remaining;
	if (new_pad == 1) // cannot pad for 1 byte only
		new_pad = 9;
	else if (new_pad == 8)
		new_pad = 0;

	return update_tlv_pad(skb, new_pad, pad_size, pad_off);
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
    tlv.value[0] = 1;
    tlv.value[1] = 2;
    tlv.value[2] = 3;
    tlv.value[3] = 4;
    tlv.value[4] = 5;
    int err = add_tlv(skb,srh, (srh->hdrlen+1) << 3, (struct sr6_tlv *)&tlv, 8);

    return (err) ? BPF_DROP : BPF_OK;
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
    tlv.value[0] = 1;
    tlv.value[1] = 2;
    tlv.value[2] = 3;
    int err = add_tlv(skb,srh, (srh->hdrlen+1) << 3, (struct sr6_tlv *)&tlv, 6);

    return (err) ? BPF_DROP : BPF_OK;
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
    memset(tlv.value, 0, 16);
    tlv.value[15] = 1;
    tlv.value[0] = 0xfc;
    int err = add_tlv(skb,srh, (srh->hdrlen+1) << 3, (struct sr6_tlv *)&tlv, 20);

    return (err) ? BPF_DROP : BPF_OK;
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
    memset(tlv.value, 0, 16);
    tlv.value[15] = 1;
    tlv.value[0] = 0xfc;
    int err = add_tlv(skb,srh, -1, (struct sr6_tlv *)&tlv, 20);

    return (err) ? BPF_DROP : BPF_OK;
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
    memset(tlv.value, 0, 16);
    tlv.value[15] = 0xef;
    tlv.value[14] = 0xbe;
    tlv.value[0] = 0xfc;
    int err = add_tlv(skb,srh, 8 + (srh->first_segment+1)*16 + 20, (struct sr6_tlv *)&tlv, 20);
    //printt("ret=%d\n",ret);

    return (err) ? BPF_DROP : BPF_OK;
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
    memset(tlv.value, 0, 16);
    tlv.value[15] = 1;
    tlv.value[0] = 0xfc;
    int err = add_tlv(skb,srh, 11, (struct sr6_tlv *)&tlv, 20);

    return (err) ? BPF_DROP : BPF_OK;
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
    memset(tlv.value, 0, 16);
    tlv.value[15] = 0x42;
    int err = add_tlv(skb,srh, 8+(srh->first_segment+1)*16, (struct sr6_tlv *)&tlv, 20);

    return (err) ? BPF_DROP : BPF_OK;
}

__section("del_first")
int do_del_first(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    /*
    struct sr6_tlv *tlv = (struct sr6_tlv *)((char *)srh+8+(srh->first_segment+1)*16);
    if ((void *)tlv > data_end) // Check needed otherwise filter not accepted by the kernel
        return BPF_OK;*/

    int err = delete_tlv(skb, srh, 8+(srh->first_segment+1)*16);
    return (err) ? BPF_DROP : BPF_OK;
}

__section("del_20")
int do_del_20(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    int err = delete_tlv(skb, srh, 8+(srh->first_segment+1)*16+20);
    return (err) ? BPF_DROP : BPF_OK;
}

__section("del_24")
 int do_del_24(struct __sk_buff *skb) {
    struct ip6_srh_t *srh = get_srh(skb);
    if (srh == NULL)
        return BPF_DROP;

    int err = delete_tlv(skb, srh, 8+(srh->first_segment+1)*16+24);
    return (err) ? BPF_DROP : BPF_OK;
}

__section("del_24_hmac")
 int do_del_24_hmac(struct __sk_buff *skb) {
	struct ip6_srh_t *srh = get_srh(skb);
	int offset = (char *)srh - (char *)(long)skb->data;
	if (srh == NULL)
		return BPF_DROP;

	uint8_t flags = srh->flags & (~SR6_FLAG_HMAC);

	int err = delete_tlv(skb, srh, 8+(srh->first_segment+1)*16+24);
	if (err)
		return BPF_DROP;

	lwt_seg6_store_bytes(skb, offset + offsetof(struct ip6_srh_t, flags), (void *) &flags, sizeof(flags));
	return BPF_OK;
}


char __license[] __section("license") = "GPL";
