#include <linux/seg6_local.h>
#include "proto.h"

BPF_PERF_OUTPUT(oam_requests);

enum request_type = {DUMP_ROUTES};

struct request {
	uint8_t type;
	char args[16];
}


static __attribute__((always_inline)) void find_oam_tlv(struct __sk_buff *skb, struct ip6_srh_t *srh) {
	int srh_offset = (char *)srh - (char *)(long)skb->data;
	int tlv_offset = srh_offset + ((srh->first_segment + 1) << 4);


	// cur_off = end of segments, start of possible TLVs
	int cur_off = srh_offset + sizeof(*srh) + sizeof(struct in6_addr) * (srh->first_segment + 1);

	#pragma clang loop unroll(full)
	for(int i=0; i < 10; i++) { // TODO limitation
		if (cur_off >= srh_offset + ((srh->hdrlen + 1) << 3))
			break;

		struct sr6_tlv tlv;
		if (bpf_skb_load_bytes(skb, cur_off, &tlv, sizeof(tlv)))
			return;
		bpf_trace_printk("TLV type %d found at offset %d\n", tlv.type, cur_off);
	
		if (tlv.type == SR6_TLV_OPAQ && tlv.len == 16) {
			if (tlv.data[0] == 0x02 && tlv.data[1] == 0x01) { // dump routes
				struct request req;
				req->type = DUMP_ROUTES;

				struct sr6_tlv tlv2;
				if (bpf_skb_load_bytes(skb, cur_off+sizeof(tlv)+tlv.len, &tlv2, sizeof(tlv2)))
					return;

				if (tlv2.type == SR6_TLV_OPAQ && tlv2.len == 16)
					if (bpf_skb_load_bytes(skb, cur_off+2*sizeof(tlv)+tlv.len, req.args, 16))
						return;

				oam_requests.perf_submit_skb(skb, skb->len, &req, sizeof(req));
			}
		}
			
		cur_off += sizeof(tlv) + tlv.len;
	}

	return NULL;
}

static __attribute__((always_inline)) struct ip6_srh_t *get_srh(struct __sk_buff *skb) {
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

    if ((void *)srh + ((srh->hdrlen + 1) << 3) > data_end)
	    return NULL;

    return srh;
}

int OAM_SID(struct __sk_buff *skb) {
	struct ip6_srh_t *srh = get_srh(skb);
	if (!srh)
		return BPF_DROP;
	if (srh->flags & SR6_FLAG_OAM) // OAM flag set, look for an OAM TLV
		find_oam_tlv(skb, srh);
	return BPF_OK;
}

char __license[] __section("license") = "GPL";
