#include "proto.h"
#include "libseg6.c"

#define SR6_TLV_OAM 8
#define SR6_TLV_URO 131
#define OAM_DUMP_RT 1

BPF_PERF_OUTPUT(oam_requests);

struct tlv_oam_t {
	uint8_t tlv_type;
	uint8_t len;
	uint8_t type;
	uint8_t reserved;
	uint16_t session_id;
	uint16_t reserved2;
	uint8_t args[16];
} BPF_PACKET_HEADER;

struct oam_request {
	struct tlv_oam_t oam_tlv;
	struct ip6_addr_t sender;
};

int SEG6_OAM(struct __sk_buff *skb) {
	struct ip6_srh_t *srh = seg6_get_srh(skb);
	if (!srh)
		return BPF_DROP;
	if (!(srh->flags & SR6_FLAG_OAM)) // if no OAM flag, let the packet simply go on
		return BPF_OK;

	struct ip6_t *ip = (void *)(long)skb->data;
	if ((void *)ip + sizeof(*ip) > (void *)(long)skb->data_end)
		return BPF_DROP;

	struct oam_request req;
	req.sender.hi = ip->src_hi;
	req.sender.lo = ip->src_lo;

	int cursor = seg6_find_tlv(skb, srh, SR6_TLV_OAM, sizeof(req.oam_tlv));
	if (cursor < 0) // no OAM TLV found, nevermind
		return BPF_OK;
	if (bpf_skb_load_bytes(skb, cursor, &req.oam_tlv, sizeof(req.oam_tlv)) < 0)
		return BPF_OK;

	oam_requests.perf_submit_skb(skb, skb->len, &req, sizeof(req));
	return BPF_OK;
}

char __license[] __section("license") = "GPL";
