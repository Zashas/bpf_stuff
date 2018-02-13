#include "bpf_seg6/proto.h"

#define NB_MAX_RULES 64

enum proto_transport {TCP, UDP, ICMP};
enum {IP_DST, IP_SRC, PROTO, SPORT, DPORT, TRANS_FLAGS};

struct sfc_rule {
	uint8_t fields;
	struct ip6_addr ip_dst;
	struct ip6_addr ip_src;
	enum proto_transport proto;
	uint16_t sport;
	uint16_t dport;
	uint8_t transport_flags;

	struct ip6_srh_t srh;
	struct ip6_addr __segments_tlv_padding[128]; // Room for 128 segments (without TLV)
    int end[0];
};
