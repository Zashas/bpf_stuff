#include "proto.h"

#define NB_MAX_RULES 64

enum proto_transport {TCP, UDP, ICMP};
enum {IP_DST, IP_SRC, PROTO, SPORT, DPORT, TRANS_FLAGS};

struct sfc_rule {
	u8 fields;
	struct ip6_addr ip_dst;
	struct ip6_addr ip_src;
	u8 ip_dst_prefix_len;
	u8 ip_src_prefix_len;
	enum proto_transport proto;
	u16 sport;
	u16 dport;
	u8 transport_flags;

	//struct ip6_srh_t srh;
	//struct ip6_addr __segments_tlv_padding[128]; // Room for 128 segments (without TLV)
};
