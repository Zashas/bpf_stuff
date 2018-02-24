//#include "bpf_seg6/seg6.h"
#include "classifier.h"

BPF_ARRAY(nb_pkts, u32, 1);
BPF_PERF_OUTPUT(dropped_pkts);

int classifier(struct __sk_buff *skb) {
	u8 *ipver;
	void *data_end = (void *)(long)skb->data_end;
	void *cursor   = (void *)(long)skb->data;
	ipver = (u8*) cursor;
	int key = 0;
	int *val = NULL;
	int val2 = 0;

	char srh_buf[72]; // room for max. 3 segments
	struct ip6_srh_t *srh = (struct ip6_srh_t *)srh_buf;
	srh->nexthdr = 0;
	srh->type = 4;
	srh->flags = 0;
	srh->tag = 0;

	struct ip6_addr *seg0 = (struct ip6_addr *)((char*) srh + sizeof(*srh));
	struct ip6_addr *seg1 = (struct ip6_addr *)((char*) seg0 + sizeof(*seg0));
	struct ip6_addr *seg2 = (struct ip6_addr *)((char*) seg1 + sizeof(*seg1));
	struct ip6_addr *seg3 = (struct ip6_addr *)((char*) seg2 + sizeof(*seg2));
	seg0->lo = 0; // This will be filled by the push_encap helper.
	seg0->hi = 0; // But still needed by the BPF verifier ..

	val = nb_pkts.lookup(&key);
	if (val) {
		lock_xadd(val, 1);
		val2 = *val;
	} else {
		val2 = 0;
	}

	// Checks needed otherwise filter not accepted by the in-kernel BPF verifier
	if ((void *)ipver + sizeof(*ipver) > data_end) 
		goto drop;

	if ((*ipver >> 4) != 6) // We only care about IPv6 packets
		goto drop;

	struct ip6_t *ip;
	ip = cursor_advance(cursor, sizeof(*ip));
	if ((void *)ip + sizeof(*ip) > data_end) 
		goto drop;

	int ret;
	if (ip->next_header == 6) { // if TCP
		struct tcp_t *tcp = cursor_advance(cursor, sizeof(struct tcp_t));
		if ((void *)tcp + sizeof(*tcp) > data_end) 
			goto drop;

		if (ntohs(tcp->dst_port) == 443) {
			bpf_trace_printk("this is HTTPS\n");
			unsigned long long hi = 0xfc00bbbb00000000;
			unsigned long long lo = 0x2;
			seg1->lo = bpf_htonll(lo);
			seg1->hi = bpf_htonll(hi);

			seg2->hi = seg1->hi;
			lo = 0x1;
			seg2->lo = bpf_htonll(lo);

			seg3->hi = 0;
			seg3->lo = 0;

			srh->hdrlen = 6;
			srh->segments_left = 2;
			srh->first_segment = 2;
			ret = bpf_skb_push_encap(skb, 1, (void *)srh, 56);
		} else if (ntohs(tcp->dst_port) == 80) {
			bpf_trace_printk("this is HTTP\n");
			unsigned long long hi = 0xfc00aaaa00000000;
			unsigned long long lo = 0x3;
			seg1->lo = bpf_htonll(lo);
			seg1->hi = bpf_htonll(hi);

			seg2->hi = seg1->hi;
			lo = 0x2;
			seg2->lo = bpf_htonll(lo);

			seg3->hi = seg1->hi;
			lo = 0x1;
			seg3->lo = bpf_htonll(lo);

			srh->hdrlen = 8;
			srh->segments_left = 3;
			srh->first_segment = 3;

			ret = bpf_skb_push_encap(skb, 0, (void *)srh, 72);
		}
		else
			goto drop;
	} else
		goto drop;

	return ret ? BPF_DROP : BPF_REDIRECT;
drop:
	dropped_pkts.perf_submit_skb(skb, skb->len, &val2, sizeof(val2));
	return BPF_DROP;
}

char __license[] __section("license") = "GPL";
