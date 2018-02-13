#include "bpf_seg6/seg6.h"
#include "classifier.h"

struct bpf_elf_map __section_maps map_rules_nb = {
   .type           =       BPF_MAP_TYPE_ARRAY,
   .id             =       44,
   .size_key       =       4,
   .size_value     =       sizeof(int),
   .max_elem       =       1,
   .pinning        =       PIN_GLOBAL_NS,
};


struct bpf_elf_map __section_maps map_rules = {
   .type           =       BPF_MAP_TYPE_ARRAY,
   .id             =       43,
   .size_key       =       4,
   .size_value     =       sizeof(struct sfc_rule),
   .max_elem       =       NB_MAX_RULES,
   .pinning        =       PIN_GLOBAL_NS,
};

/*struct bpf_elf_map __section_maps map_rules = {
   .type           =       BPF_MAP_TYPE_ARRAY,
   .id             =       42,
   .size_key       =       sizeof(uint32_t),
   .size_value     =       sizeof(uint64_t),
   .max_elem       =       3, // Tag - Seg Low - Seg High 
   .pinning    = PIN_GLOBAL_NS,
};*/



__section("classifier")
int do_classifier(struct __sk_buff *skb) {
	uint8_t *ipver;
	void *data_end = (void *)(long)skb->data_end;
	void *cursor   = (void *)(long)skb->data;
	ipver = (uint8_t*) cursor;

    // TODO we can remove some checks for seg6local as we know we have an IPv6 packet with valid SRH 
	if ((void *)ipver + sizeof(*ipver) > data_end) // Check needed otherwise filter not accepted by the kernel
		return BPF_DROP;

	if ((*ipver >> 4) != 6) // We only care about IPv6 packets
		return BPF_DROP;

	struct ip6_t *ip;
	ip = cursor_advance(cursor, sizeof(*ip));
	if ((void *)ip + sizeof(*ip) > data_end) 
		return BPF_DROP;

	int key=0;
	int *nb_rules = map_lookup_elem(&map_rules_nb, &key);
	if (!nb_rules)
		return BPF_DROP;

	struct sfc_rule *rule = NULL;
	#pragma clang loop unroll(full)
	for (int i=0; i < NB_MAX_RULES; i++) {
		int j = i; // Trick otherwise to verifier won't accept this loop
		if (i >= *nb_rules)
			break;
		rule = map_lookup_elem(&map_rules, &j);
		break;
		// TODO match
	}

	/*if (ip->next_header != 43) // We only care about IPv6 packets with the Routing header
	return BPF_DROP;*/
	if (!rule)
		return BPF_DROP;

	struct ip6_srh_t *srh = (struct ip6_srh_t *)&rule->srh;
	printt("hdrlen %d\n", srh->hdrlen);
	skb_seg6_encap_push(skb, srh);

	return BPF_OK;
}

char __license[] __section("license") = "GPL";
