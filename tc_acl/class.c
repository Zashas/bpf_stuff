#include "bpf_api.h"
#include "opp.h"
#include "proto.h"

__section("cls")
int hello(struct __sk_buff *skb) {
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    unsigned int type = ethernet->type;
    char fmt[] = "pkt %d\n";
    printt("pkt %d\n", type == 0x86dd);
    printt("%u\n",  skb->data);
    printt("%u\n",  skb->data_end);
    return 1;
}

char __license[] __section("license") = "GPL";
