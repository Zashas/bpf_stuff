#include "bpf_api.h"
#include "opp.h"
#include "proto.h"

__section("cls")
int hello(struct __sk_buff *skb) {
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    unsigned int type = ethernet->type;
    char fmt[] = "pkt %d\n";
    trace_printk(fmt, sizeof(fmt), type == 0x86dd);
    //trace_printk("%u\\n",  skb->data);
    //trace_printk("%u\\n",  skb->data_end);
    return 1;
}

char __license[] __section("license") = "GPL";
