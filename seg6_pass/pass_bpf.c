#include <stdint.h>
#include "bpf_api.h"


__section("pass")
int do_pass(struct __sk_buff *skb) {
    return BPF_OK; // packet continues
}

__section("drop")
int do_drop(struct __sk_buff *skb) {
    return BPF_DROP; // packet dropped
}


char __license[] __section("license") = "GPL";
