#!/usr/bin/python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from pyroute2 import IPRoute

ipr = IPRoute()

text = """
#include <net/sock.h>
#include <bcc/proto.h>
#include <uapi/linux/ptrace.h>


int hello(struct __sk_buff *skb) {
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    unsigned int type = ethernet->type;
    bpf_trace_printk("pkt %d\\n", type == 0x86dd);
    bpf_trace_printk("%u\\n",  skb->data);
    bpf_trace_printk("%u\\n",  skb->data_end);
    return 1;
}
"""

idx = ipr.link_lookup(ifname="lo")[0]
try:
    b = BPF(text=text)
    fn = b.load_func("hello", BPF.SCHED_CLS)
    print(fn.fd)

    ipr.tc("add", "clsact", idx)
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd,
           name=fn.name, parent="ffff:fff2", direct_action=True, classid=1)
    print("Starting tracing ...")
    b.trace_print()

finally:
    ipr.tc("del", "clsact", idx)

"""
        ipr.tc("add", "sfq", idx, "1:")
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd,
           name=fn.name, parent="1:", action="ok", classid=1)
finally:
    if "idx" in locals(): ipr.link_remove(idx)
print("BPF tc functionality - SCHED_CLS: OK")
"""
