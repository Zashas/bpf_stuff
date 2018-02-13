#include <stdint.h>
#include <stddef.h>

#include "bpf_api.h"
#include "proto.h"

#define SEG6_FLAGS 0 // TODO define proper uapi headers ?
#define SEG6_TAG 1

#define SEG6_FLAG_ALERT (1 << 4)

/* Packet parsing state machine helpers. */
#define cursor_advance(_cursor, _len) \
  ({ void *_tmp = _cursor; _cursor += _len; _tmp; })


struct ip6_srh_t *seg6_get_srh(struct __sk_buff *skb);
