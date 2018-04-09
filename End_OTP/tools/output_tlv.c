#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>

struct __sk_buff {int a;};
#include "proto.h"

#define SR6_TLV_DM 7
#define SR6_TLV_URO 131


struct timestamp_ieee1588_v2 {
	uint32_t tv_sec;
	uint32_t tv_nsec;
};

struct sr6_tlv_t_dm {
	unsigned char type; // value TBA by IANA, use NSH+1
	unsigned char len;
	unsigned short reserved;
	unsigned char version:4; // 1
	unsigned char flags:4; // R|T|0|0, R: Query(0),Response(1), T: if tc class, set to 1
	unsigned char cc;
	/* For a Query: 0x0 in-band response, 0x1 out of band, 0x2: no response 
	* For a response: 0x1 success, 0x10-0xFF: errors */
	unsigned short reserved2;
	unsigned char qtf:4; /* timestamp formats */
	unsigned char rtf:4;
	unsigned char rtpf:4;
	unsigned int reserved3:20;
	unsigned int session_id:24; /* set by the querier */
	unsigned char tc;
	struct timestamp_ieee1588_v2 timestamps[4];
	unsigned char sub_tlv[0]; // possible UDP Return Object (URO)
} BPF_PACKET_HEADER;

struct uro_v6 {
	unsigned char type; // URO = 131
	unsigned char len; // = 18
	unsigned short dport;
	struct ip6_addr_t daddr;
} BPF_PACKET_HEADER;

int main(int argc, char *argv[]) {
	struct sr6_tlv_t_dm dm;
	memset(&dm, 0, sizeof(dm));
	dm.type = SR6_TLV_DM;
	dm.len = sizeof(dm) - 2;
	dm.version = 1;
	dm.flags = 0;
	dm.cc = 0x1;
	dm.qtf = 3;
	dm.session_id = 0x42;
	dm.tc = 0;
	dm.timestamps[0].tv_sec = 0x1337;

	for(unsigned int i=2; i < sizeof(dm); i++)
		printf("%02x", (char) *((char *)&dm + i));
	printf("\n");

	struct uro_v6 uro;
	memset(&uro, 0, sizeof(uro));
	uro.type = SR6_TLV_URO;
	uro.len = 18;
	uro.dport = 4242;
	uro.daddr.hi = 0xfc00bbbb00000000;
	uro.daddr.lo = 0x2;

	for(unsigned int i=2; i < sizeof(uro); i++)
		printf("%02x", (char) *((char *)&uro + i));
	printf("\n");


}
