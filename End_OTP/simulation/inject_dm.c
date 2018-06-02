#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#ifndef __u8
#define __u8 uint8_t
#define __u16 uint16_t
#define __u32 uint32_t
#define __be32 uint32_t
#define __u64 uint64_t
#endif

struct ipv6_sr_hdr {
        __u8    nexthdr;
        __u8    hdrlen;
        __u8    type;
        __u8    segments_left;
        __u8    first_segment;
        __u8    flags;
        __u16   tag;

        struct in6_addr segments[0];
};

struct sr6_tlv {
	__u8 type;
	__u8 len;
	__u8 data[0];
};

struct timestamp_ieee1588_v2 {
	uint32_t tv_sec;
	uint32_t tv_nsec;
};

struct sr6_tlv_dm_t {
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
};

struct uro_v6 {
	unsigned char type; // URO = 131
	unsigned char len; // = 18
	unsigned short dport;
	struct in6_addr daddr;
};

int send_dm(const char *bindaddr, const char *dst, short port, int nb_segments, char **segment)
{
    int fd, err, srh_len, tot_len;
    struct ipv6_sr_hdr *srh;
    struct sockaddr_in6 sin6, sin6_bind;
    static char buf[] = "Hello with Segment Routing :)\n";

    srh_len = sizeof(*srh) + (nb_segments+1) * sizeof(struct in6_addr);
    tot_len = srh_len + sizeof(struct sr6_tlv_dm_t) + sizeof(struct uro_v6) + sizeof(4);
    srh = malloc(tot_len);
    if (!srh)
        return -1;

    srh->nexthdr = 0;
    srh->hdrlen = (tot_len - 8) >> 3;
    srh->type = 4;
    srh->segments_left = nb_segments;
    srh->first_segment = nb_segments;
    srh->tag = 0;
    srh->flags = 0;

    memset(&srh->segments[0], 0, sizeof(struct in6_addr));
    for(int i=0; i < nb_segments; i++) {
        inet_pton(AF_INET6, *(segment+i), &srh->segments[nb_segments-i]);
    }

    fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sr6_tlv_dm_t *dm = (struct sr6_tlv_dm_t *) ((char *)srh + srh_len);
    dm->type = 7;
    dm->len = sizeof(*dm) - 2;
    dm->version = 1;
    dm->cc = 0x1;
    dm->qtf = 3;

    struct timespec tstamp;
    clock_gettime(CLOCK_REALTIME, &tstamp);
    dm->timestamps[0].tv_nsec = htonl((uint32_t) tstamp.tv_nsec);
    dm->timestamps[0].tv_sec = htonl((uint32_t) tstamp.tv_sec);

    struct uro_v6 *uro = (struct uro_v6 *) ((char *)dm + sizeof(*dm));
    uro->type = 131;
    uro->dport = htons(9000);
    uro->len = sizeof(*uro) - 2;
    inet_pton(AF_INET6, bindaddr, &uro->daddr);

    struct sr6_tlv *tlv_pad = (struct sr6_tlv *) ((char *)uro + sizeof(*uro));
    tlv_pad->type = 4;
    tlv_pad->len = 2;

    printf("%d\n", tot_len);
    err = setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, srh, (socklen_t) tot_len);
    if (err < 0) {
        perror("setsockopt");
        close(fd);
        return -1;
    }

    memset(&sin6_bind, 0, sizeof(sin6_bind));
    sin6_bind.sin6_family = AF_INET6;
    inet_pton(AF_INET6, bindaddr, &sin6_bind.sin6_addr);

    err = bind(fd, (struct sockaddr *)&sin6_bind, sizeof(sin6_bind));
    if (err < 0) {
        perror("bind");
        close(fd);
        return -1;
    }

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(port);
    inet_pton(AF_INET6, dst, &sin6.sin6_addr);

    err = connect(fd, (struct sockaddr *)&sin6, sizeof(sin6));
    if (err < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    err = send(fd, buf, sizeof(buf), 0);
    if (err < 0) {
        perror("send");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int main(int ac, char **av)
{
    if (ac < 5) {
        fprintf(stderr, "Usage: %s bindaddr dst port segment1 segment2 segment3 ...\n", av[0]);
        return -1;
    }

    return send_dm(av[1], av[2], atoi(av[3]), ac-4, av+4);
}
