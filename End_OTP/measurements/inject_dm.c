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
#include <linux/net_tstamp.h>
#include <linux/errqueue.h>

#ifndef __u8
#define __u8 uint8_t
#define __u16 uint16_t
#define __u32 uint32_t
#define __be32 uint32_t
#define __u64 uint64_t
#endif

struct ipv6_sr_hdr {
	__u8	nexthdr;
	__u8	hdrlen;
	__u8	type;
	__u8	segments_left;
	__u8	first_segment;
	__u8	flags;
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

struct timespec *get_sw_ts(struct msghdr *msg)
{
	struct cmsghdr *cmsg;
	for (cmsg = CMSG_FIRSTHDR(msg);
		 cmsg;
		 cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SO_TIMESTAMPING) {
			struct timespec *stamp =
				(struct timespec *)CMSG_DATA(cmsg);
			return stamp;
		}
	}
	return NULL;
}


int send_dm(const char *bindaddr, short port, int nb_segments, char **segment)
{
	int fd, fd_bind, err, srh_len, tot_len;
	struct ipv6_sr_hdr *srh;
	struct sockaddr_in6 sin6_src, sin6_dst;
	static char buf[] = "Hello with Segment Routing :)\n";

	memset(&sin6_src, 0, sizeof(sin6_src));
	sin6_src.sin6_family = AF_INET6;
	inet_pton(AF_INET6, bindaddr, &sin6_src.sin6_addr);
	sin6_src.sin6_port = 0;

	memset(&sin6_dst, 0, sizeof(sin6_dst));
	sin6_dst.sin6_family = AF_INET6;
	inet_pton(AF_INET6, bindaddr, &sin6_dst.sin6_addr);
	sin6_dst.sin6_port = htons(port);

	srh_len = sizeof(*srh) + (nb_segments+1) * sizeof(struct in6_addr);
	tot_len = srh_len + sizeof(struct sr6_tlv_dm_t);
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

	memcpy(&srh->segments[0], &sin6_src.sin6_addr, sizeof(struct in6_addr));
	for(int i=0; i < nb_segments; i++) {
		inet_pton(AF_INET6, *(segment+i), &srh->segments[nb_segments-i]);
	}

	fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	fd_bind = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
	close(fd);
		perror("socket (2)");
		return -1;
	}

	struct sr6_tlv_dm_t *dm = (struct sr6_tlv_dm_t *) ((char *)srh + srh_len);
	dm->type = 7;
	dm->len = sizeof(*dm) - 2;
	dm->version = 1;
	dm->cc = 0x0;
	dm->qtf = 3;

	struct timespec tstamp;
	clock_gettime(CLOCK_REALTIME, &tstamp);
	dm->timestamps[0].tv_nsec = htonl((uint32_t) tstamp.tv_nsec);
	dm->timestamps[0].tv_sec = htonl((uint32_t) tstamp.tv_sec);

	err = setsockopt(fd, IPPROTO_IPV6, IPV6_RTHDR, srh, (socklen_t) tot_len);
	if (err < 0) {
		perror("setsockopt");
	goto error;
	}

	int so_timestamping_flags = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_TX_SOFTWARE;
	err = setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &so_timestamping_flags, sizeof(so_timestamping_flags));
	if (err < 0) {
		perror("setsockopt SO_TIMESTAMPING TX");
	goto error;
	}

	so_timestamping_flags = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE;
	err = setsockopt(fd_bind, SOL_SOCKET, SO_TIMESTAMPING, &so_timestamping_flags, sizeof(so_timestamping_flags));
	if (err < 0) {
		perror("setsockopt SO_TIMESTAMPING RX");
	goto error;
	}

	err = bind(fd_bind, (struct sockaddr *)&sin6_dst, sizeof(sin6_src));
	if (err < 0) {
		perror("bind");
	goto error;
	}

	err = bind(fd, (struct sockaddr *)&sin6_src, sizeof(sin6_src));
	if (err < 0) {
		perror("bind");
	goto error;
	}

	/* === TX phase === */
	char data[256];
	struct msghdr msg;
	struct iovec entry;
	struct sockaddr_in from_addr;
	struct {
		struct cmsghdr cm;
		char control[512];
	} control;
	int res;
	int len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &entry;
	msg.msg_iovlen = 1;
	entry.iov_base = data;
	entry.iov_len = sizeof(data);
	msg.msg_name = NULL;//(caddr_t)&from_addr;
	msg.msg_namelen = 0;//sizeof(from_addr);
	msg.msg_control = &control;
	msg.msg_controllen = sizeof(control);

	err = sendto(fd, buf, sizeof(buf), 0, (struct sockaddr *)&sin6_dst, sizeof(sin6_dst));
	if (err < 0) {
		perror("sendto");
		goto error;
	}

	len = recvmsg(fd, &msg, MSG_ERRQUEUE);
	if (len < 0) {
		perror("recvmsg (tx)");
		close(fd);
		return -1;
	}
	struct timespec *ts_tmp = get_sw_ts(&msg);
	struct timespec ts_tx = *ts_tmp;

	/* === RX phase === */	
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &entry;
	msg.msg_iovlen = 1;
	entry.iov_base = data;
	entry.iov_len = sizeof(data);
	msg.msg_name = NULL;//(caddr_t)&from_addr;
	msg.msg_namelen = 0;//sizeof(from_addr);
	msg.msg_control = &control;
	msg.msg_controllen = sizeof(control);

	len = recvmsg(fd_bind, &msg, 0);
	if (len < 0) {
		perror("recvmsg (rx)");
		close(fd);
		return -1;
	}

	ts_tmp = get_sw_ts(&msg);
	struct timespec ts_rx = *ts_tmp;
	printf("TX:%lu.%lu\tRX:%lu.%lu\n", ts_tx.tv_sec, ts_tx.tv_nsec, ts_rx.tv_sec, ts_rx.tv_nsec);

	close(fd);
	close(fd_bind);
	return 0;

error:
	close(fd);
	close(fd_bind);
	return -1;
}

int main(int ac, char **av)
{
	if (ac < 4) {
		fprintf(stderr, "Usage: %s bindaddr port segment1 segment2 segment3 ...\n", av[0]);
		return -1;
	}

	return send_dm(av[1], atoi(av[2]), ac-3, av+3);
}
