// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#define MESSAGE "Hello!\n"

union addr46 {
	struct in_addr addr4;
	struct in6_addr addr6;
};

/* -----------------------------------------------
 * Functions for the TCP and UDP tests:
 * - Create a STREAM or DGRAM socket, optionally with the TRANSPARENT sockopt
 * - Act only as server, the companion script will act as client
 * - Wait for a TCP connection or UDP datagram from the client
 * - Wait until the client sends a sync message (via FIFO file) to continue
 *   (the client may need to do some actions before the next step)
 * - Send a message to the client
 * ------------------------------------------------
 */
static int create_sock_ipv6(int proto, int port, bool transparent)
{
	struct sockaddr_in6 address;
	int sk, opt;

	sk = socket(AF_INET6, proto, 0);
	if (sk < 0) {
		perror("Failed to create socket");
		exit(EXIT_FAILURE);
	}

	opt = 1;
	if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
		perror("Failed to set SO_REUSEADDR");
		exit(EXIT_FAILURE);
	}
	opt = 0;
	if (setsockopt(sk, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt))) {
		perror("Failed to set IPV6_V6ONLY");
		exit(EXIT_FAILURE);
	}
	opt = 1;
	if (setsockopt(sk, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt, sizeof(opt))) {
		perror("Failed to set IPV6_PKTINFO");
		exit(EXIT_FAILURE);
	}
	opt = 1;
	if (transparent &&
	    setsockopt(sk, IPPROTO_IPV6, IPV6_TRANSPARENT, &opt, sizeof(opt))) {
		perror("Failed to set IPV6_TRANSPARENT");
		exit(EXIT_FAILURE);
	}

	memset(&address, 0, sizeof(address));
	address.sin6_family = AF_INET6;
	address.sin6_addr = in6addr_any;
	address.sin6_port = htons(port);

	if (bind(sk, (struct sockaddr *)&address, sizeof(address))) {
		perror("Failed to bind");
		exit(EXIT_FAILURE);
	}

	return sk;
}

static int create_sock_ipv4(int proto, int port, bool transparent)
{
	struct sockaddr_in address;
	int sk, opt;

	sk = socket(AF_INET, proto, 0);
	if (sk < 0) {
		perror("Failed to create socket");
		exit(EXIT_FAILURE);
	}

	opt = 1;
	if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
		perror("Failed to set SO_REUSEADDR");
		exit(EXIT_FAILURE);
	}
	opt = 1;
	if (setsockopt(sk, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt))) {
		perror("Failed to set IP_PKTINFO");
		exit(EXIT_FAILURE);
	}
	opt = 1;
	if (transparent &&
	    setsockopt(sk, IPPROTO_IP, IP_TRANSPARENT, &opt, sizeof(opt))) {
		perror("Failed to set IP_TRANSPARENT");
		exit(EXIT_FAILURE);
	}

	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_ANY);
	address.sin_port = htons(port);

	if (bind(sk, (struct sockaddr *)&address, sizeof(address))) {
		perror("Failed to bind");
		exit(EXIT_FAILURE);
	}

	return sk;
}

static void sync_wait(int sync_fd)
{
	uint8_t buff[256];

	if (sync_fd && read(sync_fd, buff, sizeof(buff) - 1) < 0) {
		perror("Failed to read from sync file");
		exit(EXIT_FAILURE);
	}
}

static void wait_and_send_tcp(int sk, int sync_fd)
{
	int con;

	if (listen(sk, 5) < 0) {
		perror("Failed to listen");
		exit(EXIT_FAILURE);
	}
	con = accept(sk, NULL, NULL);
	if (con < 0) {
		perror("Failed to accept");
		exit(EXIT_FAILURE);
	}

	sync_wait(sync_fd);

	if (send(con, MESSAGE, strlen(MESSAGE), 0) < 0) {
		perror("Failed to send");
		exit(EXIT_FAILURE);
	}

	close(con);
}

static void maybe_chg_saddr_dport(char *data, struct msghdr *msg)
{
	struct in6_addr local_addr6;
	struct in_addr local_addr4;
	int cmsg_level, cmsg_type;
	struct cmsghdr *cmsg;
	size_t datalen;
	char *portstr;

	portstr = strchr(data, ' ');
	if (!portstr)
		return;

	// remove trailing LF and split into 2 strs
	datalen = strlen(data);
	if (datalen > 0 && data[datalen - 1] == '\n')
		data[datalen - 1] = '\0';
	*(portstr++) = '\0';

	// get the new saddr and dport
	if (inet_pton(AF_INET, data, &local_addr4) == 1) {
		struct sockaddr_in *peer_addr;

		peer_addr = (struct sockaddr_in *)msg->msg_name;
		peer_addr->sin_port = htons(atoi(portstr));
		cmsg_level = IPPROTO_IP;
		cmsg_type = IP_PKTINFO;
	} else if (inet_pton(AF_INET6, data, &local_addr6) == 1) {
		struct sockaddr_in6 *peer_addr;

		peer_addr = (struct sockaddr_in6 *)msg->msg_name;
		peer_addr->sin6_port = htons(atoi(portstr));
		cmsg_level = IPPROTO_IPV6;
		cmsg_type = IPV6_PKTINFO;
	} else {
		return;
	}

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level != cmsg_level ||
		    cmsg->cmsg_type != cmsg_type) {
			continue;
		}
		if (cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo *pi;

			pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
			pi->ipi_addr = local_addr4;
			pi->ipi_spec_dst = local_addr4;
			break;
		}
		if (cmsg->cmsg_level == IPPROTO_IPV6 &&
		    cmsg->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo *pi;

			pi = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			pi->ipi6_addr = local_addr6;
			break;
		}
	}
}

static void wait_and_send_udp(int sk, int sync_fd)
{
	uint8_t data_buff[256], ctrl_buff[256];
	ssize_t nbytes;
	union {
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} peer_addr;
	struct iovec iov = {
		.iov_base = data_buff,
		.iov_len = sizeof(data_buff) - 1,
	};
	struct msghdr msg = {
		.msg_name = &peer_addr,
		.msg_namelen = sizeof(peer_addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = ctrl_buff,
		.msg_controllen = sizeof(ctrl_buff),
	};

	nbytes = recvmsg(sk, &msg, 0);
	if (nbytes < 0) {
		perror("Failed to receive");
		exit(EXIT_FAILURE);
	}

	// The "test_foreign_addr_*" tests needs us to reply to the same address
	// but different port, and also from a different local address. The new
	// saddr and dport are received in the previous message with the format
	// "new_source_address new_dest_port"
	data_buff[nbytes] = '\0';
	maybe_chg_saddr_dport((char *)data_buff, &msg);

	sync_wait(sync_fd);

	// Change the data, but keep the same ancillary data so that we use the
	// same addresses as we received.
	iov.iov_base = MESSAGE;
	iov.iov_len = strlen(MESSAGE);

	if (sendmsg(sk, &msg, 0) < 0) {
		/* Contrary to the TCP case, as UDP doesn't keep a "connection",
		 * the test cases where the source address is not configured in
		 * the host return an error here. It is expected, ignore it.
		 */
	}
}

/* -----------------------------------------------
 * Functions for the HDRINCL tests:
 * - Create a RAW socket with the HDRINCL sockopt
 * - If acting as server, wait for incoming data and print it
 * - If acting as client, craft a packet with the saddr and daddr from the args
 *   and send it.
 * ------------------------------------------------
 */
static int create_sock_ipv4_hdrincl(void)
{
	struct sockaddr_in address;
	int sk, opt;

	sk = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sk < 0) {
		perror("Failed to create socket");
		exit(EXIT_FAILURE);
	}

	opt = 1;
	if (setsockopt(sk, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
		perror("Failed to set IP_HDRINCL");
		exit(EXIT_FAILURE);
	}

	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sk, (struct sockaddr *)&address, sizeof(address))) {
		perror("Failed to bind");
		exit(EXIT_FAILURE);
	}

	return sk;
}

static int create_sock_ipv6_hdrincl(void)
{
	struct sockaddr_in6 address;
	int sk, opt;

	sk = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (sk < 0) {
		perror("Failed to create socket");
		exit(EXIT_FAILURE);
	}

	opt = 1;
	if (setsockopt(sk, IPPROTO_IPV6, IPV6_HDRINCL, &opt, sizeof(opt)) < 0) {
		perror("Failed to set IPV6_HDRINCL");
		exit(EXIT_FAILURE);
	}

	memset(&address, 0, sizeof(address));
	address.sin6_family = AF_INET6;
	address.sin6_addr = in6addr_any;

	if (bind(sk, (struct sockaddr *)&address, sizeof(address))) {
		perror("Failed to bind");
		exit(EXIT_FAILURE);
	}

	return sk;
}

size_t create_packet_ipv6(uint8_t *buff,
			  struct in6_addr saddr,
			  struct in6_addr daddr)
{
	struct ip6_hdr *iph = (struct ip6_hdr *)buff;
	uint8_t *data = (uint8_t *)(buff + sizeof(struct ip6_hdr));

	// header
	iph->ip6_flow = htonl((6 << 28) | (0 << 20) | 0);
	iph->ip6_plen = htons(sizeof(MESSAGE));
	iph->ip6_nxt = IPPROTO_RAW;
	iph->ip6_hops = 64;
	iph->ip6_src = saddr;
	iph->ip6_dst = daddr;

	// data
	memcpy(data, MESSAGE, sizeof(MESSAGE));

	return sizeof(struct ip6_hdr) + sizeof(MESSAGE);
}

size_t create_packet_ipv4(uint8_t *buff,
			  struct in_addr saddr,
			  struct in_addr daddr)
{
	struct ip *iph = (struct ip *)buff;
	uint8_t *data = (uint8_t *)(buff + sizeof(struct ip));

	// header
	iph->ip_hl = 5; // Header length (5 * 4 bytes = 20 bytes)
	iph->ip_v = 4;  // IPv4
	iph->ip_tos = 0;
	iph->ip_len = htons(sizeof(struct ip) + sizeof(MESSAGE));
	iph->ip_id = htons(12345);
	iph->ip_off = 0;
	iph->ip_ttl = 64;
	iph->ip_p = IPPROTO_RAW;
	iph->ip_src = saddr;
	iph->ip_dst = daddr;
	iph->ip_sum = 0;

	// data
	memcpy(data, MESSAGE, sizeof(MESSAGE));

	return sizeof(struct ip) + sizeof(MESSAGE);
}

static void send_or_receive_hdrincl(int sk,
				    bool is_ipv6,
				    bool send_msg,
				    union addr46 *local_addr,
				    union addr46 *peer_addr)
{
	uint8_t buff[256];
	ssize_t msglen;

	if (send_msg && is_ipv6) {
		struct sockaddr_in6 dest;

		memset(&dest, 0, sizeof(dest));
		dest.sin6_family = AF_INET6;
		dest.sin6_addr = peer_addr->addr6;
		msglen = create_packet_ipv6(buff,
					    local_addr->addr6,
					    peer_addr->addr6);
		if (sendto(sk, buff, msglen, 0, &dest, sizeof(dest)) < 0) {
			perror("Failed to send");
			exit(EXIT_FAILURE);
		}
	} else if (send_msg && !is_ipv6) {
		struct sockaddr_in dest;

		memset(&dest, 0, sizeof(dest));
		dest.sin_family = AF_INET;
		dest.sin_addr = peer_addr->addr4;
		msglen = create_packet_ipv4(buff,
					    local_addr->addr4,
					    peer_addr->addr4);
		if (sendto(sk, buff, msglen, 0, &dest, sizeof(dest)) < 0) {
			perror("Failed to send");
			exit(EXIT_FAILURE);
		}
	} else {
		msglen = read(sk, buff, sizeof(buff) - 1);
		if (msglen < 0) {
			perror("Failed to read");
			exit(EXIT_FAILURE);
		}
		buff[msglen] = '\0';

		// output the received message
		if (is_ipv6)
			printf("%s", buff);
		else if (msglen >= sizeof(struct ip))
			printf("%s", buff + sizeof(struct ip));
	}
}

/* -----------------------------------------------
 * Arguments parsing
 * ------------------------------------------------
 */
static void parse_gral_args(int argc,
			    char *argv[],
			    bool *out_is_ipv6,
			    int *out_proto)
{
	if (argc < 3) {
		fprintf(stderr, "Expected more arguments");
		exit(EXIT_FAILURE);
	}

	if (strncmp(argv[1], "ipv4", strlen("ipv4")) == 0) {
		*out_is_ipv6 = false;
	} else if (strncmp(argv[1], "ipv6", strlen("ipv6")) == 0) {
		*out_is_ipv6 = true;
	} else {
		fprintf(stderr, "Valid value for arg1: ipv4, ipv6");
		exit(EXIT_FAILURE);
	}

	if (strncmp(argv[2], "tcp", strlen("tcp")) == 0) {
		*out_proto = SOCK_STREAM;
	} else if (strncmp(argv[2], "udp", strlen("udp")) == 0) {
		*out_proto = SOCK_DGRAM;
	} else if (strncmp(argv[2], "raw", strlen("raw")) == 0) {
		*out_proto = SOCK_RAW;
	} else {
		fprintf(stderr, "Valid value for arg2: tcp, udp, raw");
		exit(EXIT_FAILURE);
	}
}

static void parse_tcp_udp_args(int argc,
			       char *argv[],
			       int *out_port,
			       bool *out_transparent,
			       int *out_sync_fd)
{
	if (argc < 5) {
		fprintf(stderr, "Expected more arguments");
		exit(EXIT_FAILURE);
	}

	*out_port = atoi(argv[3]);

	if (strncmp(argv[4], "transparent", strlen("transparent")) == 0) {
		*out_transparent = true;
	} else if (strncmp(argv[4], "normal", strlen("normal")) == 0) {
		*out_transparent = false;
	} else {
		fprintf(stderr, "Valid values for arg3: normal, transparent");
		exit(EXIT_FAILURE);
	}

	*out_sync_fd = 0;
	if (argc > 5 && strlen(argv[5]) > 0) {
		*out_sync_fd = open(argv[5], O_RDWR);
		if (*out_sync_fd < 0) {
			perror("Failed to open sync file");
			exit(EXIT_FAILURE);
		}
	}
}

static void parse_hdrincl_args(int argc,
			       char *argv[],
			       bool is_ipv6,
			       bool *out_send_msg,
			       union addr46 *out_local_addr,
			       union addr46 *out_peer_addr)
{
	if (argc == 4) {
		fprintf(stderr, "Expected more arguments");
		exit(EXIT_FAILURE);
	}

	*out_send_msg = argc < 4 ? false : true;
	if (*out_send_msg && is_ipv6) {
		inet_pton(AF_INET6, argv[3], out_local_addr);
		inet_pton(AF_INET6, argv[4], out_peer_addr);
	} else if (*out_send_msg && !is_ipv6) {
		inet_pton(AF_INET, argv[3], out_local_addr);
		inet_pton(AF_INET, argv[4], out_peer_addr);
	}
}

int main(int argc, char *argv[])
{
	union addr46 local_addr, peer_addr;
	bool is_ipv6, transparent, send_msg;
	int proto, port;
	int sync_fd;
	int sk;

	parse_gral_args(argc, argv, &is_ipv6, &proto);
	if (proto != SOCK_RAW)
		parse_tcp_udp_args(argc, argv, &port, &transparent, &sync_fd);
	else
		parse_hdrincl_args(argc,
				   argv,
				   is_ipv6,
				   &send_msg,
				   &local_addr,
				   &peer_addr);

	if (is_ipv6 && proto != SOCK_RAW)
		sk = create_sock_ipv6(proto, port, transparent);
	else if (!is_ipv6 && proto != SOCK_RAW)
		sk = create_sock_ipv4(proto, port, transparent);
	else if (is_ipv6 && proto == SOCK_RAW)
		sk = create_sock_ipv6_hdrincl();
	else // !is_ipv6 && proto == SOCK_RAW
		sk = create_sock_ipv4_hdrincl();

	if (proto == SOCK_STREAM)
		wait_and_send_tcp(sk, sync_fd);
	else if (proto == SOCK_DGRAM)
		wait_and_send_udp(sk, sync_fd);
	else // SOCK_RAW
		send_or_receive_hdrincl(sk,
					is_ipv6,
					send_msg,
					&local_addr,
					&peer_addr);

	close(sk);
	return 0;
}
