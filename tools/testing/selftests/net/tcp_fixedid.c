// SPDX-License-Identifier: GPL-2.0
/*
 * Send TCP segments with fixed or incrementing IPv4 IDs, optionally in
 * VXLAN, and report the IP IDs of TCP segments received on a device.
 *
 * tx: tcp_fixedid -T -i dev -M dmac -s saddr -d daddr [-f] [-n segs]
 *                 [-b bursts] [-l len] [-V osaddr,odaddr -m inner_dmac [-F]]
 * rx: tcp_fixedid -R -i dev [-c segs] [-w ms]
 *
 * The receiver prints "ready" once it is bound, then the number of
 * segments, of segments with an outer IPv4 header, and of distinct outer
 * and inner IDs.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <error.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TEST_PORT	9000
#define VXLAN_PORT	4789
#define FIXED_ID	0x1234

static const char *ifname;
static bool fixed_id, fixed_outer;
static int segs = 40, bursts = 10, len = 1000, wait_ms = 2000, stop;
static struct in_addr saddr, daddr, osaddr, odaddr;
static bool vxlan;
static unsigned char dmac[ETH_ALEN], inner_dmac[ETH_ALEN];

static void parse_mac(const char *s, unsigned char *mac)
{
	if (sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1],
		   &mac[2], &mac[3], &mac[4], &mac[5]) != 6)
		error(1, 0, "bad mac %s", s);
}

static void parse_addr(const char *s, struct in_addr *a)
{
	if (inet_pton(AF_INET, s, a) != 1)
		error(1, 0, "bad address %s", s);
}

static uint32_t csum_add(uint32_t sum, const void *data, size_t n)
{
	const uint8_t *p = data;

	while (n > 1) {
		sum += (p[0] << 8) | p[1];
		p += 2;
		n -= 2;
	}
	if (n)
		sum += p[0] << 8;
	return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return htons(~sum & 0xffff);
}

static void build_ip(struct iphdr *iph, int proto, int payload, uint16_t id,
		     struct in_addr s, struct in_addr d)
{
	memset(iph, 0, sizeof(*iph));
	iph->version = 4;
	iph->ihl = 5;
	iph->tot_len = htons(sizeof(*iph) + payload);
	iph->id = htons(id);
	iph->frag_off = htons(IP_DF);
	iph->ttl = 64;
	iph->protocol = proto;
	iph->saddr = s.s_addr;
	iph->daddr = d.s_addr;
	iph->check = csum_fold(csum_add(0, iph, sizeof(*iph)));
}

/* Ethernet, IPv4 and TCP header plus payload for segment @i at @p */
static int build_tcp(unsigned char *p, const unsigned char *mac, int i,
		     uint16_t id)
{
	struct ethhdr *eth = (struct ethhdr *)p;
	struct iphdr *iph = (struct iphdr *)(eth + 1);
	struct tcphdr *th = (struct tcphdr *)(iph + 1);
	struct {
		uint32_t s, d;
		uint8_t zero, proto;
		uint16_t len;
	} ph;	/* 12 bytes, no padding */
	uint32_t sum;

	memcpy(eth->h_dest, mac, ETH_ALEN);
	memset(eth->h_source, 0, ETH_ALEN);
	eth->h_source[0] = 0x02;
	eth->h_source[5] = 0x01;
	eth->h_proto = htons(ETH_P_IP);
	build_ip(iph, IPPROTO_TCP, sizeof(*th) + len, id, saddr, daddr);

	memset(th, 0, sizeof(*th));
	th->source = htons(TEST_PORT + 1);
	th->dest = htons(TEST_PORT);
	th->seq = htonl(1 + i * len);
	th->ack_seq = htonl(1);
	th->doff = 5;
	th->ack = 1;
	th->window = htons(65535);
	memset(th + 1, 'a' + i % 26, len);

	ph.s = iph->saddr;
	ph.d = iph->daddr;
	ph.zero = 0;
	ph.proto = IPPROTO_TCP;
	ph.len = htons(sizeof(*th) + len);
	sum = csum_add(0, &ph, sizeof(ph));
	th->check = csum_fold(csum_add(sum, th, sizeof(*th) + len));

	return sizeof(*eth) + sizeof(*iph) + sizeof(*th) + len;
}

static int do_tx(int fd, struct sockaddr_ll *sll)
{
	unsigned char buf[ETH_FRAME_LEN + 128];
	int b, s, i = 0, n;

	for (b = 0; b < bursts; b++) {
		for (s = 0; s < segs; s++, i++) {
			uint16_t id = fixed_id ? FIXED_ID : 0x1000 + i;
			unsigned char *p = buf;

			if (vxlan) {
				struct ethhdr *eth = (struct ethhdr *)p;
				struct iphdr *iph = (struct iphdr *)(eth + 1);
				struct udphdr *uh = (struct udphdr *)(iph + 1);
				uint32_t *vx = (uint32_t *)(uh + 1);
				int inner;

				inner = build_tcp((unsigned char *)(vx + 2),
						  inner_dmac, i, id);
				memcpy(eth->h_dest, dmac, ETH_ALEN);
				memset(eth->h_source, 0, ETH_ALEN);
				eth->h_source[0] = 0x02;
				eth->h_source[5] = 0x01;
				eth->h_proto = htons(ETH_P_IP);
				memset(uh, 0, sizeof(*uh));
				uh->source = htons(VXLAN_PORT + 1);
				uh->dest = htons(VXLAN_PORT);
				uh->len = htons(sizeof(*uh) + 8 + inner);
				vx[0] = htonl(0x08000000);
				vx[1] = htonl(42 << 8);
				build_ip(iph, IPPROTO_UDP,
					 sizeof(*uh) + 8 + inner,
					 fixed_outer ? FIXED_ID : 0x2000 + i,
					 osaddr, odaddr);
				n = sizeof(*eth) + sizeof(*iph) + sizeof(*uh) +
				    8 + inner;
			} else {
				n = build_tcp(p, dmac, i, id);
			}

			if (sendto(fd, buf, n, 0, (struct sockaddr *)sll,
				   sizeof(*sll)) != n)
				error(1, errno, "sendto");
		}
		usleep(50000);
	}
	return 0;
}

/* Return the inner IPv4 header of a TCP segment to TEST_PORT, or NULL */
static const struct iphdr *find_inner(const unsigned char *p, int n,
				      const struct iphdr **outer4)
{
	const struct ethhdr *eth = (const struct ethhdr *)p;
	const unsigned char *end = p + n;
	const unsigned char *l4;
	int proto, depth;

	*outer4 = NULL;
	if (n < (int)sizeof(*eth))
		return NULL;
	p += sizeof(*eth);

	for (depth = 0; depth < 2; depth++) {
		uint16_t etype = depth ? htons(ETH_P_IP) : eth->h_proto;

		if (etype == htons(ETH_P_IP)) {
			const struct iphdr *iph = (const struct iphdr *)p;

			if (p + sizeof(*iph) > end)
				return NULL;
			proto = iph->protocol;
			l4 = p + iph->ihl * 4;
			if (proto == IPPROTO_TCP) {
				const struct tcphdr *th;

				th = (const struct tcphdr *)l4;
				if (l4 + sizeof(*th) > end ||
				    th->dest != htons(TEST_PORT))
					return NULL;
				return iph;
			}
			if (depth)
				return NULL;
			*outer4 = iph;
		} else if (etype == htons(ETH_P_IPV6)) {
			const struct ip6_hdr *ip6h = (const struct ip6_hdr *)p;

			if (p + sizeof(*ip6h) > end)
				return NULL;
			proto = ip6h->ip6_nxt;
			l4 = p + sizeof(*ip6h);
		} else {
			return NULL;
		}

		/* step over the tunnel header to the inner IPv4 header */
		if (proto == IPPROTO_IPIP) {
			p = l4;
		} else if (proto == IPPROTO_GRE) {
			uint16_t flags;

			if (l4 + 4 > end)
				return NULL;
			flags = (l4[0] << 8) | l4[1];
			if (((l4[2] << 8) | l4[3]) != ETH_P_IP)
				return NULL;
			p = l4 + 4 + 4 * (!!(flags & 0x8000) +
					  !!(flags & 0x2000) +
					  !!(flags & 0x1000));
		} else if (proto == IPPROTO_UDP) {
			const struct udphdr *uh = (const struct udphdr *)l4;

			if (l4 + sizeof(*uh) + 8 + sizeof(*eth) > end ||
			    uh->dest != htons(VXLAN_PORT))
				return NULL;
			p = l4 + sizeof(*uh) + 8 + sizeof(*eth);
		} else {
			return NULL;
		}
	}
	return NULL;
}

static void count_id(uint8_t *map, unsigned int *distinct, uint16_t id)
{
	if (!(map[id / 8] & (1 << (id % 8)))) {
		map[id / 8] |= 1 << (id % 8);
		(*distinct)++;
	}
}

static int do_rx(int fd)
{
	static uint8_t outer_map[8192], inner_map[8192];
	unsigned int frames = 0, outer4 = 0, outer_ids = 0, inner_ids = 0;
	unsigned char buf[65536];
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	printf("ready\n");
	fflush(stdout);

	/* wait longer for the first segment than between segments */
	while (poll(&pfd, 1, frames ? wait_ms : 10 * wait_ms) > 0) {
		const struct iphdr *iph, *oiph;
		struct sockaddr_ll from;
		socklen_t fl = sizeof(from);
		int n;

		n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from,
			     &fl);
		if (n < 0)
			error(1, errno, "recvfrom");
		if (from.sll_pkttype == PACKET_OUTGOING)
			continue;
		iph = find_inner(buf, n, &oiph);
		if (!iph)
			continue;
		frames++;
		count_id(inner_map, &inner_ids, ntohs(iph->id));
		if (oiph) {
			outer4++;
			count_id(outer_map, &outer_ids, ntohs(oiph->id));
		}
		if (stop && frames == (unsigned int)stop)
			break;
	}

	printf("frames %u outer4 %u outer_ids %u inner_ids %u\n", frames,
	       outer4, outer_ids, inner_ids);
	return 0;
}

int main(int argc, char **argv)
{
	struct sockaddr_ll sll = {};
	bool tx = false, rx = false;
	char *comma;
	int c, fd;

	while ((c = getopt(argc, argv, "TRi:M:s:d:fn:b:l:V:m:Fw:c:")) != -1) {
		switch (c) {
		case 'T':
			tx = true;
			break;
		case 'R':
			rx = true;
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'M':
			parse_mac(optarg, dmac);
			break;
		case 's':
			parse_addr(optarg, &saddr);
			break;
		case 'd':
			parse_addr(optarg, &daddr);
			break;
		case 'f':
			fixed_id = true;
			break;
		case 'n':
			segs = atoi(optarg);
			break;
		case 'b':
			bursts = atoi(optarg);
			break;
		case 'l':
			len = atoi(optarg);
			break;
		case 'V':
			comma = strchr(optarg, ',');
			if (!comma)
				error(1, 0, "-V needs outer saddr,daddr");
			*comma = '\0';
			parse_addr(optarg, &osaddr);
			parse_addr(comma + 1, &odaddr);
			vxlan = true;
			break;
		case 'm':
			parse_mac(optarg, inner_dmac);
			break;
		case 'F':
			fixed_outer = true;
			break;
		case 'w':
			wait_ms = atoi(optarg);
			break;
		case 'c':
			stop = atoi(optarg);
			break;
		default:
			error(1, 0, "bad option");
		}
	}
	if (tx == rx || !ifname || len < 1 || len > 1400 || segs < 1 ||
	    bursts < 1)
		error(1, 0, "usage: see the comment at the top of %s",
		      __FILE__);

	fd = socket(AF_PACKET, SOCK_RAW, htons(tx ? 0 : ETH_P_ALL));
	if (fd < 0)
		error(1, errno, "socket");
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = if_nametoindex(ifname);
	if (!sll.sll_ifindex)
		error(1, errno, "%s", ifname);
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)))
		error(1, errno, "bind");
	sll.sll_halen = ETH_ALEN;
	memcpy(sll.sll_addr, dmac, ETH_ALEN);

	c = tx ? do_tx(fd, &sll) : do_rx(fd);
	close(fd);
	return c;
}
