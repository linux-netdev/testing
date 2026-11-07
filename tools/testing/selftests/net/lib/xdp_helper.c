// SPDX-License-Identifier: GPL-2.0
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <inttypes.h>

#include "ksft.h"

#define UMEM_SZ (1U << 16)
#define NUM_DESC (UMEM_SZ / 2048)


static void print_usage(const char *bin)
{
	fprintf(stderr, "Usage: %s ifindex queue_id [-z] [-t frame_hex]\n\n"
		"where:\n\t-z: force zerocopy mode\n"
		"\t-t: send one frame, given in hex, and exit\n", bin);
}

static int parse_frame(unsigned char *buf, const char *hex)
{
	size_t len = strlen(hex) / 2;
	size_t i;

	if (!len || len > 2048 || strlen(hex) % 2 ||
	    strspn(hex, "0123456789abcdefABCDEF") != strlen(hex))
		return -1;
	for (i = 0; i < len; i++)
		if (sscanf(hex + 2 * i, "%2hhx", &buf[i]) != 1)
			return -1;
	return len;
}

/* Send the frame at UMEM address 0 and wait until its descriptor shows up
 * on the completion ring. In copy mode this happens when the skb is freed.
 */
static int send_frame(int sock_fd, __u32 len)
{
	struct xdp_mmap_offsets off;
	socklen_t optlen = sizeof(off);
	struct xdp_desc *desc;
	size_t tx_sz, cq_sz;
	char *tx, *cq;
	int ret = 1;
	int i;

	if (getsockopt(sock_fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen)) {
		perror("getsockopt failed");
		return 1;
	}

	tx_sz = off.tx.desc + NUM_DESC * sizeof(*desc);
	tx = mmap(NULL, tx_sz, PROT_READ | PROT_WRITE, MAP_SHARED, sock_fd,
		  XDP_PGOFF_TX_RING);
	if (tx == MAP_FAILED) {
		perror("TX ring mmap failed");
		return 1;
	}

	cq_sz = off.cr.desc + NUM_DESC * sizeof(__u64);
	cq = mmap(NULL, cq_sz, PROT_READ | PROT_WRITE, MAP_SHARED, sock_fd,
		  XDP_UMEM_PGOFF_COMPLETION_RING);
	if (cq == MAP_FAILED) {
		perror("completion ring mmap failed");
		goto out_tx;
	}

	desc = (struct xdp_desc *)(tx + off.tx.desc);
	desc->addr = 0;
	desc->len = len;
	__atomic_store_n((__u32 *)(tx + off.tx.producer), 1, __ATOMIC_RELEASE);

	if (sendto(sock_fd, NULL, 0, MSG_DONTWAIT, NULL, 0) < 0) {
		perror("sendto failed");
		goto out;
	}

	for (i = 0; i < 100; i++) {
		usleep(10000);
		if (__atomic_load_n((__u32 *)(cq + off.cr.producer),
				    __ATOMIC_ACQUIRE)) {
			ret = 0;
			goto out;
		}
	}

	fprintf(stderr, "no TX completion\n");
out:
	munmap(cq, cq_sz);
out_tx:
	munmap(tx, tx_sz);
	return ret;
}

/* this is a simple helper program that creates an XDP socket and does the
 * minimum necessary to get bind() to succeed.
 *
 * without -t it does not process packets. with -t it sends one frame
 * through the TX ring and exits once the frame completes.
 *
 * it is used by queues.py to ensure the xsk netlinux attribute is set
 * correctly.
 */
int main(int argc, char **argv)
{
	struct xdp_umem_reg umem_reg = { 0 };
	struct sockaddr_xdp sxdp = { 0 };
	int num_desc = NUM_DESC;
	int frame_len = 0;
	void *umem_area;
	int retry = 0;
	int ifindex;
	int sock_fd;
	int queue;
	int ret;
	int i;

	if (argc < 3) {
		print_usage(argv[0]);
		return 1;
	}

	sock_fd = socket(AF_XDP, SOCK_RAW, 0);
	if (sock_fd < 0) {
		perror("socket creation failed");
		/* if the kernel doesn't support AF_XDP, let the test program
		 * know with -1. All other error paths return 1.
		 */
		if (errno == EAFNOSUPPORT)
			return -1;
		return 1;
	}

	/* "Probing mode", just checking if AF_XDP sockets are supported */
	if (!strcmp(argv[1], "-") && !strcmp(argv[2], "-")) {
		printf("AF_XDP support detected\n");
		close(sock_fd);
		return 0;
	}

	ifindex = atoi(argv[1]);
	queue = atoi(argv[2]);

	umem_area = mmap(NULL, UMEM_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE |
			MAP_ANONYMOUS, -1, 0);
	if (umem_area == MAP_FAILED) {
		perror("mmap failed");
		return 1;
	}

	umem_reg.addr = (uintptr_t)umem_area;
	umem_reg.len = UMEM_SZ;
	umem_reg.chunk_size = 2048;
	umem_reg.headroom = 0;

	setsockopt(sock_fd, SOL_XDP, XDP_UMEM_REG, &umem_reg,
		   sizeof(umem_reg));
	setsockopt(sock_fd, SOL_XDP, XDP_UMEM_FILL_RING, &num_desc,
		   sizeof(num_desc));
	setsockopt(sock_fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &num_desc,
		   sizeof(num_desc));
	setsockopt(sock_fd, SOL_XDP, XDP_RX_RING, &num_desc, sizeof(num_desc));

	sxdp.sxdp_family = AF_XDP;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = queue;
	sxdp.sxdp_flags = 0;

	for (i = 3; i < argc; i++) {
		if (!strcmp(argv[i], "-z")) {
			sxdp.sxdp_flags = XDP_ZEROCOPY;
		} else if (!strcmp(argv[i], "-t") && i + 1 < argc &&
			   !frame_len) {
			frame_len = parse_frame(umem_area, argv[++i]);
			if (frame_len < 0) {
				print_usage(argv[0]);
				return 1;
			}
			if (setsockopt(sock_fd, SOL_XDP, XDP_TX_RING, &num_desc,
				       sizeof(num_desc))) {
				perror("setsockopt XDP_TX_RING failed");
				return 1;
			}
		} else {
			print_usage(argv[0]);
			return 1;
		}
	}

	while (1) {
		if (bind(sock_fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) == 0)
			break;

		if (errno == EBUSY && retry < 3) {
			retry++;
			sleep(1);
			continue;
		} else {
			perror("bind failed");
			munmap(umem_area, UMEM_SZ);
			close(sock_fd);
			return 1;
		}
	}

	if (frame_len) {
		ret = send_frame(sock_fd, frame_len);
		munmap(umem_area, UMEM_SZ);
		close(sock_fd);
		return ret;
	}

	ksft_ready();
	ksft_wait();

	/* parent program will write a byte to stdin when its ready for this
	 * helper to exit
	 */

	close(sock_fd);
	return 0;
}
