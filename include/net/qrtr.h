/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _NET_QRTR_H
#define _NET_QRTR_H

#include <linux/types.h>

/*
 * Base for the node ids the host assigns to endpoints. It sits just above the
 * 16-bit range a v2 header can express, so a v2 endpoint can never claim an id
 * in it. A v1 endpoint can claim any 32-bit id, so a collision is possible,
 * but unlikely as the firmware assigned node ids are either smaller than this
 * base or in the range of 0x08e5ff85. A collision is caught when the id is
 * added to the node lookup table.
 */
#define QRTR_NODE_HOST_BASE 0x10000u

/*
 * Compute host node id from a per-device index. The index must be unique among
 * the host assigned endpoints.
 */
static inline unsigned int qrtr_host_node_id(unsigned int index)
{
	return QRTR_NODE_HOST_BASE + index;
}

#endif /* _NET_QRTR_H */
