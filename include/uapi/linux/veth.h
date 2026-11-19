/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__NET_VETH_H_
#define _UAPI__NET_VETH_H_

enum {
	VETH_INFO_UNSPEC,
	VETH_INFO_PEER,
	VETH_INFO_TX_EXTRA_HEADROOM,

	__VETH_INFO_MAX
#define VETH_INFO_MAX	(__VETH_INFO_MAX - 1)
};

#endif
