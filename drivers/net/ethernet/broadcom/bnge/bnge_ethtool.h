/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2025 Broadcom */

#ifndef _BNGE_ETHTOOL_H_
#define _BNGE_ETHTOOL_H_

struct bnge_dev;

struct bnge_reg_desc {
	u8 size;
	u16 count;
};

void bnge_copy_regs(u8 *src, u8 *dst, const struct bnge_reg_desc *desc,
		    int num_desc, int max_len);

#define BNGE_PXP_REG_LEN	0x3110

#define BNGE_MBUF_REG_START	0x3800
#define BNGE_MBUF_REG_LEN	0x12c

#define BNGE_RX_MBUF_REG_OFFSET	BNGE_MBUF_REG_START
#define BNGE_TX_MBUF_REG_OFFSET	(BNGE_RX_MBUF_REG_OFFSET + 0x64 + \
				 sizeof(struct queue_adptv_qos_rx_info))

void bnge_set_ethtool_ops(struct net_device *dev);

#endif /* _BNGE_ETHTOOL_H_ */
