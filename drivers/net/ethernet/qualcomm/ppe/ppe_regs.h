/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2025 Qualcomm Innovation Center, Inc. All rights reserved.
 */

/* PPE hardware register and table declarations. */
#ifndef __PPE_REGS_H__
#define __PPE_REGS_H__

#include <linux/bitfield.h>

/* PPE queue counters enable/disable control. */
#define PPE_EG_BRIDGE_CONFIG_ADDR		0x20044
#define PPE_EG_BRIDGE_CONFIG_QUEUE_CNT_EN	BIT(2)

/* Table addresses for per-queue dequeue setting. */
#define PPE_DEQ_OPR_TBL_ADDR			0x430000
#define PPE_DEQ_OPR_TBL_ENTRIES			300
#define PPE_DEQ_OPR_TBL_INC			0x10
#define PPE_DEQ_OPR_TBL_DEQ_DISABLE		BIT(0)

/* There are 15 BM ports and 4 BM groups supported by PPE.
 * BM port (0-7) is for EDMA port 0, BM port (8-13) is for
 * PPE physical port 1-6 and BM port 14 is for EIP port.
 */
#define PPE_BM_PORT_FC_MODE_ADDR		0x600100
#define PPE_BM_PORT_FC_MODE_ENTRIES		15
#define PPE_BM_PORT_FC_MODE_INC			0x4
#define PPE_BM_PORT_FC_MODE_EN			BIT(0)

#define PPE_BM_PORT_GROUP_ID_ADDR		0x600180
#define PPE_BM_PORT_GROUP_ID_ENTRIES		15
#define PPE_BM_PORT_GROUP_ID_INC		0x4
#define PPE_BM_PORT_GROUP_ID_SHARED_GROUP_ID	GENMASK(1, 0)

#define PPE_BM_SHARED_GROUP_CFG_ADDR		0x600290
#define PPE_BM_SHARED_GROUP_CFG_ENTRIES		4
#define PPE_BM_SHARED_GROUP_CFG_INC		0x4
#define PPE_BM_SHARED_GROUP_CFG_SHARED_LIMIT	GENMASK(10, 0)

#define PPE_BM_PORT_FC_CFG_TBL_ADDR		0x601000
#define PPE_BM_PORT_FC_CFG_TBL_ENTRIES		15
#define PPE_BM_PORT_FC_CFG_TBL_INC		0x10
#define PPE_BM_PORT_FC_W0_REACT_LIMIT		GENMASK(8, 0)
#define PPE_BM_PORT_FC_W0_RESUME_THRESHOLD	GENMASK(17, 9)
#define PPE_BM_PORT_FC_W0_RESUME_OFFSET		GENMASK(28, 18)
#define PPE_BM_PORT_FC_W0_CEILING_LOW		GENMASK(31, 29)
#define PPE_BM_PORT_FC_W1_CEILING_HIGH		GENMASK(7, 0)
#define PPE_BM_PORT_FC_W1_WEIGHT		GENMASK(10, 8)
#define PPE_BM_PORT_FC_W1_DYNAMIC		BIT(11)
#define PPE_BM_PORT_FC_W1_PRE_ALLOC		GENMASK(22, 12)

#define PPE_BM_PORT_FC_SET_REACT_LIMIT(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)tbl_cfg, value, PPE_BM_PORT_FC_W0_REACT_LIMIT)
#define PPE_BM_PORT_FC_SET_RESUME_THRESHOLD(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)tbl_cfg, value, PPE_BM_PORT_FC_W0_RESUME_THRESHOLD)
#define PPE_BM_PORT_FC_SET_RESUME_OFFSET(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)tbl_cfg, value, PPE_BM_PORT_FC_W0_RESUME_OFFSET)
#define PPE_BM_PORT_FC_SET_CEILING_LOW(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)tbl_cfg, value, PPE_BM_PORT_FC_W0_CEILING_LOW)
#define PPE_BM_PORT_FC_SET_CEILING_HIGH(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)(tbl_cfg) + 0x1, value, PPE_BM_PORT_FC_W1_CEILING_HIGH)
#define PPE_BM_PORT_FC_SET_WEIGHT(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)(tbl_cfg) + 0x1, value, PPE_BM_PORT_FC_W1_WEIGHT)
#define PPE_BM_PORT_FC_SET_DYNAMIC(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)(tbl_cfg) + 0x1, value, PPE_BM_PORT_FC_W1_DYNAMIC)
#define PPE_BM_PORT_FC_SET_PRE_ALLOC(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)(tbl_cfg) + 0x1, value, PPE_BM_PORT_FC_W1_PRE_ALLOC)

/* PPE unicast queue (0-255) configurations. */
#define PPE_AC_UNICAST_QUEUE_CFG_TBL_ADDR	0x848000
#define PPE_AC_UNICAST_QUEUE_CFG_TBL_ENTRIES	256
#define PPE_AC_UNICAST_QUEUE_CFG_TBL_INC	0x10
#define PPE_AC_UNICAST_QUEUE_CFG_W0_EN		BIT(0)
#define PPE_AC_UNICAST_QUEUE_CFG_W0_WRED_EN	BIT(1)
#define PPE_AC_UNICAST_QUEUE_CFG_W0_FC_EN	BIT(2)
#define PPE_AC_UNICAST_QUEUE_CFG_W0_CLR_AWARE	BIT(3)
#define PPE_AC_UNICAST_QUEUE_CFG_W0_GRP_ID	GENMASK(5, 4)
#define PPE_AC_UNICAST_QUEUE_CFG_W0_PRE_LIMIT	GENMASK(16, 6)
#define PPE_AC_UNICAST_QUEUE_CFG_W0_DYNAMIC	BIT(17)
#define PPE_AC_UNICAST_QUEUE_CFG_W0_WEIGHT	GENMASK(20, 18)
#define PPE_AC_UNICAST_QUEUE_CFG_W0_THRESHOLD	GENMASK(31, 21)
#define PPE_AC_UNICAST_QUEUE_CFG_W3_GRN_RESUME	GENMASK(23, 13)

#define PPE_AC_UNICAST_QUEUE_SET_EN(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)tbl_cfg, value, PPE_AC_UNICAST_QUEUE_CFG_W0_EN)
#define PPE_AC_UNICAST_QUEUE_SET_GRP_ID(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)tbl_cfg, value, PPE_AC_UNICAST_QUEUE_CFG_W0_GRP_ID)
#define PPE_AC_UNICAST_QUEUE_SET_PRE_LIMIT(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)tbl_cfg, value, PPE_AC_UNICAST_QUEUE_CFG_W0_PRE_LIMIT)
#define PPE_AC_UNICAST_QUEUE_SET_DYNAMIC(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)tbl_cfg, value, PPE_AC_UNICAST_QUEUE_CFG_W0_DYNAMIC)
#define PPE_AC_UNICAST_QUEUE_SET_WEIGHT(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)tbl_cfg, value, PPE_AC_UNICAST_QUEUE_CFG_W0_WEIGHT)
#define PPE_AC_UNICAST_QUEUE_SET_THRESHOLD(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)tbl_cfg, value, PPE_AC_UNICAST_QUEUE_CFG_W0_THRESHOLD)
#define PPE_AC_UNICAST_QUEUE_SET_GRN_RESUME(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)(tbl_cfg) + 0x3, value, PPE_AC_UNICAST_QUEUE_CFG_W3_GRN_RESUME)

/* PPE multicast queue (256-299) configurations. */
#define PPE_AC_MULTICAST_QUEUE_CFG_TBL_ADDR	0x84a000
#define PPE_AC_MULTICAST_QUEUE_CFG_TBL_ENTRIES	44
#define PPE_AC_MULTICAST_QUEUE_CFG_TBL_INC	0x10
#define PPE_AC_MULTICAST_QUEUE_CFG_W0_EN	BIT(0)
#define PPE_AC_MULTICAST_QUEUE_CFG_W0_FC_EN	BIT(1)
#define PPE_AC_MULTICAST_QUEUE_CFG_W0_CLR_AWARE	BIT(2)
#define PPE_AC_MULTICAST_QUEUE_CFG_W0_GRP_ID	GENMASK(4, 3)
#define PPE_AC_MULTICAST_QUEUE_CFG_W0_PRE_LIMIT	GENMASK(15, 5)
#define PPE_AC_MULTICAST_QUEUE_CFG_W0_THRESHOLD	GENMASK(26, 16)
#define PPE_AC_MULTICAST_QUEUE_CFG_W2_RESUME	GENMASK(17, 7)

#define PPE_AC_MULTICAST_QUEUE_SET_EN(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)tbl_cfg, value, PPE_AC_MULTICAST_QUEUE_CFG_W0_EN)
#define PPE_AC_MULTICAST_QUEUE_SET_GRN_GRP_ID(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)tbl_cfg, value, PPE_AC_MULTICAST_QUEUE_CFG_W0_GRP_ID)
#define PPE_AC_MULTICAST_QUEUE_SET_GRN_PRE_LIMIT(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)tbl_cfg, value, PPE_AC_MULTICAST_QUEUE_CFG_W0_PRE_LIMIT)
#define PPE_AC_MULTICAST_QUEUE_SET_GRN_THRESHOLD(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)tbl_cfg, value, PPE_AC_MULTICAST_QUEUE_CFG_W0_THRESHOLD)
#define PPE_AC_MULTICAST_QUEUE_SET_GRN_RESUME(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)(tbl_cfg) + 0x2, value, PPE_AC_MULTICAST_QUEUE_CFG_W2_RESUME)

/* PPE admission control group (0-3) configurations */
#define PPE_AC_GRP_CFG_TBL_ADDR			0x84c000
#define PPE_AC_GRP_CFG_TBL_ENTRIES		0x4
#define PPE_AC_GRP_CFG_TBL_INC			0x10
#define PPE_AC_GRP_W0_AC_EN			BIT(0)
#define PPE_AC_GRP_W0_AC_FC_EN			BIT(1)
#define PPE_AC_GRP_W0_CLR_AWARE			BIT(2)
#define PPE_AC_GRP_W0_THRESHOLD_LOW		GENMASK(31, 25)
#define PPE_AC_GRP_W1_THRESHOLD_HIGH		GENMASK(3, 0)
#define PPE_AC_GRP_W1_BUF_LIMIT			GENMASK(14, 4)
#define PPE_AC_GRP_W2_RESUME_GRN		GENMASK(15, 5)
#define PPE_AC_GRP_W2_PRE_ALLOC			GENMASK(26, 16)

#define PPE_AC_GRP_SET_BUF_LIMIT(tbl_cfg, value)	\
	u32p_replace_bits((u32 *)(tbl_cfg) + 0x1, value, PPE_AC_GRP_W1_BUF_LIMIT)

/* Table addresses for per-queue enqueue setting. */
#define PPE_ENQ_OPR_TBL_ADDR			0x85c000
#define PPE_ENQ_OPR_TBL_ENTRIES			300
#define PPE_ENQ_OPR_TBL_INC			0x10
#define PPE_ENQ_OPR_TBL_ENQ_DISABLE		BIT(0)
#endif
