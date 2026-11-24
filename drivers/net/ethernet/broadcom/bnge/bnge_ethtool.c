// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Broadcom.

#include <linux/unaligned.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <net/devlink.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/ethtool_netlink.h>

#include "bnge.h"
#include "bnge_ethtool.h"
#include "bnge_hwrm.h"
#include "bnge_hwrm_lib.h"
#include "bnge_netdev.h"

static int bnge_nway_reset(struct net_device *dev)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;
	bool set_pause = false;
	int rc = 0;

	if (!BNGE_PHY_CFG_ABLE(bd))
		return -EOPNOTSUPP;

	if (!(bn->eth_link_info.autoneg & BNGE_AUTONEG_SPEED))
		return -EINVAL;

	if (!(bd->phy_flags & BNGE_PHY_FL_NO_PAUSE))
		set_pause = true;

	if (netif_running(dev))
		rc = bnge_hwrm_set_link_setting(bn, set_pause);

	return rc;
}

static const char * const bnge_ring_q_stats_str[] = {
	"ucast_packets",
	"mcast_packets",
	"bcast_packets",
	"ucast_bytes",
	"mcast_bytes",
	"bcast_bytes",
};

static const char * const bnge_ring_tpa2_stats_str[] = {
	"tpa_eligible_pkt",
	"tpa_eligible_bytes",
	"tpa_pkt",
	"tpa_bytes",
	"tpa_errors",
	"tpa_events",
};

#define BNGE_RX_PORT_STATS_ENTRY(suffix)	\
	{ BNGE_RX_STATS_OFFSET(rx_##suffix), "rxp_" __stringify(suffix) }

#define BNGE_TX_PORT_STATS_ENTRY(suffix)	\
	{ BNGE_TX_STATS_OFFSET(tx_##suffix), "txp_" __stringify(suffix) }

#define BNGE_RX_STATS_EXT_ENTRY(counter)	\
	{ BNGE_RX_STATS_EXT_OFFSET(counter), __stringify(counter) }

#define BNGE_TX_STATS_EXT_ENTRY(counter)	\
	{ BNGE_TX_STATS_EXT_OFFSET(counter), __stringify(counter) }

#define BNGE_RX_STATS_EXT_PFC_ENTRY(n)				\
	BNGE_RX_STATS_EXT_ENTRY(pfc_pri##n##_rx_duration_us),	\
	BNGE_RX_STATS_EXT_ENTRY(pfc_pri##n##_rx_transitions)

#define BNGE_TX_STATS_EXT_PFC_ENTRY(n)				\
	BNGE_TX_STATS_EXT_ENTRY(pfc_pri##n##_tx_duration_us),	\
	BNGE_TX_STATS_EXT_ENTRY(pfc_pri##n##_tx_transitions)

#define BNGE_RX_STATS_EXT_PFC_ENTRIES				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(0),				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(1),				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(2),				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(3),				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(4),				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(5),				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(6),				\
	BNGE_RX_STATS_EXT_PFC_ENTRY(7)

#define BNGE_TX_STATS_EXT_PFC_ENTRIES				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(0),				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(1),				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(2),				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(3),				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(4),				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(5),				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(6),				\
	BNGE_TX_STATS_EXT_PFC_ENTRY(7)

#define BNGE_RX_STATS_EXT_COS_ENTRY(n)				\
	BNGE_RX_STATS_EXT_ENTRY(rx_bytes_cos##n),		\
	BNGE_RX_STATS_EXT_ENTRY(rx_packets_cos##n)

#define BNGE_TX_STATS_EXT_COS_ENTRY(n)				\
	BNGE_TX_STATS_EXT_ENTRY(tx_bytes_cos##n),		\
	BNGE_TX_STATS_EXT_ENTRY(tx_packets_cos##n)

#define BNGE_RX_STATS_EXT_COS_ENTRIES				\
	BNGE_RX_STATS_EXT_COS_ENTRY(0),				\
	BNGE_RX_STATS_EXT_COS_ENTRY(1),				\
	BNGE_RX_STATS_EXT_COS_ENTRY(2),				\
	BNGE_RX_STATS_EXT_COS_ENTRY(3),				\
	BNGE_RX_STATS_EXT_COS_ENTRY(4),				\
	BNGE_RX_STATS_EXT_COS_ENTRY(5),				\
	BNGE_RX_STATS_EXT_COS_ENTRY(6),				\
	BNGE_RX_STATS_EXT_COS_ENTRY(7)				\

#define BNGE_TX_STATS_EXT_COS_ENTRIES				\
	BNGE_TX_STATS_EXT_COS_ENTRY(0),				\
	BNGE_TX_STATS_EXT_COS_ENTRY(1),				\
	BNGE_TX_STATS_EXT_COS_ENTRY(2),				\
	BNGE_TX_STATS_EXT_COS_ENTRY(3),				\
	BNGE_TX_STATS_EXT_COS_ENTRY(4),				\
	BNGE_TX_STATS_EXT_COS_ENTRY(5),				\
	BNGE_TX_STATS_EXT_COS_ENTRY(6),				\
	BNGE_TX_STATS_EXT_COS_ENTRY(7)				\

#define BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(n)			\
	BNGE_RX_STATS_EXT_ENTRY(rx_discard_bytes_cos##n),	\
	BNGE_RX_STATS_EXT_ENTRY(rx_discard_packets_cos##n)

#define BNGE_RX_STATS_EXT_DISCARD_COS_ENTRIES				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(0),				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(1),				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(2),				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(3),				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(4),				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(5),				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(6),				\
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRY(7)

#define BNGE_RX_STATS_PRI_ENTRY(counter, n)		\
	{ BNGE_RX_STATS_EXT_OFFSET(counter##_cos0),	\
	  __stringify(counter##_pri##n) }

#define BNGE_TX_STATS_PRI_ENTRY(counter, n)		\
	{ BNGE_TX_STATS_EXT_OFFSET(counter##_cos0),	\
	  __stringify(counter##_pri##n) }

#define BNGE_RX_STATS_PRI_ENTRIES(counter)		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 0),		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 1),		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 2),		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 3),		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 4),		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 5),		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 6),		\
	BNGE_RX_STATS_PRI_ENTRY(counter, 7)

#define BNGE_TX_STATS_PRI_ENTRIES(counter)		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 0),		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 1),		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 2),		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 3),		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 4),		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 5),		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 6),		\
	BNGE_TX_STATS_PRI_ENTRY(counter, 7)

#define NUM_RING_Q_HW_STATS		ARRAY_SIZE(bnge_ring_q_stats_str)

static const struct {
	long offset;
	char string[ETH_GSTRING_LEN];
} bnge_tx_port_stats_ext_arr[] = {
	BNGE_TX_STATS_EXT_COS_ENTRIES,
	BNGE_TX_STATS_EXT_PFC_ENTRIES,
};

static const struct {
	long base_off;
	char string[ETH_GSTRING_LEN];
} bnge_rx_bytes_pri_arr[] = {
	BNGE_RX_STATS_PRI_ENTRIES(rx_bytes),
};

static const struct {
	long base_off;
	char string[ETH_GSTRING_LEN];
} bnge_rx_pkts_pri_arr[] = {
	BNGE_RX_STATS_PRI_ENTRIES(rx_packets),
};

static const struct {
	long base_off;
	char string[ETH_GSTRING_LEN];
} bnge_tx_bytes_pri_arr[] = {
	BNGE_TX_STATS_PRI_ENTRIES(tx_bytes),
};

static const struct {
	long base_off;
	char string[ETH_GSTRING_LEN];
} bnge_tx_pkts_pri_arr[] = {
	BNGE_TX_STATS_PRI_ENTRIES(tx_packets),
};

static const struct {
	long offset;
	char string[ETH_GSTRING_LEN];
} bnge_port_stats_arr[] = {
	BNGE_RX_PORT_STATS_ENTRY(good_vlan_frames),
	BNGE_RX_PORT_STATS_ENTRY(mtu_err_frames),
	BNGE_RX_PORT_STATS_ENTRY(tagged_frames),
	BNGE_RX_PORT_STATS_ENTRY(double_tagged_frames),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri0),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri1),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri2),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri3),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri4),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri5),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri6),
	BNGE_RX_PORT_STATS_ENTRY(pfc_ena_frames_pri7),
	BNGE_RX_PORT_STATS_ENTRY(eee_lpi_events),
	BNGE_RX_PORT_STATS_ENTRY(eee_lpi_duration),
	BNGE_RX_PORT_STATS_ENTRY(runt_bytes),
	BNGE_RX_PORT_STATS_ENTRY(runt_frames),

	BNGE_TX_PORT_STATS_ENTRY(good_vlan_frames),
	BNGE_TX_PORT_STATS_ENTRY(jabber_frames),
	BNGE_TX_PORT_STATS_ENTRY(fcs_err_frames),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri0),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri1),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri2),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri3),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri4),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri5),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri6),
	BNGE_TX_PORT_STATS_ENTRY(pfc_ena_frames_pri7),
	BNGE_TX_PORT_STATS_ENTRY(eee_lpi_events),
	BNGE_TX_PORT_STATS_ENTRY(eee_lpi_duration),
	BNGE_TX_PORT_STATS_ENTRY(xthol_frames),
};

static const struct {
	long offset;
	char string[ETH_GSTRING_LEN];
} bnge_port_stats_ext_arr[] = {
	BNGE_RX_STATS_EXT_ENTRY(continuous_pause_events),
	BNGE_RX_STATS_EXT_ENTRY(resume_pause_events),
	BNGE_RX_STATS_EXT_ENTRY(continuous_roce_pause_events),
	BNGE_RX_STATS_EXT_ENTRY(resume_roce_pause_events),
	BNGE_RX_STATS_EXT_COS_ENTRIES,
	BNGE_RX_STATS_EXT_PFC_ENTRIES,
	BNGE_RX_STATS_EXT_ENTRY(rx_bits),
	BNGE_RX_STATS_EXT_ENTRY(rx_buffer_passed_threshold),
	BNGE_RX_STATS_EXT_DISCARD_COS_ENTRIES,
	BNGE_RX_STATS_EXT_ENTRY(rx_filter_miss),
};

static int bnge_get_num_tpa_ring_stats(struct bnge_dev *bd)
{
	if (BNGE_SUPPORTS_TPA(bd))
		return BNGE_NUM_TPA_RING_STATS;
	return 0;
}

#define BNGE_NUM_PORT_STATS ARRAY_SIZE(bnge_port_stats_arr)
#define BNGE_NUM_STATS_PRI			\
	(ARRAY_SIZE(bnge_rx_bytes_pri_arr) +	\
	 ARRAY_SIZE(bnge_rx_pkts_pri_arr) +	\
	 ARRAY_SIZE(bnge_tx_bytes_pri_arr) +	\
	 ARRAY_SIZE(bnge_tx_pkts_pri_arr))

static int bnge_get_num_ring_stats(struct bnge_dev *bd)
{
	int rx, tx;

	rx = NUM_RING_Q_HW_STATS + bnge_get_num_tpa_ring_stats(bd);
	tx = NUM_RING_Q_HW_STATS;
	return rx * bd->rx_nr_rings +
	       tx * bd->tx_nr_rings_per_tc;
}

static u32 bnge_get_num_stats(struct bnge_net *bn)
{
	u32 num_stats = bnge_get_num_ring_stats(bn->bd);
	u32 len;

	if (bn->flags & BNGE_FLAG_PORT_STATS)
		num_stats += BNGE_NUM_PORT_STATS;

	if (bn->flags & BNGE_FLAG_PORT_STATS_EXT) {
		len = min_t(u32, bn->fw_rx_stats_ext_size,
			    ARRAY_SIZE(bnge_port_stats_ext_arr));
		num_stats += len;
		len = min_t(u32, bn->fw_tx_stats_ext_size,
			    ARRAY_SIZE(bnge_tx_port_stats_ext_arr));
		num_stats += len;
		if (bn->pri2cos_valid)
			num_stats += BNGE_NUM_STATS_PRI;
	}

	return num_stats;
}

static void bnge_get_drvinfo(struct net_device *dev,
			     struct ethtool_drvinfo *info)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;

	strscpy(info->driver, DRV_NAME, sizeof(info->driver));
	strscpy(info->fw_version, bd->fw_ver_str, sizeof(info->fw_version));
	strscpy(info->bus_info, pci_name(bd->pdev), sizeof(info->bus_info));
}

static int bnge_get_sset_count(struct net_device *dev, int sset)
{
	struct bnge_net *bn = netdev_priv(dev);

	switch (sset) {
	case ETH_SS_STATS:
		return bnge_get_num_stats(bn);
	default:
		return -EOPNOTSUPP;
	}
}

static bool is_rx_ring(struct bnge_dev *bd, u16 ring_num)
{
	return ring_num < bd->rx_nr_rings;
}

static bool is_tx_ring(struct bnge_dev *bd, u16 ring_num)
{
	u16 tx_base = 0;

	if (!(bd->flags & BNGE_EN_SHARED_CHNL))
		tx_base = bd->rx_nr_rings;

	return ring_num >= tx_base && ring_num < (tx_base + bd->tx_nr_rings_per_tc);
}

static void bnge_get_ethtool_stats(struct net_device *dev,
				   struct ethtool_stats *stats, u64 *buf)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;
	u32 tpa_stats;
	u32 i, j = 0;

	if (!bn->bnapi) {
		j += bnge_get_num_ring_stats(bd);
		goto skip_ring_stats;
	}

	tpa_stats = bnge_get_num_tpa_ring_stats(bd);
	for (i = 0; i < bd->nq_nr_rings; i++) {
		struct bnge_napi *bnapi = bn->bnapi[i];
		struct bnge_nq_ring_info *nqr;
		u64 *sw_stats;
		int k;

		nqr = &bnapi->nq_ring;
		sw_stats = nqr->stats.sw_stats;

		if (is_rx_ring(bd, i)) {
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, rx_ucast_pkts);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, rx_mcast_pkts);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, rx_bcast_pkts);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, rx_ucast_bytes);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, rx_mcast_bytes);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, rx_bcast_bytes);
		}
		if (is_tx_ring(bd, i)) {
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, tx_ucast_pkts);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, tx_mcast_pkts);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, tx_bcast_pkts);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, tx_ucast_bytes);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, tx_mcast_bytes);
			buf[j++] = BNGE_GET_RING_STATS64(sw_stats, tx_bcast_bytes);
		}
		if (!tpa_stats || !is_rx_ring(bd, i))
			continue;

		k = BNGE_NUM_RX_RING_STATS + BNGE_NUM_TX_RING_STATS;
		for (; k < BNGE_NUM_RX_RING_STATS + BNGE_NUM_TX_RING_STATS +
			   tpa_stats; j++, k++)
			buf[j] = sw_stats[k];
	}

skip_ring_stats:
	if (bn->flags & BNGE_FLAG_PORT_STATS) {
		u64 *port_stats = bn->port_stats.sw_stats;

		for (i = 0; i < BNGE_NUM_PORT_STATS; i++, j++)
			buf[j] = *(port_stats + bnge_port_stats_arr[i].offset);
	}
	if (bn->flags & BNGE_FLAG_PORT_STATS_EXT) {
		u64 *rx_port_stats_ext = bn->rx_port_stats_ext.sw_stats;
		u64 *tx_port_stats_ext = bn->tx_port_stats_ext.sw_stats;
		u32 len;

		len = min_t(u32, bn->fw_rx_stats_ext_size,
			    ARRAY_SIZE(bnge_port_stats_ext_arr));
		for (i = 0; i < len; i++, j++) {
			buf[j] = *(rx_port_stats_ext +
				   bnge_port_stats_ext_arr[i].offset);
		}
		len = min_t(u32, bn->fw_tx_stats_ext_size,
			    ARRAY_SIZE(bnge_tx_port_stats_ext_arr));
		for (i = 0; i < len; i++, j++) {
			buf[j] = *(tx_port_stats_ext +
				   bnge_tx_port_stats_ext_arr[i].offset);
		}
		if (bn->pri2cos_valid) {
			for (i = 0; i < 8; i++, j++) {
				long n = bnge_rx_bytes_pri_arr[i].base_off +
					 bn->pri2cos_idx[i];

				buf[j] = *(rx_port_stats_ext + n);
			}
			for (i = 0; i < 8; i++, j++) {
				long n = bnge_rx_pkts_pri_arr[i].base_off +
					 bn->pri2cos_idx[i];

				buf[j] = *(rx_port_stats_ext + n);
			}
			for (i = 0; i < 8; i++, j++) {
				long n = bnge_tx_bytes_pri_arr[i].base_off +
					 bn->pri2cos_idx[i];

				buf[j] = *(tx_port_stats_ext + n);
			}
			for (i = 0; i < 8; i++, j++) {
				long n = bnge_tx_pkts_pri_arr[i].base_off +
					 bn->pri2cos_idx[i];

				buf[j] = *(tx_port_stats_ext + n);
			}
		}
	}
}

static void bnge_get_strings(struct net_device *dev, u32 stringset, u8 *buf)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;
	u32 i, j, num_str;
	const char *str;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < bd->nq_nr_rings; i++) {
			if (is_rx_ring(bd, i))
				for (j = 0; j < NUM_RING_Q_HW_STATS; j++) {
					str = bnge_ring_q_stats_str[j];
					ethtool_sprintf(&buf, "rxq%d_%s", i,
							str);
				}
			if (is_tx_ring(bd, i))
				for (j = 0; j < NUM_RING_Q_HW_STATS; j++) {
					str = bnge_ring_q_stats_str[j];
					ethtool_sprintf(&buf, "txq%d_%s", i,
							str);
				}
			num_str = bnge_get_num_tpa_ring_stats(bd);
			if (!num_str || !is_rx_ring(bd, i))
				continue;

			for (j = 0; j < num_str; j++) {
				str = bnge_ring_tpa2_stats_str[j];
				ethtool_sprintf(&buf, "rxq%d_%s", i, str);
			}
		}

		if (bn->flags & BNGE_FLAG_PORT_STATS)
			for (i = 0; i < BNGE_NUM_PORT_STATS; i++) {
				str = bnge_port_stats_arr[i].string;
				ethtool_puts(&buf, str);
			}

		if (bn->flags & BNGE_FLAG_PORT_STATS_EXT) {
			u32 len;

			len = min_t(u32, bn->fw_rx_stats_ext_size,
				    ARRAY_SIZE(bnge_port_stats_ext_arr));
			for (i = 0; i < len; i++) {
				str = bnge_port_stats_ext_arr[i].string;
				ethtool_puts(&buf, str);
			}

			len = min_t(u32, bn->fw_tx_stats_ext_size,
				    ARRAY_SIZE(bnge_tx_port_stats_ext_arr));
			for (i = 0; i < len; i++) {
				str = bnge_tx_port_stats_ext_arr[i].string;
				ethtool_puts(&buf, str);
			}

			if (bn->pri2cos_valid) {
				for (i = 0; i < 8; i++) {
					str = bnge_rx_bytes_pri_arr[i].string;
					ethtool_puts(&buf, str);
				}

				for (i = 0; i < 8; i++) {
					str = bnge_rx_pkts_pri_arr[i].string;
					ethtool_puts(&buf, str);
				}

				for (i = 0; i < 8; i++) {
					str = bnge_tx_bytes_pri_arr[i].string;
					ethtool_puts(&buf, str);
				}

				for (i = 0; i < 8; i++) {
					str = bnge_tx_pkts_pri_arr[i].string;
					ethtool_puts(&buf, str);
				}
			}
		}
		break;
	default:
		netdev_err(bd->netdev, "%s invalid request %x\n",
			   __func__, stringset);
		break;
	}
}

static void bnge_get_eth_phy_stats(struct net_device *dev,
				   struct ethtool_eth_phy_stats *phy_stats)
{
	struct bnge_net *bn = netdev_priv(dev);
	u64 *rx;

	if (!(bn->flags & BNGE_FLAG_PORT_STATS_EXT))
		return;

	rx = bn->rx_port_stats_ext.sw_stats;
	phy_stats->SymbolErrorDuringCarrier =
		*(rx + BNGE_RX_STATS_EXT_OFFSET(rx_pcs_symbol_err));
}

static void bnge_get_eth_mac_stats(struct net_device *dev,
				   struct ethtool_eth_mac_stats *mac_stats)
{
	struct bnge_net *bn = netdev_priv(dev);
	u64 *rx, *tx;

	if (!(bn->flags & BNGE_FLAG_PORT_STATS))
		return;

	rx = bn->port_stats.sw_stats;
	tx = bn->port_stats.sw_stats + BNGE_TX_PORT_STATS_BYTE_OFFSET / 8;

	mac_stats->FramesReceivedOK =
		BNGE_GET_RX_PORT_STATS64(rx, rx_good_frames);
	mac_stats->FramesTransmittedOK =
		BNGE_GET_TX_PORT_STATS64(tx, tx_good_frames);
	mac_stats->FrameCheckSequenceErrors =
		BNGE_GET_RX_PORT_STATS64(rx, rx_fcs_err_frames);
	mac_stats->AlignmentErrors =
		BNGE_GET_RX_PORT_STATS64(rx, rx_align_err_frames);
	mac_stats->OutOfRangeLengthField =
		BNGE_GET_RX_PORT_STATS64(rx, rx_oor_len_frames);
	mac_stats->OctetsReceivedOK = BNGE_GET_RX_PORT_STATS64(rx, rx_bytes);
	mac_stats->OctetsTransmittedOK = BNGE_GET_TX_PORT_STATS64(tx, tx_bytes);
	mac_stats->MulticastFramesReceivedOK =
		BNGE_GET_RX_PORT_STATS64(rx, rx_mcast_frames);
	mac_stats->BroadcastFramesReceivedOK =
		BNGE_GET_RX_PORT_STATS64(rx, rx_bcast_frames);
	mac_stats->MulticastFramesXmittedOK =
		BNGE_GET_TX_PORT_STATS64(tx, tx_mcast_frames);
	mac_stats->BroadcastFramesXmittedOK =
		BNGE_GET_TX_PORT_STATS64(tx, tx_bcast_frames);
	mac_stats->FrameTooLongErrors =
		BNGE_GET_RX_PORT_STATS64(rx, rx_ovrsz_frames);
}

static void bnge_get_eth_ctrl_stats(struct net_device *dev,
				    struct ethtool_eth_ctrl_stats *ctrl_stats)
{
	struct bnge_net *bn = netdev_priv(dev);
	u64 *rx;

	if (!(bn->flags & BNGE_FLAG_PORT_STATS))
		return;

	rx = bn->port_stats.sw_stats;
	ctrl_stats->MACControlFramesReceived =
		BNGE_GET_RX_PORT_STATS64(rx, rx_ctrl_frames);
}

static void bnge_get_pause_stats(struct net_device *dev,
				 struct ethtool_pause_stats *pause_stats)
{
	struct bnge_net *bn = netdev_priv(dev);
	u64 *rx, *tx;

	if (!(bn->flags & BNGE_FLAG_PORT_STATS))
		return;

	rx = bn->port_stats.sw_stats;
	tx = bn->port_stats.sw_stats + BNGE_TX_PORT_STATS_BYTE_OFFSET / 8;

	pause_stats->rx_pause_frames =
		BNGE_GET_RX_PORT_STATS64(rx, rx_pause_frames);
	pause_stats->tx_pause_frames =
		BNGE_GET_TX_PORT_STATS64(tx, tx_pause_frames);
}

static const struct ethtool_rmon_hist_range bnge_rmon_ranges[] = {
	{    0,    64 },
	{   65,   127 },
	{  128,   255 },
	{  256,   511 },
	{  512,  1023 },
	{ 1024,  1518 },
	{ 1519,  2047 },
	{ 2048,  4095 },
	{ 4096,  9216 },
	{ 9217, 16383 },
	{}
};

static void bnge_get_rmon_stats(struct net_device *dev,
				struct ethtool_rmon_stats *rmon_stats,
				const struct ethtool_rmon_hist_range **ranges)
{
	struct bnge_net *bn = netdev_priv(dev);
	u64 *rx, *tx;

	if (!(bn->flags & BNGE_FLAG_PORT_STATS))
		return;

	rx = bn->port_stats.sw_stats;
	tx = bn->port_stats.sw_stats + BNGE_TX_PORT_STATS_BYTE_OFFSET / 8;

	rmon_stats->jabbers = BNGE_GET_RX_PORT_STATS64(rx, rx_jbr_frames);
	rmon_stats->oversize_pkts =
		BNGE_GET_RX_PORT_STATS64(rx, rx_ovrsz_frames);
	rmon_stats->undersize_pkts =
		BNGE_GET_RX_PORT_STATS64(rx, rx_undrsz_frames);

	rmon_stats->hist[0] = BNGE_GET_RX_PORT_STATS64(rx, rx_64b_frames);
	rmon_stats->hist[1] = BNGE_GET_RX_PORT_STATS64(rx, rx_65b_127b_frames);
	rmon_stats->hist[2] = BNGE_GET_RX_PORT_STATS64(rx, rx_128b_255b_frames);
	rmon_stats->hist[3] = BNGE_GET_RX_PORT_STATS64(rx, rx_256b_511b_frames);
	rmon_stats->hist[4] =
		BNGE_GET_RX_PORT_STATS64(rx, rx_512b_1023b_frames);
	rmon_stats->hist[5] =
		BNGE_GET_RX_PORT_STATS64(rx, rx_1024b_1518b_frames);
	rmon_stats->hist[6] =
		BNGE_GET_RX_PORT_STATS64(rx, rx_1519b_2047b_frames);
	rmon_stats->hist[7] =
		BNGE_GET_RX_PORT_STATS64(rx, rx_2048b_4095b_frames);
	rmon_stats->hist[8] =
		BNGE_GET_RX_PORT_STATS64(rx, rx_4096b_9216b_frames);
	rmon_stats->hist[9] =
		BNGE_GET_RX_PORT_STATS64(rx, rx_9217b_16383b_frames);

	rmon_stats->hist_tx[0] = BNGE_GET_TX_PORT_STATS64(tx, tx_64b_frames);
	rmon_stats->hist_tx[1] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_65b_127b_frames);
	rmon_stats->hist_tx[2] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_128b_255b_frames);
	rmon_stats->hist_tx[3] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_256b_511b_frames);
	rmon_stats->hist_tx[4] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_512b_1023b_frames);
	rmon_stats->hist_tx[5] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_1024b_1518b_frames);
	rmon_stats->hist_tx[6] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_1519b_2047b_frames);
	rmon_stats->hist_tx[7] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_2048b_4095b_frames);
	rmon_stats->hist_tx[8] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_4096b_9216b_frames);
	rmon_stats->hist_tx[9] =
		BNGE_GET_TX_PORT_STATS64(tx, tx_9217b_16383b_frames);

	*ranges = bnge_rmon_ranges;
}

static void bnge_get_pauseparam(struct net_device *dev,
				struct ethtool_pauseparam *epause)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;

	if (bd->phy_flags & BNGE_PHY_FL_NO_PAUSE) {
		epause->autoneg = 0;
		epause->rx_pause = 0;
		epause->tx_pause = 0;
		return;
	}

	epause->autoneg = !!(bn->eth_link_info.autoneg &
			     BNGE_AUTONEG_FLOW_CTRL);
	epause->rx_pause = !!(bn->eth_link_info.req_flow_ctrl &
			      BNGE_LINK_PAUSE_RX);
	epause->tx_pause = !!(bn->eth_link_info.req_flow_ctrl &
			      BNGE_LINK_PAUSE_TX);
}

static int bnge_set_pauseparam(struct net_device *dev,
			       struct ethtool_pauseparam *epause)
{
	struct bnge_ethtool_link_info old_elink_info, *elink_info;
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;
	int rc = 0;

	if (!BNGE_PHY_CFG_ABLE(bd) || (bd->phy_flags & BNGE_PHY_FL_NO_PAUSE))
		return -EOPNOTSUPP;

	elink_info = &bn->eth_link_info;
	old_elink_info = *elink_info;

	if (epause->autoneg) {
		if (!(elink_info->autoneg & BNGE_AUTONEG_SPEED))
			return -EINVAL;

		elink_info->autoneg |= BNGE_AUTONEG_FLOW_CTRL;
	} else {
		if (elink_info->autoneg & BNGE_AUTONEG_FLOW_CTRL)
			elink_info->force_link_chng = true;
		elink_info->autoneg &= ~BNGE_AUTONEG_FLOW_CTRL;
	}

	elink_info->req_flow_ctrl = 0;
	if (epause->rx_pause)
		elink_info->req_flow_ctrl |= BNGE_LINK_PAUSE_RX;
	if (epause->tx_pause)
		elink_info->req_flow_ctrl |= BNGE_LINK_PAUSE_TX;

	if (netif_running(dev)) {
		rc = bnge_hwrm_set_pause(bn);
		if (rc)
			*elink_info = old_elink_info;
	}

	return rc;
}

static void *__bnge_hwrm_pcie_qstats(struct bnge_dev *bd,
				     struct hwrm_pcie_qstats_input *req)
{
	struct pcie_ctx_hw_stats_v2 *hw_pcie_stats;
	dma_addr_t hw_pcie_stats_addr;
	int rc;

	hw_pcie_stats = bnge_hwrm_req_dma_slice(bd, req, sizeof(*hw_pcie_stats),
						&hw_pcie_stats_addr);
	if (!hw_pcie_stats)
		return NULL;

	req->pcie_stat_size = cpu_to_le16(sizeof(*hw_pcie_stats));
	req->pcie_stat_host_addr = cpu_to_le64(hw_pcie_stats_addr);
	rc = bnge_hwrm_req_send(bd, req);

	return rc ? NULL : hw_pcie_stats;
}

static int bnge_get_regs_len(struct net_device *dev)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;

	if (bd->fw_cap & BNGE_FW_CAP_MBUF_DATA)
		return BNGE_MBUF_REG_START + BNGE_MBUF_REG_LEN;

	/* Reserve room for the largest PCIe stats layout so that the size
	 * reported here does not depend on a one-time discovery at init.
	 */
	if (bd->stats_cap & BNGE_STATS_CAP_PCIE)
		return BNGE_PXP_REG_LEN + sizeof(struct pcie_ctx_hw_stats_v2);

	return BNGE_PXP_REG_LEN;
}

#define BNGE_PCIE_REG_SIZE(reg)		\
	sizeof_field(struct pcie_ctx_hw_stats_v2, pcie_##reg)

static const struct bnge_reg_desc bnge_pcie_reg[] = {
	{ BNGE_PCIE_REG_SIZE(pl_signal_integrity), 8 },
	{ sizeof(__le16), 4 }, /* pcie_equalization_time: 4x __le16 */
	{ BNGE_PCIE_REG_SIZE(ltssm_histogram[0]), 4 },
	{ BNGE_PCIE_REG_SIZE(recovery_histogram), 1 },
	{ BNGE_PCIE_REG_SIZE(tl_credit_nph_histogram[0]), 94 },
	{ BNGE_PCIE_REG_SIZE(posted_packet_count), 5 },
	{ BNGE_PCIE_REG_SIZE(rd_latency_histogram[0]), 14 },
};

static void bnge_write_val(void *dst, void *src, u8 size)
{
	switch (size) {
	case 1:
		*(u8 *)dst = *(u8 *)src;
		break;
	case 2:
		put_unaligned(get_unaligned_le16(src), (u16 *)dst);
		break;
	case 4:
		put_unaligned(get_unaligned_le32(src), (u32 *)dst);
		break;
	case 8:
		put_unaligned(get_unaligned_le64(src), (u64 *)dst);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
}

void bnge_copy_regs(u8 *src, u8 *dst, const struct bnge_reg_desc *desc,
		    int num_desc, int max_len)
{
	u32 off = 0;
	int i, j;

	for (i = 0; i < num_desc; i++) {
		const struct bnge_reg_desc *d = &desc[i];
		u8 size = d->size;

		for (j = 0; j < d->count; j++) {
			if (off + size > max_len)
				return;
			bnge_write_val(dst + off, src + off, size);
			off += size;
		}
	}
}

static void bnge_get_pcie_regs(struct bnge_dev *bd, struct ethtool_regs *regs,
			       u8 *dst)
{
	struct hwrm_pcie_qstats_output *resp;
	struct hwrm_pcie_qstats_input *req;
	u8 *src;
	int len;

	if (bnge_hwrm_req_init(bd, req, HWRM_PCIE_QSTATS))
		return;

	resp = bnge_hwrm_req_hold(bd, req);
	src = __bnge_hwrm_pcie_qstats(bd, req);
	if (!src)
		goto drop_req;

	len = min_t(int, le16_to_cpu(resp->pcie_stat_size),
		    sizeof(struct pcie_ctx_hw_stats_v2));
	if (len <= 0)
		goto drop_req;

	if (len <= sizeof(struct pcie_ctx_hw_stats))
		regs->version = 1;
	else if (len < sizeof(struct pcie_ctx_hw_stats_v2))
		regs->version = 2;
	else
		regs->version = 3;

	bnge_copy_regs(src, dst, bnge_pcie_reg, ARRAY_SIZE(bnge_pcie_reg),
		       len);
drop_req:
	bnge_hwrm_req_drop(bd, req);
}

static void bnge_get_regs(struct net_device *dev, struct ethtool_regs *regs,
			  void *_p)
{
	struct bnge_net *bn = netdev_priv(dev);
	struct bnge_dev *bd = bn->bd;
	u8 *p = _p;

	regs->version = 0;

	if (BNGE_NO_FW_ACCESS(bd))
		return;

	if (!(bd->fw_dbg_cap & DBG_QCAPS_RESP_FLAGS_REG_ACCESS_RESTRICTED)) {
		int rc;

		rc = bnge_dbg_hwrm_rd_reg(bd, 0, BNGE_PXP_REG_LEN / 4, _p);
		if (rc)
			netdev_warn(dev, "Failed to read PXP regs: %d\n", rc);
	}

	if (bd->stats_cap & BNGE_STATS_CAP_PCIE)
		bnge_get_pcie_regs(bd, regs, p + BNGE_PXP_REG_LEN);

	if (bd->fw_cap & BNGE_FW_CAP_MBUF_DATA) {
		int rc_rx, rc_tx;

		/* Version 4 is required for the userspace ethtool decoder to
		 * dump MBUF stats. At least one of the RX/TX queries is
		 * expected to be supported; the direction that is unavailable
		 * reads back as zero, which the decoder expects. Report
		 * version 4 if either query succeeded.
		 */
		rc_rx = bnge_hwrm_rx_mbuf_data(bd,
					       p + BNGE_RX_MBUF_REG_OFFSET);
		rc_tx = bnge_hwrm_tx_mbuf_data(bd,
					       p + BNGE_TX_MBUF_REG_OFFSET);
		if (!rc_rx || !rc_tx)
			regs->version = 4;
	}
}

static const struct ethtool_ops bnge_ethtool_ops = {
	.cap_link_lanes_supported	= 1,
	.get_link_ksettings	= bnge_get_link_ksettings,
	.set_link_ksettings	= bnge_set_link_ksettings,
	.get_drvinfo		= bnge_get_drvinfo,
	.get_link		= bnge_get_link,
	.nway_reset		= bnge_nway_reset,
	.get_pauseparam		= bnge_get_pauseparam,
	.set_pauseparam		= bnge_set_pauseparam,
	.get_sset_count		= bnge_get_sset_count,
	.get_strings		= bnge_get_strings,
	.get_ethtool_stats	= bnge_get_ethtool_stats,
	.get_eth_phy_stats	= bnge_get_eth_phy_stats,
	.get_eth_mac_stats	= bnge_get_eth_mac_stats,
	.get_eth_ctrl_stats	= bnge_get_eth_ctrl_stats,
	.get_pause_stats	= bnge_get_pause_stats,
	.get_rmon_stats		= bnge_get_rmon_stats,
	.get_regs_len		= bnge_get_regs_len,
	.get_regs		= bnge_get_regs,
};

void bnge_set_ethtool_ops(struct net_device *dev)
{
	dev->ethtool_ops = &bnge_ethtool_ops;
}
