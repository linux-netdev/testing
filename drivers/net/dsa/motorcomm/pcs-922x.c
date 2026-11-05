// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2026 Kyle Switch
 */

#include "chip.h"
#include "mdio_bus.h"
#include "pcs.h"
#include "smi.h"

#define to_device(priv) ((priv)->ds.dev)

static int yt922x_sds_phyaddr_get(int port,
				  enum yt922x_phy_reg_type reg_type)
{
	if (reg_type == YT922X_PHY_REG_TYPE_COMMON_EXT)
		return YT922X_COMMON_EXT_PHYADDR;

	return port;
}

static void yt922x_pcs_get_state(struct phylink_pcs *pcs, unsigned int neg_mode,
				 struct phylink_link_state *state)
{
	struct yt921x_port *pp = pcs_to_yt921x_port(pcs);
	struct yt921x_priv *priv = yt921x_port_to_priv(pp);
	int port = pp->index;
	u16 link_ctrl;
	int res;
	u16 bmsr;
	int addr;
	u16 lp;

	addr = yt922x_sds_phyaddr_get(port, YT922X_PHY_REG_TYPE_MII);
	if (addr < 0) {
		state->link = false;
		return;
	}

	mutex_lock(&priv->reg_lock);
	switch (state->interface) {
	case PHY_INTERFACE_MODE_SGMII:
	case PHY_INTERFACE_MODE_1000BASEX:
	case PHY_INTERFACE_MODE_2500BASEX:
		res = yt921x_intif_read(priv, addr, MII_BMSR, &bmsr);
		if (res)
			goto err;
		res = yt921x_intif_read(priv, addr, MII_LPA, &lp);
		if (res)
			goto err;
		phylink_mii_c22_pcs_decode_state(state, neg_mode, bmsr, lp);
		break;
	case PHY_INTERFACE_MODE_100BASEX:
		res = yt921x_intif_read(priv, addr, MII_BMSR, &bmsr);
		if (res)
			goto err;
		state->speed = SPEED_100;
		state->duplex = DUPLEX_FULL;
		state->pause |= MLO_PAUSE_TX | MLO_PAUSE_RX;
		state->link = !!(bmsr & BMSR_LSTATUS);
		break;
	case PHY_INTERFACE_MODE_USXGMII:
		res = yt921x_intif_read(priv, addr, YT922X_PCS_LINK_CTRL,
					&link_ctrl);
		if (res)
			goto err;
		state->link = FIELD_GET(YT922X_PCS_LINK_STATUS, link_ctrl);
		state->an_complete = FIELD_GET(YT922X_PCS_AN_COMPLETE,
					       link_ctrl);
		res = yt921x_intif_read(priv, addr, MII_LPA, &lp);
		if (res)
			goto err;
		if (state->link)
			phylink_decode_usxgmii_word(state, lp);
		break;
	default:
		state->link = false;
		break;
	}
	mutex_unlock(&priv->reg_lock);
	return;

err:
	mutex_unlock(&priv->reg_lock);
	state->link = false;
}

static void yt922x_pcs_an_restart(struct phylink_pcs *pcs)
{
	struct yt921x_port *pp = pcs_to_yt921x_port(pcs);
	struct yt921x_priv *priv = yt921x_port_to_priv(pp);
	struct device *dev = to_device(priv);
	int port = pp->index;
	u16 bmcr;
	int addr;
	int res;

	addr = yt922x_sds_phyaddr_get(port, YT922X_PHY_REG_TYPE_MII);
	if (addr < 0) {
		dev_err(dev, "Invalid SDS PHY addr for port %d\n", port);
		return;
	}

	mutex_lock(&priv->reg_lock);
	res = yt921x_intif_read(priv, addr, MII_BMCR, &bmcr);
	if (res)
		goto err;
	bmcr |= BMCR_ANRESTART;
	bmcr |= BMCR_RESET;
	res = yt921x_intif_write(priv, addr, MII_BMCR, bmcr);
	if (res)
		goto err;
	mutex_unlock(&priv->reg_lock);
	return;

err:
	mutex_unlock(&priv->reg_lock);
	dev_err(dev, "Failed to an restart PCS port %d: %i\n", port, res);
}

static int yt922x_pcs_config(struct phylink_pcs *pcs, unsigned int neg_mode,
			     phy_interface_t interface,
			     const unsigned long *advertising,
			     bool permit_pause_to_mac)
{
	bool inband = neg_mode & PHYLINK_PCS_NEG_INBAND;
	struct yt921x_port *pp = pcs_to_yt921x_port(pcs);
	struct yt921x_priv *priv = yt921x_port_to_priv(pp);
	bool changed = false;
	int res, port;
	u16 bmcr_old;
	u16 bmcr_new;
	u16 data;
	u16 ctrl;
	int addr;
	int adv;

	port = pp->index;
	addr = yt922x_sds_phyaddr_get
		(port, YT922X_PHY_REG_TYPE_SDS_COMMON_EXT);
	if (addr < 0)
		return addr;

	mutex_lock(&priv->reg_lock);

	/* write protect */
	res = yt921x_intif_ext_write(priv, addr, YT922X_PCS_WRITE_PROTECT, 0xd);
	if (res)
		goto err;
	switch (interface) {
	case PHY_INTERFACE_MODE_SGMII:
		ctrl = YT922X_SERDES_MODE_SGMII;
		break;
	case PHY_INTERFACE_MODE_100BASEX:
		ctrl = YT922X_SERDES_MODE_100BASEX;
		break;
	case PHY_INTERFACE_MODE_1000BASEX:
		ctrl = YT922X_SERDES_MODE_1000BASEX;
		break;
	case PHY_INTERFACE_MODE_2500BASEX:
		ctrl = YT922X_SERDES_MODE_2500BASEX;
		break;
	case PHY_INTERFACE_MODE_USXGMII:
		ctrl = YT922X_SERDES_MODE_USXGMII;
		break;
	default:
		res = -EINVAL;
		goto err;
	}
	res = yt921x_intif_ext_read(priv, addr, YT922X_PORT_SDSn, &data);
	if (res)
		goto err;
	data &= ~YT922X_SERDES_MODE_M;
	data |= ctrl;
	res = yt921x_intif_ext_write(priv, addr, YT922X_PORT_SDSn, data);
	if (res)
		goto err;

	if (inband) {
		adv = phylink_mii_c22_pcs_encode_advertisement(interface,
							       advertising);
		if (adv >= 0) {
			res = yt921x_intif_modify_changed(priv, port,
							  MII_ADVERTISE,
							  U16_MAX, adv);
			if (res < 0)
				goto err;

			changed = !!res;
		}
	}

	res = yt921x_intif_read(priv, port, MII_BMCR, &bmcr_old);
	if (res)
		goto err;

	bmcr_new = bmcr_old;
	if (neg_mode == PHYLINK_PCS_NEG_INBAND_ENABLED)
		bmcr_new |= BMCR_ANENABLE;
	else
		bmcr_new &= ~BMCR_ANENABLE;

	changed |= (bmcr_new != bmcr_old);

	res = yt921x_intif_write(priv, port, MII_BMCR, bmcr_new);
	if (res)
		goto err;
	pp->inband = inband;
	mutex_unlock(&priv->reg_lock);

	return changed;

err:
	mutex_unlock(&priv->reg_lock);

	return res;
}

static int yt922x_pcs_enable(struct phylink_pcs *pcs)
{
	struct yt921x_port *pp = pcs_to_yt921x_port(pcs);
	struct yt921x_priv *priv = yt921x_port_to_priv(pp);
	struct device *dev = yt921x_priv_to_device(priv);
	int port = pp->index;
	int addr;
	u16 bmcr;
	int res;

	addr = yt922x_sds_phyaddr_get(port, YT922X_PHY_REG_TYPE_MII);
	if (addr < 0)
		return addr;

	mutex_lock(&priv->reg_lock);

	res = yt921x_intif_read(priv, addr, MII_BMCR, &bmcr);
	if (res)
		goto end;

	bmcr &= ~BMCR_PDOWN;
	bmcr |= BMCR_ANRESTART;
	res = yt921x_intif_write(priv, addr, MII_BMCR, bmcr);

end:
	mutex_unlock(&priv->reg_lock);

	if (res)
		dev_err(dev, "Failed to enable PCS port %d: %i\n", port, res);

	return res;
}

static void yt922x_pcs_disable(struct phylink_pcs *pcs)
{
	struct yt921x_port *pp = pcs_to_yt921x_port(pcs);
	struct yt921x_priv *priv = yt921x_port_to_priv(pp);
	struct device *dev = yt921x_priv_to_device(priv);
	int port = pp->index;
	int addr;
	int res;

	addr = yt922x_sds_phyaddr_get(port, YT922X_PHY_REG_TYPE_MII);
	if (addr < 0) {
		dev_err(dev, "Invalid SDS PHY addr for port %d\n", port);
		return;
	}

	mutex_lock(&priv->reg_lock);
	res = yt921x_intif_modify(priv, addr, MII_BMCR, BMCR_PDOWN, BMCR_PDOWN);
	mutex_unlock(&priv->reg_lock);

	if (res)
		dev_err(dev, "Failed to power down PCS port %d: %i\n", port,
			res);
}

const struct phylink_pcs_ops yt922x_phylink_pcs_ops = {
	.pcs_get_state = yt922x_pcs_get_state,
	.pcs_config = yt922x_pcs_config,
	.pcs_an_restart = yt922x_pcs_an_restart,
	.pcs_enable = yt922x_pcs_enable,
	.pcs_disable = yt922x_pcs_disable,
};
