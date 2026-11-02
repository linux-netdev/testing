// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2019 Pensando Systems, Inc */

#include <linux/module.h>
#include <linux/netdevice.h>

#include "ionic.h"
#include "ionic_bus.h"
#include "ionic_lif.h"
#include "ionic_devlink.h"

static int ionic_dl_flash_update(struct devlink *dl,
				 struct devlink_flash_update_params *params,
				 struct netlink_ext_ack *extack)
{
	struct ionic *ionic = devlink_priv(dl);

	return ionic_firmware_update(ionic->lif, params->fw, extack);
}

static int ionic_dl_info_get(struct devlink *dl, struct devlink_info_req *req,
			     struct netlink_ext_ack *extack)
{
	struct ionic *ionic = devlink_priv(dl);
	struct ionic_dev *idev = &ionic->idev;
	char buf[16];
	int err = 0;

	err = devlink_info_version_running_put(req,
					       DEVLINK_INFO_VERSION_GENERIC_FW,
					       idev->dev_info.fw_version);
	if (err)
		return err;

	snprintf(buf, sizeof(buf), "0x%x", idev->dev_info.asic_type);
	err = devlink_info_version_fixed_put(req,
					     DEVLINK_INFO_VERSION_GENERIC_ASIC_ID,
					     buf);
	if (err)
		return err;

	snprintf(buf, sizeof(buf), "0x%x", idev->dev_info.asic_rev);
	err = devlink_info_version_fixed_put(req,
					     DEVLINK_INFO_VERSION_GENERIC_ASIC_REV,
					     buf);
	if (err)
		return err;

	err = devlink_info_serial_number_put(req, idev->dev_info.serial_num);

	return err;
}

enum ionic_devlink_param_id {
	IONIC_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	IONIC_DEVLINK_PARAM_ID_CMD_TIMEOUT,
};

static int ionic_dl_cmd_timeout_get(struct devlink *dl, u32 id,
				    struct devlink_param_gset_ctx *ctx,
				    struct netlink_ext_ack *extack)
{
	struct ionic *ionic = devlink_priv(dl);

	return ionic_dev_getattr_cmd_timeout(ionic, &ctx->val.vu8);
}

static int ionic_dl_cmd_timeout_set(struct devlink *dl, u32 id,
				    struct devlink_param_gset_ctx *ctx,
				    struct netlink_ext_ack *extack)
{
	struct ionic *ionic = devlink_priv(dl);

	if (test_bit(IONIC_LIF_F_FW_RESET, ionic->lif->state))
		return -EBUSY;

	return ionic_dev_setattr_cmd_timeout(ionic, ctx->val.vu8);
}

static int ionic_dl_cmd_timeout_validate(struct devlink *dl, u32 id,
					 union devlink_param_value *val,
					 struct netlink_ext_ack *extack)
{
	if (!ionic_cmd_timeout_valid(val->vu8)) {
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "cmd_timeout must be 0 or at least %d seconds",
				       IONIC_CMD_TIMEOUT_DEF);
		return -EINVAL;
	}

	return 0;
}

static const struct devlink_param ionic_dl_params[] = {
	DEVLINK_PARAM_DRIVER(IONIC_DEVLINK_PARAM_ID_CMD_TIMEOUT,
			     "cmd_timeout", DEVLINK_PARAM_TYPE_U8,
			     BIT(DEVLINK_PARAM_CMODE_PERMANENT),
			     ionic_dl_cmd_timeout_get,
			     ionic_dl_cmd_timeout_set,
			     ionic_dl_cmd_timeout_validate),
};

static const struct devlink_ops ionic_dl_ops = {
	.info_get	= ionic_dl_info_get,
	.flash_update	= ionic_dl_flash_update,
};

struct ionic *ionic_devlink_alloc(struct device *dev)
{
	struct devlink *dl;

	dl = devlink_alloc(&ionic_dl_ops, sizeof(struct ionic), dev);
	if (!dl)
		return NULL;

	return devlink_priv(dl);
}

void ionic_devlink_free(struct ionic *ionic)
{
	struct devlink *dl = priv_to_devlink(ionic);

	devlink_free(dl);
}

void ionic_devlink_params_register(struct ionic *ionic)
{
	struct devlink *dl = priv_to_devlink(ionic);
	int err;

	if (!ionic_cmd_timeout_supported(ionic))
		return;

	devl_lock(dl);
	if (ionic->dl_params_registered)
		goto out;

	err = devl_params_register(dl, ionic_dl_params,
				   ARRAY_SIZE(ionic_dl_params));
	if (err) {
		dev_err(ionic->dev, "devl_params_register failed: %d\n", err);
		goto out;
	}

	ionic->dl_params_registered = true;
out:
	devl_unlock(dl);
}

void ionic_devlink_params_unregister(struct ionic *ionic)
{
	struct devlink *dl = priv_to_devlink(ionic);

	devl_lock(dl);
	if (ionic->dl_params_registered) {
		devl_params_unregister(dl, ionic_dl_params,
				       ARRAY_SIZE(ionic_dl_params));
		ionic->dl_params_registered = false;
	}
	devl_unlock(dl);
}

int ionic_devlink_register(struct ionic *ionic)
{
	struct devlink *dl = priv_to_devlink(ionic);
	struct devlink_port_attrs attrs = {};
	int err;

	attrs.flavour = DEVLINK_PORT_FLAVOUR_PHYSICAL;
	devlink_port_attrs_set(&ionic->dl_port, &attrs);
	err = devlink_port_register(dl, &ionic->dl_port, 0);
	if (err) {
		dev_err(ionic->dev, "devlink_port_register failed: %d\n", err);
		return err;
	}

	ionic_devlink_params_register(ionic);

	SET_NETDEV_DEVLINK_PORT(ionic->lif->netdev, &ionic->dl_port);
	devlink_register(dl);
	return 0;
}

void ionic_devlink_unregister(struct ionic *ionic)
{
	struct devlink *dl = priv_to_devlink(ionic);

	devlink_unregister(dl);
	ionic_devlink_params_unregister(ionic);
	devlink_port_unregister(&ionic->dl_port);
}
