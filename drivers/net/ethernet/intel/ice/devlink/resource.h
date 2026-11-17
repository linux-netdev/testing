/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026, Intel Corporation. */

#ifndef _ICE_DEVL_RESOURCE_H_
#define _ICE_DEVL_RESOURCE_H_

#include <linux/types.h>

struct devlink;
struct ice_adapter;
struct ice_hw;
struct ice_pf;

void ice_devl_pf_resources_register(struct ice_pf *pf);
void ice_devl_whole_dev_resources_register(const struct ice_hw *hw,
					   struct ice_adapter *adapter);

bool ice_rss_lut_is_reassigned(struct ice_pf *pf);
int ice_take_rss_lut_pf(struct ice_pf *pf);
void ice_release_rss_lut_pf(struct ice_pf *pf);
void ice_prepare_rss_luts_for_reset(struct ice_pf *pf);
int ice_rebuild_rss_luts(struct ice_pf *pf);
void ice_free_rss_lut_flr(struct ice_pf *pf);

#endif /* _ICE_DEVL_RESOURCE_H_ */
