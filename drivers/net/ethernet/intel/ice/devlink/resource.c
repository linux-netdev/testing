// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026, Intel Corporation. */

#include "resource.h"
#include "ice_adapter.h"
#include "ice.h"
#include "ice_lib.h"

#define ICE_NUM_GLOBAL_LUTS	16
#define ICE_ANY_SLOT		-1

/* each NAC numbers its PFs from 0, secondary NAC ones go after primary ones */
static int ice_devl_pf_id(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->hw;

	if (ice_is_primary(hw))
		return hw->logical_pf_id;

	return hw->logical_pf_id + ICE_PORTS_PER_QUAD;
}

/* each NAC has its own global LUTs, with IDs given by its FW */
static struct ice_devl_resource *
ice_devl_res_tbl(struct ice_pf *pf, enum ice_devl_resource_id res_id)
{
	if (res_id == ICE_RSS_LUT_GLOBAL && !ice_is_primary(&pf->hw))
		return &pf->adapter->sec_nac_global_luts;

	return &pf->adapter->resources[res_id];
}

static u32 ice_devl_res_cnt(const struct ice_devl_resource *res)
{
	u32 sum = 0;

	for (int i = 0; i < ARRAY_SIZE(res->owner); i++)
		sum += res->owner[i] != NULL;

	return sum;
}

static int ice_devl_res_take(struct ice_pf *pf,
			     enum ice_devl_resource_id res_id, int slot,
			     void *owner)
{
	struct ice_devl_resource *res = ice_devl_res_tbl(pf, res_id);
	int beg, end, new_id = ICE_ANY_SLOT;
	u16 lut_id;

	if (res_id == ICE_RSS_LUT_GLOBAL) {
		int err;

		WARN_ON_ONCE(slot != ICE_ANY_SLOT);

		err = ice_alloc_rss_global_lut(&pf->hw, &lut_id);
		if (err)
			return err;

		slot = lut_id;
	}

	end = slot == ICE_ANY_SLOT ? ARRAY_SIZE(res->owner) : slot + 1;
	beg = slot == ICE_ANY_SLOT ? 0 : slot;
	for (int id = beg; id < end; id++) {
		if (!res->owner[id]) {
			new_id = id;
			break;
		}
	}
	if (new_id == ICE_ANY_SLOT) {
		if (WARN_ON(res_id == ICE_RSS_LUT_GLOBAL))
			ice_free_rss_global_lut(&pf->hw, lut_id);

		return -ENOSPC;
	}

	res->owner[new_id] = owner;
	res->pf_id[new_id] = ice_devl_pf_id(pf);
	return new_id;
}

static int ice_devl_res_free(struct ice_pf *pf,
			     enum ice_devl_resource_id res_id, void *owner)
{
	struct ice_devl_resource *res = ice_devl_res_tbl(pf, res_id);
	int err = 0, id_to_free = ICE_ANY_SLOT;

	for (int i = 0; i < ARRAY_SIZE(res->owner); i++) {
		if (res->owner[i] == owner) {
			id_to_free = i;
			break;
		}
	}
	if (id_to_free == ICE_ANY_SLOT)
		return 0;

	if (res_id == ICE_RSS_LUT_GLOBAL) {
		err = ice_free_rss_global_lut(&pf->hw, id_to_free);
		if (err)
			dev_warn(ice_pf_to_dev(pf), "failed to free global RSS LUT %d, leaked until PF reset: %d\n",
				 id_to_free, err);
	}

	res->owner[id_to_free] = NULL;
	return err;
}

static void ice_free_rss_lut_flr_locked(struct ice_pf *pf)
{
	struct ice_devl_resource *res, *resources = pf->adapter->resources;
	int pf_id = ice_devl_pf_id(pf);

	devl_assert_locked(pf->adapter->devlink);
	resources[ICE_RSS_LUT_PF].owner[pf_id] = NULL;

	res = ice_devl_res_tbl(pf, ICE_RSS_LUT_GLOBAL);
	for (int i = 0; i < ARRAY_SIZE(res->owner); i++) {
		/* On FLR/PFR resources assigned to PF are cleared by FW,
		 * reflect that in the SW table.
		 * VFs on given PF must be de-programmed too.
		 */
		if (res->pf_id[i] == pf_id)
			res->owner[i] = NULL;
	}
}

void ice_free_rss_lut_flr(struct ice_pf *pf)
{
	scoped_guard(ice_adapter_devl, pf->adapter)
		ice_free_rss_lut_flr_locked(pf);
}

void ice_free_rss_lut_vf(struct ice_vf *vf)
{
	struct ice_pf *pf = vf->pf;

	scoped_guard(ice_adapter_devl, pf->adapter) {
		ice_devl_res_free(pf, ICE_RSS_LUT_GLOBAL, vf);
		ice_devl_res_free(pf, ICE_RSS_LUT_PF, vf);
	}
}

static int ice_devl_res_owned_idx(struct ice_pf *pf,
				  enum ice_devl_resource_id res_id, void *owner)
{
	const struct ice_devl_resource *res = ice_devl_res_tbl(pf, res_id);

	for (int i = 0; i < ARRAY_SIZE(res->owner); i++) {
		if (res->owner[i] == owner)
			return i;
	}

	return -ENXIO;
}

static bool ice_is_devl_res_owned_by(struct ice_pf *pf,
				     enum ice_devl_resource_id res_id,
				     void *owner)
{
	return ice_devl_res_owned_idx(pf, res_id, owner) >= 0;
}

static u64 ice_rss_lut_whole_dev_occ_get_global(void *priv)
{
	struct ice_adapter *adapter = priv;

	return ice_devl_res_cnt(&adapter->resources[ICE_RSS_LUT_GLOBAL]) +
	       ice_devl_res_cnt(&adapter->sec_nac_global_luts);
}

static u64 ice_rss_lut_whole_dev_occ_get_pf(void *priv)
{
	struct ice_adapter *adapter = priv;

	return ice_devl_res_cnt(&adapter->resources[ICE_RSS_LUT_PF]);
}

static u64 ice_rss_lut_whole_dev_occ_get_both(void *priv)
{
	return ice_rss_lut_whole_dev_occ_get_global(priv) +
	       ice_rss_lut_whole_dev_occ_get_pf(priv);
}

static u64 ice_rss_lut_pf_occ_get_global(void *priv)
{
	struct ice_pf *pf = priv;

	scoped_guard(ice_adapter_devl, pf->adapter)
		return ice_is_devl_res_owned_by(pf, ICE_RSS_LUT_GLOBAL, pf);
}

static u64 ice_rss_lut_pf_occ_get_pf(void *priv)
{
	struct ice_pf *pf = priv;

	scoped_guard(ice_adapter_devl, pf->adapter)
		return ice_is_devl_res_owned_by(pf, ICE_RSS_LUT_PF, pf);
}

static u64 ice_rss_lut_pf_occ_get_both(void *priv)
{
	struct ice_pf *pf = priv;

	scoped_guard(ice_adapter_devl, pf->adapter)
		return ice_is_devl_res_owned_by(pf, ICE_RSS_LUT_PF, pf) +
		       ice_is_devl_res_owned_by(pf, ICE_RSS_LUT_GLOBAL, pf);
}

static u64 ice_rss_lut_vf_occ_get_global(void *priv)
{
	struct ice_vf *vf = priv;
	struct ice_pf *pf = vf->pf;

	scoped_guard(ice_adapter_devl, pf->adapter)
		return ice_is_devl_res_owned_by(pf, ICE_RSS_LUT_GLOBAL, vf);
}

static u64 ice_rss_lut_vf_occ_get_pf(void *priv)
{
	struct ice_vf *vf = priv;
	struct ice_pf *pf = vf->pf;

	scoped_guard(ice_adapter_devl, pf->adapter)
		return ice_is_devl_res_owned_by(pf, ICE_RSS_LUT_PF, vf);
}

static u64 ice_rss_lut_vf_occ_get_both(void *priv)
{
	struct ice_vf *vf = priv;
	struct ice_pf *pf = vf->pf;

	scoped_guard(ice_adapter_devl, pf->adapter)
		return ice_is_devl_res_owned_by(pf, ICE_RSS_LUT_PF, vf) +
		       ice_is_devl_res_owned_by(pf, ICE_RSS_LUT_GLOBAL, vf);
}

static int ice_devl_resource_deny_occ_set(u64 size,
					  struct netlink_ext_ack *extack,
					  void *priv)
{
	NL_SET_ERR_MSG_MOD(extack,
		"can not change directly, parent/aggregate resource just adds up children data");
	return -EPERM;
}

enum ice_rss_lut_resource_state {
	ICE_HAS_NO_LUT = 0,
	ICE_HAS_GLOBAL_LUT = BIT(ICE_RSS_LUT_GLOBAL),
	ICE_HAS_PF_LUT = BIT(ICE_RSS_LUT_PF),
	ICE_HAS_BOTH_LUTS = ICE_HAS_GLOBAL_LUT | ICE_HAS_PF_LUT,
};

/**
 * ice_rss_lut_resource_state - compute opaque resource state for given owner
 * @pf: the PF the @owner is on
 * @owner: the entity to compute state of resources for
 *
 * Return: computed current state of the RSS resources the @owner has.
 */
static enum ice_rss_lut_resource_state
ice_rss_lut_resource_state(struct ice_pf *pf, void *owner)
{
	enum ice_rss_lut_resource_state ret = ICE_HAS_NO_LUT;

	if (ice_is_devl_res_owned_by(pf, ICE_RSS_LUT_GLOBAL, owner))
		ret |= ICE_HAS_GLOBAL_LUT;
	if (ice_is_devl_res_owned_by(pf, ICE_RSS_LUT_PF, owner))
		ret |= ICE_HAS_PF_LUT;

	return ret;
}

static int ice_maybe_change_rss_lut(struct ice_pf *pf, void *owner,
				    enum ice_rss_lut_resource_state old,
				    enum ice_rss_lut_resource_state new,
				    struct netlink_ext_ack *extack)
{
	struct ice_aq_get_set_rss_lut_params params = {};
	struct ice_hw *hw = &pf->hw;
	enum ice_lut_type lut_type;
	int err, lut_size, lut_id;
	struct ice_vf *vf = NULL;
	struct ice_vsi *vsi;
	u16 rss_size;
	u8 *lut;

	if (old & new & ICE_HAS_PF_LUT)
		return 0;

	if (new & ICE_HAS_PF_LUT) {
		lut_type = ICE_LUT_PF;
	} else if (new & ICE_HAS_GLOBAL_LUT) {
		lut_id = ice_devl_res_owned_idx(pf, ICE_RSS_LUT_GLOBAL, owner);
		if (lut_id < 0)
			return lut_id;

		lut_type = ICE_LUT_GLOBAL;
		params.global_lut_id = lut_id;
	} else {
		lut_type = ICE_LUT_VSI;
		if (owner == pf) {
			NL_SET_ERR_MSG_FMT(extack, "cannot change PF to use LUT_VSI (sized 64)");
			return -EDOM;
		}
	}

	if (pf == owner) {
		vsi = ice_get_main_vsi(pf);
	} else {
		vf = owner;
		vsi = ice_get_vf_vsi(vf);
	}

	lut_size = ice_lut_type_to_size(lut_type);
	lut = kzalloc(lut_size, GFP_KERNEL);
	if (!lut)
		return -ENOMEM;
	params.lut = lut;
	params.lut_size = lut_size;
	params.lut_type = lut_type;
	params.vsi_handle = vsi->idx;
	mutex_lock(&pf->rss_lut_lock);
	rss_size = min(vsi->num_rxq, ice_lut_type_to_qs_num(lut_type));
	/* PF with RXHASH disabled keeps its LUT zeroed */
	if (vf || !vsi->netdev || vsi->netdev->features & NETIF_F_RXHASH)
		ice_fill_rss_lut(lut, lut_size, rss_size);
	err = ice_aq_set_rss_lut(hw, &params);
	if (err) {
		NL_SET_ERR_MSG_FMT(extack, "AQ failed: %s", libie_aq_str(hw->adminq.sq_last_status));
		goto out;
	}

	err = ice_vsi_update_rss_lut(vsi, lut_type, params.global_lut_id);
	if (err)
		goto out;

	devm_kfree(ice_pf_to_dev(pf), vsi->rss_lut_user);
	vsi->rss_lut_user = NULL;
	if (lut_type == ICE_LUT_GLOBAL)
		vsi->global_lut_id = params.global_lut_id;
	vsi->rss_table_size = lut_size;
	vsi->rss_lut_type = lut_type;
	vsi->rss_size = rss_size;
	if (vf) {
		u16 max_qs = ice_lut_type_to_qs_num(lut_type);

		/* don't keep queues that the new LUT can't spread traffic to */
		if ((vf->num_req_qs ?: vf->num_vf_qs) > max_qs)
			vf->num_req_qs = max_qs;
		ice_schedule_vf_reset(vf);
	}
out:
	mutex_unlock(&pf->rss_lut_lock);
	kfree(lut);
	/* the user RSS LUT was dropped above, rtnl is held for the PF */
	if (!err && vsi->netdev && netif_is_rxfh_configured(vsi->netdev))
		ethtool_rxfh_indir_lost(vsi->netdev);
	return err;
}

static int ice_devl_res_change(bool take, enum ice_devl_resource_id res_id,
			       struct ice_pf *pf, void *owner, int slot,
			       struct netlink_ext_ack *extack)
{
	enum ice_rss_lut_resource_state old, new, change;
	int err, rel_err;

	change = BIT(res_id);
	old = ice_rss_lut_resource_state(pf, owner);
	new = old;
	if (take)
		new |= change;
	else
		new &= ~change;
	if (new == old)
		return 0;

	/* reset rebuilds the table and the VSIs, see ice_rebuild_rss_luts(),
	 * pairs with adapter devl taken in ice_prepare_rss_luts_for_reset()
	 */
	if (ice_is_reset_in_progress(pf->state)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "reset in progress, try again later");
		return -EBUSY;
	}

	/* pairs with set_bit() under adapter devl in ice_setup_tc_mqprio_qdisc() */
	if (test_bit(ICE_FLAG_TC_MQPRIO, pf->flags)) {
		NL_SET_ERR_MSG_MOD(extack, "ADQ configured, can't change RSS LUTs");
		return -EOPNOTSUPP;
	}

	if (pf == owner && !take && old != ICE_HAS_BOTH_LUTS) {
		NL_SET_ERR_MSG_MOD(extack,
			"at least one of 512+ sized LUTs must be assigned to PF device at all times");
		return -EDOM;
	}

	if (take) {
		int slot_id;

		slot_id = ice_devl_res_take(pf, res_id, slot, owner);
		if (slot_id < 0)
			return slot_id;
	}

	err = ice_maybe_change_rss_lut(pf, owner, old, new, extack);
	if (err) {
		NL_SET_ERR_MSG_WEAK_MOD(extack, "failed to change RSS LUT");
		if (!take)
			/* We have not released the resource, so we don't free
			 * it, to avoid freeing LUT still in use or assigning it
			 * to other entity.
			 */
			return err;

		goto undo_res_take;
	}

	if (!take) {
undo_res_take:
		rel_err = ice_devl_res_free(pf, res_id, owner);
		if (rel_err) {
			NL_SET_ERR_MSG_FMT(extack,
				"could not free resource, err: %d", rel_err);
			if (!err)
				err = rel_err;
		}
	}

	return err;
}

/* ethtool core sizes RSS buffers by rss_table_size under rtnl, and the new
 * LUT is filled based on NETIF_F_RXHASH, which is also changed under rtnl
 */
static int ice_rss_lut_pf_occ_set(u64 size, enum ice_devl_resource_id res_id,
				  struct ice_pf *pf, int slot,
				  struct netlink_ext_ack *extack)
{
	int err;

	rtnl_lock();
	scoped_guard(ice_adapter_devl, pf->adapter)
		err = ice_devl_res_change(size, res_id, pf, pf, slot, extack);
	rtnl_unlock();

	return err;
}

static int ice_rss_lut_pf_occ_set_pf(u64 size, struct netlink_ext_ack *extack,
				     void *priv)
{
	struct ice_pf *pf = priv;

	return ice_rss_lut_pf_occ_set(size, ICE_RSS_LUT_PF, pf,
				      ice_devl_pf_id(pf), extack);
}

static int ice_rss_lut_pf_occ_set_global(u64 size,
					 struct netlink_ext_ack *extack,
					 void *priv)
{
	return ice_rss_lut_pf_occ_set(size, ICE_RSS_LUT_GLOBAL, priv,
				      ICE_ANY_SLOT, extack);
}

static int ice_rss_lut_vf_occ_set_pf(u64 size, struct netlink_ext_ack *extack,
				     void *occ_priv)
{
	struct ice_vf *vf = occ_priv;
	struct ice_pf *pf = vf->pf;
	int pf_id;

	pf_id = ice_devl_pf_id(pf);
	scoped_guard(mutex, &vf->cfg_lock) {
		if (!ice_vf_is_ready(vf))
			return -EBUSY;

		scoped_guard(ice_adapter_devl, pf->adapter)
			return ice_devl_res_change(size, ICE_RSS_LUT_PF, pf, vf,
						   pf_id, extack);
	}
}

static int ice_rss_lut_vf_occ_set_global(u64 size,
					 struct netlink_ext_ack *extack,
					 void *occ_priv)
{
	struct ice_vf *vf = occ_priv;
	struct ice_pf *pf = vf->pf;

	scoped_guard(mutex, &vf->cfg_lock) {
		if (!ice_vf_is_ready(vf))
			return -EBUSY;

		scoped_guard(ice_adapter_devl, pf->adapter)
			return ice_devl_res_change(size, ICE_RSS_LUT_GLOBAL, pf,
						   vf, ICE_ANY_SLOT, extack);
	}
}

/**
 * ice_rss_lut_is_reassigned - check if RSS LUTs of PF are in non-default state
 * @pf: the PF to check
 *
 * Return: true if @pf lost its PF LUT, or @pf or any of its VFs owns a
 * global LUT. Caller must hold the adapter devlink lock.
 */
bool ice_rss_lut_is_reassigned(struct ice_pf *pf)
{
	struct ice_devl_resource *res, *resources = pf->adapter->resources;
	int pf_id = ice_devl_pf_id(pf);

	devl_assert_locked(pf->adapter->devlink);
	if (resources[ICE_RSS_LUT_PF].owner[pf_id] != pf)
		return true;

	res = ice_devl_res_tbl(pf, ICE_RSS_LUT_GLOBAL);
	for (int i = 0; i < ARRAY_SIZE(res->owner); i++)
		if (res->owner[i] && res->pf_id[i] == pf_id)
			return true;

	return false;
}

/**
 * ice_take_rss_lut_pf - allocate PF RSS LUT for PF
 * @pf: the PF device that PF LUT is physically on, and to allocate it for
 *
 * Acquire PF RSS LUT for the caller.
 *
 * Return: 0 on success, negative on error.
 */
int ice_take_rss_lut_pf(struct ice_pf *pf)
{
	int ret, pf_id = ice_devl_pf_id(pf);

	scoped_guard(ice_adapter_devl, pf->adapter) {
		ret = ice_devl_res_take(pf, ICE_RSS_LUT_PF, pf_id, pf);
		if (ret >= 0)
			return 0;

		return ret;
	}
}

/**
 * ice_release_rss_lut_pf - release PF RSS LUT of PF
 * @pf: the PF device that PF LUT is physically on, and to release it from
 *
 * Release PF RSS LUT for the caller.
 *
 * No need to call this function in normal operation, provided for error path.
 */
void ice_release_rss_lut_pf(struct ice_pf *pf)
{
	scoped_guard(ice_adapter_devl, pf->adapter)
		ice_devl_res_free(pf, ICE_RSS_LUT_PF, pf);
}

/**
 * ice_prepare_rss_luts_for_reset - drop global RSS LUTs of PF from the table
 * @pf: the PF that is about to be reset
 *
 * FW frees global RSS LUTs of the PF and its VFs on reset, and other PFs may
 * get them from FW before ice_rebuild_rss_luts() of @pf, so drop them from
 * the table now. Taking the lock also waits for RSS LUT changes that checked
 * for reset just before it was requested.
 */
void ice_prepare_rss_luts_for_reset(struct ice_pf *pf)
{
	int pf_id = ice_devl_pf_id(pf);
	struct ice_devl_resource *res;

	scoped_guard(ice_adapter_devl, pf->adapter) {
		if (ice_rss_lut_is_reassigned(pf))
			dev_info(ice_pf_to_dev(pf),
				 "reset restores the default RSS LUT assignment\n");

		res = ice_devl_res_tbl(pf, ICE_RSS_LUT_GLOBAL);
		for (int i = 0; i < ARRAY_SIZE(res->owner); i++)
			if (res->pf_id[i] == pf_id)
				res->owner[i] = NULL;
	}
}

/**
 * ice_rebuild_rss_lut_pf - restore default RSS LUT assignment after reset
 * @pf: the PF that was reset
 *
 * FW drops RSS LUT assignments of the PF on reset, so give the PF LUT back to
 * the PF, and make the PF VSI use it.
 * Must be called before the VSIs are rebuilt.
 *
 * Return: 0 on success, negative on error.
 */
static int ice_rebuild_rss_lut_pf(struct ice_pf *pf)
{
	struct ice_vsi *vsi = ice_get_main_vsi(pf);
	struct ice_adapter *adapter = pf->adapter;
	int err;

	devl_lock(adapter->devlink);
	ice_free_rss_lut_flr_locked(pf);
	err = ice_devl_res_take(pf, ICE_RSS_LUT_PF, ice_devl_pf_id(pf), pf);
	if (err < 0)
		goto unlock;

	mutex_lock(&pf->rss_lut_lock);
	if (vsi && vsi->rss_lut_type != ICE_LUT_PF) {
		devm_kfree(ice_pf_to_dev(pf), vsi->rss_lut_user);
		vsi->rss_lut_user = NULL;
		vsi->rss_table_size = ice_lut_type_to_size(ICE_LUT_PF);
		vsi->rss_lut_type = ICE_LUT_PF;
	}
	mutex_unlock(&pf->rss_lut_lock);
	err = 0;
unlock:
	devl_unlock(adapter->devlink);

	return err;
}

/**
 * ice_rebuild_rss_luts - restore default RSS LUT assignment after reset
 * @pf: the PF that was reset
 *
 * Wrapper of ice_rebuild_rss_lut_pf() that also tells the ethtool core when
 * the user RSS LUT was dropped, and makes the VF VSIs use their default LUTs.
 * Must be called without rtnl held.
 *
 * Return: 0 on success, negative on error.
 */
int ice_rebuild_rss_luts(struct ice_pf *pf)
{
	u16 max_qs = ice_lut_type_to_qs_num(ICE_LUT_VSI);
	struct ice_vsi *vsi = ice_get_main_vsi(pf);
	struct ice_vf *vf;
	unsigned int bkt;
	int err;

	/* ethtool core sizes RSS buffers by rss_table_size under rtnl */
	rtnl_lock();
	err = ice_rebuild_rss_lut_pf(pf);
	/* the user RSS LUT is dropped when the PF goes back to the PF LUT */
	if (vsi && vsi->netdev && !vsi->rss_lut_user &&
	    netif_is_rxfh_configured(vsi->netdev))
		ethtool_rxfh_indir_lost(vsi->netdev);
	rtnl_unlock();
	if (err)
		return err;

	/* VF creation takes rtnl under table_lock, so don't nest them here */
	mutex_lock(&pf->vfs.table_lock);
	mutex_lock(&pf->rss_lut_lock);
	ice_for_each_vf(pf, bkt, vf) {
		vsi = ice_get_vf_vsi(vf);
		if (!vsi || vsi->rss_lut_type == ICE_LUT_VSI)
			continue;

		vsi->rss_table_size = ice_lut_type_to_size(ICE_LUT_VSI);
		vsi->rss_lut_type = ICE_LUT_VSI;
		/* don't keep queues that the VSI LUT can't spread traffic to */
		if ((vf->num_req_qs ?: vf->num_vf_qs) > max_qs)
			vf->num_req_qs = max_qs;
	}
	mutex_unlock(&pf->rss_lut_lock);
	mutex_unlock(&pf->vfs.table_lock);

	return 0;
}

static void ice_devl_res_register(struct devlink *devlink,
				  struct ice_devl_resource *resources,
				  void *occ_priv)
{
	struct devlink_resource_size_params size_params;

	devlink_resource_size_params_init(&size_params, 0, 0, 1,
					  DEVLINK_RESOURCE_UNIT_ENTRY);
	for (int i = 0; i < ICE_DEVL_RESOURCES_COUNT; i++) {
		struct ice_devl_resource *res = &resources[i];
		int err, resource_id = i;

		if (!res->name)
			continue; /* skip empty entries in config table */

		size_params.size_max = res->max_size;
		err = devl_resource_register(devlink, res->name,
					     res->start_size, resource_id,
					     res->parent_id, &size_params);
		if (WARN_ONCE(err, "not all resource handlers registered, err: %d, resname: %s\n",
			      err, res->name))
			break;

		devl_resource_occ_set_get_register(devlink, resource_id,
						   res->set, res->get, occ_priv);
	}
}

void ice_devl_whole_dev_resources_register(const struct ice_hw *hw,
					   struct ice_adapter *adapter)
{
	struct devlink *devlink = adapter->devlink;
	int global_lut_cnt = ICE_NUM_GLOBAL_LUTS;
	int pf_lut_cnt = hw->dev_caps.num_funcs;

	devl_assert_locked(devlink);
	/* see ice_devl_pf_id() and ice_devl_res_tbl() */
	if (ice_is_dual(hw)) {
		global_lut_cnt = 2 * ICE_NUM_GLOBAL_LUTS;
		pf_lut_cnt = 2 * ICE_PORTS_PER_QUAD;
	}

	adapter->resources[ICE_RSS_LUT_GLOBAL] = (struct ice_devl_resource) {
		.name = "lut_512",
		.parent_id = ICE_RSS_LUT_BOTH,
		.max_size = global_lut_cnt,
		.get = ice_rss_lut_whole_dev_occ_get_global,
		.set = ice_devl_resource_deny_occ_set,
	};
	adapter->resources[ICE_RSS_LUT_PF] = (struct ice_devl_resource) {
		.name = "lut_2048",
		.parent_id = ICE_RSS_LUT_BOTH,
		.max_size = pf_lut_cnt,
		.get = ice_rss_lut_whole_dev_occ_get_pf,
		.set = ice_devl_resource_deny_occ_set,
	};
	adapter->resources[ICE_RSS_LUT_BOTH] = (struct ice_devl_resource) {
		.name = "rss",
		.parent_id = ICE_TOP_RESOURCE,
		.max_size = pf_lut_cnt + global_lut_cnt,
		.get = ice_rss_lut_whole_dev_occ_get_both,
		.set = ice_devl_resource_deny_occ_set,
	};

	ice_devl_res_register(devlink, adapter->resources, adapter);
}

void ice_devl_pf_resources_register(struct ice_pf *pf)
{
	struct ice_devl_resource pf_resources[ICE_DEVL_RESOURCES_COUNT] = {
		[ICE_RSS_LUT_GLOBAL] = {
			.name = "lut_512",
			.parent_id = ICE_RSS_LUT_BOTH,
			.max_size = 1,
			.get = ice_rss_lut_pf_occ_get_global,
			.set = ice_rss_lut_pf_occ_set_global,
		},
		[ICE_RSS_LUT_PF] = {
			.name = "lut_2048",
			.parent_id = ICE_RSS_LUT_BOTH,
			.max_size = 1,
			.get = ice_rss_lut_pf_occ_get_pf,
			.set = ice_rss_lut_pf_occ_set_pf,
			.start_size = 1,
		},
		[ICE_RSS_LUT_BOTH] = {
			.name = "rss",
			.parent_id = ICE_TOP_RESOURCE,
			.max_size = 2,
			.get = ice_rss_lut_pf_occ_get_both,
			.set = ice_devl_resource_deny_occ_set,
		},
	};
	struct devlink *devlink = priv_to_devlink(pf);

	devl_assert_locked(devlink);
	ice_devl_res_register(devlink, pf_resources, pf);
}

void ice_devlink_vf_resources_register(struct ice_vf *vf)
{
	struct ice_devl_resource vf_resources[ICE_DEVL_RESOURCES_COUNT] = {
		[ICE_RSS_LUT_GLOBAL] = {
			.name = "lut_512",
			.parent_id = ICE_RSS_LUT_BOTH,
			.max_size = 1,
			.get = ice_rss_lut_vf_occ_get_global,
			.set = ice_rss_lut_vf_occ_set_global,
		},
		[ICE_RSS_LUT_PF] = {
			.name = "lut_2048",
			.parent_id = ICE_RSS_LUT_BOTH,
			.max_size = 1,
			.get = ice_rss_lut_vf_occ_get_pf,
			.set = ice_rss_lut_vf_occ_set_pf,
		},
		[ICE_RSS_LUT_BOTH] = {
			.name = "rss",
			.parent_id = ICE_TOP_RESOURCE,
			.max_size = 2,
			.get = ice_rss_lut_vf_occ_get_both,
			.set = ice_devl_resource_deny_occ_set,
		},
	};
	struct devlink *devlink = vf->devlink;

	devl_assert_locked(devlink);
	ice_devl_res_register(devlink, vf_resources, vf);
}
