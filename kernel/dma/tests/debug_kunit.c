// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

static void dma_debug_bound_lifetime_test(struct kunit *test)
{
	struct dma_debug_entry *entries;
	struct hash_bucket bucket = {};
	unsigned long bounds[7];

	entries = kunit_kcalloc(test, 3, sizeof(*entries), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, entries);
	entries[0].size = SZ_4K;
	entries[1].size = SZ_64K;
	entries[2].size = SZ_64K;
	INIT_LIST_HEAD(&bucket.list);
	spin_lock_init(&bucket.lock);
	spin_lock(&bucket.lock);
	hash_bucket_add(&bucket, &entries[0]);
	bounds[0] = bucket.max_entry_size;
	hash_bucket_add(&bucket, &entries[1]);
	hash_bucket_add(&bucket, &entries[2]);
	bounds[1] = bucket.max_entry_size;
	hash_bucket_del(&bucket, &entries[1]);
	bounds[2] = bucket.max_entry_size;
	hash_bucket_del(&bucket, &entries[2]);
	bounds[3] = bucket.max_entry_size;
	hash_bucket_del(&bucket, &entries[0]);
	bounds[4] = bucket.max_entry_size;
	hash_bucket_add(&bucket, &entries[0]);
	bounds[5] = bucket.max_entry_size;
	hash_bucket_del(&bucket, &entries[0]);
	bounds[6] = bucket.max_entry_size;
	spin_unlock(&bucket.lock);

	KUNIT_EXPECT_GE(test, bounds[0], (unsigned long)SZ_4K);
	KUNIT_EXPECT_GE(test, bounds[1], (unsigned long)SZ_64K);
	KUNIT_EXPECT_GE(test, bounds[2], (unsigned long)SZ_64K);
	KUNIT_EXPECT_GE(test, bounds[3], (unsigned long)SZ_4K);
	KUNIT_EXPECT_EQ(test, bounds[4], 0UL);
	KUNIT_EXPECT_GE(test, bounds[5], (unsigned long)SZ_4K);
	KUNIT_EXPECT_EQ(test, bounds[6], 0UL);
}

static struct kunit_case dma_debug_bound_cases[] = {
	KUNIT_CASE(dma_debug_bound_lifetime_test),
	{}
};

static struct kunit_suite dma_debug_bound_suite = {
	.name = "dma-debug-bound",
	.test_cases = dma_debug_bound_cases,
};

kunit_test_suite(dma_debug_bound_suite);
