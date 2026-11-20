// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2019-2020 Arm Ltd.

#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/export.h>
#include <linux/kasan-checks.h>
#include <linux/kernel.h>
#include <linux/unaligned.h>

#include <net/checksum.h>

/* Looks dumb, but generates nice-ish code */
static u64 accumulate(u64 sum, u64 data)
{
	__uint128_t tmp = (__uint128_t)sum + data;
	return tmp + (tmp >> 64);
}

/*
 * We over-read the buffer and this makes KASAN unhappy. Instead, disable
 * instrumentation and call kasan explicitly.
 */
unsigned int __no_sanitize_address do_csum(const unsigned char *buff, int len)
{
	unsigned int offset, shift, sum;
	const u64 *ptr;
	u64 data, sum64 = 0;

	if (unlikely(len <= 0))
		return 0;

	offset = (unsigned long)buff & 7;
	/*
	 * This is to all intents and purposes safe, since rounding down cannot
	 * result in a different page or cache line being accessed, and @buff
	 * should absolutely not be pointing to anything read-sensitive. We do,
	 * however, have to be careful not to piss off KASAN, which means using
	 * unchecked reads to accommodate the head and tail, for which we'll
	 * compensate with an explicit check up-front.
	 */
	kasan_check_read(buff, len);
	ptr = (u64 *)(buff - offset);
	len = len + offset - 8;

	/*
	 * Head: zero out any excess leading bytes. Shifting back by the same
	 * amount should be at least as fast as any other way of handling the
	 * odd/even alignment, and means we can ignore it until the very end.
	 */
	shift = offset * 8;
	data = *ptr++;
	data = (data >> shift) << shift;

	/*
	 * Body: straightforward aligned loads from here on (the paired loads
	 * underlying the quadword type still only need dword alignment). The
	 * main loop strictly excludes the tail, so the second loop will always
	 * run at least once.
	 */
	while (unlikely(len > 64)) {
		__uint128_t tmp1, tmp2, tmp3, tmp4;

		tmp1 = *(__uint128_t *)ptr;
		tmp2 = *(__uint128_t *)(ptr + 2);
		tmp3 = *(__uint128_t *)(ptr + 4);
		tmp4 = *(__uint128_t *)(ptr + 6);

		len -= 64;
		ptr += 8;

		/* This is the "don't dump the carry flag into a GPR" idiom */
		tmp1 += (tmp1 >> 64) | (tmp1 << 64);
		tmp2 += (tmp2 >> 64) | (tmp2 << 64);
		tmp3 += (tmp3 >> 64) | (tmp3 << 64);
		tmp4 += (tmp4 >> 64) | (tmp4 << 64);
		tmp1 = ((tmp1 >> 64) << 64) | (tmp2 >> 64);
		tmp1 += (tmp1 >> 64) | (tmp1 << 64);
		tmp3 = ((tmp3 >> 64) << 64) | (tmp4 >> 64);
		tmp3 += (tmp3 >> 64) | (tmp3 << 64);
		tmp1 = ((tmp1 >> 64) << 64) | (tmp3 >> 64);
		tmp1 += (tmp1 >> 64) | (tmp1 << 64);
		tmp1 = ((tmp1 >> 64) << 64) | sum64;
		tmp1 += (tmp1 >> 64) | (tmp1 << 64);
		sum64 = tmp1 >> 64;
	}
	while (len > 8) {
		__uint128_t tmp;

		sum64 = accumulate(sum64, data);
		tmp = *(__uint128_t *)ptr;

		len -= 16;
		ptr += 2;

		data = tmp >> 64;
		sum64 = accumulate(sum64, tmp);
	}
	if (len > 0) {
		sum64 = accumulate(sum64, data);
		data = *ptr;
		len -= 8;
	}
	/*
	 * Tail: zero any over-read bytes similarly to the head, again
	 * preserving odd/even alignment.
	 */
	shift = len * -8;
	data = (data << shift) >> shift;
	sum64 = accumulate(sum64, data);

	/* Finally, folding */
	sum64 += (sum64 >> 32) | (sum64 << 32);
	sum = sum64 >> 32;
	sum += (sum >> 16) | (sum << 16);
	if (offset & 1)
		return (u16)swab32(sum);

	return sum >> 16;
}

static __always_inline __uint128_t get_unaligned128(const u8 *p)
{
	u64 lo = get_unaligned((const u64 *)p);
	u64 hi = get_unaligned((const u64 *)(p + 8));

	return ((__uint128_t)hi << 64) | lo;
}

static __always_inline void put_unaligned128(__uint128_t val, u8 *p)
{
	put_unaligned((u64)val, (u64 *)p);
	put_unaligned((u64)(val >> 64), (u64 *)(p + 8));
}

static __always_inline __wsum csum_fold_acc_cy(__uint128_t acc, u64 cy)
{
	__uint128_t t;
	u64 s;

	acc += (acc >> 64) | (acc << 64);
	t = (__uint128_t)(u64)(acc >> 64) + cy;
	s = (u64)t + (u64)(t >> 64);
	s += (s >> 32) | (s << 32);
	return (__force __wsum)(u32)(s >> 32);
}

static __always_inline void csum_tree64_ovf(const u8 *s, u8 *d,
					    __uint128_t *acc, s64 *cy)
{
	__uint128_t v0 = get_unaligned128(s);
	__uint128_t v1 = get_unaligned128(s + 16);
	__uint128_t v2, v3;
	s64 o;

	put_unaligned128(v0, d);
	put_unaligned128(v1, d + 16);
	o = __builtin_add_overflow(v0, v1, &v0);

	v2 = get_unaligned128(s + 32);
	v3 = get_unaligned128(s + 48);
	put_unaligned128(v2, d + 32);
	put_unaligned128(v3, d + 48);
	o += __builtin_add_overflow(v2, v3, &v2);

	o += __builtin_add_overflow(v0, v2, &v0);
	*cy += o + __builtin_add_overflow(*acc, v0, acc);
}

static __always_inline void csum_align_src16(const u8 **ps, u8 **pd,
					     unsigned int *pulen,
					     __uint128_t *pacc, s64 *pc0)
{
	uintptr_t off = (uintptr_t)(*ps) & 15;

	if (unlikely(off) && *pulen >= 272U) {
		unsigned int adv = 16U - (unsigned int)off;
		u64 lo = get_unaligned((const u64 *)(*ps));
		u64 hi = get_unaligned((const u64 *)(*ps + 8));
		u64 odd = (u64)off & 1ULL;
		u64 m = ~0ULL >> ((off & 7) * 8);
		u64 h;

		put_unaligned(lo, (u64 *)(*pd));
		put_unaligned(hi, (u64 *)(*pd + 8));
		lo = (off & 8) ? (lo & m) : lo;
		hi = (off & 8) ? 0ULL : (hi & m);
		h = lo + hi;
		h += h < lo;
		*pacc = ror64(h, (unsigned int)(odd * 56ULL));
		/*
		 * At len <= INT_MAX, the 256B loop adds <= 16 carries per
		 * iteration (< 2^27 total before bit 62 is cleared, and c0
		 * stays < 2^33 overall), so bit 62 of @c0 cannot overflow.
		 */
		*pc0 = (s64)(odd << 62);
		*ps += adv;
		*pd += adv;
		*pulen -= adv;
	}
}

static __always_inline __wsum csum_fold_final(__uint128_t acc, u64 cy, u64 odd)
{
	__wsum res = csum_fold_acc_cy(acc, cy);

	if (unlikely(odd))
		return (__force __wsum)ror32((__force u32)res, 8);
	return res;
}

/*
 * Single-pass copy and ones' complement sum. Each summed word is read once
 * into a GPR before storing and summing, so the returned sum always matches
 * @dst even if @src is concurrently modified.
 */
__wsum __no_sanitize_address csum_partial_copy_nocheck(const void *src, void *dst, int len)
{
	const u8 *s = src;
	u8 *d = dst;
	__uint128_t acc = 0;
	s64 c0 = 0;
	u64 odd = 0;
	unsigned int ulen = (unsigned int)len;

	if (unlikely(len <= 0))
		return 0;

	kasan_check_read(src, len);
	kasan_check_write(dst, len);

	if (ulen >= 64U) {
		if (ulen >= 256U) {
			csum_align_src16(&s, &d, &ulen, &acc, &c0);
			ulen -= 256U;
			do {
				csum_tree64_ovf(s, d, &acc, &c0);
				csum_tree64_ovf(s + 64, d + 64, &acc, &c0);
				csum_tree64_ovf(s + 128, d + 128, &acc, &c0);
				csum_tree64_ovf(s + 192, d + 192, &acc, &c0);
				s += 256;
				d += 256;
			} while (!__builtin_sub_overflow(ulen, 256U, &ulen));
			odd = (u64)c0 >> 62;
			c0 &= (1LL << 62) - 1;
			ulen &= 255U;
			if (!ulen)
				goto fold;
		}
		if (ulen >= 64U) {
			ulen -= 64U;
			do {
				csum_tree64_ovf(s, d, &acc, &c0);
				s += 64;
				d += 64;
			} while (!__builtin_sub_overflow(ulen, 64U, &ulen));
			ulen &= 63U;
			if (!ulen)
				goto fold;
		}
	}
	if (likely(ulen >= 16U)) {
		ulen -= 16U;
		do {
			__uint128_t v = get_unaligned128(s);

			put_unaligned128(v, d);
			s += 16;
			d += 16;
			c0 += __builtin_add_overflow(acc, v, &acc);
		} while (!__builtin_sub_overflow(ulen, 16U, &ulen));
	}
	if (likely(ulen & 8U)) {
		u64 v = get_unaligned((const u64 *)s);

		put_unaligned(v, (u64 *)d);
		s += 8;
		d += 8;
		c0 += __builtin_add_overflow(acc, v, &acc);
	}
	if (likely(ulen & 4U)) {
		u32 v = get_unaligned((const u32 *)s);

		put_unaligned(v, (u32 *)d);
		s += 4;
		d += 4;
		c0 += v;
	}
	if (likely(ulen & 2U)) {
		u16 v = get_unaligned((const u16 *)s);

		put_unaligned(v, (u16 *)d);
		s += 2;
		d += 2;
		c0 += v;
	}
	if (ulen & 1U) {
		u8 v = *s;

		*d = v;
		c0 += v;
	}
fold:
	return csum_fold_final(acc, (u64)c0, odd);
}
EXPORT_SYMBOL(csum_partial_copy_nocheck);

__sum16 csum_ipv6_magic(const struct in6_addr *saddr,
			const struct in6_addr *daddr,
			__u32 len, __u8 proto, __wsum csum)
{
	__uint128_t src, dst;
	u64 sum = (__force u64)csum;

	src = *(const __uint128_t *)saddr->s6_addr;
	dst = *(const __uint128_t *)daddr->s6_addr;

	sum += (__force u32)htonl(len);
	sum += (u32)proto << 24;
	src += (src >> 64) | (src << 64);
	dst += (dst >> 64) | (dst << 64);

	sum = accumulate(sum, src >> 64);
	sum = accumulate(sum, dst >> 64);

	sum += ((sum >> 32) | (sum << 32));
	return csum_fold((__force __wsum)(sum >> 32));
}
EXPORT_SYMBOL(csum_ipv6_magic);
