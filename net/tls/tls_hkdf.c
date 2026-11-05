// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * TLS 1.3 HKDF-Expand-Label, RFC 9846 section 7.1.
 *
 * TLS 1.3 derives all of its secrets and keys with HKDF (RFC 5869). The
 * TLS handshake runs in user space and gives the kernel one application
 * traffic secret for each direction. For a KeyUpdate, the kernel derives
 * the next traffic secret from the current one (section 7.2), and the
 * new key and IV from the next traffic secret (section 7.3). Both steps
 * use only HKDF-Expand-Label, so this file implements only that
 * function, not the full key schedule of the handshake.
 *
 * The input is always a traffic secret. It is already a random key of
 * the hash length, so HKDF-Extract is not needed. No output is longer
 * than the hash, so HKDF-Expand is a single HMAC.
 */

#include <crypto/sha2.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/unaligned.h>

#include "tls.h"

#define TLS_HKDF_LABEL_PREFIX		"tls13 "
#define TLS_HKDF_LABEL_PREFIX_LEN	(sizeof(TLS_HKDF_LABEL_PREFIX) - 1)
#define TLS_HKDF_LABEL_MAX		32

/**
 * tls_hkdf_expand_label - HKDF-Expand-Label with an empty context
 * @secret: the secret
 * @secret_len: length of @secret, which selects the hash: SHA-256 for
 *	SHA256_DIGEST_SIZE, SHA-384 for SHA384_DIGEST_SIZE
 * @label: the label, without the "tls13 " prefix
 * @out: output buffer
 * @out_len: number of bytes to derive, at most @secret_len
 *
 * Return: 0 on success, -EINVAL if a length is not valid.
 */
int tls_hkdf_expand_label(const u8 *secret, size_t secret_len,
			  const char *label, u8 *out, size_t out_len)
{
	u8 info[2 + 1 + TLS_HKDF_LABEL_PREFIX_LEN + TLS_HKDF_LABEL_MAX + 1 + 1];
	size_t label_len = strlen(label);
	u8 tmp[SHA384_DIGEST_SIZE];
	size_t pos = 0;

	if (secret_len != SHA256_DIGEST_SIZE &&
	    secret_len != SHA384_DIGEST_SIZE)
		return -EINVAL;
	if (!out_len || out_len > secret_len || label_len > TLS_HKDF_LABEL_MAX)
		return -EINVAL;

	/* struct {
	 *	uint16 length;
	 *	opaque label<7..255>;
	 *	opaque context<0..255>;
	 * } HkdfLabel;
	 *
	 * followed by the HKDF-Expand counter for the first output block.
	 */
	put_unaligned_be16(out_len, info);
	pos += 2;
	info[pos++] = TLS_HKDF_LABEL_PREFIX_LEN + label_len;
	memcpy(info + pos, TLS_HKDF_LABEL_PREFIX, TLS_HKDF_LABEL_PREFIX_LEN);
	pos += TLS_HKDF_LABEL_PREFIX_LEN;
	memcpy(info + pos, label, label_len);
	pos += label_len;
	info[pos++] = 0;	/* empty context */
	info[pos++] = 1;	/* counter */

	if (secret_len == SHA256_DIGEST_SIZE)
		hmac_sha256_usingrawkey(secret, secret_len, info, pos, tmp);
	else
		hmac_sha384_usingrawkey(secret, secret_len, info, pos, tmp);

	memcpy(out, tmp, out_len);
	memzero_explicit(tmp, sizeof(tmp));

	return 0;
}
