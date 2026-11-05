// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Dell Technologies Inc. or its subsidiaries.
 *
 * TLS 1.3 KeyUpdate, RFC 9846 sections 4.7.3 and 7.2.
 *
 * A TLS 1.3 peer can change the key of the direction it sends in at any
 * time. It sends a KeyUpdate message, then encrypts all later records
 * with the next key. A sender must also change its key before the key
 * has protected too many records (section 5.5).
 *
 * The next key is derived from the application traffic secret, not from
 * the current key. User space gives the kernel only the key and IV, so
 * the kernel cannot derive the next key on its own. Without the secret,
 * a received KeyUpdate goes to the application, and the kernel stops
 * decrypting until the application installs the next key with TLS_RX.
 *
 * With TLS_TX_TRAFFIC_SECRET or TLS_RX_TRAFFIC_SECRET, user space also
 * gives the kernel the secret of that direction. The kernel then handles
 * KeyUpdate itself. This file derives and installs the next key, and
 * processes a received KeyUpdate. tls_sw.c sends KeyUpdate messages.
 */

#include <linux/jiffies.h>
#include <linux/skbuff.h>
#include <net/strparser.h>
#include <net/tls.h>

#include "tls.h"

/* A peer that sends more KeyUpdates than this in one second ends the
 * connection. Each one costs three HMACs and a new key, and carries no
 * data.
 */
#define TLS_KEYUPDATE_RX_MAX_PER_SEC	8

/**
 * tls_keyupdate_rekey - install the next key of one direction
 * @sk: socket
 * @tx: non-zero for the transmit direction
 *
 * Derive the next application traffic secret from the registered one,
 * then its key and IV, and install them. The record sequence number
 * restarts at zero.
 *
 * Return: 0 on success, or a negative errno. On error the installed key
 * and the registered secret do not change.
 */
int tls_keyupdate_rekey(struct sock *sk, int tx)
{
	struct tls_context *ctx = tls_get_ctx(sk);
	struct tls_traffic_secret *secret;
	const struct tls_cipher_desc *cipher_desc;
	u8 iv[TLS_MAX_SALT_SIZE + TLS_MAX_IV_SIZE];
	u8 next[TLS_MAX_TRAFFIC_SECRET_SIZE];
	union tls_crypto_context tmp;
	struct tls_crypto_info *info = (void *)&tmp;
	int rc;

	secret = tx ? &ctx->tx_secret : &ctx->rx_secret;
	cipher_desc = get_cipher_desc(ctx->prot_info.cipher_type);
	if (!cipher_desc || !secret->len ||
	    cipher_desc->salt + cipher_desc->iv > sizeof(iv))
		return -EINVAL;

	/* version and cipher_type; the rest of tmp stays zero */
	memset(&tmp, 0, sizeof(tmp));
	*info = tx ? ctx->crypto_send.info : ctx->crypto_recv.info;

	rc = tls_hkdf_expand_label(secret->data, secret->len, "traffic upd",
				   next, secret->len);
	if (rc)
		goto out;

	rc = tls_hkdf_expand_label(next, secret->len, "key",
				   crypto_info_key(info, cipher_desc),
				   cipher_desc->key);
	if (rc)
		goto out;

	rc = tls_hkdf_expand_label(next, secret->len, "iv", iv,
				   cipher_desc->salt + cipher_desc->iv);
	if (rc)
		goto out;

	memcpy(crypto_info_salt(info, cipher_desc), iv, cipher_desc->salt);
	memcpy(crypto_info_iv(info, cipher_desc), iv + cipher_desc->salt,
	       cipher_desc->iv);

	rc = tls_set_sw_offload(sk, tx, info);
	if (rc)
		goto out;

	memcpy(secret->data, next, secret->len);

out:
	memzero_explicit(next, sizeof(next));
	memzero_explicit(iv, sizeof(iv));
	memzero_explicit(&tmp, sizeof(tmp));

	return rc;
}

/**
 * tls_keyupdate_rx - process a received KeyUpdate
 * @sk: socket
 * @skb: the decrypted record, which starts with a KeyUpdate message
 *
 * Called with the socket locked, for a direction with a registered
 * secret. The caller does not pass the record to the user.
 *
 * Return: 0 on success, or a negative errno if the connection must end.
 */
int tls_keyupdate_rx(struct sock *sk, struct sk_buff *skb)
{
	struct tls_context *ctx = tls_get_ctx(sk);
	struct tls_sw_context_rx *rx_ctx = tls_sw_ctx_rx(ctx);
	const struct strp_msg *rxm = strp_msg(skb);
	u8 msg[TLS_KEYUPDATE_MSG_SIZE];
	int rc;

	/* A KeyUpdate must end its record (section 5.1). Another message
	 * in the same record is not supported.
	 */
	if (rxm->full_len != sizeof(msg) ||
	    skb_copy_bits(skb, rxm->offset, msg, sizeof(msg)))
		return -EBADMSG;

	/* msg_type, a 24-bit length of 1, then request_update */
	if (msg[1] || msg[2] || msg[3] != 1)
		return -EBADMSG;
	if (msg[4] != TLS_KEY_UPDATE_NOT_REQUESTED &&
	    msg[4] != TLS_KEY_UPDATE_REQUESTED)
		return -EBADMSG;

	if (!rx_ctx->key_update_count ||
	    time_after(jiffies, rx_ctx->key_update_window + HZ)) {
		rx_ctx->key_update_window = jiffies;
		rx_ctx->key_update_count = 0;
	}
	if (++rx_ctx->key_update_count > TLS_KEYUPDATE_RX_MAX_PER_SEC) {
		TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSRXREKEYERROR);
		net_warn_ratelimited("tls: peer sent more than %d KeyUpdates in one second\n",
				     TLS_KEYUPDATE_RX_MAX_PER_SEC);
		return -EBADMSG;
	}

	rc = tls_keyupdate_rekey(sk, 0);
	if (rc) {
		TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSRXREKEYERROR);
		return rc;
	}
	TLS_INC_STATS(sock_net(sk), LINUX_MIB_TLSRXREKEYOK);

	return 0;
}
