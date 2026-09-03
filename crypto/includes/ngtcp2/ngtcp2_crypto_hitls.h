/*
 * ngtcp2
 *
 * Copyright (c) 2026 ngtcp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef NGTCP2_CRYPTO_HITLS_H
#define NGTCP2_CRYPTO_HITLS_H

#include <ngtcp2/ngtcp2.h>

#include "hitls.h"
#include "hitls_quic_tls.h"

#ifdef __cplusplus
extern "C" {
#endif /* defined(__cplusplus) */

/**
 * @function
 *
 * `ngtcp2_crypto_hitls_from_hitls_encryption_level` translates
 * |level| to :type:`ngtcp2_encryption_level`.  This function is only
 * available for openHiTLS backend.
 */
NGTCP2_EXTERN ngtcp2_encryption_level
ngtcp2_crypto_hitls_from_hitls_encryption_level(
  HITLS_QUIC_TLS_EncryptionLevel level);

/**
 * @function
 *
 * `ngtcp2_crypto_hitls_from_ngtcp2_encryption_level` translates
 * |encryption_level| to HITLS_QUIC_TLS_EncryptionLevel.  This function is
 * only available for openHiTLS backend.
 */
NGTCP2_EXTERN HITLS_QUIC_TLS_EncryptionLevel
ngtcp2_crypto_hitls_from_ngtcp2_encryption_level(
  ngtcp2_encryption_level encryption_level);

/**
 * @function
 *
 * `ngtcp2_crypto_hitls_configure_server_session` configures |ssl| for
 * server side QUIC connection.  It registers the internal openHiTLS
 * QUIC method dispatch array on |ssl| so that the TLS stack reports
 * secrets, handshake bytes, and alerts to ngtcp2.
 *
 * The application must associate |ssl| with a
 * :type:`ngtcp2_crypto_conn_ref` by calling `HITLS_SetUserData` before
 * calling this function.  The `get_conn` member of the
 * :type:`ngtcp2_crypto_conn_ref` returns the :type:`ngtcp2_conn`
 * associated with the connection.
 *
 * For an openHiTLS `HITLS_QUIC_TLS_PROTOCOL_VIOLATION`, `send_alert`
 * may first report the underlying TLS alert.  The API return is
 * authoritative: the backend records :macro:`NGTCP2_ERR_PROTO`, which
 * overrides that alert and closes with :macro:`NGTCP2_PROTOCOL_VIOLATION`
 * (0x000a).  Other fatal TLS alerts close with
 * :macro:`NGTCP2_CRYPTO_ERROR` \| alert as usual.
 *
 * It returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_hitls_configure_server_session(HITLS_Ctx *ssl);

/**
 * @function
 *
 * `ngtcp2_crypto_hitls_configure_client_session` configures |ssl| for
 * client side QUIC connection.  See
 * `ngtcp2_crypto_hitls_configure_server_session` for the details.
 *
 * It returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_hitls_configure_client_session(HITLS_Ctx *ssl);

/**
 * @function
 *
 * `ngtcp2_crypto_hitls_configure_server_config` configures |config|
 * for server side QUIC connection.  It pins the TLS version to TLS
 * 1.3.
 *
 * It returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int
ngtcp2_crypto_hitls_configure_server_config(HITLS_Config *config);

/**
 * @function
 *
 * `ngtcp2_crypto_hitls_configure_client_config` configures |config|
 * for client side QUIC connection.  It pins the TLS version to TLS
 * 1.3.
 *
 * It returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int
ngtcp2_crypto_hitls_configure_client_config(HITLS_Config *config);

#ifdef __cplusplus
}
#endif /* defined(__cplusplus) */

#endif /* !defined(NGTCP2_CRYPTO_HITLS_H) */
