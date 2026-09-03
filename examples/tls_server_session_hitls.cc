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
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "tls_server_session_hitls.h"

#include <ngtcp2/ngtcp2_crypto_hitls.h>

#include "tls_server_config_hitls.h"
#include "server_base.h"

std::expected<void, Error>
TLSServerSession::init(const TLSServerContext &tls_ctx, HandlerBase *handler) {
  auto ssl_ctx = tls_ctx.get_native_handle();

  ssl_ = HITLS_New(ssl_ctx);
  if (!ssl_) {
    std::println(stderr, "HITLS_New failed");
    return std::unexpected{Error::CRYPTO};
  }

  if (HITLS_SetUserData(ssl_, handler->conn_ref()) != HITLS_SUCCESS) {
    std::println(stderr, "HITLS_SetUserData failed");
    return std::unexpected{Error::CRYPTO};
  }

  if (ngtcp2_crypto_hitls_configure_server_session(ssl_) != 0) {
    std::println(stderr, "ngtcp2_crypto_hitls_configure_server_session failed");
    return std::unexpected{Error::CRYPTO};
  }

  return {};
}
