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
#include "tls_client_session_hitls.h"

#include <limits>

#include <ngtcp2/ngtcp2_crypto_hitls.h>

#include "hitls_session.h"

#include "tls_client_config_hitls.h"
#include "client_base.h"
#include "template.h"
#include "util.h"

using namespace std::literals;

extern Config config;

namespace {

constexpr auto HITLS_SESSION_PEM_TYPE = "OPENHITLS SESSION PARAMETERS"sv;

} // namespace

std::expected<void, Error>
TLSClientSession::init(bool &early_data_enabled,
                       const TLSClientContext &tls_ctx, const char *remote_addr,
                       ClientBase *client, uint32_t quic_version,
                       AppProtocol app_proto) {
  early_data_enabled = false;

  auto ssl_ctx = tls_ctx.get_native_handle();

  ssl_ = HITLS_New(ssl_ctx);
  if (!ssl_) {
    std::println(stderr, "HITLS_New failed");
    return std::unexpected{Error::CRYPTO};
  }

  if (HITLS_SetUserData(ssl_, client->conn_ref()) != HITLS_SUCCESS) {
    std::println(stderr, "HITLS_SetUserData failed");
    return std::unexpected{Error::CRYPTO};
  }

  if (ngtcp2_crypto_hitls_configure_client_session(ssl_) != 0) {
    std::println(stderr, "ngtcp2_crypto_hitls_configure_client_session failed");
    return std::unexpected{Error::CRYPTO};
  }

  switch (app_proto) {
  case AppProtocol::H3:
    if (HITLS_SetAlpnProtos(ssl_, H3_ALPN.data(),
                            static_cast<uint32_t>(H3_ALPN.size())) !=
        HITLS_SUCCESS) {
      std::println(stderr, "HITLS_SetAlpnProtos failed");
      return std::unexpected{Error::CRYPTO};
    }
    break;
  case AppProtocol::HQ:
    if (HITLS_SetAlpnProtos(ssl_, HQ_ALPN.data(),
                            static_cast<uint32_t>(HQ_ALPN.size())) !=
        HITLS_SUCCESS) {
      std::println(stderr, "HITLS_SetAlpnProtos failed");
      return std::unexpected{Error::CRYPTO};
    }
    break;
  }

  const char *sni;
  if (!config.sni.empty()) {
    sni = config.sni.data();
  } else if (util::numeric_host(remote_addr)) {
    // If remote host is numeric address, just send "localhost" as SNI
    // for now.
    sni = "localhost";
  } else {
    sni = remote_addr;
  }

  if (HITLS_SetServerName(
        ssl_, reinterpret_cast<uint8_t *>(const_cast<char *>(sni)),
        static_cast<uint32_t>(strlen(sni))) != HITLS_SUCCESS) {
    std::println(stderr, "HITLS_SetServerName failed");
    return std::unexpected{Error::CRYPTO};
  }

  // RFC 9001, section 4.4 requires that the client authenticates the
  // server.  Check the server certificate against the name sent in
  // SNI.
  if (HITLS_SetHost(ssl_, const_cast<char *>(sni)) != HITLS_SUCCESS) {
    std::println(stderr, "HITLS_SetHost failed");
    return std::unexpected{Error::CRYPTO};
  }

  if (!config.session_file.empty()) {
    auto maybe_data = util::read_pem(config.session_file, "TLS session"sv,
                                     HITLS_SESSION_PEM_TYPE);
    if (maybe_data) {
      auto &data = *maybe_data;
      if (data.size() > std::numeric_limits<uint32_t>::max()) {
        std::println(stderr, "TLS session file is too large: {}",
                     config.session_file.native());
      } else {
        HITLS_Session *session = nullptr;
        if (HITLS_SESS_Decode(&session, data.data(),
                              static_cast<uint32_t>(data.size())) !=
            HITLS_SUCCESS) {
          std::println(stderr, "Could not decode TLS session file {}",
                       config.session_file.native());
        } else {
          auto session_d = defer([session] { HITLS_SESS_Free(session); });
          if (HITLS_SetSession(ssl_, session) != HITLS_SUCCESS) {
            std::println(stderr, "Could not set TLS session from file {}",
                         config.session_file.native());
          }
        }
      }
    }
  }

  return {};
}

bool TLSClientSession::get_early_data_accepted() const {
  // The openHiTLS QUIC-TLS API v1 does not support 0-RTT.
  return false;
}
