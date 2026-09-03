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
#include "tls_client_config_hitls.h"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>

#include <ngtcp2/ngtcp2_crypto_hitls.h>

#include "hitls_session.h"

#include "client_base.h"
#include "template.h"
#include "util.h"

using namespace std::literals;

extern Config config;

namespace {

constexpr auto HITLS_SESSION_PEM_TYPE = "OPENHITLS SESSION PARAMETERS"sv;

int32_t new_session_cb(HITLS_Ctx *ctx, HITLS_Session *session) {
  auto conn_ref = static_cast<ngtcp2_crypto_conn_ref *>(HITLS_GetUserData(ctx));
  if (conn_ref == nullptr || conn_ref->user_data == nullptr) {
    std::println(stderr, "Missing client data for new TLS session");
    return 0;
  }

  auto client = static_cast<ClientBase *>(conn_ref->user_data);
  client->ticket_received();

  uint32_t sessionlen = 0;
  if (HITLS_SESS_Encode(session, nullptr, 0, &sessionlen) != HITLS_SUCCESS ||
      sessionlen == 0) {
    std::println(stderr, "Could not export TLS session");
    return 0;
  }

  std::vector<uint8_t> data(sessionlen);
  uint32_t usedlen = 0;
  if (HITLS_SESS_Encode(session, data.data(), sessionlen, &usedlen) !=
        HITLS_SUCCESS ||
      usedlen > sessionlen) {
    std::println(stderr, "Could not export TLS session");
    return 0;
  }
  data.resize(usedlen);

  if (!util::write_pem(config.session_file, "TLS session"sv,
                       HITLS_SESSION_PEM_TYPE, data)) {
    std::println(stderr, "Unable to write TLS session to file");
  }

  // Returning 0 tells openHiTLS that the callback did not retain its
  // additional session reference.
  return 0;
}

// Translate a colon-separated list of RFC cipher-suite standard names to
// IANA cipher-suite ids (HITLS_CipherSuite values).  Unknown names are
// skipped.
std::vector<uint16_t> parse_ciphers(const char *ciphers) {
  static const struct {
    std::string_view name;
    uint16_t id;
  } table[] = {
    {"TLS_AES_128_GCM_SHA256"sv, 0x1301},
    {"TLS_AES_256_GCM_SHA384"sv, 0x1302},
    {"TLS_CHACHA20_POLY1305_SHA256"sv, 0x1303},
    {"TLS_AES_128_CCM_SHA256"sv, 0x1304},
    {"TLS_AES_128_CCM_8_SHA256"sv, 0x1305},
  };

  std::vector<uint16_t> res;

  for (auto s = std::string_view{ciphers}; !s.empty();) {
    auto idx = s.find(':');
    auto name = s.substr(0, idx);
    s = idx == std::string_view::npos ? "" : s.substr(idx + 1);

    auto it = std::begin(table);
    for (; it != std::end(table); ++it) {
      if (it->name == name) {
        break;
      }
    }
    if (it == std::end(table)) {
      std::println(stderr, "Unknown cipher suite: {}", name);
      continue;
    }

    res.push_back(it->id);
  }

  return res;
}

} // namespace

TLSClientContext::~TLSClientContext() {
  if (ssl_ctx_) {
    HITLS_CFG_FreeConfig(ssl_ctx_);
  }
}

HITLS_Config *TLSClientContext::get_native_handle() const { return ssl_ctx_; }

std::expected<void, Error> TLSClientContext::init(const char *private_key_file,
                                                  const char *cert_file) {
  util::ensure_hitls_init();

  ssl_ctx_ = HITLS_CFG_NewTLS13Config();
  if (!ssl_ctx_) {
    std::println(stderr, "HITLS_CFG_NewTLS13Config failed");
    return std::unexpected{Error::CRYPTO};
  }

  if (ngtcp2_crypto_hitls_configure_client_config(ssl_ctx_) != 0) {
    std::println(stderr,
                 "ngtcp2_crypto_hitls_configure_client_config failed");
    return std::unexpected{Error::CRYPTO};
  }

  // RFC 9001, section 4.4 requires that the client authenticates the
  // server.  Load the trust anchors from the file or directory set by
  // SSL_CERT_FILE/SSL_CERT_DIR, falling back to well-known system CA
  // bundle locations.
  if (auto ca_file = getenv("SSL_CERT_FILE"); ca_file != nullptr &&
                                                 *ca_file != '\0') {
    if (HITLS_CFG_LoadVerifyFile(ssl_ctx_, ca_file) != HITLS_SUCCESS) {
      std::println(stderr, "HITLS_CFG_LoadVerifyFile failed: {}", ca_file);
      return std::unexpected{Error::CRYPTO};
    }
  } else if (auto ca_dir = getenv("SSL_CERT_DIR"); ca_dir != nullptr &&
                                                       *ca_dir != '\0') {
    if (HITLS_CFG_LoadVerifyDir(ssl_ctx_, ca_dir) != HITLS_SUCCESS) {
      std::println(stderr, "HITLS_CFG_LoadVerifyDir failed: {}", ca_dir);
      return std::unexpected{Error::CRYPTO};
    }
  } else {
    constexpr std::string_view system_ca_bundles[] = {
      "/etc/ssl/certs/ca-certificates.crt"sv,
      "/etc/pki/tls/certs/ca-bundle.crt"sv,
      "/etc/ssl/ca-bundle.pem"sv,
    };

    auto loaded = false;
    for (auto bundle : system_ca_bundles) {
      if (HITLS_CFG_LoadVerifyFile(ssl_ctx_, bundle.data()) ==
          HITLS_SUCCESS) {
        loaded = true;
        break;
      }
    }

    if (!loaded) {
      std::println(stderr, "Could not load system CA trust anchors");
      return std::unexpected{Error::CRYPTO};
    }
  }

  auto ciphers = parse_ciphers(config.ciphers);
  if (!ciphers.empty() &&
      HITLS_CFG_SetCipherSuites(ssl_ctx_, ciphers.data(),
                                static_cast<uint32_t>(ciphers.size())) !=
        HITLS_SUCCESS) {
    std::println(stderr, "HITLS_CFG_SetCipherSuites failed");
    return std::unexpected{Error::CRYPTO};
  }

  if (HITLS_CFG_SetGroupList(ssl_ctx_, config.groups,
                             static_cast<uint32_t>(strlen(config.groups))) !=
      HITLS_SUCCESS) {
    std::println(stderr, "HITLS_CFG_SetGroupList failed");
    return std::unexpected{Error::CRYPTO};
  }

  if (private_key_file && cert_file) {
    if (HITLS_CFG_LoadCertFile(ssl_ctx_, cert_file, TLS_PARSE_FORMAT_PEM) !=
        HITLS_SUCCESS) {
      std::println(stderr, "HITLS_CFG_LoadCertFile failed: {}", cert_file);
      return std::unexpected{Error::CRYPTO};
    }

    if (HITLS_CFG_LoadKeyFile(ssl_ctx_, private_key_file, TLS_PARSE_FORMAT_PEM) !=
        HITLS_SUCCESS) {
      std::println(stderr, "HITLS_CFG_LoadKeyFile failed: {}",
                   private_key_file);
      return std::unexpected{Error::CRYPTO};
    }
  }

  if (!config.session_file.empty() &&
      HITLS_CFG_SetNewSessionCb(ssl_ctx_, new_session_cb) != HITLS_SUCCESS) {
    std::println(stderr, "HITLS_CFG_SetNewSessionCb failed");
    return std::unexpected{Error::CRYPTO};
  }

  return {};
}

extern std::ofstream keylog_file;

void TLSClientContext::enable_keylog() {
  HITLS_CFG_SetKeyLogCb(ssl_ctx_, [](HITLS_Ctx *ctx, const char *line) {
    (void)ctx;
    keylog_file.write(line, static_cast<std::streamsize>(strlen(line)));
    keylog_file.put('\n');
    keylog_file.flush();
  });
}
