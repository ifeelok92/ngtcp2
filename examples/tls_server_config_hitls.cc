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
#include "tls_server_config_hitls.h"

#include <cstring>
#include <fstream>
#include <vector>

#include <ngtcp2/ngtcp2_crypto_hitls.h>

#include "server_base.h"
#include "template.h"
#include "util.h"

using namespace std::literals;

extern Config config;

namespace {

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

// openHiTLS selects ALPN through a config callback.  The callback has no
// way to reach per-connection state, so the offered protocol list is
// matched against the ALPN protocol of the selected AppProtocol.
int alpn_select(HITLS_Ctx *ctx, uint8_t **selected, uint8_t *selectedLen,
                uint8_t *list, uint32_t listLen, void *arg) {
  (void)ctx;
  auto want = static_cast<std::span<const uint8_t> *>(arg);

  for (auto s = std::span{list, listLen}; s.size() >= want->size();
       s = s.subspan(s[0] + 1)) {
    if (std::ranges::equal(*want, s.first(want->size()))) {
      *selected = const_cast<uint8_t *>(&s[1]);
      *selectedLen = s[0];
      return HITLS_ALPN_ERR_OK;
    }
  }

  return HITLS_ALPN_ERR_ALERT_FATAL;
}

} // namespace

TLSServerContext::~TLSServerContext() {
  if (ssl_ctx_) {
    HITLS_CFG_FreeConfig(ssl_ctx_);
  }
}

HITLS_Config *TLSServerContext::get_native_handle() const { return ssl_ctx_; }

std::expected<void, Error> TLSServerContext::init(const char *private_key_file,
                                                  const char *cert_file,
                                                  AppProtocol app_proto) {
  util::ensure_hitls_init();

  ssl_ctx_ = HITLS_CFG_NewTLS13Config();
  if (!ssl_ctx_) {
    std::println(stderr, "HITLS_CFG_NewTLS13Config failed");
    return std::unexpected{Error::CRYPTO};
  }

  if (ngtcp2_crypto_hitls_configure_server_config(ssl_ctx_) != 0) {
    std::println(stderr,
                 "ngtcp2_crypto_hitls_configure_server_config failed");
    return std::unexpected{Error::CRYPTO};
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

  static std::span<const uint8_t> alpn_v1;
  switch (app_proto) {
  case AppProtocol::H3:
    alpn_v1 = H3_ALPN_V1;
    break;
  case AppProtocol::HQ:
    alpn_v1 = HQ_ALPN_V1;
    break;
  }

  if (HITLS_CFG_SetAlpnProtosSelectCb(ssl_ctx_, alpn_select,
                                      const_cast<std::span<const uint8_t> *>(
                                        &alpn_v1)) != HITLS_SUCCESS) {
    std::println(stderr, "HITLS_CFG_SetAlpnProtosSelectCb failed");
    return std::unexpected{Error::CRYPTO};
  }

  if (HITLS_CFG_LoadCertFile(ssl_ctx_, cert_file, TLS_PARSE_FORMAT_PEM) !=
      HITLS_SUCCESS) {
    std::println(stderr, "HITLS_CFG_LoadCertFile failed: {}", cert_file);
    return std::unexpected{Error::CRYPTO};
  }

  if (HITLS_CFG_LoadKeyFile(ssl_ctx_, private_key_file, TLS_PARSE_FORMAT_PEM) !=
      HITLS_SUCCESS) {
    std::println(stderr, "HITLS_CFG_LoadKeyFile failed: {}", private_key_file);
    return std::unexpected{Error::CRYPTO};
  }

  return {};
}

extern std::ofstream keylog_file;

void TLSServerContext::enable_keylog() {
  HITLS_CFG_SetKeyLogCb(ssl_ctx_, [](HITLS_Ctx *ctx, const char *line) {
    (void)ctx;
    keylog_file.write(line, static_cast<std::streamsize>(strlen(line)));
    keylog_file.put('\n');
    keylog_file.flush();
  });
}
