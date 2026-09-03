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
#include "util.h"

#include <fstream>

#include "crypt_eal_init.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "hitls_cert_init.h"
#include "hitls_crypt_init.h"
#include "hitls_error.h"

namespace ngtcp2 {

namespace util {

void ensure_hitls_init() {
  static const bool ok = [] {
    if (CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL) != CRYPT_SUCCESS ||
        HITLS_CertMethodInit() != HITLS_SUCCESS) {
      abort();
    }
    HITLS_CryptMethodInit();
    return true;
  }();
  (void)ok;
}


std::expected<void, Error> generate_secure_random(std::span<uint8_t> data) {
  if (CRYPT_EAL_Randbytes(data.data(), static_cast<uint32_t>(data.size())) !=
      CRYPT_SUCCESS) {
    return std::unexpected{Error::CRYPTO};
  }

  return {};
}

std::expected<HPKEPrivateKey, Error>
read_hpke_private_key_pem(const std::filesystem::path &path) {
  (void)path;
  return std::unexpected{Error::NOT_IMPLEMENTED};
}

namespace {

int base64_decode(std::span<const uint8_t> in, std::vector<uint8_t> &out) {
  static constexpr int8_t tbl[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
  };

  uint32_t acc = 0;
  int nbits = 0;

  for (auto c : in) {
    if (c == '=' || c == '\n' || c == '\r') {
      continue;
    }
    if (c >= sizeof(tbl) || tbl[c] == -1) {
      return -1;
    }
    acc = (acc << 6) | static_cast<uint32_t>(tbl[c]);
    nbits += 6;
    if (nbits >= 8) {
      nbits -= 8;
      out.push_back(static_cast<uint8_t>((acc >> nbits) & 0xff));
    }
  }

  return 0;
}

void base64_encode(std::span<const uint8_t> in, std::string &out) {
  static constexpr char tbl[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  uint32_t acc = 0;
  int nbits = 0;

  for (auto c : in) {
    acc = (acc << 8) | c;
    nbits += 8;
    while (nbits >= 6) {
      nbits -= 6;
      out.push_back(tbl[(acc >> nbits) & 0x3f]);
    }
  }
  if (nbits > 0) {
    out.push_back(tbl[(acc << (6 - nbits)) & 0x3f]);
  }
}

} // namespace

std::expected<std::vector<uint8_t>, Error>
read_pem(const std::filesystem::path &path, std::string_view name,
         std::string_view type) {
  auto f = std::ifstream{path};
  if (!f) {
    std::println(stderr, "Could not open {} file {}", name, path.native());
    return std::unexpected{Error::IO};
  }

  auto begin = std::string{"-----BEGIN "} + std::string{type} + "-----";
  auto end = std::string{"-----END "} + std::string{type} + "-----";

  std::string line;
  bool in_block = false;
  std::string b64;

  while (std::getline(f, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    if (!in_block) {
      if (line == begin) {
        in_block = true;
      }
      continue;
    }
    if (line == end) {
      std::vector<uint8_t> data;
      if (base64_decode(
            std::span{reinterpret_cast<const uint8_t *>(b64.data()), b64.size()},
            data) != 0) {
        std::println(stderr, "Could not decode {} file {}", name,
                     path.native());
        return std::unexpected{Error::IO};
      }
      return data;
    }
    b64 += line;
  }

  std::println(stderr, "Could not read {} file {}", name, path.native());
  return std::unexpected{Error::IO};
}

std::expected<void, Error> write_pem(const std::filesystem::path &path,
                                     std::string_view name,
                                     std::string_view type,
                                     std::span<const uint8_t> data) {
  auto f = std::ofstream{path};
  if (!f) {
    std::println(stderr, "Could not write {} to {}", name, path.native());
    return std::unexpected{Error::IO};
  }

  f << "-----BEGIN " << type << "-----\n";
  std::string b64;
  base64_encode(data, b64);
  for (size_t i = 0; i < b64.size(); i += 64) {
    f.write(b64.data() + i, static_cast<std::streamsize>(
                              std::min<size_t>(64, b64.size() - i)));
    f.put('\n');
  }
  f << "-----END " << type << "-----\n";

  return {};
}

const char *crypto_default_ciphers() {
  return "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"
         "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256";
}

const char *crypto_default_groups() {
  return "X25519:P-256:P-384:P-521";
}

} // namespace util

} // namespace ngtcp2
