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
#include "tls_session_base_hitls.h"

TLSSessionBase::~TLSSessionBase() {
  if (ssl_) {
    HITLS_Free(ssl_);
  }
}

HITLS_Ctx *TLSSessionBase::get_native_handle() const { return ssl_; }

std::string TLSSessionBase::get_cipher_name() const {
  auto cipher = HITLS_GetCurrentCipher(ssl_);
  if (cipher == nullptr) {
    return "";
  }

  auto name = HITLS_CFG_GetCipherSuiteStdName(cipher);
  if (name == nullptr) {
    return "";
  }

  return reinterpret_cast<const char *>(name);
}

std::string_view TLSSessionBase::get_negotiated_group() const {
  // openHiTLS does not expose a group-id to group-name query on a
  // connection; report nothing for now.
  return {};
}

std::string TLSSessionBase::get_selected_alpn() const {
  uint8_t *alpn = nullptr;
  uint32_t alpnlen = 0;

  if (HITLS_GetSelectedAlpnProto(ssl_, &alpn, &alpnlen) != HITLS_SUCCESS) {
    return "";
  }

  return std::string{alpn, alpn + alpnlen};
}
