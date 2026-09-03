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
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <assert.h>
#include <string.h>

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_hitls.h>

#include "hitls.h"
#include "hitls_config.h"
#include "hitls_crypt_type.h"
#include "hitls_error.h"
#include "hitls_quic_tls.h"

#include "crypt_eal_cipher.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_md.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_init.h"
#include "crypt_algid.h"
#include "crypt_params_key.h"
#include "crypt_types.h"
#include "crypt_errno.h"
#include "bsl_params.h"

#include "ngtcp2_macro.h"
#include "shared.h"

typedef enum crypto_hitls_cipher_type {
  CRYPTO_HITLS_CIPHER_TYPE_AES_128,
  CRYPTO_HITLS_CIPHER_TYPE_AES_256,
  CRYPTO_HITLS_CIPHER_TYPE_CHACHA20,
} crypto_hitls_cipher_type;

typedef struct crypto_hitls_cipher {
  crypto_hitls_cipher_type type;
} crypto_hitls_cipher;

static crypto_hitls_cipher crypto_cipher_aes_128 = {
  CRYPTO_HITLS_CIPHER_TYPE_AES_128,
};

static crypto_hitls_cipher crypto_cipher_aes_256 = {
  CRYPTO_HITLS_CIPHER_TYPE_AES_256,
};

static crypto_hitls_cipher crypto_cipher_chacha20 = {
  CRYPTO_HITLS_CIPHER_TYPE_CHACHA20,
};

static crypto_hitls_cipher_type
crypto_aead_get_hp_type(HITLS_CipherAlgo cipher_algo) {
  switch (cipher_algo) {
  case HITLS_CIPHER_AES_128_GCM:
  case HITLS_CIPHER_AES_128_CCM:
    return CRYPTO_HITLS_CIPHER_TYPE_AES_128;
  case HITLS_CIPHER_AES_256_GCM:
    return CRYPTO_HITLS_CIPHER_TYPE_AES_256;
  case HITLS_CIPHER_CHACHA20_POLY1305:
    return CRYPTO_HITLS_CIPHER_TYPE_CHACHA20;
  default:
    /* CCM_8 and the SM4 suites have no QUIC header-protection scheme
       (RFC 9001 Section 5.3); openHiTLS already refuses to negotiate
       them in QUIC mode, so they never get here. */
    return (crypto_hitls_cipher_type)-1;
  }
}

static const crypto_hitls_cipher *crypto_aead_get_hp(HITLS_CipherAlgo algo) {
  switch (crypto_aead_get_hp_type(algo)) {
  case CRYPTO_HITLS_CIPHER_TYPE_AES_128:
    return &crypto_cipher_aes_128;
  case CRYPTO_HITLS_CIPHER_TYPE_AES_256:
    return &crypto_cipher_aes_256;
  case CRYPTO_HITLS_CIPHER_TYPE_CHACHA20:
    return &crypto_cipher_chacha20;
  default:
    return NULL;
  }
}

/* Map an openHiTLS cipher suite id to the AEAD / hash ids used by the
   openHiTLS crypto EAL.  The public HITLS_CFG_GetCipherId /
   HITLS_CFG_GetHashId accessors are used so that the mapping always
   agrees with the negotiated cipher suite. */
static int crypto_get_cipher_and_hash(const HITLS_Cipher *cipher,
                                      HITLS_CipherAlgo *cipher_algo,
                                      HITLS_HashAlgo *hash_algo) {
  if (cipher == NULL ||
      HITLS_CFG_GetCipherId(cipher, cipher_algo) != HITLS_SUCCESS ||
      HITLS_CFG_GetHashId(cipher, hash_algo) != HITLS_SUCCESS) {
    return -1;
  }

  return 0;
}

static uint64_t
crypto_cipher_algo_get_max_encryption(HITLS_CipherAlgo cipher_algo) {
  switch (cipher_algo) {
  case HITLS_CIPHER_AES_128_GCM:
  case HITLS_CIPHER_AES_256_GCM:
    return NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_GCM;
  case HITLS_CIPHER_CHACHA20_POLY1305:
    return NGTCP2_CRYPTO_MAX_ENCRYPTION_CHACHA20_POLY1305;
  case HITLS_CIPHER_AES_128_CCM:
    return NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_CCM;
  default:
    return 0;
  }
}

static uint64_t
crypto_cipher_algo_get_max_decryption_failure(HITLS_CipherAlgo cipher_algo) {
  switch (cipher_algo) {
  case HITLS_CIPHER_AES_128_GCM:
  case HITLS_CIPHER_AES_256_GCM:
    return NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_GCM;
  case HITLS_CIPHER_CHACHA20_POLY1305:
    return NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_CHACHA20_POLY1305;
  case HITLS_CIPHER_AES_128_CCM:
    return NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_CCM;
  default:
    return 0;
  }
}

/* Convert a public HITLS_HashAlgo id into the HMAC algorithm id the
   openHiTLS HKDF implementation expects (CRYPT_PARAM_KDF_MAC_ID). */
static CRYPT_MAC_AlgId crypto_hash_to_mac_id(HITLS_HashAlgo hash_algo) {
  switch (hash_algo) {
  case HITLS_HASH_SHA_256:
    return CRYPT_MAC_HMAC_SHA256;
  case HITLS_HASH_SHA_384:
    return CRYPT_MAC_HMAC_SHA384;
  default:
    return (CRYPT_MAC_AlgId)BSL_CID_UNKNOWN;
  }
}

static int supported_cipher_algo(HITLS_CipherAlgo cipher_algo) {
  switch (cipher_algo) {
  case HITLS_CIPHER_AES_128_GCM:
  case HITLS_CIPHER_AES_256_GCM:
  case HITLS_CIPHER_CHACHA20_POLY1305:
  case HITLS_CIPHER_AES_128_CCM:
    return 1;
  default:
    return 0;
  }
}

/* The crypto AEAD / MD / HP descriptors below are pure value types:
   the openHiTLS crypto EAL identifies algorithms by integer ids rather
   than by library-provided objects.  We therefore store the negotiated
   algorithm ids in the native_handle fields as small integers encoded
   in the void * (the values are BSL_CID_* constants which fit in a
   pointer on all supported platforms). */

ngtcp2_crypto_aead *ngtcp2_crypto_aead_aes_128_gcm(ngtcp2_crypto_aead *aead) {
  aead->native_handle = (void *)(uintptr_t)CRYPT_CIPHER_AES128_GCM;
  aead->max_overhead = 16;
  return aead;
}

ngtcp2_crypto_md *ngtcp2_crypto_md_sha256(ngtcp2_crypto_md *md) {
  md->native_handle = (void *)(uintptr_t)CRYPT_MD_SHA256;
  return md;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx) {
  ngtcp2_crypto_aead_aes_128_gcm(&ctx->aead);
  ctx->md.native_handle = (void *)(uintptr_t)CRYPT_MD_SHA256;
  ctx->hp.native_handle = (void *)&crypto_cipher_aes_128;
  ctx->max_encryption = 0;
  ctx->max_decryption_failure = 0;
  return ctx;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_init(ngtcp2_crypto_aead *aead,
                                            void *aead_native_handle) {
  aead->native_handle = aead_native_handle;
  /* 16-byte tag for the AEADs permitted by RFC 9001. */
  aead->max_overhead = 16;
  return aead;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_retry(ngtcp2_crypto_aead *aead) {
  return ngtcp2_crypto_aead_aes_128_gcm(aead);
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx,
                                         void *tls_native_handle) {
  const HITLS_Cipher *cipher = HITLS_GetCurrentCipher(tls_native_handle);
  HITLS_CipherAlgo cipher_algo;
  HITLS_HashAlgo hash_algo;
  const crypto_hitls_cipher *hp;

  if (crypto_get_cipher_and_hash(cipher, &cipher_algo, &hash_algo) != 0) {
    return NULL;
  }

  if (!supported_cipher_algo(cipher_algo)) {
    return NULL;
  }

  hp = crypto_aead_get_hp(cipher_algo);
  if (hp == NULL) {
    return NULL;
  }

  ctx->aead.native_handle = (void *)(uintptr_t)cipher_algo;
  ctx->aead.max_overhead = 16;
  ctx->md.native_handle = (void *)(uintptr_t)hash_algo;
  ctx->hp.native_handle = (void *)hp;
  ctx->max_encryption = crypto_cipher_algo_get_max_encryption(cipher_algo);
  ctx->max_decryption_failure =
    crypto_cipher_algo_get_max_decryption_failure(cipher_algo);

  return ctx;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls_early(ngtcp2_crypto_ctx *ctx,
                                               void *tls_native_handle) {
  return ngtcp2_crypto_ctx_tls(ctx, tls_native_handle);
}

static size_t crypto_md_hashlen(const ngtcp2_crypto_md *md) {
  CRYPT_MD_AlgId alg = (CRYPT_MD_AlgId)(uintptr_t)md->native_handle;
  return (size_t)CRYPT_EAL_MdGetDigestSize(alg);
}

size_t ngtcp2_crypto_md_hashlen(const ngtcp2_crypto_md *md) {
  return crypto_md_hashlen(md);
}

static size_t crypto_aead_keylen(const ngtcp2_crypto_aead *aead) {
  CRYPT_CIPHER_AlgId alg = (CRYPT_CIPHER_AlgId)(uintptr_t)aead->native_handle;
  uint32_t keylen = 0;

  if (CRYPT_EAL_CipherGetInfo(alg, CRYPT_INFO_KEY_LEN, &keylen) !=
      CRYPT_SUCCESS) {
    return 0;
  }

  return (size_t)keylen;
}

size_t ngtcp2_crypto_aead_keylen(const ngtcp2_crypto_aead *aead) {
  return crypto_aead_keylen(aead);
}

static size_t crypto_aead_noncelen(const ngtcp2_crypto_aead *aead) {
  /* Packet protection nonce is always 12 bytes for the permitted
     QUIC cipher suites (RFC 9001 s5.3). */
  (void)aead;
  return 12;
}

size_t ngtcp2_crypto_aead_noncelen(const ngtcp2_crypto_aead *aead) {
  return crypto_aead_noncelen(aead);
}

/* AEAD context: a CRYPT_EAL_CipherCtx created for the AEAD algorithm id
   and initialized with the traffic key.  The nonce is supplied on every
   encrypt/decrypt call via CRYPT_EAL_CipherReinit (the openHiTLS AEAD
   interface binds a nonce per operation, matching how QUIC uses a fresh
   nonce for every packet). */

int ngtcp2_crypto_aead_ctx_encrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
  CRYPT_CIPHER_AlgId alg = (CRYPT_CIPHER_AlgId)(uintptr_t)aead->native_handle;
  CRYPT_EAL_CipherCtx *ctx;
  static const uint8_t zero_iv[16] = {0};

  (void)noncelen;
  ctx = CRYPT_EAL_CipherNewCtx(alg);
  if (ctx == NULL) {
    return -1;
  }

  if (CRYPT_EAL_CipherInit(ctx, key, (uint32_t)crypto_aead_keylen(aead),
                           zero_iv, sizeof(zero_iv), true) != CRYPT_SUCCESS) {
    CRYPT_EAL_CipherFreeCtx(ctx);
    return -1;
  }

  aead_ctx->native_handle = ctx;
  return 0;
}

int ngtcp2_crypto_aead_ctx_decrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
  CRYPT_CIPHER_AlgId alg = (CRYPT_CIPHER_AlgId)(uintptr_t)aead->native_handle;
  CRYPT_EAL_CipherCtx *ctx;
  static const uint8_t zero_iv[16] = {0};

  (void)noncelen;
  ctx = CRYPT_EAL_CipherNewCtx(alg);
  if (ctx == NULL) {
    return -1;
  }

  if (CRYPT_EAL_CipherInit(ctx, key, (uint32_t)crypto_aead_keylen(aead),
                           zero_iv, sizeof(zero_iv), false) != CRYPT_SUCCESS) {
    CRYPT_EAL_CipherFreeCtx(ctx);
    return -1;
  }

  aead_ctx->native_handle = ctx;
  return 0;
}

void ngtcp2_crypto_aead_ctx_free(ngtcp2_crypto_aead_ctx *aead_ctx) {
  if (aead_ctx->native_handle) {
    CRYPT_EAL_CipherFreeCtx(aead_ctx->native_handle);
    aead_ctx->native_handle = NULL;
  }
}

typedef struct crypto_hitls_cipher_ctx {
  CRYPT_EAL_CipherCtx *cipher_ctx;
  crypto_hitls_cipher_type type;
} crypto_hitls_cipher_ctx;

int ngtcp2_crypto_cipher_ctx_encrypt_init(ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                          const ngtcp2_crypto_cipher *cipher,
                                          const uint8_t *key) {
  crypto_hitls_cipher *hp_cipher = cipher->native_handle;
  crypto_hitls_cipher_ctx *ctx;
  CRYPT_CIPHER_AlgId alg;
  size_t keylen;
  static const uint8_t zero_iv[16] = {0};

  switch (hp_cipher->type) {
  case CRYPTO_HITLS_CIPHER_TYPE_AES_128:
    alg = CRYPT_CIPHER_AES128_ECB;
    keylen = 16;
    break;
  case CRYPTO_HITLS_CIPHER_TYPE_AES_256:
    alg = CRYPT_CIPHER_AES256_ECB;
    keylen = 32;
    break;
  case CRYPTO_HITLS_CIPHER_TYPE_CHACHA20:
    alg = CRYPT_CIPHER_CHACHA20;
    keylen = 32;
    break;
  default:
    return -1;
  }

  ctx = malloc(sizeof(*ctx));
  if (ctx == NULL) {
    return -1;
  }

  ctx->type = hp_cipher->type;
  ctx->cipher_ctx = CRYPT_EAL_CipherNewCtx(alg);
  if (ctx->cipher_ctx == NULL) {
    free(ctx);
    return -1;
  }

  if (CRYPT_EAL_CipherInit(ctx->cipher_ctx, key, (uint32_t)keylen, zero_iv,
                           sizeof(zero_iv), true) != CRYPT_SUCCESS) {
    CRYPT_EAL_CipherFreeCtx(ctx->cipher_ctx);
    free(ctx);
    return -1;
  }

  cipher_ctx->native_handle = ctx;
  return 0;
}

void ngtcp2_crypto_cipher_ctx_free(ngtcp2_crypto_cipher_ctx *cipher_ctx) {
  crypto_hitls_cipher_ctx *ctx = cipher_ctx->native_handle;
  if (ctx == NULL) {
    return;
  }

  CRYPT_EAL_CipherFreeCtx(ctx->cipher_ctx);
  free(ctx);
  cipher_ctx->native_handle = NULL;
}

int ngtcp2_crypto_hkdf_extract(uint8_t *dest, const ngtcp2_crypto_md *md,
                               const uint8_t *secret, size_t secretlen,
                               const uint8_t *salt, size_t saltlen) {
  HITLS_HashAlgo hash_algo = (HITLS_HashAlgo)(uintptr_t)md->native_handle;
  CRYPT_EAL_KdfCtx *kdf;
  CRYPT_MAC_AlgId mac_id = crypto_hash_to_mac_id(hash_algo);
  CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_EXTRACT;
  uint32_t outlen = (uint32_t)crypto_md_hashlen(md);
  BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
  int rv = -1;

  if (mac_id == (CRYPT_MAC_AlgId)BSL_CID_UNKNOWN) {
    return -1;
  }

  kdf = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
  if (kdf == NULL) {
    return -1;
  }

  if (BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID,
                          BSL_PARAM_TYPE_UINT32, &mac_id, sizeof(mac_id)) !=
        CRYPT_SUCCESS ||
      BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE,
                          BSL_PARAM_TYPE_UINT32, &mode, sizeof(mode)) !=
        CRYPT_SUCCESS ||
      BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY,
                          BSL_PARAM_TYPE_OCTETS, (void *)secret,
                          (uint32_t)secretlen) != CRYPT_SUCCESS ||
      BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT,
                          BSL_PARAM_TYPE_OCTETS, (void *)salt,
                          (uint32_t)saltlen) != CRYPT_SUCCESS ||
      BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_EXLEN,
                          BSL_PARAM_TYPE_UINT32_PTR, &outlen,
                          sizeof(outlen)) != CRYPT_SUCCESS) {
    goto fail;
  }

  if (CRYPT_EAL_KdfSetParam(kdf, params) != CRYPT_SUCCESS ||
      CRYPT_EAL_KdfDerive(kdf, dest, outlen) != CRYPT_SUCCESS) {
    goto fail;
  }

  rv = 0;

fail:
  CRYPT_EAL_KdfFreeCtx(kdf);
  return rv;
}

int ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen,
                              const ngtcp2_crypto_md *md, const uint8_t *secret,
                              size_t secretlen, const uint8_t *info,
                              size_t infolen) {
  HITLS_HashAlgo hash_algo = (HITLS_HashAlgo)(uintptr_t)md->native_handle;
  CRYPT_EAL_KdfCtx *kdf;
  CRYPT_MAC_AlgId mac_id = crypto_hash_to_mac_id(hash_algo);
  CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_EXPAND;
  BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
  int rv = -1;

  if (mac_id == (CRYPT_MAC_AlgId)BSL_CID_UNKNOWN) {
    return -1;
  }

  kdf = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
  if (kdf == NULL) {
    return -1;
  }

  if (BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID,
                          BSL_PARAM_TYPE_UINT32, &mac_id, sizeof(mac_id)) !=
        CRYPT_SUCCESS ||
      BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE,
                          BSL_PARAM_TYPE_UINT32, &mode, sizeof(mode)) !=
        CRYPT_SUCCESS ||
      BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_PRK,
                          BSL_PARAM_TYPE_OCTETS, (void *)secret,
                          (uint32_t)secretlen) != CRYPT_SUCCESS ||
      BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_INFO,
                          BSL_PARAM_TYPE_OCTETS, (void *)info,
                          (uint32_t)infolen) != CRYPT_SUCCESS) {
    goto fail;
  }

  if (CRYPT_EAL_KdfSetParam(kdf, params) != CRYPT_SUCCESS ||
      CRYPT_EAL_KdfDerive(kdf, dest, (uint32_t)destlen) != CRYPT_SUCCESS) {
    goto fail;
  }

  rv = 0;

fail:
  CRYPT_EAL_KdfFreeCtx(kdf);
  return rv;
}

int ngtcp2_crypto_hkdf(uint8_t *dest, size_t destlen,
                       const ngtcp2_crypto_md *md, const uint8_t *secret,
                       size_t secretlen, const uint8_t *salt, size_t saltlen,
                       const uint8_t *info, size_t infolen) {
  HITLS_HashAlgo hash_algo = (HITLS_HashAlgo)(uintptr_t)md->native_handle;
  CRYPT_EAL_KdfCtx *kdf;
  CRYPT_MAC_AlgId mac_id = crypto_hash_to_mac_id(hash_algo);
  CRYPT_HKDF_MODE mode = CRYPT_KDF_HKDF_MODE_FULL;
  BSL_Param params[6] = {{0}, {0}, {0}, {0}, {0}, BSL_PARAM_END};
  int rv = -1;

  if (mac_id == (CRYPT_MAC_AlgId)BSL_CID_UNKNOWN) {
    return -1;
  }

  kdf = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
  if (kdf == NULL) {
    return -1;
  }

  if (BSL_PARAM_InitValue(&params[0], CRYPT_PARAM_KDF_MAC_ID,
                          BSL_PARAM_TYPE_UINT32, &mac_id, sizeof(mac_id)) !=
        CRYPT_SUCCESS ||
      BSL_PARAM_InitValue(&params[1], CRYPT_PARAM_KDF_MODE,
                          BSL_PARAM_TYPE_UINT32, &mode, sizeof(mode)) !=
        CRYPT_SUCCESS ||
      BSL_PARAM_InitValue(&params[2], CRYPT_PARAM_KDF_KEY,
                          BSL_PARAM_TYPE_OCTETS, (void *)secret,
                          (uint32_t)secretlen) != CRYPT_SUCCESS ||
      BSL_PARAM_InitValue(&params[3], CRYPT_PARAM_KDF_SALT,
                          BSL_PARAM_TYPE_OCTETS, (void *)salt,
                          (uint32_t)saltlen) != CRYPT_SUCCESS ||
      BSL_PARAM_InitValue(&params[4], CRYPT_PARAM_KDF_INFO,
                          BSL_PARAM_TYPE_OCTETS, (void *)info,
                          (uint32_t)infolen) != CRYPT_SUCCESS) {
    goto fail;
  }

  if (CRYPT_EAL_KdfSetParam(kdf, params) != CRYPT_SUCCESS ||
      CRYPT_EAL_KdfDerive(kdf, dest, (uint32_t)destlen) != CRYPT_SUCCESS) {
    goto fail;
  }

  rv = 0;

fail:
  CRYPT_EAL_KdfFreeCtx(kdf);
  return rv;
}

/* AEAD encrypt: dest = seal(nonce, aad, plaintext) || tag.
   The openHiTLS AEAD interface appends the tag after the ciphertext. */
int ngtcp2_crypto_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen) {
  CRYPT_EAL_CipherCtx *ctx = aead_ctx->native_handle;
  uint32_t outlen = (uint32_t)(plaintextlen + aead->max_overhead);
  uint32_t taglen = 16;
  int32_t ret;

  (void)noncelen;

  ret = CRYPT_EAL_CipherReinit(ctx, (uint8_t *)nonce, 12);
  if (ret != CRYPT_SUCCESS) {
    return -1;
  }

  ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, (void *)aad,
                             (uint32_t)aadlen);
  if (ret != CRYPT_SUCCESS) {
    return -1;
  }

  ret = CRYPT_EAL_CipherUpdate(ctx, plaintext, (uint32_t)plaintextlen, dest,
                               &outlen);
  if (ret != CRYPT_SUCCESS) {
    return -1;
  }

  ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_GET_TAG, dest + outlen, taglen);
  if (ret != CRYPT_SUCCESS) {
    return -1;
  }

  return 0;
}

/* AEAD decrypt: the openHiTLS AEAD interface requires the expected tag
   to be set, then verified by CipherFinal. */
int ngtcp2_crypto_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen) {
  CRYPT_EAL_CipherCtx *ctx = aead_ctx->native_handle;
  const uint8_t *tag;
  size_t plainlen;
  uint32_t outlen;
  int32_t ret;

  (void)noncelen;

  if (ciphertextlen < aead->max_overhead) {
    return -1;
  }

  plainlen = ciphertextlen - aead->max_overhead;
  tag = ciphertext + plainlen;

  ret = CRYPT_EAL_CipherReinit(ctx, (uint8_t *)nonce, 12);
  if (ret != CRYPT_SUCCESS) {
    return -1;
  }

  ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_AAD, (void *)aad,
                             (uint32_t)aadlen);
  if (ret != CRYPT_SUCCESS) {
    return -1;
  }

  outlen = (uint32_t)plainlen;
  ret = CRYPT_EAL_CipherUpdate(ctx, ciphertext, (uint32_t)plainlen, dest,
                               &outlen);
  if (ret != CRYPT_SUCCESS) {
    return -1;
  }

  ret = CRYPT_EAL_CipherCtrl(ctx, CRYPT_CTRL_SET_TAG, (void *)tag, 16);
  if (ret != CRYPT_SUCCESS) {
    return -1;
  }

  {
    uint32_t finlen = 0;
    ret = CRYPT_EAL_CipherFinal(ctx, dest + outlen, &finlen);
    if (ret != CRYPT_SUCCESS) {
      return -1;
    }
    outlen += finlen;
  }

  return 0;
}

/* Header protection mask:
   - AES: HP == AES-ECB(key, sample) (RFC 9001 s5.4.3).
   - ChaCha20: HP == raw ChaCha20(key, counter=sample[0..3],
     nonce=sample[4..15]) over 16 zero bytes (RFC 9001 s5.4.4). */
int ngtcp2_crypto_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                          const ngtcp2_crypto_cipher_ctx *hp_ctx,
                          const uint8_t *sample) {
  static const uint8_t PLAINTEXT[16] = {0};
  crypto_hitls_cipher_ctx *ctx = hp_ctx->native_handle;
  uint32_t outlen = 16;
  int32_t ret;

  (void)hp;

  switch (ctx->type) {
  case CRYPTO_HITLS_CIPHER_TYPE_AES_128:
  case CRYPTO_HITLS_CIPHER_TYPE_AES_256:
    /* AES HP == AES-ECB(key, sample).  The sample is exactly one AES block
       and ECB with padding disabled emits it directly from CipherUpdate, so
       no CipherFinal is needed.  Calling it would flip the openHiTLS EAL
       state to FINAL, which would make the next CipherUpdate fail with
       CRYPT_EAL_ERR_STATE (the hp_ctx is reused for every packet header). */
    ret = CRYPT_EAL_CipherUpdate(ctx->cipher_ctx, sample,
                                 NGTCP2_HP_SAMPLELEN, dest, &outlen);
    if (ret != CRYPT_SUCCESS) {
      return -1;
    }

    return 0;

  case CRYPTO_HITLS_CIPHER_TYPE_CHACHA20: {
    uint8_t nonce[12];
    uint8_t counter[4];
    uint32_t counter32;

    memcpy(counter, sample, sizeof(counter));
    memcpy(&counter32, counter, sizeof(counter32));
    memcpy(nonce, sample + 4, sizeof(nonce));

    ret = CRYPT_EAL_CipherCtrl(ctx->cipher_ctx, CRYPT_CTRL_SET_COUNT,
                               &counter32, sizeof(counter32));
    if (ret != CRYPT_SUCCESS) {
      return -1;
    }

    ret = CRYPT_EAL_CipherReinit(ctx->cipher_ctx, nonce, sizeof(nonce));
    if (ret != CRYPT_SUCCESS) {
      return -1;
    }

    ret = CRYPT_EAL_CipherUpdate(ctx->cipher_ctx, PLAINTEXT,
                                 sizeof(PLAINTEXT), dest, &outlen);
    if (ret != CRYPT_SUCCESS) {
      return -1;
    }

    return 0;
  }

  default:
    return -1;
  }
}

/*
 * openHiTLS may report an underlying TLS alert before returning the
 * authoritative HITLS_QUIC_TLS_PROTOCOL_VIOLATION.  NGTCP2_ERR_PROTO
 * overrides that staged alert so the final close uses the QUIC transport
 * error PROTOCOL_VIOLATION (0x000a), not CRYPTO_ERROR.
 */
static void crypto_hitls_set_transport_error(ngtcp2_conn *conn,
                                             int32_t ret) {
  if (ret == HITLS_QUIC_TLS_PROTOCOL_VIOLATION) {
    ngtcp2_conn_set_tls_error(conn, NGTCP2_ERR_PROTO);
  }
}

int ngtcp2_crypto_read_write_crypto_data(
  ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level,
  const uint8_t *data, size_t datalen) {
  HITLS_Ctx *ctx = ngtcp2_conn_get_tls_native_handle2(conn);
  HITLS_QUIC_TLS_EncryptionLevel level =
    ngtcp2_crypto_hitls_from_ngtcp2_encryption_level(encryption_level);
  int32_t ret;
  uint8_t handshake_done;

  if (datalen) {
    ret = HITLS_QUIC_TLS_ProvideData(ctx, level, data, datalen);
    if (ret != HITLS_SUCCESS) {
      crypto_hitls_set_transport_error(conn, ret);
      return -1;
    }
  }

  if (!ngtcp2_conn_get_handshake_completed2(conn)) {
    ret = ngtcp2_conn_is_server2(conn) ? HITLS_Accept(ctx) : HITLS_Connect(ctx);
    if (ret != HITLS_SUCCESS && ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY &&
        ret != HITLS_REC_NORMAL_IO_BUSY) {
      crypto_hitls_set_transport_error(conn, ret);
      return -1;
    }

    if (HITLS_IsHandShakeDone(ctx, &handshake_done) == HITLS_SUCCESS &&
        handshake_done) {
      ngtcp2_conn_tls_handshake_completed(conn);
    }

    return 0;
  }

  ret = HITLS_QUIC_TLS_ProcessPostHandshake(ctx);
  if (ret != HITLS_SUCCESS && ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY) {
    crypto_hitls_set_transport_error(conn, ret);
    return -1;
  }

  return 0;
}

int ngtcp2_crypto_set_remote_transport_params(ngtcp2_conn *conn, void *tls) {
  const uint8_t *tp;
  size_t tplen;
  int rv;

  if (HITLS_QUIC_TLS_GetPeerTransportParams(tls, &tp, &tplen) != HITLS_SUCCESS) {
    return -1;
  }

  if (tp == NULL) {
    return 0;
  }

  rv = ngtcp2_conn_decode_and_set_remote_transport_params(conn, tp, tplen);
  if (rv != 0) {
    ngtcp2_conn_set_tls_error(conn, rv);
    return -1;
  }

  return 0;
}

int ngtcp2_crypto_set_local_transport_params(void *tls, const uint8_t *buf,
                                             size_t len) {
  if (HITLS_QUIC_TLS_SetTransportParams(tls, buf, len) != HITLS_SUCCESS) {
    return -1;
  }

  return 0;
}

ngtcp2_encryption_level ngtcp2_crypto_hitls_from_hitls_encryption_level(
  HITLS_QUIC_TLS_EncryptionLevel level) {
  switch (level) {
  case HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL:
    return NGTCP2_ENCRYPTION_LEVEL_INITIAL;
  case HITLS_QUIC_TLS_ENCRYPTION_LEVEL_EARLY_DATA:
    return NGTCP2_ENCRYPTION_LEVEL_0RTT;
  case HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE:
    return NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE;
  case HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION:
    return NGTCP2_ENCRYPTION_LEVEL_1RTT;
  default:
    assert(0);
    abort();
  }
}

HITLS_QUIC_TLS_EncryptionLevel ngtcp2_crypto_hitls_from_ngtcp2_encryption_level(
  ngtcp2_encryption_level encryption_level) {
  switch (encryption_level) {
  case NGTCP2_ENCRYPTION_LEVEL_INITIAL:
    return HITLS_QUIC_TLS_ENCRYPTION_LEVEL_INITIAL;
  case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
    return HITLS_QUIC_TLS_ENCRYPTION_LEVEL_HANDSHAKE;
  case NGTCP2_ENCRYPTION_LEVEL_1RTT:
    return HITLS_QUIC_TLS_ENCRYPTION_LEVEL_APPLICATION;
  case NGTCP2_ENCRYPTION_LEVEL_0RTT:
    return HITLS_QUIC_TLS_ENCRYPTION_LEVEL_EARLY_DATA;
  default:
    assert(0);
    abort();
  }
}

int ngtcp2_crypto_get_path_challenge_data_cb(ngtcp2_conn *conn, uint8_t *data,
                                             void *user_data) {
  (void)conn;
  (void)user_data;

  if (CRYPT_EAL_Randbytes(data, NGTCP2_PATH_CHALLENGE_DATALEN) !=
      CRYPT_SUCCESS) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

int ngtcp2_crypto_get_path_challenge_data2_cb(ngtcp2_conn *conn,
                                              ngtcp2_path_challenge_data *data,
                                              void *user_data) {
  (void)conn;
  (void)user_data;

  if (CRYPT_EAL_Randbytes(data->data, NGTCP2_PATH_CHALLENGE_DATALEN) !=
      CRYPT_SUCCESS) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

int ngtcp2_crypto_random(uint8_t *data, size_t datalen) {
  static int rand_ready = 0;

  /* The openHiTLS crypto EAL is initialized at load time without the RNG
     module (the constructor only enables CPU and provider init).  Initialize
     the RNG once, on first use, so that applications that only link this
     backend do not have to call CRYPT_EAL_Init themselves. */
  if (!rand_ready) {
    if (CRYPT_EAL_Init(CRYPT_EAL_INIT_RAND) != CRYPT_SUCCESS) {
      return -1;
    }
    rand_ready = 1;
  }

  if (datalen > UINT32_MAX ||
      CRYPT_EAL_Randbytes(data, (uint32_t)datalen) != CRYPT_SUCCESS) {
    return -1;
  }

  return 0;
}

static int set_read_secret(HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level,
                           const HITLS_Cipher *cipher, const uint8_t *secret,
                           size_t secretlen, void *arg) {
  ngtcp2_crypto_conn_ref *conn_ref = HITLS_GetUserData(ctx);
  ngtcp2_conn *conn;
  ngtcp2_encryption_level ngtcp2_level =
    ngtcp2_crypto_hitls_from_hitls_encryption_level(level);

  (void)cipher;
  (void)arg;

  if (!conn_ref) {
    return HITLS_REC_CB_FAIL;
  }

  conn = conn_ref->get_conn(conn_ref);

  if (ngtcp2_crypto_derive_and_install_rx_key(conn, NULL, NULL, NULL,
                                              ngtcp2_level, secret,
                                              secretlen) != 0) {
    return HITLS_REC_CB_FAIL;
  }

  return HITLS_SUCCESS;
}

static int set_write_secret(HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level,
                            const HITLS_Cipher *cipher, const uint8_t *secret,
                            size_t secretlen, void *arg) {
  ngtcp2_crypto_conn_ref *conn_ref = HITLS_GetUserData(ctx);
  ngtcp2_conn *conn;
  ngtcp2_encryption_level ngtcp2_level =
    ngtcp2_crypto_hitls_from_hitls_encryption_level(level);

  (void)cipher;
  (void)arg;

  if (!conn_ref) {
    return HITLS_REC_CB_FAIL;
  }

  conn = conn_ref->get_conn(conn_ref);

  if (ngtcp2_crypto_derive_and_install_tx_key(conn, NULL, NULL, NULL,
                                              ngtcp2_level, secret,
                                              secretlen) != 0) {
    return HITLS_REC_CB_FAIL;
  }

  return HITLS_SUCCESS;
}

static int add_handshake_data(HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level,
                              const uint8_t *data, size_t datalen, void *arg) {
  ngtcp2_crypto_conn_ref *conn_ref = HITLS_GetUserData(ctx);
  ngtcp2_conn *conn;
  ngtcp2_encryption_level ngtcp2_level =
    ngtcp2_crypto_hitls_from_hitls_encryption_level(level);
  int rv;

  (void)arg;

  if (!conn_ref) {
    return HITLS_REC_CB_FAIL;
  }

  conn = conn_ref->get_conn(conn_ref);

  rv = ngtcp2_conn_submit_crypto_data(conn, ngtcp2_level, data, datalen);
  if (rv != 0) {
    ngtcp2_conn_set_tls_error(conn, rv);
    return HITLS_REC_CB_FAIL;
  }

  return HITLS_SUCCESS;
}

static int flush_flight(HITLS_Ctx *ctx, void *arg) {
  (void)ctx;
  (void)arg;
  return HITLS_SUCCESS;
}

static int send_alert(HITLS_Ctx *ctx, HITLS_QUIC_TLS_EncryptionLevel level,
                      uint8_t alert, void *arg) {
  ngtcp2_crypto_conn_ref *conn_ref = HITLS_GetUserData(ctx);
  ngtcp2_conn *conn;

  (void)level;
  (void)arg;

  if (!conn_ref) {
    return HITLS_SUCCESS;
  }

  conn = conn_ref->get_conn(conn_ref);

  ngtcp2_conn_set_tls_alert(conn, alert);

  return HITLS_SUCCESS;
}

static const HITLS_QUIC_TLS_Callbacks quic_method[] = {
  {HITLS_QUIC_TLS_FUNC_SET_READ_SECRET, (void *)set_read_secret},
  {HITLS_QUIC_TLS_FUNC_SET_WRITE_SECRET, (void *)set_write_secret},
  {HITLS_QUIC_TLS_FUNC_ADD_HANDSHAKE_DATA, (void *)add_handshake_data},
  {HITLS_QUIC_TLS_FUNC_FLUSH_FLIGHT, (void *)flush_flight},
  {HITLS_QUIC_TLS_FUNC_SEND_ALERT, (void *)send_alert},
  HITLS_QUIC_TLS_CALLBACKS_END,
};

static int crypto_hitls_configure_session(HITLS_Ctx *ssl) {
  if (HITLS_QUIC_TLS_SetQuicTlsMethod(ssl, quic_method, NULL) !=
      HITLS_SUCCESS) {
    return -1;
  }

  return 0;
}

int ngtcp2_crypto_hitls_configure_server_session(HITLS_Ctx *ssl) {
  return crypto_hitls_configure_session(ssl);
}

int ngtcp2_crypto_hitls_configure_client_session(HITLS_Ctx *ssl) {
  return crypto_hitls_configure_session(ssl);
}

static int crypto_hitls_configure_version(HITLS_Config *config) {
  if (HITLS_CFG_SetVersion(config, HITLS_VERSION_TLS13, HITLS_VERSION_TLS13) !=
      HITLS_SUCCESS) {
    return -1;
  }

  return 0;
}

int ngtcp2_crypto_hitls_configure_server_config(HITLS_Config *config) {
  return crypto_hitls_configure_version(config);
}

int ngtcp2_crypto_hitls_configure_client_config(HITLS_Config *config) {
  return crypto_hitls_configure_version(config);
}
