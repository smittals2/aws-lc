// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "internal.h"

#define TLS1_PRF_MAXBUF 1024

/* TLS KDF pkey context structure */
typedef struct {
    /* Digest to use for PRF */
    const EVP_MD *md;
    /* Secret value to use for PRF */
    uint8_t *sec;
    size_t sec_len;
    /* Buffer of concatenated seed data */
    uint8_t seed[TLS1_PRF_MAXBUF];
    size_t seed_len;
} TLS1_PRF_PKEY_CTX;

static int pkey_tls1_prf_init(EVP_PKEY_CTX *ctx) {
  TLS1_PRF_PKEY_CTX *kctx;

  if(ctx == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_MISSING_PARAMETERS);
    return 0;
  }

  kctx = OPENSSL_zalloc(sizeof(*kctx));
  if (kctx == NULL) {
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  ctx->data = kctx;
  return 1;
}

static void pkey_tls1_prf_cleanup(EVP_PKEY_CTX *ctx) {
  TLS1_PRF_PKEY_CTX *kctx = ctx->data;
  if(kctx != NULL) {
    OPENSSL_free(kctx->sec);
    OPENSSL_memset(kctx->seed, 0, kctx->seed_len);
    OPENSSL_free(kctx);
    ctx->data = NULL;
  }
}

static int pkey_tls1_prf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
  TLS1_PRF_PKEY_CTX *kctx = ctx->data;

  switch (type) {
    case EVP_PKEY_CTRL_TLS_MD:
      kctx->md = p2;
      return 1;

    case EVP_PKEY_CTRL_TLS_SECRET: {
      if (p1 < 0) {
        return 0;
      }
      if (kctx->sec != NULL) {
        OPENSSL_free(kctx->sec);
      }
      OPENSSL_memset(kctx->seed, 0, kctx->seed_len);
      kctx->seed_len = 0;

      kctx->sec = OPENSSL_memdup(p2, p1);
      if (kctx->sec == NULL) {
        return 0;
      }
      kctx->sec_len = p1;
      return 1;
    }
    case EVP_PKEY_CTRL_TLS_SEED: {
      if (p1 == 0 || p2 == NULL) {
        return 1;
      }
      if (p1 < 0 || p1 > (int)(TLS1_PRF_MAXBUF - kctx->seed_len)) {
        return 0;
      }
      OPENSSL_memcpy(kctx->seed + kctx->seed_len, p2, p1);
      kctx->seed_len += p1;
      return 1;
    }
    default:
      OPENSSL_PUT_ERROR(EVP, EVP_R_COMMAND_NOT_SUPPORTED);
      return 0;
  }
}

static int pkey_tls1_prf_derive(EVP_PKEY_CTX *ctx, uint8_t *out,
                                size_t *out_len) {
  TLS1_PRF_PKEY_CTX *kctx = ctx->data;
  if (kctx->md == NULL || kctx->sec == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_MISSING_PARAMETERS);
    return 0;
  }
  if(kctx->seed <= 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_BUFFER_TOO_SMALL);
    return 0;
  }

  return CRYPTO_tls1_prf(kctx->md, out, *out_len, kctx->sec, kctx->sec_len,
                      NULL, 0, kctx->seed, kctx->seed_len, NULL, 0);
}

DEFINE_METHOD_FUNCTION(EVP_PKEY_METHOD, EVP_PKEY_tls1_prf_pkey_meth) {
  out->pkey_id = EVP_PKEY_TLS1_PRF;
  out->init = pkey_tls1_prf_init;
  out->copy = NULL;
  out->cleanup = pkey_tls1_prf_cleanup;
  out->keygen = NULL;
  out->sign_init = NULL;
  out->sign = NULL;
  out->sign_message = NULL;
  out->verify_init = NULL;
  out->verify = NULL;
  out->verify_message = NULL;
  out->verify_recover = NULL;
  out->encrypt = NULL;
  out->decrypt = NULL;
  out->derive = pkey_tls1_prf_derive;
  out->paramgen = NULL;
  out->ctrl = pkey_tls1_prf_ctrl;
}

int EVP_PKEY_CTX_set_tls1_prf_md(EVP_PKEY_CTX *pctx, const EVP_MD *md) {
  return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE,
                           EVP_PKEY_CTRL_TLS_MD, 0, (void *)md);
}

int EVP_PKEY_CTX_set1_tls1_prf_secret(EVP_PKEY_CTX *pctx, uint8_t *sec,
                                      int sec_len) {
  return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE,
                           EVP_PKEY_CTRL_TLS_SECRET, sec_len, (void *)sec);
}

int EVP_PKEY_CTX_add1_tls1_prf_seed(EVP_PKEY_CTX *pctx, uint8_t *seed,
                                    int seed_len) {
  return EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE,
                           EVP_PKEY_CTRL_TLS_SEED, seed_len, (void *)seed);
}
