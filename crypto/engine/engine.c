/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/engine.h>

#include <string.h>
#include <assert.h>

#include <openssl/ec_key.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/rsa.h>
#include <openssl/thread.h>

#include "../internal.h"


struct engine_st {
  RSA_METHOD *rsa_method;
  union {
      ECDSA_METHOD *ecdsa_method;
      EC_KEY_METHOD *eckey_method;
  } eckey_type;
};

ENGINE *ENGINE_new(void) { return OPENSSL_zalloc(sizeof(ENGINE)); }

int ENGINE_free(ENGINE *engine) {
  // Methods are currently required to be static so are not unref'ed.
  OPENSSL_free(engine);
  return 1;
}

// set_method takes a pointer to a method and its given size and sets
// |*out_member| to point to it. This function might want to be extended in the
// future to support making a copy of the method so that a stable ABI for
// ENGINEs can be supported. But, for the moment, all *_METHODS must be
// static.
static int set_method(void **out_member, const void *method, size_t method_size,
                      size_t compiled_size) {
  const struct openssl_method_common_st *common = method;
  if (method_size != compiled_size || !common->is_static) {
    return 0;
  }

  *out_member = (void*) method;
  return 1;
}

int ENGINE_set_RSA_method(ENGINE *engine, const RSA_METHOD *method,
                         size_t method_size) {
  return set_method((void **)&engine->rsa_method, method, method_size,
                    sizeof(RSA_METHOD));
}

RSA_METHOD *ENGINE_get_RSA_method(const ENGINE *engine) {
  return engine->rsa_method;
}

int ENGINE_set_ECDSA_method(ENGINE *engine, const ECDSA_METHOD *method,
                            size_t method_size) {
  // Only one custom implementation may be defined per ENGINE for an EC_KEY
  if(engine->eckey_type.eckey_method) {
    OPENSSL_PUT_ERROR(engine, ENGINE_R_OPERATION_NOT_SUPPORTED);
    return 0;
  }

  return set_method((void **)&engine->eckey_type.ecdsa_method, method,
                    method_size, sizeof(ECDSA_METHOD));
}

ECDSA_METHOD *ENGINE_get_ECDSA_method(const ENGINE *engine) {
  if(engine->eckey_type.eckey_method) {
    OPENSSL_PUT_ERROR(engine, ENGINE_R_OPERATION_NOT_SUPPORTED);
    return 0;
  }

  return engine->eckey_type.ecdsa_method;
}

// We don't take in a user defined size for this method, so default is passed in
int ENGINE_set_EC(ENGINE *engine, const EC_KEY_METHOD *method) {
  // Only one custom implementation may be defined per ENGINE for an EC_KEY
  if(engine->eckey_type.ecdsa_method) {
    OPENSSL_PUT_ERROR(engine, ENGINE_R_OPERATION_NOT_SUPPORTED);
    return 0;
  }

  return set_method((void **)&engine->eckey_type.eckey_method, method,
                    sizeof(EC_KEY_METHOD), sizeof(EC_KEY_METHOD));
}

const EC_KEY_METHOD *ENGINE_get_EC(const ENGINE *engine) {
  if(engine->eckey_type.ecdsa_method) {
    OPENSSL_PUT_ERROR(engine, ENGINE_R_OPERATION_NOT_SUPPORTED);
    return 0;
  }

  return engine->eckey_type.eckey_method;
}

void METHOD_ref(void *method_in) {
  assert(((struct openssl_method_common_st*) method_in)->is_static);
}

void METHOD_unref(void *method_in) {
  struct openssl_method_common_st *method = method_in;

  if (method == NULL) {
    return;
  }
  assert(method->is_static);
}

OPENSSL_DECLARE_ERROR_REASON(ENGINE, OPERATION_NOT_SUPPORTED)

void ENGINE_cleanup(void) {}
