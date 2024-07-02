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
  // Changed to EC_KEY_METHOD
  EC_KEY_METHOD *ecdsa_method;
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

// memory Ownership issue here. Do we free passed in ECDSA_METHOD which will
// create behavioral change since users could technically still access the method
// when references were passed in before. Or change contract to make
// consumer free the object.
int ENGINE_set_ECDSA_method(ENGINE *engine, const ECDSA_METHOD *method,
                            size_t method_size) {

  // Refactor to EC_KEY_METHOD and then set
  EC_KEY_METHOD *ret = OPENSSL_zalloc(sizeof(EC_KEY_METHOD));

  ret->common = method->common;

  ret->init = method->init;
  ret->finish = method->finish;
  ret->sign = method->sign;
  ret->group_order_size = method->group_order_size;
  ret->app_data = method->app_data;
  ret->flags = method->flags;

  return set_method((void **)&engine->ecdsa_method, ret, method_size,
                    sizeof(EC_KEY_METHOD));
}

// Will we have to change the function contract since now we are allocating
// and returning a new struct but before memory was automatically managed
// as a part of the engine object???
ECDSA_METHOD *ENGINE_get_ECDSA_method(const ENGINE *engine) {
  // Refactor from EC_KEY_METHOD and then return
  ECDSA_METHOD *ret = OPENSSL_zalloc(sizeof(ECDSA_METHOD));

  ret->common = engine->ecdsa_method->common;

  ret->init = engine->ecdsa_method->init;
  ret->finish = engine->ecdsa_method->finish;
  ret->sign = engine->ecdsa_method->sign;
  ret->group_order_size = engine->ecdsa_method->group_order_size;
  ret->app_data = engine->ecdsa_method->app_data;
  ret->flags = engine->ecdsa_method->flags;

  return ret;
}

int ENGINE_set_EC_KEY_METHOD(ENGINE *engine, const EC_KEY_METHOD *method,
                                            size_t method_size) {
  return set_method((void **)&engine->ecdsa_method, method, method_size,
                    sizeof(EC_KEY_METHOD));
}

EC_KEY_METHOD *ENGINE_get_EC_KEY_METHOD(const ENGINE *engine) {
  return engine->ecdsa_method;
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
