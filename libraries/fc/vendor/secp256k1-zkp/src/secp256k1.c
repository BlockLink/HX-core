/**********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include "include/secp256k1.h"
#include "include/secp256k1_recovery.h"

#include "util.h"
#include "num_impl.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "ecmult_impl.h"
#include "ecmult_const_impl.h"
#include "ecmult_gen_impl.h"
#include "ecdsa_impl.h"
#include "eckey_impl.h"
#include "hash_impl.h"
#include "scratch_impl.h"
#include "rangeproof_impl.h"
#include "borromean_impl.h"

#define ARG_CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        secp256k1_callback_call(&ctx->illegal_callback, #cond); \
        return 0; \
    } \
} while(0)

static void default_illegal_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "[libsecp256k1] illegal argument: %s\n", str);
    abort();
}

static const secp256k1_callback default_illegal_callback = {
    default_illegal_callback_fn,
    NULL
};

static void default_error_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "[libsecp256k1] internal consistency check failed: %s\n", str);
    abort();
}

static const secp256k1_callback default_error_callback = {
    default_error_callback_fn,
    NULL
};


struct secp256k1_context_struct {
    secp256k1_ecmult_context ecmult_ctx;
    secp256k1_ecmult_gen_context ecmult_gen_ctx;
	secp256k1_ecmult_gen2_context ecmult_gen2_ctx;
	secp256k1_rangeproof_context_t rangeproof_ctx;
    secp256k1_callback illegal_callback;
    secp256k1_callback error_callback;
};

secp256k1_context* secp256k1_context_create(unsigned int flags) {
    secp256k1_context* ret = (secp256k1_context*)checked_malloc(&default_error_callback, sizeof(secp256k1_context));
    ret->illegal_callback = default_illegal_callback;
    ret->error_callback = default_error_callback;

    if (EXPECT((flags & SECP256K1_FLAGS_TYPE_MASK) != SECP256K1_FLAGS_TYPE_CONTEXT, 0)) {
            secp256k1_callback_call(&ret->illegal_callback,
                                    "Invalid flags");
            free(ret);
            return NULL;
    }

    secp256k1_ecmult_context_init(&ret->ecmult_ctx);
    secp256k1_ecmult_gen_context_init(&ret->ecmult_gen_ctx);

    if (flags & SECP256K1_FLAGS_BIT_CONTEXT_SIGN) {
        secp256k1_ecmult_gen_context_build(&ret->ecmult_gen_ctx, &ret->error_callback);
    }
    if (flags & SECP256K1_FLAGS_BIT_CONTEXT_VERIFY) {
        secp256k1_ecmult_context_build(&ret->ecmult_ctx, &ret->error_callback);
    }

    return ret;
}

secp256k1_context* secp256k1_context_clone(const secp256k1_context* ctx) {
    secp256k1_context* ret = (secp256k1_context*)checked_malloc(&ctx->error_callback, sizeof(secp256k1_context));
    ret->illegal_callback = ctx->illegal_callback;
    ret->error_callback = ctx->error_callback;
    secp256k1_ecmult_context_clone(&ret->ecmult_ctx, &ctx->ecmult_ctx, &ctx->error_callback);
    secp256k1_ecmult_gen_context_clone(&ret->ecmult_gen_ctx, &ctx->ecmult_gen_ctx, &ctx->error_callback);
    return ret;
}

void secp256k1_context_destroy(secp256k1_context* ctx) {
    if (ctx != NULL) {
        secp256k1_ecmult_context_clear(&ctx->ecmult_ctx);
        secp256k1_ecmult_gen_context_clear(&ctx->ecmult_gen_ctx);

        free(ctx);
    }
}

void secp256k1_context_set_illegal_callback(secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    if (fun == NULL) {
        fun = default_illegal_callback_fn;
    }
    ctx->illegal_callback.fn = fun;
    ctx->illegal_callback.data = data;
}

void secp256k1_context_set_error_callback(secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    if (fun == NULL) {
        fun = default_error_callback_fn;
    }
    ctx->error_callback.fn = fun;
    ctx->error_callback.data = data;
}

secp256k1_scratch_space* secp256k1_scratch_space_create(const secp256k1_context* ctx, size_t init_size, size_t max_size) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(max_size >= init_size);

    return secp256k1_scratch_create(&ctx->error_callback, init_size, max_size);
}

void secp256k1_scratch_space_destroy(secp256k1_scratch_space* scratch) {
    secp256k1_scratch_destroy(scratch);
}

static int secp256k1_pubkey_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_pubkey* pubkey) {
    if (sizeof(secp256k1_ge_storage) == 64) {
        /* When the secp256k1_ge_storage type is exactly 64 byte, use its
         * representation inside secp256k1_pubkey, as conversion is very fast.
         * Note that secp256k1_pubkey_save must use the same representation. */
        secp256k1_ge_storage s;
        memcpy(&s, &pubkey->data[0], sizeof(s));
        secp256k1_ge_from_storage(ge, &s);
    } else {
        /* Otherwise, fall back to 32-byte big endian for X and Y. */
        secp256k1_fe x, y;
        secp256k1_fe_set_b32(&x, pubkey->data);
        secp256k1_fe_set_b32(&y, pubkey->data + 32);
        secp256k1_ge_set_xy(ge, &x, &y);
    }
    ARG_CHECK(!secp256k1_fe_is_zero(&ge->x));
    return 1;
}

static void secp256k1_pubkey_save(secp256k1_pubkey* pubkey, secp256k1_ge* ge) {
    if (sizeof(secp256k1_ge_storage) == 64) {
        secp256k1_ge_storage s;
        secp256k1_ge_to_storage(&s, ge);
        memcpy(&pubkey->data[0], &s, sizeof(s));
    } else {
        VERIFY_CHECK(!secp256k1_ge_is_infinity(ge));
        secp256k1_fe_normalize_var(&ge->x);
        secp256k1_fe_normalize_var(&ge->y);
        secp256k1_fe_get_b32(pubkey->data, &ge->x);
        secp256k1_fe_get_b32(pubkey->data + 32, &ge->y);
    }
}

int secp256k1_ec_pubkey_parse(const secp256k1_context* ctx, secp256k1_pubkey* pubkey, const unsigned char *input, size_t inputlen) {
    secp256k1_ge Q;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(input != NULL);
    if (!secp256k1_eckey_pubkey_parse(&Q, input, inputlen)) {
        return 0;
    }
    secp256k1_pubkey_save(pubkey, &Q);
    secp256k1_ge_clear(&Q);
    return 1;
}

int secp256k1_ec_pubkey_serialize(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_pubkey* pubkey, unsigned int flags) {
    secp256k1_ge Q;
    size_t len;
    int ret = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(outputlen != NULL);
    ARG_CHECK(*outputlen >= ((flags & SECP256K1_FLAGS_BIT_COMPRESSION) != 0 ? 33u : 65u));
    len = *outputlen;
    *outputlen = 0;
    ARG_CHECK(output != NULL);
    memset(output, 0, len);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK((flags & SECP256K1_FLAGS_TYPE_MASK) == SECP256K1_FLAGS_TYPE_COMPRESSION);
    if (secp256k1_pubkey_load(ctx, &Q, pubkey)) {
        ret = secp256k1_eckey_pubkey_serialize(&Q, output, &len, flags & SECP256K1_FLAGS_BIT_COMPRESSION);
        if (ret) {
            *outputlen = len;
        }
    }
    return ret;
}

static void secp256k1_ecdsa_signature_load(const secp256k1_context* ctx, secp256k1_scalar* r, secp256k1_scalar* s, const secp256k1_ecdsa_signature* sig) {
    (void)ctx;
    if (sizeof(secp256k1_scalar) == 32) {
        /* When the secp256k1_scalar type is exactly 32 byte, use its
         * representation inside secp256k1_ecdsa_signature, as conversion is very fast.
         * Note that secp256k1_ecdsa_signature_save must use the same representation. */
        memcpy(r, &sig->data[0], 32);
        memcpy(s, &sig->data[32], 32);
    } else {
        secp256k1_scalar_set_b32(r, &sig->data[0], NULL);
        secp256k1_scalar_set_b32(s, &sig->data[32], NULL);
    }
}

static void secp256k1_ecdsa_signature_save(secp256k1_ecdsa_signature* sig, const secp256k1_scalar* r, const secp256k1_scalar* s) {
    if (sizeof(secp256k1_scalar) == 32) {
        memcpy(&sig->data[0], r, 32);
        memcpy(&sig->data[32], s, 32);
    } else {
        secp256k1_scalar_get_b32(&sig->data[0], r);
        secp256k1_scalar_get_b32(&sig->data[32], s);
    }
}

int secp256k1_ecdsa_signature_parse_der(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
    secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input != NULL);

    if (secp256k1_ecdsa_sig_parse(&r, &s, input, inputlen)) {
        secp256k1_ecdsa_signature_save(sig, &r, &s);
        return 1;
    } else {
        memset(sig, 0, sizeof(*sig));
        return 0;
    }
}

int secp256k1_ecdsa_signature_parse_compact(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input64) {
    secp256k1_scalar r, s;
    int ret = 1;
    int overflow = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input64 != NULL);

    secp256k1_scalar_set_b32(&r, &input64[0], &overflow);
    ret &= !overflow;
    secp256k1_scalar_set_b32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret) {
        secp256k1_ecdsa_signature_save(sig, &r, &s);
    } else {
        memset(sig, 0, sizeof(*sig));
    }
    return ret;
}

int secp256k1_ecdsa_signature_serialize_der(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_ecdsa_signature* sig) {
    secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(outputlen != NULL);
    ARG_CHECK(sig != NULL);

    secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return secp256k1_ecdsa_sig_serialize(output, outputlen, &r, &s);
}

int secp256k1_ecdsa_signature_serialize_compact(const secp256k1_context* ctx, unsigned char *output64, const secp256k1_ecdsa_signature* sig) {
    secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output64 != NULL);
    ARG_CHECK(sig != NULL);

    secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    secp256k1_scalar_get_b32(&output64[0], &r);
    secp256k1_scalar_get_b32(&output64[32], &s);
    return 1;
}

int secp256k1_ecdsa_signature_normalize(const secp256k1_context* ctx, secp256k1_ecdsa_signature *sigout, const secp256k1_ecdsa_signature *sigin) {
    secp256k1_scalar r, s;
    int ret = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sigin != NULL);

    secp256k1_ecdsa_signature_load(ctx, &r, &s, sigin);
    ret = secp256k1_scalar_is_high(&s);
    if (sigout != NULL) {
        if (ret) {
            secp256k1_scalar_negate(&s, &s);
        }
        secp256k1_ecdsa_signature_save(sigout, &r, &s);
    }

    return ret;
}

int secp256k1_ecdsa_verify(const secp256k1_context* ctx, const secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pubkey) {
    secp256k1_ge q;
    secp256k1_scalar r, s;
    secp256k1_scalar m;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(pubkey != NULL);

    secp256k1_scalar_set_b32(&m, msg32, NULL);
    secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return (!secp256k1_scalar_is_high(&s) &&
            secp256k1_pubkey_load(ctx, &q, pubkey) &&
            secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &r, &s, &q, &m));
}

static SECP256K1_INLINE void buffer_append(unsigned char *buf, unsigned int *offset, const void *data, unsigned int len) {
    memcpy(buf + *offset, data, len);
    *offset += len;
}

static int nonce_function_rfc6979(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
   unsigned char keydata[112];
   unsigned int offset = 0;
   secp256k1_rfc6979_hmac_sha256 rng;
   unsigned int i;
   /* We feed a byte array to the PRNG as input, consisting of:
    * - the private key (32 bytes) and message (32 bytes), see RFC 6979 3.2d.
    * - optionally 32 extra bytes of data, see RFC 6979 3.6 Additional Data.
    * - optionally 16 extra bytes with the algorithm name.
    * Because the arguments have distinct fixed lengths it is not possible for
    *  different argument mixtures to emulate each other and result in the same
    *  nonces.
    */
   buffer_append(keydata, &offset, key32, 32);
   buffer_append(keydata, &offset, msg32, 32);
   if (data != NULL) {
       buffer_append(keydata, &offset, data, 32);
   }
   if (algo16 != NULL) {
       buffer_append(keydata, &offset, algo16, 16);
   }
   secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, offset);
   memset(keydata, 0, sizeof(keydata));
   for (i = 0; i <= counter; i++) {
       secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
   }
   secp256k1_rfc6979_hmac_sha256_finalize(&rng);
   return 1;
}

const secp256k1_nonce_function secp256k1_nonce_function_rfc6979 = nonce_function_rfc6979;
const secp256k1_nonce_function secp256k1_nonce_function_default = nonce_function_rfc6979;

int secp256k1_ecdsa_sign(const secp256k1_context* ctx, secp256k1_ecdsa_signature *signature, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void* noncedata) {
    secp256k1_scalar r, s;
    secp256k1_scalar sec, non, msg;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);
    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_default;
    }

    secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (!overflow && !secp256k1_scalar_is_zero(&sec)) {
        unsigned char nonce32[32];
        unsigned int count = 0;
        secp256k1_scalar_set_b32(&msg, msg32, NULL);
        while (1) {
            ret = noncefp(nonce32, msg32, seckey, NULL, (void*)noncedata, count);
            if (!ret) {
                break;
            }
            secp256k1_scalar_set_b32(&non, nonce32, &overflow);
            if (!overflow && !secp256k1_scalar_is_zero(&non)) {
                if (secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, &r, &s, &sec, &msg, &non, NULL)) {
                    break;
                }
            }
            count++;
        }
        memset(nonce32, 0, 32);
        secp256k1_scalar_clear(&msg);
        secp256k1_scalar_clear(&non);
        secp256k1_scalar_clear(&sec);
    }
    if (ret) {
        secp256k1_ecdsa_signature_save(signature, &r, &s);
    } else {
        memset(signature, 0, sizeof(*signature));
    }
    return ret;
}

int secp256k1_ecdsa_sign_compact(const secp256k1_context* ctx, const unsigned char *msg32, secp256k1_ecdsa_signature *signature, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void* noncedata, int *recid) {
	secp256k1_scalar r, s;
	secp256k1_scalar sec, non, msg;
	int ret = 0;
	int overflow = 0;
	VERIFY_CHECK(ctx != NULL);
	ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
	ARG_CHECK(msg32 != NULL);
	ARG_CHECK(signature != NULL);
	ARG_CHECK(seckey != NULL);
	if (noncefp == NULL) {
		noncefp = secp256k1_nonce_function_default;
	}

	secp256k1_scalar_set_b32(&sec, seckey, &overflow);
	/* Fail if the secret key is invalid. */
	if (!overflow && !secp256k1_scalar_is_zero(&sec)) {
		unsigned char nonce32[32];
		unsigned int count = 0;
		secp256k1_scalar_set_b32(&msg, msg32, NULL);
		while (1) {
			ret = noncefp(nonce32, msg32, seckey, NULL, (void*)noncedata, count);
			if (!ret) {
				break;
			}
			secp256k1_scalar_set_b32(&non, nonce32, &overflow);
			if (!overflow && !secp256k1_scalar_is_zero(&non)) {
				if (secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, &r, &s, &sec, &msg, &non, recid)) {
					break;
				}
			}
			count++;
		}
		memset(nonce32, 0, 32);
		secp256k1_scalar_clear(&msg);
		secp256k1_scalar_clear(&non);
		secp256k1_scalar_clear(&sec);
	}
	if (ret) {
		secp256k1_ecdsa_signature_save(signature, &r, &s);
	}
	else {
		memset(signature, 0, sizeof(*signature));
	}
	return ret;
}

int secp256k1_ec_seckey_verify(const secp256k1_context* ctx, const unsigned char *seckey) {
    secp256k1_scalar sec;
    int ret;
    int overflow;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);

    secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    ret = !overflow && !secp256k1_scalar_is_zero(&sec);
    secp256k1_scalar_clear(&sec);
    return ret;
}

int secp256k1_ec_pubkey_decompress(const secp256k1_context* ctx, unsigned char *pubkey, int *pubkeylen) {
	secp256k1_ge p;
	int ret = 0;
	ARG_CHECK(pubkey != NULL);
	ARG_CHECK(pubkeylen != NULL);
	(void)ctx;

	if (secp256k1_eckey_pubkey_parse(&p, pubkey, *pubkeylen)) {
		ret = secp256k1_eckey_pubkey_serialize(&p, pubkey, pubkeylen, 0);
	}
	return ret;
}

int secp256k1_ec_pubkey_create(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *seckey) {
    secp256k1_gej pj;
    secp256k1_ge p;
    secp256k1_scalar sec;
    int overflow;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(seckey != NULL);

    secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    ret = (!overflow) & (!secp256k1_scalar_is_zero(&sec));
    if (ret) {
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pj, &sec);
        secp256k1_ge_set_gej(&p, &pj);
        secp256k1_pubkey_save(pubkey, &p);
    }
    secp256k1_scalar_clear(&sec);
    return ret;
}

int secp256k1_ec_privkey_negate(const secp256k1_context* ctx, unsigned char *seckey) {
    secp256k1_scalar sec;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);

    secp256k1_scalar_set_b32(&sec, seckey, NULL);
    secp256k1_scalar_negate(&sec, &sec);
    secp256k1_scalar_get_b32(seckey, &sec);

    return 1;
}

int secp256k1_ec_pubkey_negate(const secp256k1_context* ctx, secp256k1_pubkey *pubkey) {
    int ret = 0;
    secp256k1_ge p;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);

    ret = secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        secp256k1_ge_neg(&p, &p);
        secp256k1_pubkey_save(pubkey, &p);
    }
    return ret;
}

int secp256k1_ec_privkey_tweak_add(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak) {
    secp256k1_scalar term;
    secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(tweak != NULL);

    secp256k1_scalar_set_b32(&term, tweak, &overflow);
    secp256k1_scalar_set_b32(&sec, seckey, NULL);

    ret = !overflow && secp256k1_eckey_privkey_tweak_add(&sec, &term);
    memset(seckey, 0, 32);
    if (ret) {
        secp256k1_scalar_get_b32(seckey, &sec);
    }

    secp256k1_scalar_clear(&sec);
    secp256k1_scalar_clear(&term);
    return ret;
}

int secp256k1_ec_pubkey_tweak_add(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *tweak) {
    secp256k1_ge p;
    secp256k1_scalar term;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(tweak != NULL);

    secp256k1_scalar_set_b32(&term, tweak, &overflow);
    ret = !overflow && secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        if (secp256k1_eckey_pubkey_tweak_add(&ctx->ecmult_ctx, &p, &term)) {
            secp256k1_pubkey_save(pubkey, &p);
        } else {
            ret = 0;
        }
    }

    return ret;
}

int secp256k1_ec_privkey_tweak_mul(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak) {
    secp256k1_scalar factor;
    secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(tweak != NULL);

    secp256k1_scalar_set_b32(&factor, tweak, &overflow);
    secp256k1_scalar_set_b32(&sec, seckey, NULL);
    ret = !overflow && secp256k1_eckey_privkey_tweak_mul(&sec, &factor);
    memset(seckey, 0, 32);
    if (ret) {
        secp256k1_scalar_get_b32(seckey, &sec);
    }

    secp256k1_scalar_clear(&sec);
    secp256k1_scalar_clear(&factor);
    return ret;
}

int secp256k1_ec_pubkey_tweak_mul(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *tweak) {
    secp256k1_ge p;
    secp256k1_scalar factor;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(tweak != NULL);

    secp256k1_scalar_set_b32(&factor, tweak, &overflow);
    ret = !overflow && secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        if (secp256k1_eckey_pubkey_tweak_mul(&ctx->ecmult_ctx, &p, &factor)) {
            secp256k1_pubkey_save(pubkey, &p);
        } else {
            ret = 0;
        }
    }

    return ret;
}

int secp256k1_context_randomize(secp256k1_context* ctx, const unsigned char *seed32) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    secp256k1_ecmult_gen_blind(&ctx->ecmult_gen_ctx, seed32);
    return 1;
}

int secp256k1_ec_pubkey_combine(const secp256k1_context* ctx, secp256k1_pubkey *pubnonce, const secp256k1_pubkey * const *pubnonces, size_t n) {
    size_t i;
    secp256k1_gej Qj;
    secp256k1_ge Q;

    ARG_CHECK(pubnonce != NULL);
    memset(pubnonce, 0, sizeof(*pubnonce));
    ARG_CHECK(n >= 1);
    ARG_CHECK(pubnonces != NULL);

    secp256k1_gej_set_infinity(&Qj);

    for (i = 0; i < n; i++) {
        secp256k1_pubkey_load(ctx, &Q, pubnonces[i]);
        secp256k1_gej_add_ge(&Qj, &Qj, &Q);
    }
    if (secp256k1_gej_is_infinity(&Qj)) {
        return 0;
    }
    secp256k1_ge_set_gej(&Q, &Qj);
    secp256k1_pubkey_save(pubnonce, &Q);
    return 1;
}

/* Generates a pedersen commitment: *commit = blind * G + value * G2. The commitment is 33 bytes, the blinding factor is 32 bytes.*/
int secp256k1_pedersen_commit(const secp256k1_context* ctx, unsigned char *commit, unsigned char *blind, uint64_t value) {
	secp256k1_gej rj;
	secp256k1_ge r;
	secp256k1_scalar sec;
	int sz;
	int overflow;
	int ret = 0;
	VERIFY_CHECK(ctx != NULL);
	VERIFY_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
	VERIFY_CHECK(secp256k1_ecmult_gen2_context_is_built(&ctx->ecmult_gen2_ctx));
	ARG_CHECK(commit != NULL);
	ARG_CHECK(blind != NULL);
	secp256k1_scalar_set_b32(&sec, blind, &overflow);
	if (!overflow) {
		secp256k1_ecmult_gen_gen2(&ctx->ecmult_gen_ctx, &ctx->ecmult_gen2_ctx, &rj, &sec, value);
		if (!secp256k1_gej_is_infinity(&rj)) {
			secp256k1_ge_set_gej(&r, &rj);
			sz = 33;
			ret = secp256k1_eckey_pubkey_serialize(&r, commit, &sz, 1);
		}
		secp256k1_gej_clear(&rj);
		secp256k1_ge_clear(&r);
	}
	secp256k1_scalar_clear(&sec);
	return ret;
}

/** Takes a list of n pointers to 32 byte blinding values, the first negs of which are treated with positive sign and the rest
*  negative, then calculates an additional blinding value that adds to zero.
*/
int secp256k1_pedersen_blind_sum(const secp256k1_context* ctx, unsigned char *blind_out, const unsigned char * const *blinds, int n, int npositive) {
	secp256k1_scalar acc;
	secp256k1_scalar x;
	int i;
	int overflow;
	VERIFY_CHECK(ctx != NULL);
	ARG_CHECK(blind_out != NULL);
	ARG_CHECK(blinds != NULL);
	secp256k1_scalar_set_int(&acc, 0);
	for (i = 0; i < n; i++) {
		secp256k1_scalar_set_b32(&x, blinds[i], &overflow);
		if (overflow) {
			return 0;
		}
		if (i >= npositive) {
			secp256k1_scalar_negate(&x, &x);
		}
		secp256k1_scalar_add(&acc, &acc, &x);
	}
	secp256k1_scalar_get_b32(blind_out, &acc);
	secp256k1_scalar_clear(&acc);
	secp256k1_scalar_clear(&x);
	return 1;
}

/* Takes two list of 33-byte commitments and sums the first set and subtracts the second and verifies that they sum to excess. */
int secp256k1_pedersen_verify_tally(const secp256k1_context* ctx, const unsigned char * const *commits, int pcnt,
	const unsigned char * const *ncommits, int ncnt, int64_t excess) {
	secp256k1_gej accj;
	secp256k1_ge add;
	int i;
	VERIFY_CHECK(ctx != NULL);
	ARG_CHECK(!pcnt || (commits != NULL));
	ARG_CHECK(!ncnt || (ncommits != NULL));
	VERIFY_CHECK(secp256k1_ecmult_gen2_context_is_built(&ctx->ecmult_gen2_ctx));
	secp256k1_gej_set_infinity(&accj);
	if (excess) {
		uint64_t ex;
		int neg;
		/* Take the absolute value, and negate the result if the input was negative. */
		neg = secp256k1_sign_and_abs64(&ex, excess);
		secp256k1_ecmult_gen2_small(&ctx->ecmult_gen2_ctx, &accj, ex);
		if (neg) {
			secp256k1_gej_neg(&accj, &accj);
		}
	}
	for (i = 0; i < ncnt; i++) {
		if (!secp256k1_eckey_pubkey_parse(&add, ncommits[i], 33)) {
			return 0;
		}
		secp256k1_gej_add_ge_var(&accj, &accj, &add, NULL);
	}
	secp256k1_gej_neg(&accj, &accj);
	for (i = 0; i < pcnt; i++) {
		if (!secp256k1_eckey_pubkey_parse(&add, commits[i], 33)) {
			return 0;
		}
		secp256k1_gej_add_ge_var(&accj, &accj, &add, NULL);
	}
	return secp256k1_gej_is_infinity(&accj);
}


int secp256k1_rangeproof_verify(const secp256k1_context* ctx, uint64_t *min_value, uint64_t *max_value,
	const unsigned char *commit, const unsigned char *proof, int plen) {
	VERIFY_CHECK(ctx != NULL);
	ARG_CHECK(commit != NULL);
	ARG_CHECK(proof != NULL);
	ARG_CHECK(min_value != NULL);
	ARG_CHECK(max_value != NULL);
	VERIFY_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
	VERIFY_CHECK(secp256k1_ecmult_gen2_context_is_built(&ctx->ecmult_gen2_ctx));
	VERIFY_CHECK(secp256k1_rangeproof_context_is_built(&ctx->rangeproof_ctx));
	return secp256k1_rangeproof_verify_impl(&ctx->ecmult_ctx, NULL, &ctx->ecmult_gen2_ctx, &ctx->rangeproof_ctx,
		NULL, NULL, NULL, NULL, NULL, min_value, max_value, commit, proof, plen);
}

int secp256k1_rangeproof_sign(const secp256k1_context* ctx, unsigned char *proof, int *plen, uint64_t min_value,
	const unsigned char *commit, const unsigned char *blind, const unsigned char *nonce, int exp, int min_bits, uint64_t value) {
	VERIFY_CHECK(ctx != NULL);
	ARG_CHECK(proof != NULL);
	ARG_CHECK(plen != NULL);
	ARG_CHECK(commit != NULL);
	ARG_CHECK(blind != NULL);
	ARG_CHECK(nonce != NULL);
	VERIFY_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
	VERIFY_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
	VERIFY_CHECK(secp256k1_ecmult_gen2_context_is_built(&ctx->ecmult_gen2_ctx));
	VERIFY_CHECK(secp256k1_rangeproof_context_is_built(&ctx->rangeproof_ctx));
	return secp256k1_rangeproof_sign_impl(&ctx->ecmult_ctx, &ctx->ecmult_gen_ctx, &ctx->ecmult_gen2_ctx, &ctx->rangeproof_ctx,
		proof, plen, min_value, commit, blind, nonce, exp, min_bits, value);
}

int secp256k1_rangeproof_rewind(const secp256k1_context* ctx,
	unsigned char *blind_out, uint64_t *value_out, unsigned char *message_out, int *outlen, const unsigned char *nonce,
	uint64_t *min_value, uint64_t *max_value,
	const unsigned char *commit, const unsigned char *proof, int plen) {
	VERIFY_CHECK(ctx != NULL);
	ARG_CHECK(commit != NULL);
	ARG_CHECK(proof != NULL);
	ARG_CHECK(min_value != NULL);
	ARG_CHECK(max_value != NULL);
	VERIFY_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
	VERIFY_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
	VERIFY_CHECK(secp256k1_ecmult_gen2_context_is_built(&ctx->ecmult_gen2_ctx));
	VERIFY_CHECK(secp256k1_rangeproof_context_is_built(&ctx->rangeproof_ctx));
	return secp256k1_rangeproof_verify_impl(&ctx->ecmult_ctx, &ctx->ecmult_gen_ctx, &ctx->ecmult_gen2_ctx, &ctx->rangeproof_ctx,
		blind_out, value_out, message_out, outlen, nonce, min_value, max_value, commit, proof, plen);
}

int secp256k1_rangeproof_info(const secp256k1_context* ctx, int *exp, int *mantissa,
	uint64_t *min_value, uint64_t *max_value, const unsigned char *proof, int plen) {
	int offset;
	uint64_t scale;
	ARG_CHECK(exp != NULL);
	ARG_CHECK(mantissa != NULL);
	ARG_CHECK(min_value != NULL);
	ARG_CHECK(max_value != NULL);
	offset = 0;
	scale = 1;
	(void)ctx;
	return secp256k1_rangeproof_getheader_impl(&offset, exp, mantissa, &scale, min_value, max_value, proof, plen);
}


#ifdef ENABLE_MODULE_ECDH
# include "modules/ecdh/main_impl.h"
#endif

#ifdef ENABLE_MODULE_RECOVERY
# include "modules/recovery/main_impl.h"
#endif
