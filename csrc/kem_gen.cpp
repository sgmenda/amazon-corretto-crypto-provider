// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "auto_free.h"
#include "bn.h"
#include "buffer.h"
#include "env.h"
#include "generated-headers.h"
#include "keyutils.h"
#include "util.h"
#include <openssl/evp.h>
#include <openssl/nid.h>

using namespace AmazonCorrettoCryptoProvider;

void generateKeyFromNid(raii_env* env, EVP_PKEY_auto& key, jint nid)
{
    EVP_PKEY_CTX_auto ctx;
    ctx.set(EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, nullptr));
    CHECK_OPENSSL(ctx.isInitialized());
    CHECK_OPENSSL(EVP_PKEY_CTX_kem_set_params(ctx, nid));
    CHECK_OPENSSL(EVP_PKEY_keygen_init(ctx));
    CHECK_OPENSSL(EVP_PKEY_keygen(ctx, key.getAddressOfPtr()));
}

/*
 * Class:     com_amazon_corretto_crypto_provider_KemGen
 * Method:    generateEvpKemKeyFromSpec
 * Signature: (I)J
 */
JNIEXPORT jlong JNICALL Java_com_amazon_corretto_crypto_provider_KemGen_generateEvpKemKeyFromSpec(
    JNIEnv* pEnv, jclass, jint nid)
{
    EVP_PKEY_auto key;
    try {
        raii_env env(pEnv);
        generateKeyFromNid(&env, key, nid);
        return reinterpret_cast<jlong>(key.take());
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return 0;
    }
}
