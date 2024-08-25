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
#include <openssl/hpke.h>
#include <openssl/nid.h>

using namespace AmazonCorrettoCryptoProvider;

/*
 * Class:     com_amazon_corretto_crypto_provider_HpkeCipher
 * Method:    hpkeWrap
 * Signature: (JIIIIB[IIB[IB[I)I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_HpkeCipher_hpkeCipher(JNIEnv* pEnv,
    jclass,
    jlong keyHandle,
    jint javaCipherMode,
    jint kemId,
    jint kdfId,
    jint aeadId,
    jbyteArray input,
    jint inputOffset,
    jint inputLen,
    jbyteArray aad,
    jint aadLen,
    jbyteArray output,
    jint outputOffset)
{
    try {
        raii_env env(pEnv);

        if (!input) {
            throw_java_ex(EX_NPE, "Empty input array");
        }
        if (!output) {
            throw_java_ex(EX_NPE, "Empty output array");
        }
        if (inputLen < 0) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Negative input length");
        }
        const size_t input_length = (size_t)inputLen;

        const EVP_HPKE_KEY* key = reinterpret_cast<EVP_HPKE_KEY*>(keyHandle);
        const EVP_HPKE_KEM* kem = EVP_HPKE_KEM_find_by_id(kemId);
        const EVP_HPKE_KDF* kdf = EVP_HPKE_KDF_find_by_id(kdfId);
        const EVP_HPKE_AEAD* aead = EVP_HPKE_AEAD_find_by_id(aeadId);
        const size_t aead_overhead = EVP_AEAD_max_overhead(EVP_HPKE_AEAD_aead(aead));
        const size_t kem_overhead = EVP_HPKE_KEM_enc_len(kem);

        if (kemId != EVP_HPKE_KEM_id(EVP_HPKE_KEY_kem(key))) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "KEM in the key does not match the param");
        }

        std::vector<uint8_t> info(0);
        java_buffer aadBuf = java_buffer::from_array(env, aad, 0, aadLen);

        size_t result = -1;

        if ((javaCipherMode == 1 /* Encrypt */) || (javaCipherMode == 3 /* Wrap */)) {
            // Serialize public key
            std::vector<uint8_t> public_key_r(EVP_HPKE_KEM_public_key_len(kem));
            size_t public_key_r_len;
            CHECK_OPENSSL(EVP_HPKE_KEY_public_key(key, public_key_r.data(), &public_key_r_len, public_key_r.size()));

            // The input is the plaintext message
            java_buffer inBuf = java_buffer::from_array(env, input, inputOffset, input_length);

            // We write the enc and the ciphertext to the output buffer
            const size_t encBufLen = kem_overhead;
            const size_t ctBufLen = input_length + aead_overhead;
            const size_t outBufLen = encBufLen + ctBufLen;
            java_buffer outBuf = java_buffer::from_array(env, output, outputOffset, outBufLen);
            size_t enc_len = 0;
            size_t ct_len = 0;

            {
                jni_borrow in(env, inBuf, "input plaintext");
                jni_borrow aad(env, aadBuf, "aad");
                jni_borrow out(env, outBuf, "output enc and ciphertext");

                CHECK_OPENSSL(EVP_HPKE_seal(out.data(), &enc_len, encBufLen, out.data() + encBufLen, &ct_len, ctBufLen,
                    kem, kdf, aead, public_key_r.data(), public_key_r_len, info.data(), info.size(), in.data(),
                    in.len(), aad.data(), aad.len()));
                if (enc_len != encBufLen) {
                    throw_java_ex(EX_RUNTIME_CRYPTO, "Unexpected error, enc buffer length is wrong!");
                }
                if (ct_len != ctBufLen) {
                    throw_java_ex(EX_RUNTIME_CRYPTO, "Unexpected error, ciphertext buffer length is wrong!");
                }
                result = outBufLen;
            }
        } else if ((javaCipherMode == 2 /* Decrypt */) || (javaCipherMode == 4 /* Unwrap */)) {
            // The input is the enc and the ciphertext
            const size_t encBufLen = kem_overhead;
            if (input_length < (encBufLen + aead_overhead)) {
                throw_java_ex(EX_RUNTIME_CRYPTO, "input too short to unwrap with HPKE");
            }
            const size_t ctBufLen = input_length - encBufLen;
            java_buffer inBuf = java_buffer::from_array(env, input, inputOffset, input_length);

            // We write the plaintext message to the output buffer
            java_buffer outBuf = java_buffer::from_array(env, output, outputOffset);
            size_t msg_len = 0;
            {
                jni_borrow in(env, inBuf, "input enc and ciphertext");
                jni_borrow aad(env, aadBuf, "aad");
                jni_borrow out(env, outBuf, "output plaintext");

                CHECK_OPENSSL(EVP_HPKE_open(out.data(), &msg_len, out.len(), key, kdf, aead, in.data(), encBufLen,
                    info.data(), info.size(), in.data() + encBufLen, ctBufLen, aad.data(), aad.len()))
                result = msg_len;
            }
        } else {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unsupported cipher mode");
        }
        return (jint)result;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}

/*
 * Class:     com_amazon_corretto_crypto_provider_HpkeCipher
 * Method:    hpkeOutputSize
 * Signature: (IIIII)I
 */
JNIEXPORT jint JNICALL Java_com_amazon_corretto_crypto_provider_HpkeCipher_hpkeOutputSize(
    JNIEnv* pEnv, jclass, jint javaCipherMode, jint kemId, jint kdfId, jint aeadId, jint inputLen)
{
    const EVP_HPKE_KEM* kem = EVP_HPKE_KEM_find_by_id(kemId);
    const EVP_HPKE_AEAD* aead = EVP_HPKE_AEAD_find_by_id(aeadId);
    const size_t aead_overhead = EVP_AEAD_max_overhead(EVP_HPKE_AEAD_aead(aead));
    const size_t enc_len = EVP_HPKE_KEM_enc_len(kem);

    try {
        raii_env env(pEnv);

        if (inputLen < 0) {
            throw_java_ex(EX_RUNTIME_CRYPTO, "negative input length");
        }
        const size_t input_length = (size_t)inputLen;

        size_t ret = -1;

        if ((javaCipherMode == 1 /* Encrypt */) || (javaCipherMode == 3 /* Wrap */)) {
            // We write the enc and the ciphertext to the output buffer
            ret = input_length + enc_len + aead_overhead;
        } else if ((javaCipherMode == 2 /* Decrypt */) || (javaCipherMode == 4 /* Unwrap */)) {
            // We write the plaintext to the output buffer
            if (input_length < (enc_len + aead_overhead)) {
                throw_java_ex(EX_RUNTIME_CRYPTO, "input too short to unwrap with HPKE");
            }
            ret = (input_length - enc_len - aead_overhead);
        } else {
            throw_java_ex(EX_RUNTIME_CRYPTO, "Unsupported cipher mode");
        }
        return (jint)ret;
    } catch (java_ex& ex) {
        ex.throw_to_java(pEnv);
        return -1;
    }
}
