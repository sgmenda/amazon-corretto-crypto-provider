// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

class KemGen extends KeyPairGeneratorSpi {
  private final AmazonCorrettoCryptoProvider provider_;
  private KemParameterSpec spec = null;

  KemGen(AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    provider_ = provider;
  }

  /**
   * Generates a new KEM key and returns a pointer to it.
   *
   * @param nid NID
   */
  private static native long generateEvpKemKeyFromSpec(int nid);

  @Override
  public void initialize(final AlgorithmParameterSpec params, final SecureRandom rnd)
      throws InvalidAlgorithmParameterException {
    if (params instanceof KemParameterSpec) {
      // TODO: do validation
      spec = (KemParameterSpec) params;
    } else {
      throw new InvalidAlgorithmParameterException("Unsupported AlgorithmParameterSpec: " + spec);
    }
  }

  @Override
  public void initialize(final int keysize, final SecureRandom rnd)
      throws InvalidParameterException {
    throw new InvalidParameterException(
        "Cannot initialize a KEM key with keysize, must use AlgorithmParameterSpec.");
  }

  @Override
  public KeyPair generateKeyPair() {
    if (spec == null) {
      // TODO: support default spec?
      throw new InvalidParameterException("Spec not initialized");
    }
    final EvpKemPrivateKey privateKey =
        new EvpKemPrivateKey(generateEvpKemKeyFromSpec(spec.getNID()));
    final EvpKemPublicKey publicKey = privateKey.getPublicKey();
    return new KeyPair(publicKey, privateKey);
  }
}
