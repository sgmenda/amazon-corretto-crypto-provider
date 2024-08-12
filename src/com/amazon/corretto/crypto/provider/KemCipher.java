// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.crypto.*;

public class KemCipher extends CipherSpi {
  static {
    Loader.load();
  }

  private final AmazonCorrettoCryptoProvider provider_;
  private final Object lock_ = new Object();

  private int mode_;
  private EvpKemPrivateKey privateKey_;
  private EvpKemPublicKey publicKey_;
  private KemParameterSpec params_;

  KemCipher(AmazonCorrettoCryptoProvider provider) {
    Loader.checkNativeLibraryAvailability();
    provider_ = provider;
  }

  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (params == null) {
      throw new InvalidAlgorithmParameterException("KemCipher does not support a null parameters.");
    }
    if (!(params instanceof KemParameterSpec)) {
      throw new InvalidAlgorithmParameterException(
          "KemCipher only supports KemParameterSpec parameters.");
    }
    switch (opmode) {
      case Cipher.WRAP_MODE -> {
        if (!(key instanceof EvpKemPublicKey)) {
          throw new InvalidKeyException("WRAP_MODE can only be used with EvpKemPublicKey.");
        }
        synchronized (lock_) {
          publicKey_ = (EvpKemPublicKey) key;
          mode_ = Cipher.WRAP_MODE;
        }
      }
      case Cipher.UNWRAP_MODE -> {
        if (!(key instanceof EvpKemPrivateKey)) {
          throw new InvalidKeyException("UNWRAP_MODE can only be used with EvpKemPrivateKey.");
        }
        synchronized (lock_) {
          privateKey_ = (EvpKemPrivateKey) key;
          mode_ = Cipher.UNWRAP_MODE;
        }
      }
      default -> throw new InvalidParameterException(
          "KemCipher only supports WRAP and UNWRAP mode, given: " + opmode);
    }
  }

  private int wrapLengthBytes() {
    // TODO: implement this based on public key
    return 999;
  }

  /**
   * Does a KEM encapsulation and returns a byte array of [ciphertext] and [shared secret].
   */
  @Override
  protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
    if (key != null) {
      throw new InvalidKeyException("KemCipher cannot wrap a given Key, key must be null.");
    }
    synchronized (lock_) {
      if (publicKey_ == null) {
        throw new IllegalStateException("PublicKey should be set before wrapping.");
      }
      byte[] result = new byte[wrapLengthBytes()];

      return result;
    }
  }

  /**
   * Does a KEM decapsulation and returns a buffer containing the [shared secret].
   */
  @Override
  protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType) throws InvalidKeyException, NoSuchAlgorithmException {
    return super.engineUnwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
  }

  // Boilerplate methods
  // -------------------

  @Override
  protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
    try {
      engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
    } catch (InvalidAlgorithmParameterException e) {
      throw new InvalidKeyException(e);
    }
  }

  @Override
  protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    // Copied from RsaCipher
    try {
      engineInit(
          opmode,
          key,
          params != null ? params.getParameterSpec(KemParameterSpec.class) : null,
          random);
    } catch (final InvalidParameterSpecException e) {
      throw new InvalidAlgorithmParameterException(e);
    }
  }

  // Unsupported methods
  // -------------------

  @Override
  protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
    throw new NoSuchAlgorithmException("KemCipher does not support modes.");
  }

  @Override
  protected void engineSetPadding(String padding) throws NoSuchPaddingException {
    throw new NoSuchPaddingException("KemCipher does not support padding.");
  }

  @Override
  protected int engineGetBlockSize() {
    // Not supported
    return 0;
  }

  @Override
  protected int engineGetOutputSize(int inputLen) {
    // Not supported
    return 0;
  }

  @Override
  protected byte[] engineGetIV() {
    // Not supported
    return null;
  }

  @Override
  protected AlgorithmParameters engineGetParameters() {
    // Not supported
    // TODO: maybe implement this?
    return null;
  }

  @Override
  protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
    throw new IllegalStateException("KemCipher does not support Update.");
  }

  @Override
  protected int engineUpdate(
      byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException {
    throw new IllegalStateException("KemCipher does not support Update.");
  }

  @Override
  protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    throw new IllegalStateException("KemCipher does not support DoFinal.");
  }

  @Override
  protected int engineDoFinal(
      byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    throw new IllegalStateException("KemCipher does not support DoFinal.");
  }
}
