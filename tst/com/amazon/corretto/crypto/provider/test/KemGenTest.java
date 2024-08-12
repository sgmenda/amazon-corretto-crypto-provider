// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider.test;

import static org.junit.Assert.assertNotNull;

import com.amazon.corretto.crypto.provider.EvpKemPrivateKey;
import com.amazon.corretto.crypto.provider.EvpKemPublicKey;
import com.amazon.corretto.crypto.provider.KemParameterSpec;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceAccessMode;
import org.junit.jupiter.api.parallel.ResourceLock;

@ExtendWith(TestResultLogger.class)
@Execution(ExecutionMode.CONCURRENT)
@ResourceLock(value = TestUtil.RESOURCE_GLOBAL, mode = ResourceAccessMode.READ)
public class KemGenTest {
  private KeyPairGenerator getGenerator() throws GeneralSecurityException {
    return KeyPairGenerator.getInstance("KEM", TestUtil.NATIVE_PROVIDER);
  }

  @Test
  public void testNamedSpecs() throws GeneralSecurityException {
    final KemParameterSpec[] namedSpecs = {
      KemParameterSpec.mlkem512ipd,
      KemParameterSpec.mlkem768ipd,
      KemParameterSpec.mlkem1024ipd,
      KemParameterSpec.pqt25519,
      KemParameterSpec.pqt256,
      KemParameterSpec.pqt384
    };
    for (final KemParameterSpec spec : namedSpecs) {
      final KeyPairGenerator generator = getGenerator();
      generator.initialize(spec);
      final KeyPair keyPair = generator.generateKeyPair();
      final EvpKemPublicKey pubKey = (EvpKemPublicKey) keyPair.getPublic();
      final EvpKemPrivateKey privKey = (EvpKemPrivateKey) keyPair.getPrivate();

      assertNotNull(pubKey);
      assertNotNull(privKey);
      // TODO: do more checks
    }
  }
}
