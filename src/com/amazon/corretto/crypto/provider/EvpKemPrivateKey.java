// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

import com.amazon.corretto.crypto.provider.EvpKey.CanDerivePublicKey;
import java.security.PrivateKey;

public class EvpKemPrivateKey extends EvpKemKey
    implements PrivateKey, CanDerivePublicKey<EvpKemPublicKey> {
  private static final long serialVersionUID = 1;

  EvpKemPrivateKey(InternalKey key) {
    super(key, false);
  }

  EvpKemPrivateKey(final long ptr) {
    this(new InternalKey(ptr));
  }

  // Copied from EvpEcPrivateKey
  @Override
  public EvpKemPublicKey getPublicKey() {
    // Once our internal key could be elsewhere, we can no longer safely release it when done
    ephemeral = false;
    sharedKey = true;
    final EvpKemPublicKey result = new EvpKemPublicKey(internalKey);
    result.sharedKey = true;
    return result;
  }
}
