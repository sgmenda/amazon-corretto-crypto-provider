// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package com.amazon.corretto.crypto.provider;

class EvpKemKey extends EvpKey {
  private static final long serialVersionUID = 1;

  EvpKemKey(final InternalKey key, final boolean isPublicKey) {
    super(key, EvpKeyType.KEM, isPublicKey);
  }
}
